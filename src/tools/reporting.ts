import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SkillIndex } from '../services/skill-index.js';
import { generateFullReport, buildFindings, buildAttackNarrative, buildRemediationRanking } from '../services/report-generator.js';
import type { ReportInput } from '../services/report-generator.js';
import { renderReportHtml } from '../services/report-html.js';
import type { HtmlReportData, HtmlTimelineEntry, HtmlComplianceMapping } from '../services/report-html.js';
import { runRetrospective, buildCredentialChains } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import { classifyAllFindings, generateNavigatorLayer } from '../services/finding-classifier.js';
import { validateFilePath } from '../utils/path-validation.js';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { withErrorBoundary } from './error-boundary.js';
import { redactReportText, redactSecretKeys } from '../services/report-redaction.js';

/**
 * Phase I: scrub a fully-rendered markdown report for client delivery.
 * Strips operator-machine paths and replaces fenced evidence/raw-output
 * blocks with redaction placeholders. The structured json/html paths use
 * `redactSecretKeys` for deeper redaction; markdown gets this practical
 * regex pass so the operator-default rendering remains untouched and the
 * client variant still tells the story without leaking secrets.
 */
function scrubMarkdownForClient(md: string): string {
  let out = redactReportText(md, { client_safe: true }) ?? md;
  // Replace ``` ... ``` blocks that follow an "Output:" / "raw_output" /
  // "stdout"-style header line with a placeholder. The original block
  // content is dropped; the surrounding narrative stays.
  out = out.replace(
    /(\*\*?(?:Raw Output|Stdout(?: Preview)?|Evidence Content|Output)\*\*?:?\s*\n)```[\s\S]*?```/gi,
    '$1```\n<redacted for client delivery — full evidence available in operator report>\n```',
  );
  // Inline credential disclosures: `cred_value: ...`, `password: ...`,
  // common hash field names. We keep the key for readability.
  out = out.replace(
    /\b(cred_value|password|nt_hash|lm_hash|aes256_hash|aes128_hash|secret|token|bearer|api_key|private_key)\s*[:=]\s*([^\s,'"`<>{}]+)/gi,
    (_m, k) => `${k}: <redacted>`,
  );
  return out;
}

export function registerReportingTools(server: McpServer, engine: GraphEngine, skills: SkillIndex): void {

  // ============================================================
  // Tool: generate_report
  // Full pentest report with per-finding detail, narrative, evidence
  // ============================================================
  server.registerTool(
    'generate_report',
    {
      title: 'Generate Pentest Report',
      description: `Generate a comprehensive penetration test report from the engagement graph and activity history.

Produces a client-deliverable report with:
- **Executive summary** with severity distribution
- **Per-finding sections** — each compromised host, credential, and vulnerability gets its own section with evidence and auto-generated remediation
- **Attack narrative** — chronological prose description of the engagement phases (Recon → Initial Access → Lateral Movement → PrivEsc → Objective)
- **Compliance mapping** — CWE, OWASP Top 10, NIST 800-53, PCI DSS tables
- **MITRE ATT&CK** — technique coverage and optional Navigator layer export
- **Risk heatmap** — severity × category distribution
- **Remediation priority ranking** — CVSS × blast radius × credential exposure
- **Evidence chains** — command → tool output → graph mutation linkage for each finding
- **Credential chains** — derivation paths showing how credentials were obtained
- **Objectives status** and recommendations

Use this at the end of an engagement to produce the final deliverable report.`,
      inputSchema: {
        format: z.enum(['markdown', 'md', 'html', 'json']).default('markdown')
          .describe('Output format: markdown (or md), html, or json (structured findings data)'),
        include_evidence: z.boolean().default(true)
          .describe('Include evidence chains for each finding'),
        include_narrative: z.boolean().default(true)
          .describe('Include attack narrative section'),
        include_retrospective: z.boolean().default(false)
          .describe('Include retrospective analysis (inference gaps, skill gaps)'),
        include_compliance: z.boolean().default(true)
          .describe('Include compliance mapping (CWE, OWASP, NIST, PCI) and ATT&CK techniques'),
        include_attack_navigator: z.boolean().default(false)
          .describe('Generate ATT&CK Navigator layer JSON file (requires write_to_disk)'),
        include_gap_analysis: z.boolean().default(false)
          .describe('Include ATT&CK coverage gap analysis section in the report'),
        write_to_disk: z.boolean().default(false)
          .describe('Save report file(s) to output_dir'),
        output_dir: z.string().default('./reports/')
          .describe('Directory for output files (used when write_to_disk is true)'),
        theme: z.enum(['light', 'dark']).default('light')
          .describe('Theme for HTML output'),
        client_safe: z.boolean().default(false)
          .describe('Phase I: produce a client-deliverable variant. Strips cred_value, raw_output, stdout/stderr previews, and operator-machine paths from the rendered report. Output files get a `.client-safe.<ext>` suffix when written to disk. Defaults to false so the operator-internal report is unchanged.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('generate_report', async ({
      format: rawFormat, include_evidence, include_narrative,
      include_retrospective, include_compliance, include_attack_navigator,
      include_gap_analysis, write_to_disk, output_dir, theme, client_safe,
    }) => {
      const format = rawFormat === 'md' ? 'markdown' : rawFormat;
      const redactionOpts = { client_safe: client_safe === true };
      const config = engine.getConfig();
      const graph = engine.exportGraph();
      const history = engine.getFullHistory();
      const agents = engine.getAllAgents();

      let retrospective: ReportInput['retrospective'];
      if (include_retrospective) {
        const inferenceRules = engine.getInferenceRules();
        const allSkills = skills.listSkills();
        const retroInput: RetrospectiveInput = {
          config, graph, history, inferenceRules, agents,
          skillNames: allSkills.map(s => s.name),
          skillTags: allSkills.flatMap(s => s.tags),
        };
        const result = runRetrospective(retroInput);
        retrospective = {
          inference_suggestions: result.inference_suggestions,
          skill_gaps: result.skill_gaps,
          context_improvements: result.context_improvements,
          trace_quality: result.trace_quality,
        };
      }

      const reportInput: ReportInput = {
        config, graph, history, agents, retrospective,
      };

      // F9: wire the evidence store loader so markdown/html previews can
      // include head/tail snippets of captured stdout for findings whose
      // action recorded a `stdout_evidence_id`. Without this, reports cite
      // evidence IDs but never inline the proof preview.
      const evidenceLoader = (id: string): string | null => {
        try {
          return engine.getEvidenceStore().getRawOutput(id);
        } catch {
          return null;
        }
      };

      const options = {
        include_evidence, include_narrative, include_retrospective,
        include_compliance, include_attack_navigator, include_gap_analysis,
        evidence_loader: evidenceLoader,
      };
      const rawMarkdown = generateFullReport(reportInput, options);
      // Phase I: redact operator paths post-generation. Evidence-blob redaction
      // for client_safe=true happens via redactSecretKeys on the structured
      // findings (json/html paths) and via a markdown-targeted regex pass.
      const markdown = redactionOpts.client_safe
        ? scrubMarkdownForClient(rawMarkdown)
        : rawMarkdown;

      // Build JSON structured output for 'json' format
      let jsonOutput: string | undefined;
      if (format === 'json') {
        const rawFindings = buildFindings(graph, history, config, { evidenceLoader });
        const classifications = classifyAllFindings(rawFindings, graph);
        const navigatorLayer = include_attack_navigator
          ? generateNavigatorLayer(rawFindings, graph, config.name)
          : undefined;
        const remRanking = buildRemediationRanking(rawFindings, graph);

        const jsonPayload = {
          engagement: { id: config.id, name: config.name },
          findings: rawFindings.map(f => ({
            ...f,
            classification: classifications.get(f.id) ?? f.classification,
          })),
          remediation_ranking: remRanking,
          ...(navigatorLayer ? { attack_navigator_layer: navigatorLayer } : {}),
        };
        const finalJson = redactionOpts.client_safe ? redactSecretKeys(jsonPayload, redactionOpts) : jsonPayload;
        jsonOutput = JSON.stringify(finalJson, null, 2);
      }

      let html: string | undefined;
      if (format === 'html') {
        // R2-7: thread the same evidenceLoader used for markdown so HTML
        // findings include head/tail stdout previews and streamed-evidence
        // diagnostics. Without this, the HTML deliverable cited
        // stdout_evidence_id but never inlined the proof preview.
        const htmlFindings = buildFindings(graph, history, config, { evidenceLoader });
        const htmlNarrative = include_narrative ? buildAttackNarrative(graph, history, config) : [];
        const credentialChains = buildCredentialChains(graph);

        const nodesByType: Record<string, number> = {};
        for (const n of graph.nodes) {
          nodesByType[n.properties.type] = (nodesByType[n.properties.type] || 0) + 1;
        }
        const edgesByType: Record<string, number> = {};
        let confirmed = 0;
        let inferred = 0;
        for (const e of graph.edges) {
          edgesByType[e.properties.type] = (edgesByType[e.properties.type] || 0) + 1;
          if (e.properties.confidence >= 1.0) confirmed++;
          else inferred++;
        }

        const completedAgents = agents.filter(a => a.status === 'completed').length;
        const failedAgents = agents.filter(a => a.status === 'failed').length;

        const maxTimeline = 50;
        const timelineEntries: HtmlTimelineEntry[] = history.slice(-maxTimeline).map(entry => ({
          timestamp: entry.timestamp,
          description: entry.description,
          agent_id: entry.agent_id,
        }));

        const recs: string[] = [];
        const highPriority = htmlFindings
          .filter(f => f.severity === 'critical' || f.severity === 'high')
          .slice(0, 10);
        for (const f of highPriority) {
          recs.push(`**${f.title}:** ${f.remediation.split('\n')[0]}`);
        }
        const untestedInferred = graph.edges.filter(e => e.properties.confidence < 1.0 && !e.properties.tested);
        if (untestedInferred.length > 0) {
          recs.push(`**${untestedInferred.length} inferred edge(s) remain untested** — these represent potential attack paths not validated during the engagement.`);
        }
        const pendingObjectives = config.objectives.filter(o => !o.achieved);
        if (pendingObjectives.length > 0) {
          recs.push(`**${pendingObjectives.length} objective(s) not achieved** — ${pendingObjectives.map(o => o.description).join(', ')}.`);
        }

        const htmlData: HtmlReportData = {
          config, graph,
          findings: htmlFindings,
          narrative: htmlNarrative,
          credentialChains,
          discoveryStats: { nodesByType, edgesByType, confirmed, inferred },
          agents: { total: agents.length, completed: completedAgents, failed: failedAgents },
          timeline: timelineEntries,
          recommendations: recs,
        };

        // Build heatmap data
        if (htmlFindings.length > 0) {
          const categories = [...new Set(htmlFindings.map(f => f.category))];
          const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
          const matrix = categories.map(cat =>
            severities.map(s => htmlFindings.filter(f => f.category === cat && f.severity === s).length)
          );
          htmlData.heatmap = { categories, severities: [...severities], matrix };
        }

        // Build remediation ranking
        const remRanking = buildRemediationRanking(htmlFindings, graph);
        if (remRanking.length > 0) {
          htmlData.remediationRanking = remRanking;
        }

        // Build compliance mapping
        if (include_compliance && htmlFindings.some(f => f.classification)) {
          const compliance: HtmlComplianceMapping = {};

          const cweFindngs = htmlFindings.filter(f => f.classification?.cwe);
          if (cweFindngs.length > 0) {
            compliance.cwe_findings = cweFindngs.map(f => ({
              title: f.title,
              cwe: f.classification!.cwe!,
              cwe_name: f.classification!.cwe_name || '',
            }));
          }

          const owaspMap = new Map<string, number>();
          for (const f of htmlFindings) {
            if (f.classification?.owasp_category) {
              owaspMap.set(f.classification.owasp_category, (owaspMap.get(f.classification.owasp_category) || 0) + 1);
            }
          }
          if (owaspMap.size > 0) {
            compliance.owasp_groups = [...owaspMap.entries()].map(([category, count]) => ({ category, count }));
          }

          const nistMap = new Map<string, number>();
          for (const f of htmlFindings) {
            if (f.classification) {
              for (const ctrl of f.classification.nist_controls) {
                nistMap.set(ctrl, (nistMap.get(ctrl) || 0) + 1);
              }
            }
          }
          if (nistMap.size > 0) {
            compliance.nist_controls = [...nistMap.entries()]
              .sort((a, b) => b[1] - a[1]).slice(0, 20)
              .map(([control, count]) => ({ control, count }));
          }

          const pciMap = new Map<string, number>();
          for (const f of htmlFindings) {
            if (f.classification) {
              for (const req of f.classification.pci_requirements) {
                pciMap.set(req, (pciMap.get(req) || 0) + 1);
              }
            }
          }
          if (pciMap.size > 0) {
            compliance.pci_requirements = [...pciMap.entries()]
              .sort((a, b) => b[1] - a[1]).slice(0, 20)
              .map(([requirement, count]) => ({ requirement, count }));
          }

          htmlData.complianceMapping = compliance;
        }

        // Build ATT&CK techniques
        if (include_compliance) {
          const techMap = new Map<string, { name: string; count: number }>();
          for (const f of htmlFindings) {
            if (!f.classification) continue;
            for (const t of f.classification.attack_techniques) {
              const existing = techMap.get(t.id);
              if (existing) existing.count++;
              else techMap.set(t.id, { name: t.name, count: 1 });
            }
          }
          if (techMap.size > 0) {
            htmlData.attackTechniques = [...techMap.entries()]
              .sort((a, b) => b[1].count - a[1].count)
              .map(([id, { name, count }]) => ({ id, name, count }));
          }
        }
        if (retrospective) {
          htmlData.retrospective = {
            context_improvements: retrospective.context_improvements ? {
              frontier_observations: retrospective.context_improvements.frontier_observations.map(o => ({
                area: o.area, observation: o.observation, confidence: o.confidence,
              })),
              context_gaps: retrospective.context_improvements.context_gaps.map(g => ({
                area: g.area, gap: g.gap, recommendation: g.recommendation,
              })),
            } : undefined,
            inference_suggestions: retrospective.inference_suggestions?.map(s => ({
              rule: { name: s.rule.name }, evidence: s.evidence,
            })),
            skill_gaps: retrospective.skill_gaps ? {
              missing_skills: retrospective.skill_gaps.missing_skills,
              failed_techniques: retrospective.skill_gaps.failed_techniques,
            } : undefined,
            trace_quality: retrospective.trace_quality ? {
              total_actions: retrospective.trace_quality.total_actions,
              with_frontier_id: retrospective.trace_quality.structured_count,
              with_action_id: retrospective.trace_quality.structured_count + retrospective.trace_quality.mixed_count,
              coverage_pct: retrospective.trace_quality.total_actions > 0
                ? Math.round(((retrospective.trace_quality.structured_count + retrospective.trace_quality.mixed_count) / retrospective.trace_quality.total_actions) * 100)
                : 0,
            } : undefined,
          };
        }
        const renderData = redactionOpts.client_safe ? redactSecretKeys(htmlData, redactionOpts) : htmlData;
        html = renderReportHtml(renderData, { theme, include_toc: true, include_compliance });
      }

      const output = format === 'html' ? html! : format === 'json' ? jsonOutput! : markdown;

      if (write_to_disk) {
        let validatedDir: string;
        try {
          validatedDir = validateFilePath(join(output_dir, config.id));
        } catch (error) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Invalid output_dir: ${error instanceof Error ? error.message : String(error)}` }, null, 2) }],
            isError: true,
          };
        }
        if (!existsSync(validatedDir)) {
          mkdirSync(validatedDir, { recursive: true });
        }
        // Phase I: client-safe variants get a `.client-safe.<ext>` suffix so
        // the operator-internal and client-deliverable versions are visually
        // distinct on disk.
        const suffix = redactionOpts.client_safe ? '.client-safe' : '';
        writeFileSync(join(validatedDir, `report${suffix}.md`), markdown);
        if (html) {
          writeFileSync(join(validatedDir, `report${suffix}.html`), html);
        }
        if (jsonOutput) {
          writeFileSync(join(validatedDir, `report${suffix}.json`), jsonOutput);
        }
        if (include_attack_navigator) {
          const navFindings = buildFindings(graph, history, config);
          const navLayer = generateNavigatorLayer(navFindings, graph, config.name);
          writeFileSync(join(validatedDir, 'attack-navigator.json'), JSON.stringify(navLayer, null, 2));
        }
      }

      const findings = buildFindings(graph, history, config);
      const criticalCount = findings.filter(f => f.severity === 'critical').length;
      const highCount = findings.filter(f => f.severity === 'high').length;

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            format,
            findings_count: findings.length,
            severity_summary: {
              critical: criticalCount,
              high: highCount,
              medium: findings.filter(f => f.severity === 'medium').length,
              low: findings.filter(f => f.severity === 'low').length,
              info: findings.filter(f => f.severity === 'info').length,
            },
            report_preview: output.slice(0, 800) + (output.length > 800 ? '...' : ''),
            report_length: output.length,
            ...(write_to_disk ? { output_dir: join(output_dir, config.id) } : {}),
          }, null, 2),
        }],
      };
    })
  );
}
