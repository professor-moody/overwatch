import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SkillIndex } from '../services/skill-index.js';
import { generateFullReport, buildFindings, buildAttackNarrative } from '../services/report-generator.js';
import type { ReportInput } from '../services/report-generator.js';
import { renderReportHtml } from '../services/report-html.js';
import type { HtmlReportData, HtmlTimelineEntry } from '../services/report-html.js';
import { runRetrospective, buildCredentialChains } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { withErrorBoundary } from './error-boundary.js';

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
- **Evidence chains** — command → tool output → graph mutation linkage for each finding
- **Credential chains** — derivation paths showing how credentials were obtained
- **Objectives status** and recommendations

Use this at the end of an engagement to produce the final deliverable report.`,
      inputSchema: {
        format: z.enum(['markdown', 'html']).default('markdown')
          .describe('Output format: markdown or styled HTML'),
        include_evidence: z.boolean().default(true)
          .describe('Include evidence chains for each finding'),
        include_narrative: z.boolean().default(true)
          .describe('Include attack narrative section'),
        include_retrospective: z.boolean().default(false)
          .describe('Include retrospective analysis (inference gaps, skill gaps)'),
        write_to_disk: z.boolean().default(false)
          .describe('Save report file(s) to output_dir'),
        output_dir: z.string().default('./reports/')
          .describe('Directory for output files (used when write_to_disk is true)'),
        theme: z.enum(['light', 'dark']).default('light')
          .describe('Theme for HTML output'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('generate_report', async ({
      format, include_evidence, include_narrative,
      include_retrospective, write_to_disk, output_dir, theme,
    }) => {
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

      const options = { include_evidence, include_narrative, include_retrospective };
      const markdown = generateFullReport(reportInput, options);

      let html: string | undefined;
      if (format === 'html') {
        const htmlFindings = buildFindings(graph, history, config);
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
              total_actions: 0, with_frontier_id: 0, with_action_id: 0, coverage_pct: 0,
            } : undefined,
          };
        }
        html = renderReportHtml(htmlData, { theme, include_toc: true });
      }

      const output = format === 'html' ? html! : markdown;

      if (write_to_disk) {
        const dir = join(output_dir, config.id);
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        writeFileSync(join(dir, 'report.md'), markdown);
        if (html) {
          writeFileSync(join(dir, 'report.html'), html);
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
