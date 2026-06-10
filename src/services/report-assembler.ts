// ============================================================
// Report assembler: shared "engine → rendered output" helper used by
// both the `generate_report` MCP tool and the dashboard's
// `POST /api/reports/render` endpoint. Keeps a single source of truth
// for which options drive the markdown / HTML / JSON pipeline so the
// dashboard can't drift out of sync with the CLI.
//
// Out of scope here: write-to-disk, response shaping. Both callers do
// their own thing with the assembled output.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { SkillIndex } from './skill-index.js';
import {
  generateFullReport, buildFindings, buildAttackNarrative, buildRemediationRanking,
  buildAttackPaths,
  buildReportEvidenceModel,
} from './report-generator.js';
import type { ReportInput, AttackPath, ReportProfile, EvidenceStyle, ReportOptions } from './report-generator.js';
import type { HtmlReportData, HtmlTimelineEntry } from './report-html.js';
import type { HtmlComplianceMapping } from './report-html.js';
import { renderReportHtml } from './report-html.js';
import { runRetrospective, buildCredentialChains } from './retrospective.js';
import type { RetrospectiveInput } from './retrospective.js';
import { classifyAllFindings, generateNavigatorLayer } from './finding-classifier.js';
import { redactReportText, redactSecretKeys } from './report-redaction.js';
import { buildTrustSignalsResponse } from './trust-signal-summary.js';
import type { TrustSignalDto } from './trust-signal-summary.js';
import { displayFindingCategory, displayFindingShortTitle, displayFindingTitle } from './finding-presentation.js';
import { buildActionPlan, buildExecutiveSummary } from './report-deliverable.js';

export type ReportFormat = 'markdown' | 'html' | 'json';
/** Format the dashboard / generate_report tool can request, including PDF (which is rendered from HTML by `renderReportPdf`). */
export type RenderFormat = ReportFormat | 'pdf';

export interface AssembleOptions {
  format: ReportFormat;
  include_evidence?: boolean;
  include_narrative?: boolean;
  include_retrospective?: boolean;
  include_compliance?: boolean;
  include_attack_navigator?: boolean;
  include_gap_analysis?: boolean;
  include_attack_paths?: boolean;
  max_paths_per_objective?: number;
  theme?: 'light' | 'dark';
  client_safe?: boolean;
  profile?: ReportProfile;
  evidence_style?: EvidenceStyle;
}

export interface AssembledReport {
  format: ReportFormat;
  /** Rendered output in the requested format. UTF-8 string. */
  content: string;
  /** Findings count (after build, pre-redaction filtering — these are the same set the renderer used). */
  findings_count: number;
  evidence_count: number;
  profile: ReportProfile;
  redaction_mode: 'operator' | 'client_safe';
  navigator_layer?: unknown;
  severity_summary: { critical: number; high: number; medium: number; low: number; info: number };
}

function scrubMarkdownForClient(md: string): string {
  let out = redactReportText(md, { client_safe: true }) ?? md;
  out = out.replace(
    /(\*\*?(?:Raw Output|Stdout(?: Preview)?|Evidence Content|Output)\*\*?:?\s*\n)```[\s\S]*?```/gi,
    '$1```\n<redacted for client delivery — full evidence available in operator report>\n```',
  );
  out = out.replace(
    /\b(cred_value|password|nt_hash|lm_hash|aes256_hash|aes128_hash|secret|token|bearer|api_key|private_key)\s*[:=]\s*([^\s,'"`<>{}]+)/gi,
    (_m, k) => `${k}: <redacted>`,
  );
  return out;
}

function appendTrustSignalNotes(md: string, signals: TrustSignalDto[]): string {
  if (signals.length === 0) return md;
  const lines = [
    '',
    '## Operator Verification Notes',
    '',
    'The following tool-output or scoring caveats were present when this report was generated. They are not standalone findings; use them to verify parser coverage, path completeness, and estimated severity before treating absence of evidence as final.',
    '',
    '| Severity | Signal | Context |',
    '|----------|--------|---------|',
  ];
  for (const signal of signals.slice(0, 20)) {
    const context = [
      signal.source_event?.event_type,
      signal.action_id ? `action ${signal.action_id.slice(0, 8)}` : undefined,
      signal.finding_id ? `finding ${signal.finding_id}` : undefined,
      signal.node_ids?.length ? `nodes ${signal.node_ids.slice(0, 3).join(', ')}` : undefined,
    ].filter(Boolean).join(' · ') || signal.source;
    const detail = signal.detail ? `${signal.label}: ${signal.detail}` : signal.label;
    lines.push(`| ${signal.severity} | ${escapeMarkdownTable(detail)} | ${escapeMarkdownTable(context)} |`);
  }
  if (signals.length > 20) {
    lines.push(`| info | ${signals.length - 20} additional verification signal(s) omitted from this section | See dashboard Activity and Findings panels |`);
  }
  lines.push('');
  return `${md.trimEnd()}\n${lines.join('\n')}`;
}

function escapeMarkdownTable(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

/**
 * Assemble a rendered report from current engine state + options.
 * Pure function — does not write to disk or persist to archive.
 */
export function assembleReport(
  engine: GraphEngine,
  skills: SkillIndex,
  opts: AssembleOptions,
): AssembledReport {
  const {
    format,
    include_evidence = true,
    include_narrative = true,
    include_retrospective = false,
    include_compliance = true,
    include_attack_navigator = false,
    include_gap_analysis = false,
    include_attack_paths = true,
    max_paths_per_objective = 3,
    theme = 'light',
    client_safe = false,
    evidence_style = 'proof_cards',
  } = opts;

  const profile: ReportProfile = opts.profile ?? (client_safe ? 'client' : 'operator');
  const effectiveClientSafe = client_safe || profile === 'client';
  const redactionOpts = { client_safe: effectiveClientSafe };
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

  let attackPaths: AttackPath[] | undefined;
  if (include_attack_paths) {
    const all: AttackPath[] = [];
    for (const obj of config.objectives) {
      const raw = engine.findPathsToObjective(obj.id, max_paths_per_objective);
      if (raw.length === 0) continue;
      all.push(...buildAttackPaths(raw, graph, {
        objective_id: obj.id,
        objective_label: obj.description,
      }));
    }
    if (all.length > 0) attackPaths = all;
  }

  const reportInput: ReportInput = {
    config, graph, history, agents, retrospective,
    attack_paths: attackPaths,
  };

  const evidenceLoader = (id: string): string | null => {
    try { return engine.getEvidenceStore().getRawOutput(id); } catch { return null; }
  };
  const evidenceRecordLoader: NonNullable<ReportOptions['evidence_record_loader']> = (id: string) => {
    try { return engine.getEvidenceStore().getRecord(id); } catch { return undefined; }
  };

  const renderOptions = {
    include_evidence, include_narrative, include_retrospective,
    include_compliance, include_attack_navigator, include_gap_analysis,
    evidence_loader: evidenceLoader,
    evidence_record_loader: evidenceRecordLoader,
    report_profile: profile,
    evidence_style,
  };

  const baseFindings = buildFindings(graph, history, config, { evidenceLoader, evidenceRecordLoader });
  const proofModel = buildReportEvidenceModel(baseFindings, { profile, includeEvidence: include_evidence });
  const findings = proofModel.findings;
  const trustSignalSummary = buildTrustSignalsResponse({ history, findings });
  const executiveSummary = buildExecutiveSummary({
    config,
    graph,
    findings,
    profile,
    evidenceCount: proofModel.evidenceCount,
    trustSignals: trustSignalSummary.signals,
  });
  const actionPlan = buildActionPlan({
    config,
    graph,
    findings,
    profile,
    evidenceCount: proofModel.evidenceCount,
    trustSignals: trustSignalSummary.signals,
  });
  const rawMarkdown = appendTrustSignalNotes(generateFullReport(reportInput, {
    ...renderOptions,
    trust_signals: trustSignalSummary.signals,
  }), trustSignalSummary.signals);
  const markdown = redactionOpts.client_safe ? scrubMarkdownForClient(rawMarkdown) : rawMarkdown;
  const severitySummary = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  let content: string;
  const navigatorLayer = include_attack_navigator
    ? generateNavigatorLayer(findings, graph, config.name)
    : undefined;
  if (format === 'json') {
    const classifications = classifyAllFindings(findings, graph);
    const remRanking = buildRemediationRanking(findings, graph);
    const jsonPayload = {
      engagement: { id: config.id, name: config.name },
      findings: findings.map(f => ({
        ...f,
        classification: classifications.get(f.id) ?? f.classification,
      })),
      report_profile: profile,
      evidence_style,
      executive_summary: executiveSummary,
      action_plan: actionPlan,
      evidence_appendix: proofModel.appendix,
      trust_signals: trustSignalSummary.signals,
      remediation_ranking: remRanking,
      attack_paths: attackPaths,
      ...(navigatorLayer ? { attack_navigator_layer: navigatorLayer } : {}),
    };
    const finalJson = redactionOpts.client_safe ? redactSecretKeys(jsonPayload, redactionOpts) : jsonPayload;
    content = JSON.stringify(finalJson, null, 2);
  } else if (format === 'html') {
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
      const isInferred = !!e.properties.inferred_by_rule && !e.properties.confirmed_at;
      if (isInferred) inferred++;
      else confirmed++;
    }

    const completedAgents = agents.filter(a => a.status === 'completed').length;
    const failedAgents = agents.filter(a => a.status === 'failed').length;

    const maxTimeline = 50;
    const timelineEntries: HtmlTimelineEntry[] = history.slice(-maxTimeline).map(entry => ({
      timestamp: entry.timestamp,
      description: entry.description,
      agent_id: entry.agent_id,
    }));

    const htmlData: HtmlReportData = {
      config, graph,
      findings,
      narrative: htmlNarrative,
      credentialChains,
      discoveryStats: { nodesByType, edgesByType, confirmed, inferred },
      agents: { total: agents.length, completed: completedAgents, failed: failedAgents },
      timeline: timelineEntries,
      executiveSummary,
      actionPlan,
      trustSignals: trustSignalSummary.signals,
      evidenceAppendix: proofModel.appendix,
      reportProfile: profile,
      evidenceStyle: evidence_style,
    };

    if (findings.length > 0) {
      const categories = [...new Set(findings.map(f => f.category))];
      const severities: Array<'critical' | 'high' | 'medium' | 'low' | 'info'> = ['critical', 'high', 'medium', 'low', 'info'];
      const matrix = categories.map(cat =>
        severities.map(s => findings.filter(f => f.category === cat && f.severity === s).length),
      );
      htmlData.heatmap = { categories: categories.map(displayFindingCategory), severities, matrix };
    }

    if (include_compliance && findings.length > 0) {
      const classifications = classifyAllFindings(findings, graph);
      // Stamp classification onto each finding so the renderer's
      // per-finding views can read it; also build the rolled-up
      // complianceMapping struct.
      for (const f of findings) {
        const c = classifications.get(f.id);
        if (c) f.classification = c;
      }

      const compliance: HtmlComplianceMapping = {};
      const cweFindings = findings.filter(f => f.classification?.cwe);
      if (cweFindings.length > 0) {
        compliance.cwe_findings = cweFindings.map(f => ({
          title: profile === 'client' ? displayFindingShortTitle(f) : displayFindingTitle(f),
          cwe: f.classification!.cwe!,
          cwe_name: f.classification!.cwe_name || '',
        }));
      }
      const owaspMap = new Map<string, number>();
      for (const f of findings) {
        if (f.classification?.owasp_category) {
          owaspMap.set(f.classification.owasp_category, (owaspMap.get(f.classification.owasp_category) || 0) + 1);
        }
      }
      if (owaspMap.size > 0) {
        compliance.owasp_groups = [...owaspMap.entries()].map(([category, count]) => ({ category, count }));
      }
      const nistMap = new Map<string, number>();
      for (const f of findings) {
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
      for (const f of findings) {
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

      // Roll up ATT&CK techniques across all classifications.
      const techMap = new Map<string, { name: string; count: number }>();
      for (const f of findings) {
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
    content = renderReportHtml(renderData as HtmlReportData, { theme, include_toc: true, include_compliance });
  } else {
    content = markdown;
  }

  return {
    format,
    content,
    findings_count: findings.length,
    evidence_count: proofModel.evidenceCount,
    profile,
    redaction_mode: effectiveClientSafe ? 'client_safe' : 'operator',
    navigator_layer: navigatorLayer,
    severity_summary: severitySummary,
  };
}
