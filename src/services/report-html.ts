// ============================================================
// Overwatch — HTML Report Renderer
// Converts structured report data into a styled, self-contained
// HTML document suitable for client delivery.
// ============================================================

import { createHash } from 'crypto';
import type { ReportFinding, NarrativePhase, FindingSeverity, EvidenceProofCard, EvidenceAppendixEntry } from './report-generator.js';
import type { EngagementConfig, ExportedGraph } from '../types.js';
import type { CredentialChain } from './retrospective.js';
import type { TrustSignalDto } from './trust-signal-summary.js';

export interface HtmlDiscoveryStats {
  nodesByType: Record<string, number>;
  edgesByType: Record<string, number>;
  confirmed: number;
  inferred: number;
}

export interface HtmlAgentStats {
  total: number;
  completed: number;
  failed: number;
}

export interface HtmlRetrospective {
  context_improvements?: { frontier_observations: { area: string; observation: string; confidence: string }[]; context_gaps: { area: string; gap: string; recommendation: string }[] };
  inference_suggestions?: { rule: { name: string }; evidence: string }[];
  skill_gaps?: { missing_skills: string[]; failed_techniques: string[] };
  trace_quality?: { total_actions: number; with_frontier_id: number; with_action_id: number; coverage_pct: number };
}

export interface HtmlTimelineEntry {
  timestamp: string;
  description: string;
  agent_id?: string;
}

export interface HtmlReportData {
  config: EngagementConfig;
  graph: ExportedGraph;
  findings: ReportFinding[];
  narrative: NarrativePhase[];
  credentialChains?: CredentialChain[];
  discoveryStats?: HtmlDiscoveryStats;
  agents?: HtmlAgentStats;
  retrospective?: HtmlRetrospective;
  timeline?: HtmlTimelineEntry[];
  recommendations?: string[];
  heatmap?: HtmlHeatmapData;
  remediationRanking?: HtmlRemediationRanking[];
  complianceMapping?: HtmlComplianceMapping;
  attackTechniques?: HtmlAttackTechnique[];
  trustSignals?: TrustSignalDto[];
  evidenceAppendix?: EvidenceAppendixEntry[];
  reportProfile?: 'operator' | 'client';
  evidenceStyle?: 'proof_cards' | 'appendix' | 'full_inline';
}

export interface HtmlHeatmapData {
  categories: string[];
  severities: FindingSeverity[];
  matrix: number[][];  // [category_idx][severity_idx] = count
}

export interface HtmlRemediationRanking {
  title: string;
  cvss: number;
  cvss_estimated: boolean;
  blast_radius: number;
  cred_exposure: number;
  priority_score: number;
}

export interface HtmlComplianceMapping {
  cwe_findings?: { title: string; cwe: string; cwe_name: string }[];
  owasp_groups?: { category: string; count: number }[];
  nist_controls?: { control: string; count: number }[];
  pci_requirements?: { requirement: string; count: number }[];
}

export interface HtmlAttackTechnique {
  id: string;
  name: string;
  count: number;
}

export interface HtmlReportOptions {
  theme?: 'light' | 'dark';
  include_toc?: boolean;
  include_compliance?: boolean;
}

// ============================================================
// Main Renderer
// ============================================================

export function renderReportHtml(data: HtmlReportData, options: HtmlReportOptions = {}): string {
  const { theme = 'light', include_toc = true } = options;
  const config = data.config;
  const findings = [...data.findings].sort((a, b) => b.risk_score - a.risk_score);
  const narrative = data.narrative;

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;

  const objectivesAchieved = config.objectives.filter(o => o.achieved).length;
  const generatedAt = new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="en" data-theme="${theme === 'dark' ? 'dark' : 'light'}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pentest Report: ${esc(config.name)}</title>
  <style>${CSS_STYLES}</style>
</head>
<body>
  <header class="report-header">
    <h1>Penetration Test Report</h1>
    <p class="engagement-name">${esc(config.name)}</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Engagement ID</span><span class="meta-value">${esc(config.id)}</span></div>
      <div class="meta-item"><span class="meta-label">OPSEC Profile</span><span class="meta-value">${esc(config.opsec.name)} (noise: ${config.opsec.max_noise})</span></div>
      <div class="meta-item"><span class="meta-label">Report Generated</span><span class="meta-value">${formatTs(generatedAt)}</span></div>
      <div class="meta-item"><span class="meta-label">Objectives</span><span class="meta-value">${objectivesAchieved}/${config.objectives.length} achieved</span></div>
    </div>
  </header>

${include_toc ? renderToc(findings, narrative, data) : ''}

  <section id="executive-summary">
    <h2>Executive Summary</h2>
    <p>This penetration test targeted ${config.scope.cidrs.length} CIDR range(s)${config.scope.domains.length > 0 ? ` and ${config.scope.domains.length} domain(s)` : ''}.
    The assessment identified <strong>${findings.length} finding(s)</strong> across the target environment.</p>
    <div class="severity-grid">
      <div class="severity-card severity-critical"><span class="sev-count">${criticalCount}</span><span class="sev-label">Critical</span></div>
      <div class="severity-card severity-high"><span class="sev-count">${highCount}</span><span class="sev-label">High</span></div>
      <div class="severity-card severity-medium"><span class="sev-count">${mediumCount}</span><span class="sev-label">Medium</span></div>
      <div class="severity-card severity-low"><span class="sev-count">${lowCount}</span><span class="sev-label">Low</span></div>
      <div class="severity-card severity-info"><span class="sev-count">${infoCount}</span><span class="sev-label">Info</span></div>
    </div>
    <p>${objectivesAchieved} of ${config.objectives.length} objective(s) were achieved.
    Graph: ${data.graph.nodes.length} nodes, ${data.graph.edges.length} edges.</p>
  </section>

  <section id="scope">
    <h2>Scope</h2>
    <table>
      <thead><tr><th>Type</th><th>Values</th></tr></thead>
      <tbody>
        <tr><td>CIDRs</td><td>${esc(config.scope.cidrs.join(', ') || 'none')}</td></tr>
        <tr><td>Domains</td><td>${esc(config.scope.domains.join(', ') || 'none')}</td></tr>
        <tr><td>Exclusions</td><td>${esc(config.scope.exclusions.join(', ') || 'none')}</td></tr>
        ${config.scope.aws_accounts?.length ? `<tr><td>AWS Accounts</td><td>${esc(config.scope.aws_accounts.join(', '))}</td></tr>` : ''}
        ${config.scope.azure_subscriptions?.length ? `<tr><td>Azure Subscriptions</td><td>${esc(config.scope.azure_subscriptions.join(', '))}</td></tr>` : ''}
        ${config.scope.gcp_projects?.length ? `<tr><td>GCP Projects</td><td>${esc(config.scope.gcp_projects.join(', '))}</td></tr>` : ''}
        ${config.scope.url_patterns?.length ? `<tr><td>URL Patterns</td><td>${esc(config.scope.url_patterns.join(', '))}</td></tr>` : ''}
      </tbody>
    </table>
  </section>

  <section id="findings-summary">
    <h2>Findings Summary</h2>
    ${findings.length === 0 ? '<p>No significant findings were identified.</p>' : `
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Risk</th></tr></thead>
      <tbody>
        ${findings.map((f, i) => `<tr><td>${i + 1}</td><td>${severityHtml(f.severity)}</td><td><a href="#finding-${i}">${esc(f.title)}</a></td><td>${f.risk_score.toFixed(1)}</td></tr>`).join('\n        ')}
      </tbody>
    </table>`}
  </section>

  <section id="detailed-findings">
    <h2>Detailed Findings</h2>
    ${findings.map((f, i) => renderFindingHtml(f, i)).join('\n')}
  </section>

${data.evidenceAppendix && data.evidenceAppendix.length > 0 ? renderEvidenceAppendixHtml(data.evidenceAppendix) : ''}

${narrative.length > 0 ? `
  <section id="attack-narrative">
    <h2>Attack Narrative</h2>
    ${narrative.map(phase => `
    <div class="narrative-phase">
      <h3>${esc(phase.name)}</h3>
      ${phase.start_time ? `<p class="phase-time">${formatTs(phase.start_time)}${phase.end_time && phase.end_time !== phase.start_time ? ` — ${formatTs(phase.end_time)}` : ''}</p>` : ''}
      ${phase.paragraphs.map(p => `<p>${esc(p)}</p>`).join('\n      ')}
    </div>`).join('\n')}
  </section>` : ''}

  <section id="objectives">
    <h2>Objectives</h2>
    <table>
      <thead><tr><th>Objective</th><th>Status</th><th>Achieved At</th></tr></thead>
      <tbody>
        ${config.objectives.map(obj => `<tr><td>${esc(obj.description)}</td><td>${obj.achieved ? '<span class="badge badge-success">Achieved</span>' : '<span class="badge badge-pending">Pending</span>'}</td><td>${obj.achieved_at ? formatTs(obj.achieved_at) : '—'}</td></tr>`).join('\n        ')}
      </tbody>
    </table>
  </section>

${data.heatmap ? renderHeatmapHtml(data.heatmap) : ''}

${data.remediationRanking && data.remediationRanking.length > 0 ? renderRemediationRankingHtml(data.remediationRanking) : ''}

${data.complianceMapping ? renderComplianceMappingHtml(data.complianceMapping) : ''}

${data.attackTechniques && data.attackTechniques.length > 0 ? renderAttackTechniquesHtml(data.attackTechniques) : ''}

${data.trustSignals && data.trustSignals.length > 0 ? renderTrustSignalsHtml(data.trustSignals) : ''}

${data.credentialChains && data.credentialChains.length > 0 ? renderCredentialChainsHtml(data.credentialChains) : ''}

${data.discoveryStats ? renderDiscoverySummaryHtml(data.discoveryStats) : ''}

${data.agents && data.agents.total > 0 ? renderAgentActivityHtml(data.agents) : ''}

${data.retrospective && hasRetrospectiveContent(data.retrospective) ? renderRetrospectiveHtml(data.retrospective) : ''}

${data.timeline && data.timeline.length > 0 ? renderTimelineHtml(data.timeline) : ''}

${data.recommendations && data.recommendations.length > 0 ? renderRecommendationsHtml(data.recommendations) : ''}

  <footer>
    <p>Generated by Overwatch at ${formatTs(generatedAt)}</p>
  </footer>
</body>
</html>`;
}

// ============================================================
// Sub-Renderers
// ============================================================

function renderToc(findings: ReportFinding[], narrative: NarrativePhase[], data: HtmlReportData): string {
  return `
  <nav id="toc">
    <h2>Table of Contents</h2>
    <ol>
      <li><a href="#executive-summary">Executive Summary</a></li>
      <li><a href="#scope">Scope</a></li>
      <li><a href="#findings-summary">Findings Summary</a></li>
      <li><a href="#detailed-findings">Detailed Findings</a>
        <ol>${findings.map((f, i) => `<li><a href="#finding-${i}">${esc(f.title)}</a></li>`).join('')}</ol>
      </li>
      ${narrative.length > 0 ? '<li><a href="#attack-narrative">Attack Narrative</a></li>' : ''}
      ${data.evidenceAppendix && data.evidenceAppendix.length > 0 ? '<li><a href="#evidence-appendix">Evidence Appendix</a></li>' : ''}
      <li><a href="#objectives">Objectives</a></li>
      ${data.heatmap ? '<li><a href="#risk-heatmap">Risk Heatmap</a></li>' : ''}
      ${data.remediationRanking && data.remediationRanking.length > 0 ? '<li><a href="#remediation-ranking">Remediation Priority Ranking</a></li>' : ''}
      ${data.complianceMapping ? '<li><a href="#compliance-mapping">Compliance Mapping</a></li>' : ''}
      ${data.attackTechniques && data.attackTechniques.length > 0 ? '<li><a href="#attack-techniques">ATT&amp;CK Techniques</a></li>' : ''}
      ${data.trustSignals && data.trustSignals.length > 0 ? '<li><a href="#operator-verification">Operator Verification</a></li>' : ''}
      ${data.credentialChains && data.credentialChains.length > 0 ? '<li><a href="#credential-chains">Credential Chains</a></li>' : ''}
      ${data.discoveryStats ? '<li><a href="#discovery-summary">Discovery Summary</a></li>' : ''}
      ${data.agents && data.agents.total > 0 ? '<li><a href="#agent-activity">Agent Activity</a></li>' : ''}
      ${data.retrospective && hasRetrospectiveContent(data.retrospective) ? '<li><a href="#retrospective">Retrospective Findings</a></li>' : ''}
      ${data.timeline && data.timeline.length > 0 ? '<li><a href="#activity-timeline">Activity Timeline</a></li>' : ''}
      ${data.recommendations && data.recommendations.length > 0 ? '<li><a href="#recommendations">Recommendations</a></li>' : ''}
    </ol>
  </nav>`;
}

function renderFindingHtml(finding: ReportFinding, index: number): string {
  const cvssDisplay = finding.cvss_score !== undefined
    ? `<span class="cvss-score cvss-${cvssColorClass(finding.cvss_score)}">${finding.cvss_score.toFixed(1)}${finding.cvss_estimated ? '†' : ''}</span>`
    : '';
  const vectorDisplay = finding.cvss_vector
    ? `<span class="cvss-vector">${esc(finding.cvss_vector)}</span>`
    : '';
  const attackBadges = finding.classification?.attack_techniques
    ? finding.classification.attack_techniques.slice(0, 5).map(t =>
      `<span class="badge badge-attack" title="${esc(t.name)}">${esc(t.id)}</span>`
    ).join(' ')
    : '';
  const complianceBadges: string[] = [];
  if (finding.classification?.owasp_category) {
    complianceBadges.push(`<span class="badge badge-owasp">${esc(finding.classification.owasp_category)}</span>`);
  }
  if (finding.classification?.cwe) {
    complianceBadges.push(`<span class="badge badge-cwe">${esc(finding.classification.cwe)}</span>`);
  }
  const proofCards = proofCardsForRender(finding);

  return `
    <div class="finding" id="finding-${index}">
      <div class="finding-header">
        <h3>${index + 1}. ${esc(finding.title)}</h3>
        <div class="finding-meta">
          ${severityHtml(finding.severity)}
          ${cvssDisplay}
          <span class="risk-score">Risk: ${finding.risk_score.toFixed(1)}</span>
          <span class="badge badge-category">${esc(finding.category)}</span>
          ${complianceBadges.join(' ')}
        </div>
        ${vectorDisplay ? `<div class="finding-vector">${vectorDisplay}</div>` : ''}
        ${attackBadges ? `<div class="finding-attack-badges">${attackBadges}</div>` : ''}
      </div>
      <div class="finding-body">
        <h4>Description</h4>
        <div class="finding-description">${blockMarkdownToHtml(finding.description)}</div>
        <h4>Affected Assets</h4>
        <ul>${finding.affected_assets.slice(0, 10).map(a => `<li>${esc(a)}</li>`).join('')}${finding.affected_assets.length > 10 ? `<li>... and ${finding.affected_assets.length - 10} more</li>` : ''}</ul>
        ${proofCards.length > 0 ? `
        <h4>Evidence</h4>
        <div class="proof-grid">
          ${proofCards.slice(0, 10).map(card => renderProofCardHtml(card)).join('\n          ')}
        </div>` : ''}
        <h4>Remediation</h4>
        <div class="remediation">${inlineMarkdownToHtml(finding.remediation).replace(/\n/g, '<br>')}</div>
      </div>
    </div>`;
}

function proofCardsForRender(finding: ReportFinding): EvidenceProofCard[] {
  if (finding.proof_cards && finding.proof_cards.length > 0) return finding.proof_cards;
  return finding.evidence.map((ev) => {
    const key = ev.stdout_evidence_id
      || ev.stderr_evidence_id
      || ev.action_id
      || ev.evidence_filename
      || `${ev.timestamp || ''}|${ev.claim}`;
    return {
      id: stableRenderId('proof', `${key}|${ev.claim}`),
      appendix_ref: stableRenderId('ev', key),
      claim: ev.claim,
      proof: ev.stdout_evidence_id || ev.raw_output || ev.evidence_content
        ? 'Captured command output is linked to this finding and supports the claimed state change.'
        : 'The activity log references the affected asset during the engagement timeline.',
      source_kind: ev.stdout_evidence_id || ev.raw_output || ev.evidence_content ? 'direct_output' : 'activity',
      tool: ev.tool,
      technique: ev.technique,
      command: ev.command,
      timestamp: ev.timestamp,
      action_id: ev.action_id,
      evidence_id: ev.stdout_evidence_id || ev.stderr_evidence_id,
      content_hash: ev.stdout_content_hash || ev.stderr_content_hash,
      filename: ev.evidence_filename,
      evidence_type: ev.evidence_type,
      raw_preview: ev.stdout_preview || ev.raw_output || ev.evidence_content,
      raw_preview_redacted: false,
    };
  });
}

function stableRenderId(prefix: string, value: string): string {
  return `${prefix}-${createHash('sha256').update(value).digest('hex').slice(0, 12)}`;
}

function renderProofCardHtml(card: EvidenceProofCard): string {
  const meta = [
    card.tool ? `<span>${esc(card.tool)}</span>` : '',
    card.timestamp ? `<span>${formatTs(card.timestamp)}</span>` : '',
    card.action_id ? `<code>${esc(card.action_id)}</code>` : '',
    card.evidence_id ? `<code>${esc(card.evidence_id.slice(0, 12))}</code>` : '',
    card.filename ? `<span>${esc(card.filename)}</span>` : '',
  ].filter(Boolean).join('');
  return `
    <article class="proof-card" id="${esc(card.id)}">
      <div class="proof-card-head">
        <span class="proof-kind proof-${esc(card.source_kind)}">${esc(sourceKindLabel(card.source_kind))}</span>
        ${card.appendix_ref ? `<a class="proof-ref" href="#${esc(card.appendix_ref)}">${esc(card.appendix_ref)}</a>` : ''}
      </div>
      <p class="proof-claim">${inlineMarkdownToHtml(card.claim)}</p>
      <p class="proof-text">${esc(card.proof)}</p>
      ${meta ? `<div class="proof-meta">${meta}</div>` : ''}
      ${card.content_hash ? `<div class="proof-hash">sha256 <code>${esc(card.content_hash)}</code></div>` : ''}
      ${card.parsed_summary ? `<div class="proof-summary">${esc(card.parsed_summary)}</div>` : ''}
      ${card.command ? `<pre class="evidence-command">${esc(card.command)}</pre>` : ''}
      ${card.raw_preview_redacted ? `<div class="evidence-warning">Raw output preview redacted for this report profile.</div>` : ''}
      ${card.raw_preview ? `<details class="proof-raw"><summary>Raw preview</summary><pre>${esc(limitPreview(card.raw_preview, 4096, 80))}</pre></details>` : ''}
    </article>`;
}

// ============================================================
// Optional Section Renderers
// ============================================================

function renderEvidenceAppendixHtml(entries: EvidenceAppendixEntry[]): string {
  if (entries.length === 0) return '';
  const rows = entries.map(entry => `
    <article class="appendix-entry" id="${esc(entry.id)}">
      <h3>${esc(entry.title)}</h3>
      <p>${inlineMarkdownToHtml(entry.claim)}</p>
      <dl class="appendix-meta">
        <div><dt>Source</dt><dd>${esc(sourceKindLabel(entry.source_kind))}</dd></div>
        ${entry.timestamp ? `<div><dt>Time</dt><dd>${formatTs(entry.timestamp)}</dd></div>` : ''}
        ${entry.tool ? `<div><dt>Tool</dt><dd>${esc(entry.tool)}</dd></div>` : ''}
        ${entry.action_id ? `<div><dt>Action</dt><dd><code>${esc(entry.action_id)}</code></dd></div>` : ''}
        ${entry.evidence_id ? `<div><dt>Evidence</dt><dd><code>${esc(entry.evidence_id)}</code></dd></div>` : ''}
        ${entry.content_hash ? `<div><dt>SHA-256</dt><dd><code>${esc(entry.content_hash)}</code></dd></div>` : ''}
        ${entry.size_bytes !== undefined ? `<div><dt>Size</dt><dd>${entry.size_bytes.toLocaleString()} bytes</dd></div>` : ''}
        <div><dt>Report Profile</dt><dd>${esc(entry.redaction_mode)}</dd></div>
      </dl>
      <p class="appendix-findings">Referenced by ${entry.finding_titles.map(title => `<span>${esc(title)}</span>`).join(' ')}</p>
      ${entry.command ? `<pre class="evidence-command">${esc(entry.command)}</pre>` : ''}
      ${entry.raw_preview_redacted ? `<div class="evidence-warning">Raw output preview redacted for this report profile.</div>` : ''}
      ${entry.raw_preview ? `<details class="proof-raw"><summary>Raw preview</summary><pre>${esc(limitPreview(entry.raw_preview, 8192, 120))}</pre></details>` : ''}
    </article>`).join('\n');

  return `
  <section id="evidence-appendix">
    <h2>Evidence Appendix</h2>
    <p>Each cited artifact is indexed once with stable action, evidence, and hash references where available.</p>
    ${rows}
  </section>`;
}

function sourceKindLabel(kind: EvidenceProofCard['source_kind']): string {
  switch (kind) {
    case 'direct_output': return 'Command output';
    case 'parsed_result': return 'Parsed result';
    case 'provenance': return 'Graph provenance';
    case 'activity': return 'Activity record';
  }
}

function renderCredentialChainsHtml(chains: CredentialChain[]): string {
  if (chains.length === 0) return '';
  const rows = chains.map(chain => {
    const parts: string[] = [];
    for (let i = 0; i < chain.labels.length; i++) {
      if (i > 0) parts.push(` → <em>[${esc(chain.methods[i - 1])}]</em> → `);
      parts.push(esc(chain.labels[i]));
    }
    return `<tr><td>${parts.join('')}</td></tr>`;
  }).join('\n        ');

  return `
  <section id="credential-chains">
    <h2>Credential Chains</h2>
    <p>The following credential derivation chains were identified:</p>
    <table>
      <thead><tr><th>Derivation Chain</th></tr></thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </section>`;
}

function renderDiscoverySummaryHtml(stats: HtmlDiscoveryStats): string {
  const nodeRows = Object.entries(stats.nodesByType)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => `<tr><td>${esc(type)}</td><td>${count}</td></tr>`)
    .join('\n          ');
  const nodeTotal = Object.values(stats.nodesByType).reduce((a, b) => a + b, 0);

  const edgeRows = Object.entries(stats.edgesByType)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => `<tr><td>${esc(type)}</td><td>${count}</td></tr>`)
    .join('\n          ');
  const edgeTotal = Object.values(stats.edgesByType).reduce((a, b) => a + b, 0);

  return `
  <section id="discovery-summary">
    <h2>Discovery Summary</h2>
    <h3>Nodes</h3>
    <table>
      <thead><tr><th>Type</th><th>Count</th></tr></thead>
      <tbody>
          ${nodeRows}
          <tr><td><strong>Total</strong></td><td><strong>${nodeTotal}</strong></td></tr>
      </tbody>
    </table>
    <h3>Edges</h3>
    <table>
      <thead><tr><th>Type</th><th>Count</th></tr></thead>
      <tbody>
          ${edgeRows}
          <tr><td><strong>Total</strong></td><td><strong>${edgeTotal}</strong> (${stats.confirmed} confirmed, ${stats.inferred} inferred)</td></tr>
      </tbody>
    </table>
  </section>`;
}

function renderAgentActivityHtml(agents: HtmlAgentStats): string {
  return `
  <section id="agent-activity">
    <h2>Agent Activity</h2>
    <ul>
      <li><strong>Total agents dispatched:</strong> ${agents.total}</li>
      <li><strong>Completed:</strong> ${agents.completed}</li>
      <li><strong>Failed:</strong> ${agents.failed}</li>
    </ul>
  </section>`;
}

function hasRetrospectiveContent(retro: HtmlRetrospective): boolean {
  return !!(
    retro.context_improvements ||
    (retro.inference_suggestions && retro.inference_suggestions.length > 0) ||
    retro.skill_gaps ||
    retro.trace_quality
  );
}

function renderRetrospectiveHtml(retro: HtmlRetrospective): string {
  const parts: string[] = [];

  if (retro.context_improvements) {
    const ci = retro.context_improvements;
    const items: string[] = [];
    for (const obs of (ci.frontier_observations || []).slice(0, 3)) {
      items.push(`<li><strong>${esc(obs.area)}:</strong> ${esc(obs.observation)} (${esc(obs.confidence)} confidence)</li>`);
    }
    for (const gap of (ci.context_gaps || []).slice(0, 3)) {
      items.push(`<li><strong>${esc(gap.area)}:</strong> ${esc(gap.gap)} Recommendation: ${esc(gap.recommendation)}</li>`);
    }
    if (items.length > 0) {
      parts.push(`<h3>Context Improvements</h3>\n    <ul>${items.join('\n      ')}</ul>`);
    }
  }

  if (retro.inference_suggestions && retro.inference_suggestions.length > 0) {
    const items = retro.inference_suggestions.slice(0, 3)
      .map(s => `<li>${esc(s.rule.name)}: ${esc(s.evidence)}</li>`).join('\n      ');
    parts.push(`<h3>Inference Opportunities</h3>\n    <ul>${items}</ul>`);
  }

  if (retro.skill_gaps) {
    const sg = retro.skill_gaps;
    const items: string[] = [];
    if (sg.missing_skills.length > 0) {
      items.push(`<li>Missing coverage: ${esc(sg.missing_skills.slice(0, 5).join(', '))}</li>`);
    }
    if (sg.failed_techniques.length > 0) {
      items.push(`<li>Failed techniques: ${esc(sg.failed_techniques.slice(0, 5).join(', '))}</li>`);
    }
    if (items.length > 0) {
      parts.push(`<h3>Skill Gaps</h3>\n    <ul>${items.join('\n      ')}</ul>`);
    }
  }

  if (retro.trace_quality) {
    const tq = retro.trace_quality;
    parts.push(`<h3>Trace Quality</h3>
    <ul>
      <li>Total actions: ${tq.total_actions}</li>
      <li>With frontier ID: ${tq.with_frontier_id}</li>
      <li>With action ID: ${tq.with_action_id}</li>
      <li>Coverage: ${tq.coverage_pct.toFixed(1)}%</li>
    </ul>`);
  }

  if (parts.length === 0) return '';

  return `
  <section id="retrospective">
    <h2>Retrospective Findings</h2>
    ${parts.join('\n    ')}
  </section>`;
}

function renderTimelineHtml(timeline: HtmlTimelineEntry[]): string {
  if (timeline.length === 0) return '';
  const rows = timeline.map(entry => {
    const agent = entry.agent_id ? ` <code>${esc(entry.agent_id)}</code>` : '';
    return `<tr><td>${formatTs(entry.timestamp)}</td><td>${esc(entry.description)}${agent}</td></tr>`;
  }).join('\n        ');

  return `
  <section id="activity-timeline">
    <h2>Activity Timeline</h2>
    <table>
      <thead><tr><th>Time</th><th>Event</th></tr></thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </section>`;
}

function renderRecommendationsHtml(recs: string[]): string {
  if (recs.length === 0) return '';
  const items = recs.map(r => `<li>${inlineMarkdownToHtml(r)}</li>`).join('\n      ');
  return `
  <section id="recommendations">
    <h2>Recommendations</h2>
    <ol>
      ${items}
    </ol>
  </section>`;
}

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

function severityHtml(severity: FindingSeverity): string {
  const safe = VALID_SEVERITIES.has(severity) ? severity : 'info';
  return `<span class="badge severity-badge severity-${safe}">${esc(severity.toUpperCase())}</span>`;
}

function cvssColorClass(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

function renderHeatmapHtml(data: HtmlHeatmapData): string {
  const sevHeaders = data.severities.map(s => `<th class="heatmap-${s}">${esc(s)}</th>`).join('');
  const rows = data.categories.map((cat, ci) => {
    const cells = data.severities.map((s, si) => {
      const count = data.matrix[ci]?.[si] ?? 0;
      const intensity = count > 0 ? ` heatmap-cell-${s}` : '';
      return `<td class="heatmap-cell${intensity}">${count}</td>`;
    }).join('');
    const total = (data.matrix[ci] ?? []).reduce((a, b) => a + b, 0);
    return `<tr><td>${esc(cat)}</td>${cells}<td><strong>${total}</strong></td></tr>`;
  }).join('\n        ');

  return `
  <section id="risk-heatmap">
    <h2>Risk Heatmap</h2>
    <table class="heatmap-table">
      <thead><tr><th>Category</th>${sevHeaders}<th>Total</th></tr></thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </section>`;
}

function renderRemediationRankingHtml(rankings: HtmlRemediationRanking[]): string {
  const rows = rankings.map((r, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${esc(r.title)}</td>
      <td><span class="cvss-score cvss-${cvssColorClass(r.cvss)}">${r.cvss.toFixed(1)}${r.cvss_estimated ? '†' : ''}</span></td>
      <td>${r.blast_radius}</td>
      <td>${r.cred_exposure}</td>
      <td><strong>${r.priority_score.toFixed(1)}</strong></td>
    </tr>`).join('\n');

  return `
  <section id="remediation-ranking">
    <h2>Remediation Priority Ranking</h2>
    <p>Findings ranked by combined CVSS score, blast radius, and credential exposure.</p>
    <table>
      <thead><tr><th>#</th><th>Finding</th><th>CVSS</th><th>Blast Radius</th><th>Cred. Exposure</th><th>Priority</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="footnote">† CVSS score estimated from engagement context</p>
  </section>`;
}

function renderComplianceMappingHtml(data: HtmlComplianceMapping): string {
  const parts: string[] = [];

  if (data.cwe_findings && data.cwe_findings.length > 0) {
    const rows = data.cwe_findings.map(f =>
      `<tr><td>${esc(f.title)}</td><td>${esc(f.cwe)}</td><td>${esc(f.cwe_name)}</td></tr>`
    ).join('\n          ');
    parts.push(`<h3>CWE Classification</h3>
    <table><thead><tr><th>Finding</th><th>CWE</th><th>Name</th></tr></thead><tbody>${rows}</tbody></table>`);
  }

  if (data.owasp_groups && data.owasp_groups.length > 0) {
    const rows = data.owasp_groups.map(g =>
      `<tr><td>${esc(g.category)}</td><td>${g.count}</td></tr>`
    ).join('\n          ');
    parts.push(`<h3>OWASP Top 10 (2021)</h3>
    <table><thead><tr><th>Category</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>`);
  }

  if (data.nist_controls && data.nist_controls.length > 0) {
    const rows = data.nist_controls.map(c =>
      `<tr><td>${esc(c.control)}</td><td>${c.count}</td></tr>`
    ).join('\n          ');
    parts.push(`<h3>NIST 800-53 Controls</h3>
    <table><thead><tr><th>Control</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>`);
  }

  if (data.pci_requirements && data.pci_requirements.length > 0) {
    const rows = data.pci_requirements.map(r =>
      `<tr><td>${esc(r.requirement)}</td><td>${r.count}</td></tr>`
    ).join('\n          ');
    parts.push(`<h3>PCI DSS v4.0</h3>
    <table><thead><tr><th>Requirement</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>`);
  }

  if (parts.length === 0) return '';

  return `
  <section id="compliance-mapping">
    <h2>Compliance Mapping</h2>
    ${parts.join('\n    ')}
  </section>`;
}

function renderAttackTechniquesHtml(techniques: HtmlAttackTechnique[]): string {
  const rows = techniques.map(t =>
    `<tr><td><code>${esc(t.id)}</code></td><td>${esc(t.name)}</td><td>${t.count}</td></tr>`
  ).join('\n        ');

  return `
  <section id="attack-techniques">
    <h2>MITRE ATT&amp;CK Techniques</h2>
    <table>
      <thead><tr><th>Technique</th><th>Name</th><th>Findings</th></tr></thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </section>`;
}

function renderTrustSignalsHtml(signals: TrustSignalDto[]): string {
  const rows = signals.slice(0, 20).map(signal => {
    const context = [
      signal.source_event?.event_type,
      signal.action_id ? `action ${signal.action_id.slice(0, 8)}` : undefined,
      signal.finding_id ? `finding ${signal.finding_id}` : undefined,
      signal.node_ids?.length ? `nodes ${signal.node_ids.slice(0, 3).join(', ')}` : undefined,
    ].filter(Boolean).join(' · ') || signal.source;
    const detail = signal.detail ? `${signal.label}: ${signal.detail}` : signal.label;
    return `<tr><td>${esc(signal.severity)}</td><td>${esc(detail)}</td><td>${esc(context)}</td></tr>`;
  }).join('\n        ');

  return `
  <section id="operator-verification">
    <h2>Operator Verification</h2>
    <p>These notes identify parser, ingest, path-analysis, IAM, or scoring caveats present when the report was generated. They are verification prompts, not standalone findings.</p>
    <table>
      <thead><tr><th>Severity</th><th>Signal</th><th>Context</th></tr></thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </section>`;
}

// ============================================================
// Helpers
// ============================================================

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function inlineMarkdownToHtml(text: string): string {
  let result = '';
  let i = 0;
  let plainStart = 0; // Track start of plain text segment for batch escaping
  while (i < text.length) {
    if (text[i] === '`') {
      const end = text.indexOf('`', i + 1);
      if (end !== -1) {
        if (i > plainStart) result += esc(text.slice(plainStart, i));
        result += `<code>${esc(text.slice(i + 1, end))}</code>`;
        i = end + 1;
        plainStart = i;
        continue;
      }
    }
    if (text[i] === '*' && text[i + 1] === '*') {
      const end = text.indexOf('**', i + 2);
      if (end !== -1) {
        if (i > plainStart) result += esc(text.slice(plainStart, i));
        result += `<strong>${esc(text.slice(i + 2, end))}</strong>`;
        i = end + 2;
        plainStart = i;
        continue;
      }
    }
    if (text[i] === '*' && text[i + 1] !== '*') {
      const end = text.indexOf('*', i + 1);
      if (end !== -1 && text[end + 1] !== '*') {
        if (i > plainStart) result += esc(text.slice(plainStart, i));
        result += `<em>${esc(text.slice(i + 1, end))}</em>`;
        i = end + 1;
        plainStart = i;
        continue;
      }
    }
    i++;
  }
  // Flush remaining plain text
  if (plainStart < text.length) result += esc(text.slice(plainStart));
  return result;
}

function blockMarkdownToHtml(text: string): string {
  const lines = text.split(/\n+/).map(line => line.trim()).filter(Boolean);
  if (lines.length === 0) return '';
  const parts: string[] = [];
  let bullets: string[] = [];
  const flushBullets = () => {
    if (bullets.length === 0) return;
    parts.push(`<ul>${bullets.map(item => `<li>${inlineMarkdownToHtml(item)}</li>`).join('')}</ul>`);
    bullets = [];
  };

  for (const line of lines) {
    if (line.startsWith('- ')) {
      bullets.push(line.slice(2));
      continue;
    }
    flushBullets();
    parts.push(`<p>${inlineMarkdownToHtml(line)}</p>`);
  }
  flushBullets();
  return parts.join('');
}

function limitPreview(text: string, maxChars: number, maxLines: number): string {
  const charSlice = text.length > maxChars ? `${text.slice(0, maxChars)}\n[preview truncated]` : text;
  const lines = charSlice.split('\n');
  return lines.length > maxLines ? `${lines.slice(0, maxLines).join('\n')}\n[preview truncated]` : charSlice;
}

function formatTs(ts: string): string {
  try {
    return new Date(ts).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  } catch {
    return esc(ts);
  }
}

// ============================================================
// Embedded CSS
// ============================================================

const CSS_STYLES = `
  :root {
    --bg: #ffffff; --fg: #1a1a2e; --card-bg: #f8f9fa; --border: #dee2e6;
    --accent: #4361ee; --header-bg: #1a1a2e; --header-fg: #ffffff;
    --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #0d6efd; --info: #6c757d;
    --success: #198754; --pending: #6c757d;
  }
  [data-theme="dark"] {
    --bg: #0d1117; --fg: #c9d1d9; --card-bg: #161b22; --border: #30363d;
    --accent: #58a6ff; --header-bg: #010409; --header-fg: #f0f6fc;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.6; max-width: 960px; margin: 0 auto; padding: 2rem; overflow-wrap: break-word; }
  h1, h2, h3, h4 { margin-top: 1.5rem; margin-bottom: 0.5rem; }
  h1 { font-size: 1.8rem; } h2 { font-size: 1.4rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.3rem; } h3 { font-size: 1.15rem; }
  p { margin-bottom: 0.75rem; }
  a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; table-layout: fixed; }
  th, td { padding: 0.5rem 0.75rem; border: 1px solid var(--border); text-align: left; overflow-wrap: anywhere; }
  code, pre, .meta-value { overflow-wrap: anywhere; word-break: break-word; }
  th { background: var(--card-bg); font-weight: 600; }
  .report-header { background: var(--header-bg); color: var(--header-fg); padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }
  .report-header h1 { margin-top: 0; color: var(--header-fg); border: none; }
  .engagement-name { font-size: 1.1rem; opacity: 0.9; margin-bottom: 1rem; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; }
  .meta-item { display: flex; flex-direction: column; }
  .meta-label { font-size: 0.75rem; text-transform: uppercase; opacity: 0.7; }
  .meta-value { font-weight: 600; }
  .severity-grid { display: flex; gap: 0.75rem; margin: 1rem 0; flex-wrap: wrap; }
  .severity-card { padding: 1rem 1.5rem; border-radius: 8px; text-align: center; min-width: 80px; color: #fff; }
  .severity-critical { background: var(--critical); } .severity-high { background: var(--high); }
  .severity-medium { background: var(--medium); color: #000; } .severity-low { background: var(--low); }
  .severity-info { background: var(--info); }
  .sev-count { display: block; font-size: 1.8rem; font-weight: 700; } .sev-label { font-size: 0.8rem; text-transform: uppercase; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .severity-badge.severity-critical { background: var(--critical); color: #fff; }
  .severity-badge.severity-high { background: var(--high); color: #fff; }
  .severity-badge.severity-medium { background: var(--medium); color: #000; }
  .severity-badge.severity-low { background: var(--low); color: #fff; }
  .severity-badge.severity-info { background: var(--info); color: #fff; }
  .badge-success { background: var(--success); color: #fff; } .badge-pending { background: var(--pending); color: #fff; }
  .badge-category { background: var(--card-bg); color: var(--fg); border: 1px solid var(--border); }
  .finding { border: 1px solid var(--border); border-radius: 8px; margin: 1.5rem 0; overflow: hidden; }
  .finding-header { background: var(--card-bg); padding: 1rem 1.25rem; }
  .finding-header h3 { margin-top: 0; }
  .finding-meta { display: flex; gap: 0.5rem; align-items: center; margin-top: 0.5rem; flex-wrap: wrap; }
  .finding-body { padding: 1.25rem; }
  .finding-body h4 { margin-top: 1rem; margin-bottom: 0.3rem; font-size: 0.95rem; }
  .finding-body ul { padding-left: 1.5rem; margin-bottom: 0.75rem; }
  .finding-description p { margin-bottom: 0.45rem; }
  .finding-description ul { margin-top: 0.25rem; }
  .risk-score { font-weight: 600; font-size: 0.85rem; }
  .proof-grid { display: grid; gap: 0.75rem; margin: 0.75rem 0 1rem; }
  .proof-card { border: 1px solid var(--border); border-radius: 6px; padding: 0.85rem; background: var(--bg); break-inside: avoid; page-break-inside: avoid; }
  .proof-card-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.4rem; flex-wrap: wrap; }
  .proof-kind { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.02em; color: var(--accent); }
  .proof-ref { font-family: monospace; font-size: 0.75rem; overflow-wrap: anywhere; }
  .proof-claim { font-weight: 600; margin-bottom: 0.35rem; }
  .proof-text { font-size: 0.9rem; color: var(--fg); margin-bottom: 0.35rem; }
  .proof-meta { display: flex; gap: 0.5rem; flex-wrap: wrap; color: var(--info); font-size: 0.78rem; }
  .proof-meta span, .proof-meta code { background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.08rem 0.35rem; }
  .proof-hash, .proof-summary { font-size: 0.78rem; color: var(--info); margin-top: 0.35rem; overflow-wrap: anywhere; }
  .proof-raw { margin-top: 0.45rem; }
  .proof-raw summary { cursor: pointer; color: var(--accent); font-size: 0.82rem; }
  .proof-raw pre, .evidence-command { background: var(--card-bg); border: 1px solid var(--border); padding: 0.7rem; border-radius: 4px; font-size: 0.78rem; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; margin-top: 0.4rem; }
  .evidence-tool { color: var(--accent); font-size: 0.85rem; } .evidence-time { color: var(--info); font-size: 0.85rem; }
  .evidence-action { background: var(--card-bg); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.8rem; }
  .evidence-file { font-size: 0.85rem; color: var(--accent); margin-top: 0.25rem; }
  .evidence-content { background: var(--card-bg); border: 1px solid var(--border); padding: 0.75rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; margin-top: 0.25rem; }
  .evidence-section details { margin-top: 0.25rem; } .evidence-section details summary { cursor: pointer; font-size: 0.85rem; color: var(--accent); }
  .evidence-section details pre { background: var(--card-bg); border: 1px solid var(--border); padding: 0.75rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; }
  .evidence-warning { color: #8a5a00; background: rgba(255,193,7,0.16); border: 1px solid rgba(255,193,7,0.35); border-radius: 4px; padding: 0.4rem 0.55rem; font-size: 0.8rem; margin-top: 0.45rem; }
  .evidence-error { color: var(--critical); background: rgba(220,53,69,0.12); border: 1px solid rgba(220,53,69,0.3); border-radius: 4px; padding: 0.4rem 0.55rem; font-size: 0.8rem; margin-top: 0.45rem; }
  .evidence-meta { font-size: 0.78rem; color: var(--info); margin-top: 0.3rem; overflow-wrap: anywhere; }
  .appendix-entry { border-top: 1px solid var(--border); padding: 1rem 0; break-inside: avoid; page-break-inside: avoid; }
  .appendix-entry h3 { overflow-wrap: anywhere; }
  .appendix-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.5rem 0.75rem; margin: 0.75rem 0; }
  .appendix-meta div { background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.45rem; min-width: 0; }
  .appendix-meta dt { color: var(--info); font-size: 0.68rem; text-transform: uppercase; }
  .appendix-meta dd { font-size: 0.82rem; overflow-wrap: anywhere; }
  .appendix-findings { display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center; color: var(--info); font-size: 0.82rem; }
  .appendix-findings span { background: var(--card-bg); border: 1px solid var(--border); border-radius: 999px; padding: 0.1rem 0.45rem; color: var(--fg); }
  .remediation { background: var(--card-bg); padding: 1rem; border-radius: 4px; border-left: 4px solid var(--success); font-size: 0.9rem; }
  .narrative-phase { margin: 1.5rem 0; padding: 1rem 1.25rem; border-left: 3px solid var(--accent); }
  .phase-time { font-style: italic; color: var(--info); font-size: 0.9rem; }
  #toc { background: var(--card-bg); padding: 1.25rem 1.5rem; border-radius: 8px; margin-bottom: 2rem; }
  #toc h2 { border: none; margin-top: 0; font-size: 1.1rem; } #toc ol { padding-left: 1.25rem; }
  #toc li { margin: 0.25rem 0; } #toc ol ol { font-size: 0.9rem; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); text-align: center; color: var(--info); font-size: 0.85rem; }
  @media print {
    body { max-width: 100%; padding: 0; }
    details.proof-raw[open], details.proof-raw { break-inside: avoid; }
    .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .severity-card, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .finding, .proof-card, .appendix-entry, .remediation { break-inside: avoid; page-break-inside: avoid; }
  }
  .cvss-score { font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }
  .cvss-critical { background: var(--critical); color: #fff; }
  .cvss-high { background: var(--high); color: #fff; }
  .cvss-medium { background: var(--medium); color: #000; }
  .cvss-low { background: var(--low); color: #fff; }
  .cvss-info { background: var(--info); color: #fff; }
  .cvss-vector { font-family: monospace; font-size: 0.75rem; color: var(--info); }
  .finding-vector { margin-top: 0.3rem; }
  .finding-attack-badges { margin-top: 0.3rem; display: flex; gap: 0.3rem; flex-wrap: wrap; }
  .badge-attack { background: #6f42c1; color: #fff; font-size: 0.7rem; font-family: monospace; }
  .badge-owasp { background: #0d6efd; color: #fff; font-size: 0.7rem; }
  .badge-cwe { background: #20c997; color: #000; font-size: 0.7rem; font-family: monospace; }
  .heatmap-table { text-align: center; }
  .heatmap-table th { text-transform: capitalize; }
  .heatmap-cell-critical { background: rgba(220,53,69,0.25); font-weight: 700; }
  .heatmap-cell-high { background: rgba(253,126,20,0.25); font-weight: 700; }
  .heatmap-cell-medium { background: rgba(255,193,7,0.2); }
  .heatmap-cell-low { background: rgba(13,110,253,0.15); }
  .heatmap-cell-info { background: rgba(108,117,125,0.1); }
  .footnote { font-size: 0.8rem; color: var(--info); font-style: italic; }
`;
