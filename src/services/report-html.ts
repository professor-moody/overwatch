// ============================================================
// Overwatch — HTML Report Renderer
// Converts structured report data into a styled, self-contained
// HTML document suitable for client delivery.
// ============================================================

import type { ReportFinding, NarrativePhase, FindingSeverity, EvidenceChain } from './report-generator.js';
import type { EngagementConfig, ExportedGraph } from '../types.js';
import type { CredentialChain } from './retrospective.js';

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
}

export interface HtmlReportOptions {
  theme?: 'light' | 'dark';
  include_toc?: boolean;
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

${data.credentialChains && data.credentialChains.length > 0 ? renderCredentialChainsHtml(data.credentialChains) : ''}

${data.discoveryStats ? renderDiscoverySummaryHtml(data.discoveryStats) : ''}

${data.agents && data.agents.total > 0 ? renderAgentActivityHtml(data.agents) : ''}

${data.retrospective && hasRetrospectiveContent(data.retrospective) ? renderRetrospectiveHtml(data.retrospective) : ''}

${data.timeline && data.timeline.length > 0 ? renderTimelineHtml(data.timeline) : ''}

${data.recommendations && data.recommendations.length > 0 ? renderRecommendationsHtml(data.recommendations) : ''}

  <footer>
    <p>Generated by Overwatch at ${formatTs(generatedAt)}</p>
  </footer>

  <script>
    document.querySelectorAll('.evidence-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.nextElementSibling;
        if (target) {
          target.classList.toggle('collapsed');
          btn.textContent = target.classList.contains('collapsed') ? 'Show Evidence' : 'Hide Evidence';
        }
      });
    });
  </script>
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
      <li><a href="#objectives">Objectives</a></li>
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
  return `
    <div class="finding" id="finding-${index}">
      <div class="finding-header">
        <h3>${index + 1}. ${esc(finding.title)}</h3>
        <div class="finding-meta">
          ${severityHtml(finding.severity)}
          <span class="risk-score">Risk: ${finding.risk_score.toFixed(1)}</span>
          <span class="badge badge-category">${esc(finding.category)}</span>
        </div>
      </div>
      <div class="finding-body">
        <h4>Description</h4>
        <p>${inlineMarkdownToHtml(finding.description)}</p>
        <h4>Affected Assets</h4>
        <ul>${finding.affected_assets.slice(0, 10).map(a => `<li>${esc(a)}</li>`).join('')}${finding.affected_assets.length > 10 ? `<li>... and ${finding.affected_assets.length - 10} more</li>` : ''}</ul>
        ${finding.evidence.length > 0 ? `
        <button class="evidence-toggle">Show Evidence</button>
        <div class="evidence-section collapsed">
          <h4>Evidence</h4>
          <ul>${finding.evidence.slice(0, 10).map(ev => `<li>${renderEvidenceHtml(ev)}</li>`).join('')}</ul>
        </div>` : ''}
        <h4>Remediation</h4>
        <div class="remediation">${inlineMarkdownToHtml(finding.remediation).replace(/\n/g, '<br>')}</div>
      </div>
    </div>`;
}

function renderEvidenceHtml(ev: EvidenceChain): string {
  let html = esc(ev.claim);
  if (ev.tool) html += ` <span class="evidence-tool">(${esc(ev.tool)})</span>`;
  if (ev.timestamp) html += ` <span class="evidence-time">${formatTs(ev.timestamp)}</span>`;
  if (ev.action_id) html += ` <code class="evidence-action">${esc(ev.action_id.slice(0, 8))}</code>`;
  if (ev.evidence_filename) html += `\n<div class="evidence-file">File: ${esc(ev.evidence_filename)}</div>`;
  if (ev.evidence_content) {
    const truncated = truncateText(ev.evidence_content, 2048, 30);
    html += `\n<pre class="evidence-content">${esc(truncated)}</pre>`;
  }
  if (ev.raw_output) {
    const truncated = truncateText(ev.raw_output, 2048, 30);
    html += `\n<details><summary>Raw Output</summary><pre>${esc(truncated)}</pre></details>`;
  }
  return html;
}

// ============================================================
// Optional Section Renderers
// ============================================================

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

// ============================================================
// Helpers
// ============================================================

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function inlineMarkdownToHtml(text: string): string {
  let result = '';
  let i = 0;
  while (i < text.length) {
    if (text[i] === '`') {
      const end = text.indexOf('`', i + 1);
      if (end !== -1) {
        result += `<code>${esc(text.slice(i + 1, end))}</code>`;
        i = end + 1;
        continue;
      }
    }
    if (text[i] === '*' && text[i + 1] === '*') {
      const end = text.indexOf('**', i + 2);
      if (end !== -1) {
        result += `<strong>${esc(text.slice(i + 2, end))}</strong>`;
        i = end + 2;
        continue;
      }
    }
    if (text[i] === '*' && text[i + 1] !== '*') {
      const end = text.indexOf('*', i + 1);
      if (end !== -1 && text[end + 1] !== '*') {
        result += `<em>${esc(text.slice(i + 1, end))}</em>`;
        i = end + 1;
        continue;
      }
    }
    result += esc(text[i]);
    i++;
  }
  return result;
}

function truncateText(text: string, maxChars: number, maxLines: number): string {
  const charSlice = text.slice(0, maxChars);
  const lines = charSlice.split('\n');
  if (lines.length > maxLines) return lines.slice(0, maxLines).join('\n');
  return charSlice;
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
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.6; max-width: 960px; margin: 0 auto; padding: 2rem; }
  h1, h2, h3, h4 { margin-top: 1.5rem; margin-bottom: 0.5rem; }
  h1 { font-size: 1.8rem; } h2 { font-size: 1.4rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.3rem; } h3 { font-size: 1.15rem; }
  p { margin-bottom: 0.75rem; }
  a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
  th, td { padding: 0.5rem 0.75rem; border: 1px solid var(--border); text-align: left; }
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
  .risk-score { font-weight: 600; font-size: 0.85rem; }
  .evidence-toggle { background: var(--accent); color: #fff; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; font-size: 0.85rem; margin-top: 0.5rem; }
  .evidence-section.collapsed { display: none; }
  .evidence-tool { color: var(--accent); font-size: 0.85rem; } .evidence-time { color: var(--info); font-size: 0.85rem; }
  .evidence-action { background: var(--card-bg); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.8rem; }
  .evidence-file { font-size: 0.85rem; color: var(--accent); margin-top: 0.25rem; }
  .evidence-content { background: var(--card-bg); border: 1px solid var(--border); padding: 0.75rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; margin-top: 0.25rem; }
  .evidence-section details { margin-top: 0.25rem; } .evidence-section details summary { cursor: pointer; font-size: 0.85rem; color: var(--accent); }
  .evidence-section details pre { background: var(--card-bg); border: 1px solid var(--border); padding: 0.75rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; }
  .remediation { background: var(--card-bg); padding: 1rem; border-radius: 4px; border-left: 4px solid var(--success); font-size: 0.9rem; }
  .narrative-phase { margin: 1.5rem 0; padding: 1rem 1.25rem; border-left: 3px solid var(--accent); }
  .phase-time { font-style: italic; color: var(--info); font-size: 0.9rem; }
  #toc { background: var(--card-bg); padding: 1.25rem 1.5rem; border-radius: 8px; margin-bottom: 2rem; }
  #toc h2 { border: none; margin-top: 0; font-size: 1.1rem; } #toc ol { padding-left: 1.25rem; }
  #toc li { margin: 0.25rem 0; } #toc ol ol { font-size: 0.9rem; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); text-align: center; color: var(--info); font-size: 0.85rem; }
  @media print {
    body { max-width: 100%; padding: 0; }
    .evidence-toggle { display: none; }
    .evidence-section.collapsed { display: block !important; }
    .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .severity-card, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .finding { break-inside: avoid; }
  }
`;
