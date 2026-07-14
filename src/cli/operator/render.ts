// ============================================================
// Operator CLI — human-readable renderers
// ============================================================
// Minimal local interfaces (only the fields rendered) keep the CLI decoupled
// from the dashboard's type module. Raw shapes are documented in
// src/dashboard-next/src/lib/api.ts / types.ts.

import { bold, cyan, dim, green, red, yellow, blue, gray, formatTable, keyValues, heading } from './format.js';

const sev = (s: string): ((x: string) => string) => {
  switch (s) {
    case 'critical': return red;
    case 'high': return red;
    case 'medium': return yellow;
    case 'low': return blue;
    default: return gray;
  }
};
const agentStatusColor = (s: string): ((x: string) => string) => {
  switch (s) {
    case 'running': return green;
    case 'failed': return red;
    case 'interrupted': return red;
    case 'pending': return yellow;
    default: return dim;
  }
};

interface StateResponse {
  state: {
    engagement?: { id?: string; name?: string; profile?: string };
    config?: { name?: string };
    graph_summary?: { total_nodes: number; total_edges: number; confirmed_edges: number; inferred_edges: number };
    objectives?: Array<{ description: string; achieved: boolean }>;
    frontier?: FrontierItem[];
    agents?: AgentInfo[];
    pending_actions?: unknown[];
    sessions?: unknown[];
    access_level?: string;
    access_summary?: { current_access_level?: string; compromised_hosts?: string[]; valid_credentials?: string[] };
    lab_readiness?: { status: string; top_issues: string[] };
  };
  history_count?: number;
}
interface FrontierItem { id: string; type: string; description: string; opsec_noise?: number; graph_metrics?: { confidence?: number; hops_to_objective?: number } }
interface AgentInfo { id: string; status: string; agent_id?: string; skill?: string; current_action?: string }
interface FindingDto { id: string; severity: string; title: string; risk_score: number; affected_assets: string[] }
interface FindingsResponse { findings: FindingDto[]; total: number; severity_summary: Record<string, number> }
interface PendingAction { action_id: string; technique?: string; target?: string; description: string; noise_level?: number; agent_id?: string }
interface SessionInfo { id: string; kind: string; state: string; title?: string; host?: string; agent_id?: string }
interface AgentQuery { query_id: string; agent_id?: string; question: string }
interface OpsecBudget { global_noise_spent: number; noise_budget_remaining: number; max_noise: number; recommended_approach: string; time_window_remaining_hours?: number; warning?: string }

export function renderStatus(data: StateResponse): string {
  const s = data.state || {};
  const eng = s.engagement;
  const g = s.graph_summary;
  const objs = s.objectives ?? [];
  const achieved = objs.filter(o => o.achieved).length;
  const agents = s.agents ?? [];
  const running = agents.filter(a => a.status === 'running').length;
  const pendingCount = (s.pending_actions ?? []).length;
  const out: string[] = [];

  const name = eng?.name ?? s.config?.name ?? 'Engagement';
  out.push(heading(name) + dim(eng?.id ? `  (${eng.id})` : ''));
  const pairs: Array<[string, string]> = [];
  if (eng?.profile) pairs.push(['profile', eng.profile]);
  if (g) pairs.push(['graph', `${g.total_nodes} nodes · ${g.total_edges} edges (${g.confirmed_edges} confirmed / ${g.inferred_edges} inferred)`]);
  pairs.push(['objectives', `${achieved}/${objs.length} achieved`]);
  const access = s.access_summary?.current_access_level ?? s.access_level;
  if (access) {
    const compromised = s.access_summary?.compromised_hosts?.length ?? 0;
    const creds = s.access_summary?.valid_credentials?.length ?? 0;
    pairs.push(['access', `${access}${compromised || creds ? dim(`  (${compromised} hosts · ${creds} creds)`) : ''}`]);
  }
  pairs.push(['agents', `${agents.length} (${running > 0 ? green(`${running} running`) : dim('0 running')})`]);
  pairs.push(['approvals', pendingCount > 0 ? yellow(`${pendingCount} pending`) : dim('0 pending')]);
  if (typeof data.history_count === 'number') pairs.push(['activity', `${data.history_count} events`]);
  if (s.lab_readiness) pairs.push(['readiness', s.lab_readiness.status]);
  out.push(keyValues(pairs));

  if (objs.length) {
    out.push('');
    out.push(heading('Objectives'));
    out.push(objs.map(o => `  ${o.achieved ? green('✓') : dim('○')} ${o.description}`).join('\n'));
  }

  const frontier = s.frontier ?? [];
  if (frontier.length) {
    out.push('');
    out.push(heading(`Frontier (top ${Math.min(5, frontier.length)} of ${frontier.length})`));
    out.push(renderFrontier(frontier.slice(0, 5)));
  }

  if (s.lab_readiness?.top_issues?.length) {
    out.push('');
    out.push(heading('Needs attention'));
    out.push(s.lab_readiness.top_issues.map(i => `  ${yellow('!')} ${i}`).join('\n'));
  }
  return out.join('\n');
}

export function renderFrontier(items: FrontierItem[]): string {
  return formatTable(
    ['TYPE', 'DESCRIPTION', 'CONF', 'NOISE'],
    items.map(i => [
      i.type,
      i.description,
      i.graph_metrics?.confidence !== undefined ? i.graph_metrics.confidence.toFixed(2) : '—',
      i.opsec_noise !== undefined ? i.opsec_noise.toFixed(2) : '—',
    ]),
    { color: [cyan, undefined, undefined, undefined] },
  );
}

export function renderFindings(resp: FindingsResponse): string {
  const sum = resp.severity_summary || {};
  const header = `${bold(String(resp.total))} findings  ` +
    [['critical', red], ['high', red], ['medium', yellow], ['low', blue], ['info', gray]]
      .map(([k, c]) => (c as (x: string) => string)(`${sum[k as string] ?? 0} ${k}`)).join(dim(' · '));
  const table = formatTable(
    ['SEV', 'TITLE', 'RISK', 'ASSETS'],
    resp.findings.map(f => [f.severity, f.title, String(f.risk_score ?? ''), String(f.affected_assets?.length ?? 0)]),
    { color: [s => sev(s.trim())(s), undefined, undefined, undefined] },
  );
  return `${header}\n\n${table}`;
}

export function renderAgents(agents: AgentInfo[]): string {
  return formatTable(
    ['STATUS', 'ID', 'TASK', 'NOW'],
    // TASK is the agent's job/label. `task` never existed on the API payload (always
    // undefined → blank column); use the skill, falling back to the agent_id label.
    agents.map(a => [a.status, a.id, a.skill ?? a.agent_id ?? '—', a.current_action ?? '']),
    { color: [s => agentStatusColor(s.trim())(s), dim, undefined, dim] },
  );
}

export function renderApprovals(pending: PendingAction[]): string {
  if (!pending.length) return green('No pending approvals.');
  return formatTable(
    ['ACTION ID', 'TECHNIQUE', 'TARGET', 'NOISE', 'DESCRIPTION'],
    pending.map(p => [
      p.action_id,
      p.technique ?? '—',
      p.target ?? '—',
      p.noise_level !== undefined ? p.noise_level.toFixed(2) : '—',
      p.description,
    ]),
    { color: [yellow, undefined, undefined, undefined, undefined] },
  );
}

export function renderSessions(sessions: SessionInfo[]): string {
  return formatTable(
    ['STATE', 'ID', 'KIND', 'TITLE', 'AGENT'],
    sessions.map(s => [s.state, s.id, s.kind, s.title ?? s.host ?? '', s.agent_id ?? '']),
    { color: [s => (s.trim() === 'connected' ? green : s.trim() === 'error' ? red : dim)(s), dim, undefined, undefined, dim] },
  );
}

export function renderQueries(queries: AgentQuery[]): string {
  if (!queries.length) return green('No agents waiting on you.');
  return queries.map(q => `  ${yellow('?')} ${dim(q.query_id)} ${dim(`[${q.agent_id ?? 'agent'}]`)}\n    ${q.question}`).join('\n');
}

/** A green one-line success confirmation for write commands. */
export function ok(message: string): string {
  return `${green('✓')} ${message}`;
}

interface DeployResult { dispatched: boolean; task?: { id: string; agent_id: string; archetype?: string }; archetype?: string; scope?: { affected_node_count: number }; reason?: string }
interface DispatchResult { dispatched: boolean; task?: { id: string; agent_id: string }; reason?: string; existing_task_id?: string }

export function renderDeploy(r: DeployResult, target: string): string {
  if (r.dispatched && r.task) {
    const scope = r.scope ? dim(`  (${r.scope.affected_node_count} node(s) in scope)`) : '';
    return green(`Deployed ${r.task.archetype ?? r.archetype ?? 'agent'} at ${target}`) +
      `  → task ${bold(r.task.id)} ${dim(`(agent ${r.task.agent_id})`)}${scope}`;
  }
  return yellow(`Not deployed: ${r.reason ?? 'unknown reason'}`);
}

export function renderDispatch(r: DispatchResult): string {
  if (r.dispatched && r.task) {
    return green('Dispatched') + `  → task ${bold(r.task.id)} ${dim(`(agent ${r.task.agent_id})`)}`;
  }
  const existing = r.existing_task_id ? dim(` (already on task ${r.existing_task_id})`) : '';
  return yellow(`Not dispatched: ${r.reason ?? 'unknown reason'}`) + existing;
}

export function renderOpsec(b: OpsecBudget): string {
  const approachColor = b.recommended_approach === 'quiet' ? green : b.recommended_approach === 'loud' ? red : yellow;
  const pairs: Array<[string, string]> = [
    ['noise spent', b.global_noise_spent.toFixed(2)],
    ['remaining', `${b.noise_budget_remaining.toFixed(2)} / ${b.max_noise.toFixed(2)}`],
    ['approach', approachColor(b.recommended_approach)],
  ];
  if (b.time_window_remaining_hours !== undefined) pairs.push(['window', `${b.time_window_remaining_hours.toFixed(1)}h remaining`]);
  let out = heading('OPSEC budget') + '\n' + keyValues(pairs);
  if (b.warning) out += `\n  ${yellow('!')} ${b.warning}`;
  return out;
}
