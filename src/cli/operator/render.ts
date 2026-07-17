// ============================================================
// Operator CLI — human-readable renderers
// ============================================================
// Minimal local interfaces (only the fields rendered) keep the CLI decoupled
// from the dashboard's type module. Raw shapes are documented in
// src/dashboard-next/src/lib/api.ts / types.ts.

import { bold, cyan, dim, green, red, yellow, blue, gray, formatTable, keyValues, heading } from './format.js';
import type {
  ConfigRecoveryStatus,
  PersistenceRecoveryStatus,
  StateMigrationStatus,
} from '../../types.js';
import type { StateMigrationInspection } from '../../services/state-migration.js';

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
    persistence_recovery?: PersistenceRecoveryStatus;
  };
  history_count?: number;
}
interface FrontierItem { id: string; type: string; description: string; opsec_noise?: number; graph_metrics?: { confidence?: number; hops_to_objective?: number } }
interface AgentInfo { id: string; status: string; agent_id?: string; skill?: string; current_action?: string }
interface FindingDto { id: string; severity: string; title: string; risk_score: number; affected_assets: string[] }
interface FindingsResponse { findings: FindingDto[]; total: number; severity_summary: Record<string, number> }
interface PendingAction { action_id: string; technique?: string; target?: string; description: string; noise_level?: number; agent_id?: string }
interface SessionInfo {
  id: string;
  kind: string;
  state: string;
  title?: string;
  host?: string;
  agent_id?: string;
  claimed_by?: string;
  connection_generation?: number;
  connection_id?: string;
}
interface AgentQuery { query_id: string; agent_id?: string; question: string }
interface OpsecBudget { global_noise_spent: number; noise_budget_remaining: number; max_noise: number; recommended_approach: string; time_window_remaining_hours?: number; warning?: string }

function renderPersistenceRecovery(recovery: PersistenceRecoveryStatus): string {
  const writable = recovery.writable ? 'writable' : 'read-only';
  const source = recovery.outcome === 'clean' ? '' : ` from ${recovery.source}`;
  const appliedLogical = recovery.highest_contiguous_applied_logical_seq
    ?? recovery.highest_contiguous_applied_seq;
  const sequence = recovery.journal.enabled
    ? ` · seq ${appliedLogical}/${recovery.highest_on_disk_seq}`
    : '';
  const frames = recovery.journal.enabled
    && recovery.highest_allocated_frame_seq !== undefined
    && recovery.highest_physical_frame_seq !== undefined
    ? ` · frames ${recovery.highest_allocated_frame_seq}/${recovery.highest_physical_frame_seq}`
    : '';
  const failures = recovery.consecutive_persistence_failures > 0
    ? ` · ${recovery.consecutive_persistence_failures} write failure${recovery.consecutive_persistence_failures === 1 ? '' : 's'}`
    : '';
  const reason = recovery.reason || recovery.last_persistence_error;
  const reasonDetail = reason && (recovery.outcome === 'incomplete' || recovery.outcome === 'reinitialized' || !recovery.writable)
    ? ` · ${reason}`
    : '';
  const summary = `${recovery.outcome}${source} · ${writable}${sequence}${frames}${failures}${reasonDetail}`;

  if (recovery.outcome === 'incomplete' || recovery.outcome === 'reinitialized' || !recovery.writable) {
    return red(summary);
  }
  if (
    recovery.consecutive_persistence_failures > 0
    || recovery.journal.preserved
    || recovery.artifact_recovery?.reports.writable === false
    || (recovery.artifact_recovery?.generation_warnings?.length ?? 0) > 0
    || (recovery.runtime_ownership_warnings?.length ?? 0) > 0
    || (recovery.outcome === 'recovered' && recovery.source === 'snapshot')
  ) {
    return yellow(summary);
  }
  return green(summary);
}

interface RecoveryResponse {
  recovery: PersistenceRecoveryStatus;
}

function renderConfigRecovery(recovery: ConfigRecoveryStatus): string {
  const pairs: Array<[string, string]> = [
    ['status', recovery.status],
    ['resolution required', recovery.resolution_required ? 'yes' : 'no'],
    ['write intent', recovery.intent_present ? 'present' : 'none'],
  ];
  if (recovery.file_valid !== undefined) pairs.push(['file valid', recovery.file_valid ? 'yes' : 'no']);
  if (recovery.file_revision !== undefined) pairs.push(['file revision', String(recovery.file_revision)]);
  if (recovery.state_revision !== undefined) pairs.push(['state revision', String(recovery.state_revision)]);
  if (recovery.runtime_revision !== undefined) pairs.push(['runtime revision', String(recovery.runtime_revision)]);
  if (recovery.file_hash) pairs.push(['observed file hash', recovery.file_hash]);
  if (recovery.state_hash) pairs.push(['durable state hash', recovery.state_hash]);
  if (recovery.runtime_hash) pairs.push(['runtime hash', recovery.runtime_hash]);
  if (recovery.allowed_resolutions?.length) pairs.push(['allowed resolutions', recovery.allowed_resolutions.join(', ')]);
  if (recovery.last_resolution) pairs.push(['last resolution', recovery.last_resolution]);
  if (recovery.reason) pairs.push(['reason', recovery.reason]);
  return keyValues(pairs);
}

function renderStateWalHealth(recovery: PersistenceRecoveryStatus): string {
  const state = recovery.state_recovery;
  if (state) {
    if (!state.complete || !state.writable || state.outcome === 'incomplete' || state.outcome === 'reinitialized') {
      return red(`degraded${state.reason ? ` · ${state.reason}` : ''}`);
    }
    if (
      recovery.consecutive_persistence_failures > 0
      || recovery.journal.malformed
      || recovery.journal.preserved
      || (state.outcome === 'recovered' && state.source === 'snapshot')
    ) {
      return yellow(`healthy with recovery warning${state.reason ? ` · ${state.reason}` : ''}`);
    }
    if (recovery.config_recovery?.status === 'write_incomplete' || recovery.config_recovery?.intent_present) {
      return green('healthy · writes paused for configuration write recovery');
    }
    if (recovery.config_recovery?.resolution_required) {
      return green('healthy · writes paused only for configuration reconciliation');
    }
    return green('healthy');
  }
  if (recovery.persistence_reason) {
    return red(`degraded · ${recovery.persistence_reason}`);
  }
  if (recovery.config_recovery?.status === 'write_incomplete' || recovery.config_recovery?.intent_present) {
    return green('healthy · writes paused for configuration write recovery');
  }
  if (recovery.config_recovery?.resolution_required) {
    return green('healthy · writes paused only for configuration reconciliation');
  }
  if (!recovery.complete || !recovery.writable) {
    return red(`degraded${recovery.reason ? ` · ${recovery.reason}` : ''}`);
  }
  if (recovery.consecutive_persistence_failures > 0 || recovery.journal.malformed) {
    return yellow('degraded');
  }
  return green('healthy');
}

function renderStateMigrationStatus(status: StateMigrationStatus): string {
  const pairs: Array<[string, string]> = [
    ['status', status.status],
    ['supported state version', String(status.supported_state_version)],
    ['supported journal version', String(status.supported_journal_version)],
    ['migration required', status.migration_required ? 'yes' : 'no'],
  ];
  if (status.observed_state_version !== undefined) {
    pairs.push(['observed state version', String(status.observed_state_version)]);
  }
  if (status.observed_journal_version !== undefined) {
    pairs.push(['observed journal version', String(status.observed_journal_version)]);
  }
  if (status.backup_path) pairs.push(['migration backup', status.backup_path]);
  if (status.backup_manifest_sha256) {
    pairs.push(['backup manifest SHA-256', status.backup_manifest_sha256]);
  }
  if (status.reason) pairs.push(['reason', status.reason]);
  return keyValues(pairs);
}

export function renderRecovery(data: RecoveryResponse): string {
  const recovery = data.recovery;
  const allocatedLogical = recovery.highest_allocated_logical_seq
    ?? recovery.highest_allocated_seq;
  const appliedLogical = recovery.highest_contiguous_applied_logical_seq
    ?? recovery.highest_contiguous_applied_seq;
  const persistencePairs: Array<[string, string]> = [
    ['combined status', renderPersistenceRecovery(recovery)],
    ['state/WAL health', renderStateWalHealth(recovery)],
    ['durable mutations', recovery.writable ? 'enabled' : 'paused'],
    ['base checkpoint', String(recovery.base_checkpoint)],
    ['applied / on-disk checkpoint', `${appliedLogical}/${recovery.highest_on_disk_seq}`],
    ['allocated sequence', String(allocatedLogical)],
    ['WAL', recovery.journal.enabled ? `${recovery.journal.applied} applied · ${recovery.journal.skipped} skipped · ${recovery.journal.failed} failed` : 'disabled'],
    ['WAL preserved', recovery.journal.preserved ? 'yes' : 'no'],
    ['WAL malformed', recovery.journal.malformed ? 'yes' : 'no'],
  ];
  if (
    recovery.highest_allocated_frame_seq !== undefined
    && recovery.highest_physical_frame_seq !== undefined
  ) {
    persistencePairs.splice(6, 0,
      ['logical applied checkpoint', String(appliedLogical)],
      ['logical allocated high-water', String(allocatedLogical)],
      [
      'physical frames allocated / on-disk',
      `${recovery.highest_allocated_frame_seq}/${recovery.highest_physical_frame_seq}`,
      ],
    );
  }
  if (recovery.journal.path) persistencePairs.push(['WAL path', recovery.journal.path]);
  if (recovery.persistence_reason) persistencePairs.push(['persistence reason', recovery.persistence_reason]);
  if (recovery.last_persistence_error) persistencePairs.push(['last persistence error', recovery.last_persistence_error]);
  const out = [
    heading('Recovery'),
    keyValues(persistencePairs),
  ];
  if (recovery.config_recovery) {
    out.push('', heading('Active configuration'), renderConfigRecovery(recovery.config_recovery));
  }
  if (recovery.state_migration) {
    out.push('', heading('State format'), renderStateMigrationStatus(recovery.state_migration));
  }
  if (recovery.artifact_recovery) {
    const reports = recovery.artifact_recovery.reports;
    out.push('', heading('Artifact recovery'));
    out.push(keyValues([
      ['report archive mutations', reports.writable ? 'enabled' : 'paused'],
      ['ambiguous report deletions', reports.uncertain_deletion_ids.length > 0
        ? reports.uncertain_deletion_ids.join(', ')
        : 'none'],
      ...(reports.reason ? [['report archive reason', reports.reason] as [string, string]] : []),
    ]));
    if (recovery.artifact_recovery.generation_warnings?.length) {
      out.push(recovery.artifact_recovery.generation_warnings
        .map(warning => `  ${yellow('!')} ${warning.namespace} · ${warning.root}: ${warning.message}`)
        .join('\n'));
    }
  }
  if (recovery.runtime_ownership_warnings?.length) {
    out.push('', heading('Runtime ownership warnings'));
    out.push(recovery.runtime_ownership_warnings
      .map(warning => {
        const pid = warning.pid === undefined ? '' : ` · PID ${warning.pid}`;
        return `  ${yellow('!')} ${warning.run_id}${pid} · ${warning.lifecycle}: ${warning.message}`;
      })
      .join('\n'));
  }
  if (recovery.coordination_warnings?.length) {
    out.push('', heading('Coordination recovery warnings'));
    out.push(recovery.coordination_warnings
      .map(warning => `  ${yellow('!')} ${warning.message}`)
      .join('\n'));
  }
  return out.join('\n');
}

export function renderStateMigrationInspection(
  inspection: StateMigrationInspection,
): string {
  const pairs: Array<[string, string]> = [
    ['status', inspection.status],
    ['state file', inspection.state_file],
    ['ready', inspection.ready ? 'yes' : 'no'],
    ['migration required', inspection.migration_required ? 'yes' : 'no'],
    ['supported state version', String(inspection.supported_state_version)],
    ['supported journal version', String(inspection.supported_journal_version)],
  ];
  if (inspection.config_file) pairs.push(['config file', inspection.config_file]);
  if (inspection.selected_base) pairs.push(['selected recovery base', inspection.selected_base]);
  if (inspection.observed_state_version !== undefined) {
    pairs.push(['observed state version', String(inspection.observed_state_version)]);
  }
  if (inspection.observed_journal_version !== undefined) {
    pairs.push(['observed journal version', String(inspection.observed_journal_version)]);
  }
  if (inspection.config_semantics_match !== undefined) {
    pairs.push(['config semantics match', inspection.config_semantics_match ? 'yes' : 'no']);
  }
  if (inspection.config_revision_seed_allowed !== undefined) {
    pairs.push(['revision 1 seed allowed', inspection.config_revision_seed_allowed ? 'yes' : 'no']);
  }
  const out = [heading('State migration check'), keyValues(pairs)];
  if (inspection.blockers.length > 0) {
    out.push('', heading('Blockers'));
    out.push(inspection.blockers.map(blocker => `  ${red('!')} ${blocker}`).join('\n'));
  }
  if (inspection.warnings.length > 0) {
    out.push('', heading('Warnings'));
    out.push(inspection.warnings.map(warning => `  ${yellow('!')} ${warning}`).join('\n'));
  }
  return out.join('\n');
}

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
  if (s.persistence_recovery) pairs.push(['recovery', renderPersistenceRecovery(s.persistence_recovery)]);
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
    ['STATE', 'ID', 'KIND', 'GEN', 'TITLE', 'AGENT'],
    sessions.map(s => [
      s.state,
      s.id,
      s.kind,
      String(s.connection_generation ?? 0),
      s.title ?? s.host ?? '',
      s.claimed_by ?? s.agent_id ?? '',
    ]),
    { color: [s => (s.trim() === 'connected' ? green : s.trim() === 'error' ? red : dim)(s), dim, undefined, dim, undefined, dim] },
  );
}

export function renderQueries(queries: AgentQuery[]): string {
  if (!queries.length) return green('No agents waiting on you.');
  return queries.map(q => `  ${yellow('?')} ${dim(q.query_id)} ${dim(`[${q.agent_id ?? 'agent'}]`)}\n    ${q.question}`).join('\n');
}

interface PlaybookListResponse {
  runs: Array<{
    run_id: string;
    schema_version?: number;
    credential_id?: string;
    definition?: { title?: string; provider?: string };
    status?: string;
    report_status?: string;
    steps?: Array<{ status?: string; attempts?: Array<{ status?: string; claimed_by_task_id?: string; claimed_via?: string }> }>;
    updated_at?: string;
  }>;
  total: number;
}

export function renderPlaybooks(response: PlaybookListResponse): string {
  if (!response.runs.length) return dim('No playbook runs match the filter.');
  return formatTable(
    ['STATUS', 'RUN', 'PROVIDER', 'CREDENTIAL', 'PROGRESS', 'OWNER', 'REPORT'],
    response.runs.map(run => {
      const steps = run.steps ?? [];
      const complete = steps.filter(step => step.status === 'succeeded').length;
      const active = steps.flatMap(step => step.attempts ?? [])
        .find(attempt => ['claimed', 'awaiting_approval', 'running'].includes(attempt.status ?? ''));
      return [
        run.status ?? 'legacy',
        run.run_id,
        run.definition?.provider ?? '—',
        run.credential_id ?? '—',
        `${complete}/${steps.length}`,
        active?.claimed_by_task_id ?? active?.claimed_via ?? '—',
        run.report_status ?? '—',
      ];
    }),
    { color: [s => (s.trim() === 'succeeded' ? green : s.trim() === 'failed' || s.trim() === 'interrupted' ? yellow : cyan)(s), dim, undefined, dim, undefined, dim, undefined] },
  );
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
