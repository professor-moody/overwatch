import type { ActivityLogEntry } from './engine-context.js';
import type { AgentTask } from '../types.js';
import { agentLabelOf, taskIdOf } from './agent-identity.js';

export type AgentConsoleKind =
  | 'thought'
  | 'action'
  | 'approval'
  | 'finding'
  | 'session'
  | 'transcript'
  | 'system'
  | 'command';

export type AgentConsoleSeverity = 'info' | 'success' | 'warning' | 'error';

export type AgentConsoleSourceKind = 'primary' | 'subagent' | 'runner' | 'system' | 'dashboard';

/** Non-subagent events collapse to this agent_id so the operator console can show them. */
export const OPERATOR_CONSOLE_SOURCE = 'operator';

export interface AgentConsoleLinks {
  action_id?: string;
  frontier_item_id?: string;
  evidence_id?: string;
  session_id?: string;
  finding_ids?: string[];
  node_ids?: string[];
}

export interface AgentConsoleEvent {
  id: string;
  timestamp: string;
  agent_id: string;
  // 3A.3: attribution so the live WS-pushed stream is primary-first (matches the
  // polled /api/history builder). Without these, primary/operator events were
  // dropped from the WS push and the console only showed sub-agents.
  source_kind?: AgentConsoleSourceKind;
  source_label?: string;
  operator_name?: string;
  operator_model?: string;
  kind: AgentConsoleKind;
  severity: AgentConsoleSeverity;
  title: string;
  summary: string;
  status?: string;
  links?: AgentConsoleLinks;
  raw?: Record<string, unknown>;
}

export interface AgentConsoleQuery {
  limit?: number;
  after?: string;
  allowLegacyLabel?: boolean;
}

export interface OperatorConsoleQuery {
  limit?: number;
  after?: string;
}

/** Project the fleet/operator stream through the same canonical mapping used
 * by per-agent HTTP and WebSocket deltas. Exact task relationships win; a
 * legacy label is accepted only when it identifies one task. */
export function buildOperatorConsoleEvents(
  entries: ActivityLogEntry[],
  tasks: AgentTask[],
  query: OperatorConsoleQuery = {},
): AgentConsoleEvent[] {
  const taskById = new Map(tasks.map(task => [taskIdOf(task), task]));
  const tasksByLabel = new Map<string, AgentTask[]>();
  for (const task of tasks) {
    const label = agentLabelOf(task);
    tasksByLabel.set(label, [...(tasksByLabel.get(label) ?? []), task]);
  }

  let projected = entriesAfterCursor(entries, query.after)
    .map(entry => {
      const detailTaskId = stringDetail(entry.details?.task_id) || stringDetail(entry.details?.linked_agent_task_id);
      const exactTaskId = entry.linked_agent_task_id
        || detailTaskId
        || (entry.agent_id && taskById.has(entry.agent_id) ? entry.agent_id : undefined);
      const legacyMatches = !exactTaskId && entry.agent_id ? tasksByLabel.get(entry.agent_id) : undefined;
      const task = exactTaskId
        ? taskById.get(exactTaskId)
        : legacyMatches?.length === 1 ? legacyMatches[0] : undefined;
      return activityToAgentConsoleEvent(entry, task);
    })
    .filter((event): event is AgentConsoleEvent => event !== null)
    .sort((left, right) => left.timestamp.localeCompare(right.timestamp));

  if (query.limit && query.limit > 0) projected = projected.slice(-query.limit);
  return projected;
}

export function activityMatchesAgent(
  entry: ActivityLogEntry,
  task: AgentTask,
  allowLegacyLabel = true,
): boolean {
  const taskId = taskIdOf(task);
  const agentLabel = agentLabelOf(task);
  return entry.agent_id === taskId
    || entry.linked_agent_task_id === taskId
    || entry.details?.task_id === taskId
    || entry.details?.linked_agent_task_id === taskId
    || (allowLegacyLabel && (
      entry.agent_id === agentLabel
      || entry.details?.agent_id === agentLabel
    ));
}

export function buildAgentConsoleEvents(
  entries: ActivityLogEntry[],
  task: AgentTask,
  query: AgentConsoleQuery = {},
): AgentConsoleEvent[] {
  let matched = entries
    .filter(entry => activityMatchesAgent(entry, task, query.allowLegacyLabel ?? true))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  matched = entriesAfterCursor(matched, query.after);

  if (query.limit && query.limit > 0) {
    matched = matched.slice(-query.limit);
  }

  return matched
    .map(entry => activityToAgentConsoleEvent(entry, task))
    .filter((event): event is AgentConsoleEvent => event !== null);
}

/**
 * `after` accepts either the stable id/action id of a returned event or a
 * timestamp. IDs are positional cursors: exclude the matched event and return
 * everything after it. Timestamp cursors retain the compatibility comparison.
 */
function entriesAfterCursor(
  entries: ActivityLogEntry[],
  after?: string,
): ActivityLogEntry[] {
  if (!after) return entries;
  const cursorIndex = entries.findIndex(entry =>
    entry.event_id === after || entry.action_id === after
  );
  if (cursorIndex >= 0) return entries.slice(cursorIndex + 1);
  return entries.filter(entry => entry.timestamp > after);
}

export function activityToAgentConsoleEvent(entry: ActivityLogEntry, task?: AgentTask): AgentConsoleEvent | null {
  if (entry.event_type === 'heartbeat') return null;

  const sourceKind = task ? 'subagent' : (entry.source_kind || inferSourceKind(entry));
  const subAgentId = (task ? taskIdOf(task) : undefined)
    || entry.linked_agent_task_id
    || entry.agent_id
    || stringDetail(entry.details?.task_id)
    || stringDetail(entry.details?.agent_id);
  // Subagent events need a real agent id; everything else (primary operator,
  // dashboard commands, runner, system) collapses to the operator lane so the
  // console surfaces it instead of dropping it (the old behavior).
  if (sourceKind === 'subagent' && !subAgentId) return null;
  const agentId = sourceKind === 'subagent' ? subAgentId! : OPERATOR_CONSOLE_SOURCE;

  const kind = classifyAgentConsoleKind(entry);
  const severity = classifySeverity(entry);
  const links = extractLinks(entry);
  const title = buildTitle(entry, kind);
  const status = entry.result_classification || entry.validation_result || entry.outcome || statusFromEventType(entry.event_type);

  return {
    id: entry.event_id || `${entry.timestamp}-${entry.event_type || 'event'}-${entry.action_id || agentId}`,
    timestamp: entry.timestamp,
    agent_id: agentId,
    source_kind: sourceKind,
    source_label: sourceLabelFor(entry, sourceKind, agentId, task),
    operator_name: entry.operator_name,
    operator_model: entry.operator_model,
    kind,
    severity,
    title,
    summary: projectConsoleSummary(entry, task),
    status,
    links: hasLinks(links) ? links : undefined,
    raw: {
      event_type: entry.event_type,
      category: entry.category,
      provenance: entry.provenance,
      source_kind: sourceKind,
      action_id: entry.action_id,
      frontier_item_id: entry.frontier_item_id,
      details: entry.details,
    },
  };
}

/**
 * Keep the tamper-evident activity row untouched, but repair the presentation of
 * legacy agent-registration rows that interpolated an absent frontier id. Those
 * rows are durable and otherwise keep showing `for undefined` after the runtime
 * bug is fixed.
 */
function projectConsoleSummary(entry: ActivityLogEntry, task?: AgentTask): string {
  const legacyDispatch = /^Agent dispatched:\s*(.*?)\s+(?:for|as)\s+undefined\s*$/i
    .exec(entry.description);
  if (entry.event_type !== 'agent_registered' && !legacyDispatch) return entry.description;
  const details = entry.details || {};
  // Old persisted tasks and activity rows predate canonical agent_label. Keep
  // presentation total even when the task object exists but its legacy label is
  // absent; otherwise JavaScript interpolation recreates the literal
  // "Agent dispatched: undefined" bug we are trying to repair.
  const taskLabel = task ? stringDetail(agentLabelOf(task)) : undefined;
  const label = taskLabel
    || stringDetail(details.agent_label)
    || stringDetail(details.agent_id)
    || entry.agent_id
    || legacyDispatch?.[1]
    || 'Agent';
  const frontierId = entry.frontier_item_id
    || stringDetail(details.frontier_item_id);
  if (frontierId) return `Agent dispatched: ${label} for frontier ${frontierId}`;
  const role = task?.role || stringDetail(details.role);
  if (role === 'planner') return `Agent dispatched: ${label} as operator planner`;
  const nodeIds = task?.subgraph_node_ids
    || (Array.isArray(details.subgraph_node_ids)
      ? details.subgraph_node_ids.filter((value): value is string => typeof value === 'string')
      : []);
  if (nodeIds.length > 0) return `Agent dispatched: ${label} at ${nodeIds.length} node(s)`;
  return `Agent dispatched: ${label}`;
}

/**
 * Fallback source-kind inference for entries the engine didn't already stamp
 * (engine-context.normalizeActivityLogEntry stamps source_kind for most paths).
 * Mirrors the client operator-console inference + the engine's inferSourceKind.
 */
function inferSourceKind(entry: ActivityLogEntry): AgentConsoleSourceKind {
  const details = entry.details || {};
  const source = stringDetail(details.source)?.toLowerCase() || '';
  const invokingTool = stringDetail(details.invoking_tool)?.toLowerCase() || '';
  if (source === 'dashboard' || invokingTool === 'dashboard') return 'dashboard';
  if (source.includes('runner') || invokingTool.includes('runner')) return 'runner';
  if (entry.agent_id || stringDetail(details.agent_id) || entry.category === 'agent') return 'subagent';
  if (entry.category === 'system' || (entry.event_type || '').startsWith('session_') || (entry.event_type || '').startsWith('mock_service_')) return 'system';
  return 'primary';
}

function sourceLabelFor(entry: ActivityLogEntry, sourceKind: AgentConsoleSourceKind, agentId: string, task?: AgentTask): string {
  if (sourceKind === 'subagent') return task ? agentLabelOf(task) : agentId;
  if (sourceKind === 'runner') return 'Scripted runner';
  if (sourceKind === 'dashboard') return 'Dashboard';
  if (sourceKind === 'system') return 'System';
  return `${entry.operator_name || 'Primary Operator'} · ${entry.operator_model || 'model unknown'}`;
}

function classifyAgentConsoleKind(entry: ActivityLogEntry): AgentConsoleKind {
  const type = (entry.event_type || '').toLowerCase();
  const category = (entry.category || '').toLowerCase();
  const description = (entry.description || '').toLowerCase();

  if (type === 'operator_command' || type === 'plan_proposed') return 'command';
  if (type === 'thought' || category === 'reasoning') return 'thought';
  if (type.includes('approval') || description.includes('approval')) return 'approval';
  if (type.includes('finding') || type === 'parse_output' || category === 'finding') return 'finding';
  if (type.includes('session') || type.includes('mock_service')) return 'session';
  if (type.includes('transcript')) return 'transcript';
  if (type.includes('warning') || category === 'system') return 'system';
  return 'action';
}

function classifySeverity(entry: ActivityLogEntry): AgentConsoleSeverity {
  const type = (entry.event_type || '').toLowerCase();
  if (entry.result_classification === 'failure' || entry.outcome === 'failure' || type.includes('failed') || type.includes('error')) return 'error';
  // 'partial' (e.g. an operator command where some ops failed) surfaces as a
  // warning so it isn't hidden from the console "errors" filter.
  if (entry.result_classification === 'partial' || entry.validation_result === 'warning_only' || type.includes('warning')) return 'warning';
  if (entry.result_classification === 'success' || entry.outcome === 'success' || type.includes('completed') || type.includes('connected')) return 'success';
  return 'info';
}

function buildTitle(entry: ActivityLogEntry, kind: AgentConsoleKind): string {
  const thoughtKind = stringDetail(entry.details?.kind);
  if (kind === 'command') return entry.event_type === 'plan_proposed' ? 'Plan proposed' : 'Operator command';
  if (kind === 'thought') return thoughtKind ? titleCase(thoughtKind) : 'Thought';
  if (kind === 'approval') return 'Approval';
  if (kind === 'finding') return entry.event_type === 'parse_output' ? 'Parsed Output' : 'Finding';
  if (kind === 'session') return 'Session';
  if (kind === 'transcript') return 'Transcript';
  if (kind === 'system') return 'System Warning';
  if (entry.event_type === 'action_started') return 'Action Started';
  if (entry.event_type === 'action_completed') return 'Action Completed';
  if (entry.event_type === 'action_failed') return 'Action Failed';
  if (entry.event_type === 'action_validated') return 'Validated Action';
  return titleCase((entry.event_type || 'action').replace(/_/g, ' '));
}

function statusFromEventType(eventType?: string): string | undefined {
  if (!eventType) return undefined;
  if (eventType.endsWith('_started')) return 'started';
  if (eventType.endsWith('_completed')) return 'completed';
  if (eventType.endsWith('_failed')) return 'failed';
  if (eventType.endsWith('_connected')) return 'connected';
  if (eventType.endsWith('_closed')) return 'closed';
  return undefined;
}

function extractLinks(entry: ActivityLogEntry): AgentConsoleLinks {
  const details = entry.details || {};
  const nodeIds = new Set<string>();
  const findingIds = new Set<string>();

  for (const nodeId of entry.target_node_ids || []) nodeIds.add(nodeId);
  for (const value of [
    details.node_id,
    details.target_node,
    details.source_node,
    details.edge_source,
    details.edge_target,
    details.credential_node,
    details.principal_node,
  ]) {
    if (typeof value === 'string' && value.trim()) nodeIds.add(value.trim());
  }
  for (const findingId of entry.linked_finding_ids || []) findingIds.add(findingId);
  for (const value of [details.finding_id, details.finding_ids]) {
    if (typeof value === 'string' && value.trim()) findingIds.add(value.trim());
    if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item.trim()) findingIds.add(item.trim());
    }
  }

  return {
    action_id: entry.action_id || stringDetail(details.action_id),
    frontier_item_id: entry.frontier_item_id || stringDetail(details.frontier_item_id),
    evidence_id: stringDetail(details.evidence_id) || stringDetail(details.stdout_evidence_id) || stringDetail(details.stderr_evidence_id),
    session_id: stringDetail(details.session_id),
    finding_ids: findingIds.size > 0 ? [...findingIds] : undefined,
    node_ids: nodeIds.size > 0 ? [...nodeIds] : undefined,
  };
}

function hasLinks(links: AgentConsoleLinks): boolean {
  return Boolean(
    links.action_id
    || links.frontier_item_id
    || links.evidence_id
    || links.session_id
    || links.finding_ids?.length
    || links.node_ids?.length,
  );
}

function stringDetail(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function titleCase(value: string): string {
  return value.replace(/\w\S*/g, part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase());
}
