import type { ActivityLogEntry } from './engine-context.js';
import type { AgentTask } from '../types.js';

export type AgentConsoleKind =
  | 'thought'
  | 'action'
  | 'approval'
  | 'finding'
  | 'session'
  | 'transcript'
  | 'system';

export type AgentConsoleSeverity = 'info' | 'success' | 'warning' | 'error';

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
}

export function activityMatchesAgent(entry: ActivityLogEntry, task: AgentTask): boolean {
  return entry.agent_id === task.agent_id
    || entry.agent_id === task.id
    || entry.linked_agent_task_id === task.id
    || entry.details?.agent_id === task.agent_id
    || entry.details?.task_id === task.id
    || entry.details?.linked_agent_task_id === task.id;
}

export function buildAgentConsoleEvents(
  entries: ActivityLogEntry[],
  task: AgentTask,
  query: AgentConsoleQuery = {},
): AgentConsoleEvent[] {
  let matched = entries
    .filter(entry => activityMatchesAgent(entry, task))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const after = query.after;
  if (after) {
    matched = matched.filter(entry =>
      entry.timestamp > after
      || entry.event_id === after
      || entry.action_id === after
    );
  }

  if (query.limit && query.limit > 0) {
    matched = matched.slice(-query.limit);
  }

  return matched
    .map(entry => activityToAgentConsoleEvent(entry, task))
    .filter((event): event is AgentConsoleEvent => event !== null);
}

export function activityToAgentConsoleEvent(entry: ActivityLogEntry, task?: AgentTask): AgentConsoleEvent | null {
  const agentId = task?.id
    || entry.linked_agent_task_id
    || entry.agent_id
    || stringDetail(entry.details?.task_id)
    || stringDetail(entry.details?.agent_id);
  if (!agentId) return null;

  const kind = classifyAgentConsoleKind(entry);
  const severity = classifySeverity(entry);
  const links = extractLinks(entry);
  const title = buildTitle(entry, kind);
  const status = entry.result_classification || entry.validation_result || entry.outcome || statusFromEventType(entry.event_type);

  return {
    id: entry.event_id || `${entry.timestamp}-${entry.event_type || 'event'}-${entry.action_id || agentId}`,
    timestamp: entry.timestamp,
    agent_id: agentId,
    kind,
    severity,
    title,
    summary: entry.description,
    status,
    links: hasLinks(links) ? links : undefined,
    raw: {
      event_type: entry.event_type,
      category: entry.category,
      provenance: entry.provenance,
      action_id: entry.action_id,
      frontier_item_id: entry.frontier_item_id,
      details: entry.details,
    },
  };
}

function classifyAgentConsoleKind(entry: ActivityLogEntry): AgentConsoleKind {
  const type = (entry.event_type || '').toLowerCase();
  const category = (entry.category || '').toLowerCase();
  const description = (entry.description || '').toLowerCase();

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
  if (entry.validation_result === 'warning_only' || type.includes('warning')) return 'warning';
  if (entry.result_classification === 'success' || entry.outcome === 'success' || type.includes('completed') || type.includes('connected')) return 'success';
  return 'info';
}

function buildTitle(entry: ActivityLogEntry, kind: AgentConsoleKind): string {
  const thoughtKind = stringDetail(entry.details?.kind);
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
