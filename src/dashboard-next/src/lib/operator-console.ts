import type { ActivityEntry, AgentConsoleEvent, AgentInfo } from './types';
import { classifyActivity, extractActivityLinks } from './activity-console';

export const OPERATOR_CONSOLE_SOURCE = 'operator';

export interface OperatorConsoleBuildOptions {
  agents?: AgentInfo[];
  limit?: number;
}

export function buildOperatorConsoleEvents(
  entries: ActivityEntry[],
  options: OperatorConsoleBuildOptions = {},
): AgentConsoleEvent[] {
  const agentLabels = new Map<string, string>();
  for (const agent of options.agents || []) {
    agentLabels.set(agent.id, agent.agent_id || agent.id);
    if (agent.agent_id) agentLabels.set(agent.agent_id, agent.agent_id);
  }

  const events = entries
    .map((entry, index) => activityToOperatorConsoleEvent(entry, index, agentLabels))
    .filter((event): event is AgentConsoleEvent => !!event)
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  return options.limit ? events.slice(-options.limit) : events;
}

function activityToOperatorConsoleEvent(
  entry: ActivityEntry,
  index: number,
  agentLabels: Map<string, string>,
): AgentConsoleEvent | null {
  const eventType = (entry.event_type || '').toLowerCase();
  if (eventType === 'heartbeat') return null;

  const links = extractActivityLinks(entry);
  const details = entry.details || {};
  const sourceKind = entry.source_kind || inferConsoleSourceKind(entry);
  const agentId = sourceKind === 'subagent'
    ? (entry.agent_id || links.agentId || stringDetail(details.agent_id) || OPERATOR_CONSOLE_SOURCE)
    : OPERATOR_CONSOLE_SOURCE;
  const kind = consoleKindFor(entry);
  const severity = consoleSeverityFor(entry);
  const title = consoleTitleFor(entry);
  const sourceLabel = sourceLabelFor(entry, sourceKind, agentId, agentLabels);

  return {
    id: entry.event_id || entry.id || `${entry.timestamp || 'activity'}-${eventType || 'event'}-${index}`,
    timestamp: entry.timestamp || new Date(0).toISOString(),
    agent_id: agentId,
    source_kind: sourceKind,
    source_label: sourceLabel,
    kind,
    severity,
    title,
    summary: entry.description || title,
    status: statusFor(entry),
    links: {
      action_id: links.actionId,
      frontier_item_id: links.frontierItemId,
      evidence_id: evidenceIdFor(details),
      session_id: stringDetail(details.session_id),
      finding_ids: arrayOfStrings(details.finding_ids || details.findings),
      node_ids: links.nodeIds,
    },
    raw: {
      event_type: entry.event_type,
      source_kind: sourceKind,
      operator_name: entry.operator_name,
      operator_model: entry.operator_model,
      details,
    },
  };
}

function inferConsoleSourceKind(entry: ActivityEntry): AgentConsoleEvent['source_kind'] {
  const details = entry.details || {};
  const source = stringDetail(details.source)?.toLowerCase() || '';
  const invokingTool = stringDetail(details.invoking_tool)?.toLowerCase() || '';
  if (entry.agent_id) return 'subagent';
  if (source === 'dashboard' || invokingTool === 'dashboard') return 'dashboard';
  if (source.includes('runner') || invokingTool.includes('runner')) return 'runner';
  if (entry.event_type === 'system' || entry.event_type?.startsWith('session_') || entry.event_type?.startsWith('mock_service_')) return 'system';
  return 'primary';
}

function sourceLabelFor(
  entry: ActivityEntry,
  sourceKind: AgentConsoleEvent['source_kind'],
  agentId: string,
  agentLabels: Map<string, string>,
): string {
  if (sourceKind === 'subagent') return agentLabels.get(agentId) || agentId;
  if (sourceKind === 'runner') return 'Scripted runner';
  if (sourceKind === 'dashboard') return 'Dashboard';
  if (sourceKind === 'system') return 'System';
  const name = entry.operator_name || 'Primary Operator';
  const model = entry.operator_model || 'model unknown';
  return `${name} · ${model}`;
}

function consoleKindFor(entry: ActivityEntry): AgentConsoleEvent['kind'] {
  const type = (entry.event_type || '').toLowerCase();
  const desc = (entry.description || '').toLowerCase();
  if (type.includes('thought') || type.includes('decision') || desc.includes('thought')) return 'thought';
  if (type.includes('approval') || desc.includes('approval') || desc.includes('approved') || desc.includes('denied')) return 'approval';
  if (type.includes('session') || desc.includes('session')) return 'session';
  if (type.includes('transcript')) return 'transcript';
  if (type.includes('warning') || type.includes('guardrail') || type.includes('system')) return 'system';
  if (classifyActivity(entry) === 'finding') return 'finding';
  return 'action';
}

function consoleSeverityFor(entry: ActivityEntry): AgentConsoleEvent['severity'] {
  const type = (entry.event_type || '').toLowerCase();
  const desc = (entry.description || '').toLowerCase();
  if (
    entry.result_classification === 'failure'
    || type.includes('failed')
    || type.includes('error')
    || desc.includes('failed')
    || desc.includes('error')
  ) return 'error';
  if (type.includes('warning') || desc.includes('warning') || desc.includes('approval')) return 'warning';
  if (entry.result_classification === 'success' || type.includes('completed') || type.includes('finding')) return 'success';
  return 'info';
}

function consoleTitleFor(entry: ActivityEntry): string {
  const type = (entry.event_type || '').toLowerCase();
  if (type.includes('thought')) return 'Thought';
  if (type.includes('approval')) return 'Approval';
  if (type.includes('action_started')) return 'Action started';
  if (type.includes('action_completed')) return 'Action completed';
  if (type.includes('action_failed')) return 'Action failed';
  if (type.includes('validated')) return 'Action validated';
  if (type.includes('parse') || type.includes('finding')) return 'Finding';
  if (type.includes('session_opened')) return 'Session opened';
  if (type.includes('session_closed')) return 'Session closed';
  if (type.includes('session')) return 'Session';
  if (type.includes('transcript')) return 'Transcript submitted';
  if (type.includes('agent_registered')) return 'Agent registered';
  if (type.includes('agent_updated')) return 'Agent updated';
  if (type.includes('warning')) return 'Warning';
  return titleCase(entry.event_type || 'Activity');
}

function statusFor(entry: ActivityEntry): string | undefined {
  const details = entry.details || {};
  return stringDetail(details.status)
    || stringDetail(details.approval_status)
    || stringDetail(details.session_state)
    || entry.validation_result
    || entry.result_classification;
}

function evidenceIdFor(details: Record<string, unknown>): string | undefined {
  return stringDetail(details.evidence_id)
    || stringDetail(details.stdout_evidence_id)
    || stringDetail(details.stderr_evidence_id);
}

function stringDetail(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function arrayOfStrings(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const strings = value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0);
  return strings.length > 0 ? strings : undefined;
}

function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}
