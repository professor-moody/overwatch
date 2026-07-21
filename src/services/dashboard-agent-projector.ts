import type { AgentTask, Campaign } from '../types.js';
import type { AgentDto } from '../contracts/dashboard-v1.js';
import type { ActivityLogEntry } from './engine-context.js';
import { agentLabelOf, taskIdOf } from './agent-identity.js';
import { readAgentWorkMetadata } from './agent-work.js';

const BOOKKEEPING_EVENTS = new Set([
  'instrumentation_warning',
  'operator_command',
  'agent_registered',
  'agent_updated',
  'heartbeat',
]);

interface LatestActivity {
  description: string;
  event_type?: string;
  timestamp: string;
}

/**
 * Project persisted agent tasks into the one dashboard DTO used by REST and
 * state/WebSocket snapshots. Exact task linkage always wins. Legacy label-only
 * events are attributed only when that label belongs to one task, never by
 * guessing between duplicate labels.
 */
export function projectAgentDtos(
  tasks: AgentTask[],
  history: ActivityLogEntry[],
  campaigns: Campaign[],
  now: number = Date.now(),
): AgentDto[] {
  const taskById = new Map(tasks.map(task => [taskIdOf(task), task]));
  const taskIdsByLabel = new Map<string, string[]>();
  for (const task of tasks) {
    const label = agentLabelOf(task);
    const ids = taskIdsByLabel.get(label) ?? [];
    ids.push(taskIdOf(task));
    taskIdsByLabel.set(label, ids);
  }

  const latestByTask = new Map<string, LatestActivity>();
  const lastFindingAtByTask = new Map<string, string>();
  const findingIdsByTask = new Map<string, Set<string>>();

  // Action completion/finding events do not always repeat the task ID. Build
  // the authoritative action→task index first so later projection never has to
  // guess from a potentially duplicated agent label.
  const taskIdByAction = new Map<string, string>();
  for (const entry of history) {
    if (!entry.action_id) continue;
    const detailTaskId = (entry.details as { task_id?: unknown } | undefined)?.task_id;
    const explicitTaskId = typeof entry.linked_agent_task_id === 'string'
      ? entry.linked_agent_task_id
      : typeof detailTaskId === 'string'
        ? detailTaskId
        : undefined;
    if (explicitTaskId) taskIdByAction.set(entry.action_id, explicitTaskId);
  }

  for (const entry of history) {
    const detailTaskId = (entry.details as { task_id?: unknown } | undefined)?.task_id;
    const explicitlyLinkedTaskId = typeof entry.linked_agent_task_id === 'string'
      ? entry.linked_agent_task_id
      : typeof detailTaskId === 'string'
        ? detailTaskId
        : entry.action_id
          ? taskIdByAction.get(entry.action_id)
          : undefined;
    // Explicit linkage remains authoritative even when the linked task is not
    // in this projection subset (for example, a campaign-detail filter). Never
    // reattribute it to a visible task that happens to share the same label.
    if (explicitlyLinkedTaskId && !taskById.has(explicitlyLinkedTaskId)) continue;
    const legacyIds = !explicitlyLinkedTaskId && entry.agent_id ? taskIdsByLabel.get(entry.agent_id) : undefined;
    const taskId = explicitlyLinkedTaskId ?? (legacyIds?.length === 1 ? legacyIds[0] : undefined);
    if (!taskId) continue;

    const isBookkeeping = entry.category === 'system' || BOOKKEEPING_EVENTS.has(entry.event_type ?? '');
    if (!isBookkeeping) {
      const previous = latestByTask.get(taskId);
      if (!previous || entry.timestamp > previous.timestamp) {
        latestByTask.set(taskId, {
          description: entry.description,
          event_type: entry.event_type,
          timestamp: entry.timestamp,
        });
      }
    }

    const linkedFindingIds = entry.linked_finding_ids ?? [];
    const isFinding = linkedFindingIds.length > 0
      || entry.category === 'finding'
      || (entry.event_type ?? '').startsWith('finding')
      || entry.event_type === 'parse_output';
    if (isFinding) {
      const previous = lastFindingAtByTask.get(taskId);
      if (!previous || entry.timestamp > previous) lastFindingAtByTask.set(taskId, entry.timestamp);
    }
    if (linkedFindingIds.length > 0) {
      const ids = findingIdsByTask.get(taskId) ?? new Set<string>();
      for (const findingId of linkedFindingIds) ids.add(findingId);
      findingIdsByTask.set(taskId, ids);
    }
  }

  const campaignById = new Map(campaigns.map(campaign => [campaign.id, campaign]));
  const mergedSourceIdsByTask = new Map<string, string[]>();
  for (const task of tasks) {
    const canonicalTaskId = task.work?.merged_into_task_id;
    if (!canonicalTaskId) continue;
    const sourceIds = mergedSourceIdsByTask.get(canonicalTaskId) ?? [];
    sourceIds.push(taskIdOf(task));
    mergedSourceIdsByTask.set(canonicalTaskId, sourceIds);
  }
  for (const sourceIds of mergedSourceIdsByTask.values()) sourceIds.sort();

  return tasks.map(task => {
    const taskId = taskIdOf(task);
    const agentLabel = agentLabelOf(task);
    const latest = task.status === 'running' ? latestByTask.get(taskId) : undefined;
    // NOTE: elapsed runtime is intentionally NOT projected here. It is a value that
    // changes every tick, so emitting it marked every running agent "changed" on each
    // projection and defeated the bounded/keyed agent patch. The client derives it from
    // `assigned_at` (see agentElapsedMs in dashboard-next lib/utils).
    const campaign = task.campaign_id ? campaignById.get(task.campaign_id) : undefined;
    const heartbeatAt = task.heartbeat_at ? new Date(task.heartbeat_at).getTime() : NaN;
    const heartbeatTtlMs = (task.heartbeat_ttl_seconds ?? 120) * 1_000;
    const staleHeartbeat = task.status === 'running'
      && Number.isFinite(heartbeatAt)
      && now - heartbeatAt > heartbeatTtlMs;
    const lifecycle = task.status === 'pending'
      ? 'queued' as const
      : task.status === 'running'
        ? staleHeartbeat ? 'stale' as const : 'live' as const
        : task.status;

    return {
      ...task,
      task_id: taskId,
      agent_label: agentLabel,
      id: taskId,
      agent_id: agentLabel,
      assigned_at: task.assigned_at,
      subgraph_node_ids: task.subgraph_node_ids ?? [],
      queued: task.status === 'pending',
      lifecycle,
      live: lifecycle === 'live',
      ...(campaign ? { campaign: { id: campaign.id, name: campaign.name, strategy: campaign.strategy } } : {}),
      ...(latest ? {
        current_action: latest.description,
        current_action_type: latest.event_type,
        current_action_at: latest.timestamp,
      } : {}),
      ...(lastFindingAtByTask.has(taskId) ? { last_finding_at: lastFindingAtByTask.get(taskId) } : {}),
      findings_count: findingIdsByTask.get(taskId)?.size ?? 0,
      work: readAgentWorkMetadata(task),
      ...(mergedSourceIdsByTask.has(taskId)
        ? { merged_source_task_ids: mergedSourceIdsByTask.get(taskId) }
        : {}),
    } satisfies AgentDto;
  });
}
