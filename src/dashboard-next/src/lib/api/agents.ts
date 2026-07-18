import type {
  ActivityEntry,
  AgentConsoleEvent,
} from '../types';
import {
  AgentListResponseSchema,
  normalizeLegacyAgentDispatchDescription,
  type ActivityEntryDto,
  type AgentArchetypeSummary as ContractAgentArchetypeSummary,
  type AgentDto,
  type AgentListResponse,
  type AgentQueryDto,
} from '@overwatch/dashboard-contracts';
import {
  DashboardApiError,
  requestDashboardEndpoint,
  type GeneratedDashboardOperationId,
  type GeneratedDashboardOutput,
  type GeneratedDashboardRequestFor,
} from '../api.generated';
import {
  agentDisplayLabel,
  type AgentReference,
} from '../agent-reference';

export {
  agentDisplayLabel,
  canonicalAgentTaskId,
  resolveAgentReference,
  type AgentReference,
} from '../agent-reference';

async function request<T extends GeneratedDashboardOperationId>(
  operationId: T,
  input: GeneratedDashboardRequestFor<T> = {},
): Promise<GeneratedDashboardOutput<T>> {
  return requestDashboardEndpoint(operationId, input);
}

export async function getAgents(): Promise<AgentListResponse> {
  return AgentListResponseSchema.parse(await request('getAgents'));
}

export async function getAgentContext(agentId: string): Promise<{
  task: AgentDto | (Record<string, unknown> & {
    id: string;
    agent_id: string;
    task_id?: string;
    agent_label?: string;
  });
  subgraph: { nodes: unknown[]; edges: unknown[] };
}> {
  return request('getAgentContext', { path: { task_id: agentId } });
}

export async function cancelAgent(agentId: string): Promise<{ ok: boolean }> {
  return request('cancelAgent', { path: { task_id: agentId } });
}

export type DirectiveKind = 'pause' | 'resume' | 'stop' | 'narrow_scope' | 'skip_types' | 'prioritize' | 'instruct';

export async function issueDirective(
  taskId: string,
  kind: DirectiveKind,
  opts: { node_ids?: string[]; frontier_types?: string[]; note?: string } = {},
): Promise<{ ok: boolean; results: unknown[] }> {
  return request('issueAgentDirective', {
    path: { task_id: taskId },
    body: { kind, ...opts },
  });
}

export async function fleetDirective(
  kind: 'pause' | 'resume' | 'stop',
  campaignId?: string,
): Promise<{ ok: boolean; applied: number; total: number }> {
  return request('issueFleetDirective', { body: { kind, campaign_id: campaignId } });
}

export async function fleetInstruct(
  note: string,
  campaignId?: string,
): Promise<{ ok: boolean; applied: number; total: number }> {
  return request('issueFleetDirective', { body: { kind: 'instruct', note, campaign_id: campaignId } });
}

export async function dismissAgent(
  taskId: string,
  opts?: { force?: boolean },
): Promise<{ dismissed: boolean; task_id: string; forced?: boolean }> {
  return request('dismissAgent', {
    path: { task_id: taskId },
    ...(opts?.force ? { body: { force: true } } : {}),
  });
}

export async function fleetDismiss(
  campaignId?: string,
): Promise<{ ok: boolean; dismissed: number; total: number }> {
  return request('dismissFleetAgents', { body: { campaign_id: campaignId } });
}

export interface DispatchAgentResult {
  dispatched: boolean;
  task?: AgentReference;
  reason?: string;
  existing_task_id?: string;
  existing_agent_id?: string;
}

export function dispatchedAgentLabel(
  task: DispatchAgentResult['task'] | QuickDeployResult['task'],
): string {
  return task ? agentDisplayLabel(task) : 'Agent queued';
}

export type AgentArchetypeSummary = ContractAgentArchetypeSummary;

export async function getArchetypes(): Promise<{
  archetypes: AgentArchetypeSummary[];
  models?: { available: string[]; default?: string };
}> {
  return request('getAgentArchetypes');
}

export interface QuickDeployResult {
  dispatched: boolean;
  task?: AgentReference & {
    archetype?: string;
    objective?: string;
  };
  archetype?: string;
  scope?: { added_cidrs: string[]; added_domains: string[]; affected_node_count: number };
  reason?: string;
}

export async function quickDeploy(body: {
  target: string;
  archetype?: string;
  model?: string;
}): Promise<QuickDeployResult> {
  try {
    const result = await request('quickDeployAgent', { body });
    if (typeof result.dispatched === 'boolean') return result as unknown as QuickDeployResult;
    return {
      dispatched: false,
      reason: String(result.reason ?? result.error ?? 'Agent could not be deployed'),
    };
  } catch (error) {
    if (error instanceof DashboardApiError && error.status === 400) {
      const record = error.body && typeof error.body === 'object'
        ? error.body as Record<string, unknown>
        : {};
      return {
        dispatched: false,
        reason: String(record.reason ?? record.error ?? 'invalid request'),
      };
    }
    throw error;
  }
}

export async function dispatchAgent(body: {
  target_node_ids?: string[];
  skill?: string;
  campaign_id?: string;
  frontier_item_id?: string;
  archetype?: string;
  model?: string;
}): Promise<DispatchAgentResult> {
  const result = await request('dispatchAgent', { body });
  if (typeof result.dispatched === 'boolean') return result as unknown as DispatchAgentResult;
  return {
    dispatched: false,
    reason: String(result.reason ?? result.error ?? 'Agent could not be dispatched'),
  };
}

export type DispatchBatchResult = import('@overwatch/dashboard-contracts').DispatchBatchResponse;

export async function dispatchBatch(body: {
  target_node_ids: string[];
  mode?: 'per-node' | 'per-batch';
  batch_size?: number;
  archetype?: string;
  skill?: string;
  model?: string;
  objective?: string;
}): Promise<DispatchBatchResult> {
  return request('dispatchAgentBatch', { body });
}

export type AgentQuery = AgentQueryDto;

export async function getAgentQueries(): Promise<{ queries: AgentQuery[] }> {
  return request('getAgentQueries');
}

export async function answerAgentQuery(queryId: string, answer: string): Promise<{ ok: boolean }> {
  return request('answerAgentQuery', { path: { query_id: queryId }, body: { answer } });
}

export async function answerAgentQueryBatch(
  queryIds: string[],
  answer: string,
): Promise<{ ok: boolean; answered: number }> {
  return request('answerAgentQueriesBatch', { body: { query_ids: queryIds, answer } });
}

export function normalizeActivityEntries(entries: ActivityEntryDto[]): ActivityEntry[] {
  return entries.map(entry => ({
    ...entry,
    id: entry.id ?? entry.event_id,
    event_type: entry.event_type ?? 'system',
    description: normalizeLegacyAgentDispatchDescription({
      event_type: entry.event_type,
      description: entry.description,
      details: entry.details,
    }),
  }));
}

export async function getAgentHistory(taskId: string): Promise<{
  entries: ActivityEntry[];
  total: number;
}> {
  const response = await request('getAgentHistory', { path: { task_id: taskId } });
  return { ...response, entries: normalizeActivityEntries(response.entries) };
}

export async function getAgentConsole(taskId: string, params?: {
  limit?: number;
  after?: string;
}): Promise<{ events: AgentConsoleEvent[]; total: number }> {
  return request('getAgentConsole', { path: { task_id: taskId }, query: params });
}

export async function getOperatorConsole(params?: {
  limit?: number;
  after?: string;
}): Promise<{ events: AgentConsoleEvent[]; total: number }> {
  return request('getOperatorConsole', { query: params });
}
