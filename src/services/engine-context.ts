// ============================================================
// Overwatch — Engine Context
// Shared mutable state holder for all GraphEngine submodules.
// Submodules hold a reference to this object, NOT to individual
// fields. When recovery/rollback replaces ctx.graph, every
// module sees the new graph immediately.
// ============================================================

import type { AbstractGraph } from 'graphology-types';
import { v4 as uuidv4 } from 'uuid';
import type {
  EngagementConfig, InferenceRule, AgentTask,
  NodeProperties, EdgeProperties,
} from '../types.js';
import type { TrackedProcess } from './process-tracker.js';
import { ColdStore } from './cold-store.js';

export type OverwatchGraph = AbstractGraph<NodeProperties, EdgeProperties>;

export type ActivityEventType =
  | 'action_planned'
  | 'action_validated'
  | 'action_started'
  | 'action_completed'
  | 'action_failed'
  | 'finding_reported'
  | 'finding_ingested'
  | 'parse_output'
  | 'graph_corrected'
  | 'instrumentation_warning'
  | 'agent_registered'
  | 'agent_updated'
  | 'inference_generated'
  | 'credential_degradation'
  | 'objective_achieved'
  | 'session_opened'
  | 'session_connected'
  | 'session_signaled'
  | 'session_closed'
  | 'session_error'
  | 'session_access_confirmed'
  | 'session_access_unconfirmed'
  | 'scope_updated'
  | 'system';

export type ActivityLogEntry = {
  event_id: string;
  timestamp: string;
  description: string;
  agent_id?: string;
  category?: 'finding' | 'inference' | 'frontier' | 'objective' | 'agent' | 'system';
  frontier_type?: 'incomplete_node' | 'inferred_edge' | 'untested_edge' | 'network_discovery' | 'network_pivot';
  outcome?: 'success' | 'failure' | 'neutral';
  action_id?: string;
  event_type?: ActivityEventType;
  tool_name?: string;
  technique?: string;
  target_node_ids?: string[];
  target_ips?: string[];
  target_edge?: { source: string; target: string; type?: string };
  frontier_item_id?: string;
  validation_result?: 'valid' | 'invalid' | 'warning_only';
  result_classification?: 'success' | 'failure' | 'partial' | 'neutral';
  linked_finding_ids?: string[];
  linked_agent_task_id?: string;
  details?: Record<string, unknown>;
};

export type GraphUpdateDetail = {
  new_nodes?: string[];
  new_edges?: string[];
  updated_nodes?: string[];
  updated_edges?: string[];
  inferred_edges?: string[];
  removed_nodes?: string[];
  removed_edges?: string[];
};

export type GraphUpdateCallback = (detail: GraphUpdateDetail) => void;
export const MAX_ACTIVITY_LOG_ENTRIES = 5000;

export class EngineContext {
  graph: OverwatchGraph;            // graphology Graph instance — may be replaced on recovery
  config: EngagementConfig;
  inferenceRules: InferenceRule[];
  activityLog: ActivityLogEntry[];
  agents: Map<string, AgentTask>;
  stateFilePath: string;
  updateCallbacks: GraphUpdateCallback[];
  lastSnapshotTime: number;
  pathGraphCache: Map<string, OverwatchGraph>;  // cached undirected projections keyed by optimize mode
  communityCache: Map<string, number> | null;  // cached Louvain community assignments
  trackedProcesses: TrackedProcess[];
  actionFrontierMap: Map<string, { frontier_item_id: string; frontier_type?: ActivityLogEntry['frontier_type'] }>;
  coldStore: ColdStore;

  constructor(graph: OverwatchGraph, config: EngagementConfig, stateFilePath: string) {
    this.graph = graph;
    this.config = config;
    this.inferenceRules = [];
    this.activityLog = [];
    this.agents = new Map();
    this.stateFilePath = stateFilePath;
    this.updateCallbacks = [];
    this.lastSnapshotTime = 0;
    this.pathGraphCache = new Map();
    this.communityCache = null;
    this.trackedProcesses = [];
    this.actionFrontierMap = new Map();
    this.coldStore = new ColdStore();
  }

  log(message: string, agentId?: string, extra?: Partial<Pick<ActivityLogEntry, 'category' | 'frontier_type' | 'outcome'>>): void {
    this.logEvent({
      description: message,
      agent_id: agentId,
      ...extra,
    });
  }

  logEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry {
    // Auto-thread frontier_item_id from action_id mapping when caller omits it
    let enriched = event;
    if (event.action_id && event.frontier_item_id) {
      this.actionFrontierMap.set(event.action_id, {
        frontier_item_id: event.frontier_item_id,
        frontier_type: event.frontier_type,
      });
    } else if (event.action_id && !event.frontier_item_id) {
      const cached = this.actionFrontierMap.get(event.action_id);
      if (cached) {
        enriched = {
          ...event,
          frontier_item_id: cached.frontier_item_id,
          frontier_type: event.frontier_type || cached.frontier_type,
        };
      }
    }
    const entry = normalizeActivityLogEntry({
      ...enriched,
      timestamp: new Date().toISOString(),
    });
    this.activityLog.push({
      ...entry,
    });
    if (this.activityLog.length > MAX_ACTIVITY_LOG_ENTRIES) {
      this.activityLog = tieredTruncate(this.activityLog, MAX_ACTIVITY_LOG_ENTRIES);
    }
    return entry;
  }

  rebuildActionFrontierMap(): void {
    this.actionFrontierMap.clear();
    for (const entry of this.activityLog) {
      if (entry.action_id && entry.frontier_item_id) {
        this.actionFrontierMap.set(entry.action_id, {
          frontier_item_id: entry.frontier_item_id,
          frontier_type: entry.frontier_type,
        });
      }
    }
  }

  invalidatePathGraph(): void {
    this.pathGraphCache.clear();
    this.communityCache = null;
  }

  fireUpdateCallbacks(detail: GraphUpdateDetail): void {
    for (const cb of this.updateCallbacks) {
      try { cb(detail); } catch { /* dashboard errors must not break engine */ }
    }
  }
}

export function normalizeActivityLogEntry(
  entry: Partial<ActivityLogEntry> & { description: string; timestamp?: string },
): ActivityLogEntry {
  const normalizedOutcome = entry.outcome || normalizeOutcome(entry.result_classification, entry.validation_result);
  return {
    event_id: entry.event_id || uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    description: entry.description,
    agent_id: entry.agent_id,
    category: entry.category,
    frontier_type: entry.frontier_type,
    outcome: normalizedOutcome,
    action_id: entry.action_id,
    event_type: entry.event_type,
    tool_name: entry.tool_name,
    technique: entry.technique,
    target_node_ids: entry.target_node_ids,
    target_ips: entry.target_ips,
    target_edge: entry.target_edge,
    frontier_item_id: entry.frontier_item_id,
    validation_result: entry.validation_result,
    result_classification: entry.result_classification,
    linked_finding_ids: entry.linked_finding_ids,
    linked_agent_task_id: entry.linked_agent_task_id,
    details: entry.details,
  };
}

function normalizeOutcome(
  resultClassification?: ActivityLogEntry['result_classification'],
  validationResult?: ActivityLogEntry['validation_result'],
): ActivityLogEntry['outcome'] | undefined {
  if (resultClassification === 'success') return 'success';
  if (resultClassification === 'failure') return 'failure';
  if (resultClassification === 'partial' || resultClassification === 'neutral') return 'neutral';

  if (validationResult === 'invalid') return 'failure';
  if (validationResult === 'warning_only') return 'neutral';
  if (validationResult === 'valid') return 'success';

  return undefined;
}

const MILESTONE_EVENT_TYPES: Set<ActivityEventType | undefined> = new Set([
  'objective_achieved',
  'action_completed',
  'action_failed',
  'finding_ingested',
  'finding_reported',
  'scope_updated',
  'credential_degradation',
  'session_access_confirmed',
  // Causal-linkage events needed by retrospective analysis and evidence attribution
  'action_validated',
  'parse_output',
  'instrumentation_warning',
  'session_access_unconfirmed',
  'session_error',
  'graph_corrected',
]);

export function isMilestoneEntry(entry: ActivityLogEntry): boolean {
  return MILESTONE_EVENT_TYPES.has(entry.event_type);
}

/**
 * Tiered truncation: preserves all milestone events (objectives, completed
 * actions, ingested findings) while trimming ephemeral events (action_started,
 * inference_generated, system) to stay within the budget.
 */
export function tieredTruncate(log: ActivityLogEntry[], budget: number): ActivityLogEntry[] {
  if (log.length <= budget) return log;

  const milestones: ActivityLogEntry[] = [];
  const ephemeral: ActivityLogEntry[] = [];

  for (const entry of log) {
    if (isMilestoneEntry(entry)) {
      milestones.push(entry);
    } else {
      ephemeral.push(entry);
    }
  }

  if (milestones.length >= budget) {
    return milestones.slice(milestones.length - budget);
  }

  const ephemeralBudget = budget - milestones.length;
  const keptEphemeral = ephemeral.slice(ephemeral.length - ephemeralBudget);

  const result = [...milestones, ...keptEphemeral];
  result.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  return result;
}
