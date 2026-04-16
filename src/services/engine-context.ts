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
  EngagementConfig, InferenceRule, AgentTask, Campaign,
  NodeProperties, EdgeProperties,
} from '../types.js';
import type { TrackedProcess } from './process-tracker.js';
import { ColdStore } from './cold-store.js';
import { OpsecTracker } from './opsec-tracker.js';
import { PendingActionQueue } from './pending-action-queue.js';

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

export type ActivityLogDetails =
  | { parsed_nodes: number; parsed_edges: number; ingested: boolean; new_nodes?: number; new_edges?: number; inferred_edges?: number; [key: string]: unknown }
  | { validation_errors: string[]; [key: string]: unknown }
  | { evidence_type?: string; evidence_id?: string; evidence_content?: string; raw_output?: string; [key: string]: unknown }
  | { warning: string; [key: string]: unknown }
  | Record<string, unknown>;

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
  noise_estimate?: number;
  noise_actual?: number;
  details?: ActivityLogDetails;
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
  campaigns: Map<string, Campaign>;
  stateFilePath: string;
  updateCallbacks: GraphUpdateCallback[];
  lastSnapshotTime: number;
  pathGraphCache: Map<string, OverwatchGraph>;  // cached undirected projections keyed by optimize mode
  communityCache: Map<string, number> | null;  // cached Louvain community assignments
  trackedProcesses: TrackedProcess[];
  actionFrontierMap: Map<string, { frontier_item_id: string; agent_id?: string; frontier_type?: ActivityLogEntry['frontier_type'] }>;
  coldStore: ColdStore;
  opsecTracker: OpsecTracker;
  pendingActionQueue: PendingActionQueue;

  constructor(graph: OverwatchGraph, config: EngagementConfig, stateFilePath: string) {
    this.graph = graph;
    this.config = config;
    this.inferenceRules = [];
    this.activityLog = [];
    this.agents = new Map();
    this.campaigns = new Map();
    this.stateFilePath = stateFilePath;
    this.updateCallbacks = [];
    this.lastSnapshotTime = 0;
    this.pathGraphCache = new Map();
    this.communityCache = null;
    this.trackedProcesses = [];
    this.actionFrontierMap = new Map();
    this.coldStore = new ColdStore();
    this.opsecTracker = new OpsecTracker(this);
    this.pendingActionQueue = new PendingActionQueue(this);
  }

  log(message: string, agentId?: string, extra?: Partial<Pick<ActivityLogEntry, 'category' | 'frontier_type' | 'outcome'>>): void {
    this.logEvent({
      description: message,
      agent_id: agentId,
      ...extra,
    });
  }

  logEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry {
    // Auto-thread frontier_item_id from action_id mapping when caller omits it.
    // Guard against cross-agent action_id collisions: only cache/inherit when
    // the agent_id is consistent with the first writer.
    let enriched = event;
    if (event.action_id && event.frontier_item_id) {
      const existing = this.actionFrontierMap.get(event.action_id);
      if (existing && existing.agent_id && event.agent_id && existing.agent_id !== event.agent_id) {
        // Different agent reusing the same action_id — log a warning instead of overwriting
        this.logEvent({
          description: `action_id ${event.action_id} collision: agent "${event.agent_id}" tried to associate fi "${event.frontier_item_id}" but it is already mapped to fi "${existing.frontier_item_id}" by agent "${existing.agent_id}"`,
          event_type: 'instrumentation_warning',
          category: 'system',
          action_id: event.action_id,
          agent_id: event.agent_id,
        });
      } else {
        this.actionFrontierMap.set(event.action_id, {
          frontier_item_id: event.frontier_item_id,
          agent_id: event.agent_id,
          frontier_type: event.frontier_type,
        });
      }
    } else if (event.action_id && !event.frontier_item_id) {
      const cached = this.actionFrontierMap.get(event.action_id);
      if (cached) {
        // Only auto-thread if the agent_id matches (or one side is undefined)
        const agentMatch = !cached.agent_id || !event.agent_id || cached.agent_id === event.agent_id;
        if (agentMatch) {
          enriched = {
            ...event,
            frontier_item_id: cached.frontier_item_id,
            frontier_type: event.frontier_type || cached.frontier_type,
          };
        }
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
          agent_id: entry.agent_id,
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
  const resolvedCategory = entry.category || inferCategoryFromEventType(entry.event_type);
  const resolvedOutcome = entry.outcome
    || normalizeOutcome(entry.result_classification, entry.validation_result)
    || inferOutcomeFromEventType(entry.event_type);
  return {
    event_id: entry.event_id || uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    description: entry.description,
    agent_id: entry.agent_id,
    category: resolvedCategory,
    frontier_type: entry.frontier_type,
    outcome: resolvedOutcome,
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

function inferCategoryFromEventType(eventType?: ActivityEventType): ActivityLogEntry['category'] | undefined {
  if (!eventType) return undefined;
  if (eventType.startsWith('action_')) return 'frontier';
  if (eventType.startsWith('finding_') || eventType === 'parse_output') return 'finding';
  if (eventType.startsWith('inference_')) return 'inference';
  if (eventType.startsWith('objective_')) return 'objective';
  if (eventType.startsWith('agent_')) return 'agent';
  if (eventType.startsWith('session_') || eventType === 'scope_updated' || eventType === 'graph_corrected' || eventType === 'instrumentation_warning' || eventType === 'credential_degradation' || eventType === 'system') return 'system';
  return undefined;
}

function inferOutcomeFromEventType(eventType?: ActivityEventType): ActivityLogEntry['outcome'] | undefined {
  if (!eventType) return undefined;
  if (eventType === 'action_completed' || eventType === 'finding_reported' || eventType === 'finding_ingested' || eventType === 'objective_achieved' || eventType === 'session_access_confirmed') return 'success';
  if (eventType === 'action_failed' || eventType === 'session_error') return 'failure';
  if (eventType === 'action_planned' || eventType === 'action_started' || eventType === 'action_validated') return 'neutral';
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
