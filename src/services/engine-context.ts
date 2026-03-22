// ============================================================
// Overwatch — Engine Context
// Shared mutable state holder for all GraphEngine submodules.
// Submodules hold a reference to this object, NOT to individual
// fields. When recovery/rollback replaces ctx.graph, every
// module sees the new graph immediately.
// ============================================================

import type { AbstractGraph } from 'graphology-types';
import type {
  EngagementConfig, InferenceRule, AgentTask,
  NodeProperties, EdgeProperties,
} from '../types.js';
import type { TrackedProcess } from './process-tracker.js';

export type OverwatchGraph = AbstractGraph<NodeProperties, EdgeProperties>;

export type ActivityLogEntry = {
  timestamp: string;
  description: string;
  agent_id?: string;
  category?: 'finding' | 'inference' | 'frontier' | 'objective' | 'agent' | 'system';
  frontier_type?: 'incomplete_node' | 'inferred_edge' | 'untested_edge';
  outcome?: 'success' | 'failure' | 'neutral';
};

export type GraphUpdateDetail = {
  new_nodes?: string[];
  new_edges?: string[];
  updated_nodes?: string[];
  updated_edges?: string[];
  inferred_edges?: string[];
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
  pathGraphCache: OverwatchGraph | null;  // cached undirected projection for pathfinding
  trackedProcesses: TrackedProcess[];

  constructor(graph: OverwatchGraph, config: EngagementConfig, stateFilePath: string) {
    this.graph = graph;
    this.config = config;
    this.inferenceRules = [];
    this.activityLog = [];
    this.agents = new Map();
    this.stateFilePath = stateFilePath;
    this.updateCallbacks = [];
    this.lastSnapshotTime = 0;
    this.pathGraphCache = null;
    this.trackedProcesses = [];
  }

  log(message: string, agentId?: string, extra?: Partial<Pick<ActivityLogEntry, 'category' | 'frontier_type' | 'outcome'>>): void {
    this.activityLog.push({
      timestamp: new Date().toISOString(),
      description: message,
      agent_id: agentId,
      ...extra,
    });
    if (this.activityLog.length > MAX_ACTIVITY_LOG_ENTRIES) {
      this.activityLog.splice(0, this.activityLog.length - MAX_ACTIVITY_LOG_ENTRIES);
    }
  }

  invalidatePathGraph(): void {
    this.pathGraphCache = null;
  }

  fireUpdateCallbacks(detail: GraphUpdateDetail): void {
    for (const cb of this.updateCallbacks) {
      try { cb(detail); } catch { /* dashboard errors must not break engine */ }
    }
  }
}
