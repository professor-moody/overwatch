// ============================================================
// Overwatch — Engine Context
// Shared mutable state holder for all GraphEngine submodules.
// Submodules hold a reference to this object, NOT to individual
// fields. When recovery/rollback replaces ctx.graph, every
// module sees the new graph immediately.
// ============================================================

import type {
  EngagementConfig, InferenceRule, AgentTask,
} from '../types.js';

export type ActivityLogEntry = {
  timestamp: string;
  description: string;
  agent_id?: string;
};

export type GraphUpdateCallback = (detail: {
  new_nodes?: string[];
  new_edges?: string[];
  inferred_edges?: string[];
}) => void;

export class EngineContext {
  graph: any;                      // graphology Graph instance — may be replaced on recovery
  config: EngagementConfig;
  inferenceRules: InferenceRule[];
  activityLog: ActivityLogEntry[];
  agents: Map<string, AgentTask>;
  stateFilePath: string;
  updateCallbacks: GraphUpdateCallback[];
  lastSnapshotTime: number;
  pathGraphCache: any;             // cached undirected projection for pathfinding

  constructor(graph: any, config: EngagementConfig, stateFilePath: string) {
    this.graph = graph;
    this.config = config;
    this.inferenceRules = [];
    this.activityLog = [];
    this.agents = new Map();
    this.stateFilePath = stateFilePath;
    this.updateCallbacks = [];
    this.lastSnapshotTime = 0;
    this.pathGraphCache = null;
  }

  log(message: string, agentId?: string): void {
    this.activityLog.push({
      timestamp: new Date().toISOString(),
      description: message,
      agent_id: agentId,
    });
  }

  invalidatePathGraph(): void {
    this.pathGraphCache = null;
  }

  fireUpdateCallbacks(detail: { new_nodes?: string[]; new_edges?: string[]; inferred_edges?: string[] }): void {
    for (const cb of this.updateCallbacks) {
      try { cb(detail); } catch { /* dashboard errors must not break engine */ }
    }
  }
}
