import { WebSocket, WebSocketServer } from 'ws';
import type { GraphEngine } from './graph-engine.js';
import type { SessionEvent, SessionManager } from './session-manager.js';
import type { GraphUpdateDetail } from './engine-context.js';
import { DeltaAccumulator } from './delta-accumulator.js';
import { buildOperatorConsoleEvents } from './agent-console.js';
import {
  projectDashboardSnapshot,
  projectDashboardStatePatch,
  projectGraphDelta,
  projectGraphDeltaData,
  type DashboardState,
} from './dashboard-projectors.js';
import { MainWebSocketEventSchema } from '../contracts/dashboard-v1.js';
import { PlaybookRunService } from './playbook-run-service.js';
import type { RuntimeBuildInfo } from './runtime-build-info.js';
import type { ExportedGraph } from '../types.js';

export interface DashboardMainWebSocketHubOptions {
  buildState: () => DashboardState<unknown, unknown>;
  buildGraph?: () => ExportedGraph;
  runtimeBuild: RuntimeBuildInfo;
  debounceMs?: number;
}

/** Owns the `/ws` state channel, its listeners, delta accumulator, and clients. */
export class DashboardMainWebSocketHub {
  readonly server = new WebSocketServer({ noServer: true });
  clients = new Set<WebSocket>();
  private readonly clientContracts = new WeakMap<WebSocket, 1 | 2>();
  private contractFilter: 1 | 2 | undefined;
  private readonly accumulator = new DeltaAccumulator();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private stateRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private stateRefreshDirty = false;
  private seenConsoleEventIds: Set<string>;
  private readonly disposers: Array<() => void> = [];
  private readonly debounceMs: number;
  private coldInventoryRevision: number;
  private readonly hiddenNodeIds: Set<string>;
  private readonly pendingVisibilityChanges = new Set<string>();
  private disposed = false;
  private cachedState: DashboardState<unknown, unknown> | undefined;
  private stateRevision = 0;

  constructor(
    private readonly engine: GraphEngine,
    sessionManager: SessionManager | null,
    private readonly options: DashboardMainWebSocketHubOptions,
  ) {
    this.debounceMs = options.debounceMs ?? 500;
    this.coldInventoryRevision = engine.getColdInventoryRevision();
    this.hiddenNodeIds = new Set(engine.getSupersededNodeIds());
    this.seenConsoleEventIds = new Set(engine.getFullHistory().map(entry => entry.event_id));
    this.server.on('error', () => { /* individual socket errors remove their client */ });
    this.server.on('connection', (ws, request) => {
      let contract: 1 | 2 = 1;
      try {
        const url = new URL(request.url ?? '/', 'ws://localhost');
        if (url.searchParams.get('contract') === '2') contract = 2;
      } catch { /* malformed upgrade URLs are rejected by DashboardServer */ }
      this.attachConnection(ws, contract);
    });

    this.disposers.push(engine.onUpdate(detail => this.onGraphUpdate(detail)));
    this.disposers.push(engine.getAgentQueryStore().onChange(() => {
      if (this.clients.size === 0) return;
      this.broadcast({
        type: 'agent_query',
        timestamp: new Date().toISOString(),
        data: { queries: engine.getAgentQueryStore().getOpen() },
      });
    }));
    this.disposers.push(engine.getPendingActionQueue().onEvent((type, data) => {
      this.broadcast({ type, timestamp: new Date().toISOString(), data });
    }));
    this.disposers.push(PlaybookRunService.onChange(engine, run => {
      if (this.clients.size === 0) return;
      this.broadcast({
        type: 'playbook_run_update',
        timestamp: new Date().toISOString(),
        data: { run },
      });
    }));
    if (typeof sessionManager?.onEvent === 'function') {
      this.disposers.push(sessionManager.onEvent((event: SessionEvent) => {
        this.broadcast({
          type: 'session_update',
          timestamp: new Date().toISOString(),
          data: event,
        });
      }));
    }
  }

  attachConnection(ws: WebSocket, contract: 1 | 2 = 1): void {
    const firstConnection = this.clients.size === 0;
    const hadContractV2Client = this.hasContract(2);
    this.clients.add(ws);
    this.clientContracts.set(ws, contract);
    const state = this.options.buildState();
    const graph = this.options.buildGraph?.()
      ?? this.engine.exportGraph({ includeDerivedCommunities: true });
    // The first full-state graph is the client's authoritative baseline, so
    // assignments accumulated before any browser was connected are already
    // represented and need not be replayed as a follow-up patch.
    const baselineCommunityChanges = firstConnection
      ? this.engine.peekCommunityChanges()
      : undefined;
    const snapshot = projectDashboardSnapshot(
      state,
      graph,
      this.engine.getHistoryCount(),
      this.options.runtimeBuild,
    );
    const nextStateRevision = contract === 2 ? this.stateRevision + 1 : this.stateRevision;
    const fullState = {
      type: 'full_state',
      ...(contract === 2 ? { contract_version: 2 as const } : {}),
      timestamp: new Date().toISOString(),
      data: contract === 2
        ? { ...snapshot, state_revision: nextStateRevision }
        : snapshot,
    };
    if (contract === 2 && hadContractV2Client) {
      // Contract-v2 patches share one authoritative baseline. A joining client
      // can observe state newer than an existing client's last publication, so
      // advance every v2 client together before replacing the shared baseline.
      // Reconnects are rare and already require a full graph snapshot; this
      // keeps subsequent keyed patches exact without per-client state copies.
      this.send(ws, fullState);
      for (const client of this.clients) {
        if (client === ws || (this.clientContracts.get(client) ?? 1) !== 2) continue;
        try {
          this.send(client, fullState);
        } catch {
          client.close();
        }
      }
    } else {
      this.send(ws, fullState);
    }
    if (contract === 2 || (firstConnection && this.cachedState === undefined)) {
      this.cachedState = state;
    }
    if (contract === 2) this.stateRevision = nextStateRevision;
    if (baselineCommunityChanges) {
      this.engine.acknowledgeCommunityChanges(baselineCommunityChanges);
    }
    const cleanup = () => this.clients.delete(ws);
    ws.on('close', cleanup);
    ws.on('error', cleanup);
  }

  broadcast(event: unknown): void {
    const validated = MainWebSocketEventSchema.parse(event);
    const message = JSON.stringify(validated);
    for (const ws of this.clients) {
      if (this.contractFilter !== undefined
        && (this.clientContracts.get(ws) ?? 1) !== this.contractFilter) continue;
      if (ws.readyState !== WebSocket.OPEN) continue;
      try {
        ws.send(message);
      } catch {
        ws.close();
      }
    }
  }

  private broadcastContract(event: unknown, contract: 1 | 2): void {
    if (!this.hasContract(contract)) return;
    this.contractFilter = contract;
    try {
      this.broadcast(event);
    } finally {
      this.contractFilter = undefined;
    }
  }

  private hasContract(contract: 1 | 2): boolean {
    for (const ws of this.clients) {
      if ((this.clientContracts.get(ws) ?? 1) === contract) return true;
    }
    return false;
  }

  onGraphUpdate(detail: GraphUpdateDetail): void {
    const consoleEvents = this.collectNewConsoleEvents();
    const visibilityChanges = this.refreshNodeVisibility(detail);
    if (this.clients.size === 0) return;
    if (consoleEvents.length > 0) {
      this.broadcast({
        type: 'agent_console_update',
        timestamp: new Date().toISOString(),
        data: { events: consoleEvents },
      });
    }
    for (const id of visibilityChanges) this.pendingVisibilityChanges.add(id);
    this.accumulator.push(detail);
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => this.flushPendingUpdate(), this.debounceMs);
    if (typeof this.debounceTimer.unref === 'function') this.debounceTimer.unref();
  }

  flush(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.flushPendingUpdate();
  }

  closeConnections(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = null;
    if (this.stateRefreshTimer) clearTimeout(this.stateRefreshTimer);
    this.stateRefreshTimer = null;
    this.stateRefreshDirty = false;
    this.accumulator.drain();
    for (const ws of this.clients) ws.close();
    this.clients.clear();
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.closeConnections();
    for (const dispose of this.disposers.splice(0)) dispose();
  }

  closeServer(): Promise<void> {
    this.dispose();
    return new Promise(resolve => this.server.close(() => resolve()));
  }

  private collectNewConsoleEvents() {
    const history = this.engine.getFullHistory();
    const entries = history.filter(entry => !this.seenConsoleEventIds.has(entry.event_id));
    this.seenConsoleEventIds = new Set(history.map(entry => entry.event_id));
    return entries.length > 0
      ? buildOperatorConsoleEvents(entries, this.engine.getAllAgents())
      : [];
  }

  private flushPendingUpdate(): void {
    let detail = this.accumulator.drain();
    this.debounceTimer = null;
    if (!detail || this.clients.size === 0) return;

    // A graph delta must remain proportional to changed IDs. Global summaries,
    // frontier/community projections, and health are coalesced into the
    // state_refresh that follows instead of blocking this live graph update.
    // Compatibility-v1 state construction can itself populate derived caches
    // and emit a nested detail. Build it before the nested drain so one flush
    // still coalesces those changes; v2-only hubs skip this roster-sized work.
    const v1State = this.hasContract(1)
      ? (this.cachedState ?? this.options.buildState())
      : undefined;
    const historyCount = this.engine.getHistoryCount();
    const nestedDetail = this.accumulator.drain();
    if (nestedDetail) {
      if (this.debounceTimer) clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
      detail = mergeGraphUpdateDetails(detail, nestedDetail);
    }
    const coldRevision = this.engine.getColdInventoryRevision();
    const coldNodesChanged = coldRevision !== this.coldInventoryRevision;
    if (coldNodesChanged) detail = { ...detail, cold_nodes_changed: true };
    const graph = this.engine.exportGraphSelection({
      node_ids: [...(detail.new_nodes || []), ...(detail.updated_nodes || [])],
      edge_ids: [
        ...(detail.new_edges || []),
        ...(detail.updated_edges || []),
        ...(detail.inferred_edges || []),
      ],
      includeCold: coldNodesChanged,
      includeIncidentEdges: false,
      incident_node_ids: this.pendingVisibilityChanges,
      includeDerivedCommunities: false,
    });
    this.pendingVisibilityChanges.clear();
    const bounded = projectGraphDeltaData(graph, detail, historyCount);
    if (v1State) {
      this.broadcastContract({
        type: 'graph_update',
        timestamp: new Date().toISOString(),
        data: projectGraphDelta(v1State, graph, detail, historyCount),
      }, 1);
    }
    this.broadcastContract({
      type: 'graph_update',
      contract_version: 2,
      timestamp: new Date().toISOString(),
      data: bounded,
    }, 2);
    this.coldInventoryRevision = coldRevision;
    this.scheduleStateRefresh();
  }

  private scheduleStateRefresh(): void {
    this.stateRefreshDirty = true;
    // Throttle from the first dirty update instead of debouncing from the
    // newest one. Sustained findings therefore cannot starve authoritative
    // frontier/agent/campaign/objective state indefinitely.
    if (this.stateRefreshTimer) return;
    this.stateRefreshTimer = setTimeout(() => {
      this.stateRefreshTimer = null;
      if (this.clients.size === 0 || this.disposed || !this.stateRefreshDirty) {
        this.stateRefreshDirty = false;
        return;
      }
      this.stateRefreshDirty = false;
      const state = this.options.buildState();
      const previousState = this.cachedState;
      // buildState() above has populated the community cache. Taking the
      // detector-produced patch is proportional only to assignments that
      // changed since the previous publication.
      const communityChanges = this.engine.peekCommunityChanges();
      const communityIds = Object.fromEntries(communityChanges);
      if (this.hasContract(1)) {
        this.broadcastContract({
          type: 'state_refresh',
          timestamp: new Date().toISOString(),
          data: {
            state,
            history_count: this.engine.getHistoryCount(),
            // buildState() has already populated the topology-derived cache. Send
            // only changed assignments so browser work remains proportional to
            // the derived patch rather than the complete engagement graph.
            community_ids: communityIds,
          },
        }, 1);
      }
      if (this.hasContract(2)) {
        const baseRevision = this.stateRevision;
        const stateRevision = baseRevision + 1;
        this.broadcastContract({
          type: 'state_refresh',
          contract_version: 2,
          timestamp: new Date().toISOString(),
          data: {
            patch: projectDashboardStatePatch(previousState, state),
            base_revision: baseRevision,
            state_revision: stateRevision,
            history_count: this.engine.getHistoryCount(),
            community_ids: communityIds,
          },
        }, 2);
        this.stateRevision = stateRevision;
      }
      this.cachedState = state;
      this.engine.acknowledgeCommunityChanges(communityChanges);
    }, 750);
    if (typeof this.stateRefreshTimer.unref === 'function') this.stateRefreshTimer.unref();
  }

  private refreshNodeVisibility(detail: GraphUpdateDetail): string[] {
    const changed = new Set([
      ...(detail.new_nodes || []),
      ...(detail.updated_nodes || []),
    ]);
    const transitions: string[] = [];
    for (const id of changed) {
      const node = this.engine.getNode(id);
      const hidden = node?.identity_status === 'superseded';
      const wasHidden = this.hiddenNodeIds.has(id);
      if (hidden) this.hiddenNodeIds.add(id);
      else this.hiddenNodeIds.delete(id);
      if (hidden !== wasHidden) transitions.push(id);
    }
    for (const id of detail.removed_nodes || []) this.hiddenNodeIds.delete(id);
    return transitions;
  }

  private send(ws: WebSocket, event: unknown): void {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify(MainWebSocketEventSchema.parse(event)));
  }
}

export function mergeGraphUpdateDetails(
  left: GraphUpdateDetail,
  right: GraphUpdateDetail,
): GraphUpdateDetail {
  const merged: GraphUpdateDetail = { ...left };
  const keys = [
    'new_nodes',
    'new_edges',
    'updated_nodes',
    'updated_edges',
    'inferred_edges',
    'removed_nodes',
    'removed_edges',
  ] as const;
  for (const key of keys) {
    const values = [...new Set([...(left[key] || []), ...(right[key] || [])])];
    if (values.length > 0) merged[key] = values;
  }
  if (left.cold_nodes_changed || right.cold_nodes_changed) merged.cold_nodes_changed = true;
  return merged;
}
