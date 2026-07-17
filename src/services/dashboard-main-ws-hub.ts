import { WebSocket, WebSocketServer } from 'ws';
import type { GraphEngine } from './graph-engine.js';
import type { SessionEvent, SessionManager } from './session-manager.js';
import type { GraphUpdateDetail } from './engine-context.js';
import { DeltaAccumulator } from './delta-accumulator.js';
import { buildOperatorConsoleEvents } from './agent-console.js';
import {
  projectDashboardSnapshot,
  projectGraphDelta,
  type DashboardState,
} from './dashboard-projectors.js';
import { MainWebSocketEventSchema } from '../contracts/dashboard-v1.js';
import { PlaybookRunService } from './playbook-run-service.js';

export interface DashboardMainWebSocketHubOptions {
  buildState: () => DashboardState<unknown, unknown>;
  debounceMs?: number;
}

/** Owns the `/ws` state channel, its listeners, delta accumulator, and clients. */
export class DashboardMainWebSocketHub {
  readonly server = new WebSocketServer({ noServer: true });
  clients = new Set<WebSocket>();
  private readonly accumulator = new DeltaAccumulator();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private seenConsoleEventIds: Set<string>;
  private readonly disposers: Array<() => void> = [];
  private readonly debounceMs: number;
  private disposed = false;

  constructor(
    private readonly engine: GraphEngine,
    sessionManager: SessionManager | null,
    private readonly options: DashboardMainWebSocketHubOptions,
  ) {
    this.debounceMs = options.debounceMs ?? 500;
    this.seenConsoleEventIds = new Set(engine.getFullHistory().map(entry => entry.event_id));
    this.server.on('error', () => { /* individual socket errors remove their client */ });
    this.server.on('connection', ws => this.attachConnection(ws));

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

  attachConnection(ws: WebSocket): void {
    this.clients.add(ws);
    const state = this.options.buildState();
    const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
    this.send(ws, {
      type: 'full_state',
      timestamp: new Date().toISOString(),
      data: projectDashboardSnapshot(state, graph, this.engine.getFullHistory().length),
    });
    const cleanup = () => this.clients.delete(ws);
    ws.on('close', cleanup);
    ws.on('error', cleanup);
  }

  broadcast(event: unknown): void {
    const validated = MainWebSocketEventSchema.parse(event);
    const message = JSON.stringify(validated);
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) ws.send(message);
    }
  }

  onGraphUpdate(detail: GraphUpdateDetail): void {
    const consoleEvents = this.collectNewConsoleEvents();
    if (this.clients.size === 0) return;
    if (consoleEvents.length > 0) {
      this.broadcast({
        type: 'agent_console_update',
        timestamp: new Date().toISOString(),
        data: { events: consoleEvents },
      });
    }
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

    const state = this.options.buildState();
    const historyCount = this.engine.getFullHistory().length;
    const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
    const nestedDetail = this.accumulator.drain();
    if (nestedDetail) {
      if (this.debounceTimer) clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
      detail = mergeGraphUpdateDetails(detail, nestedDetail);
    }
    this.broadcast({
      type: 'graph_update',
      timestamp: new Date().toISOString(),
      data: projectGraphDelta(state, graph, detail, historyCount),
    });
  }

  private send(ws: WebSocket, event: unknown): void {
    ws.send(JSON.stringify(MainWebSocketEventSchema.parse(event)));
  }
}

export function mergeGraphUpdateDetails(
  left: GraphUpdateDetail,
  right: GraphUpdateDetail,
): GraphUpdateDetail {
  const merged: GraphUpdateDetail = { ...left };
  const keys: Array<keyof GraphUpdateDetail> = [
    'new_nodes',
    'new_edges',
    'updated_nodes',
    'updated_edges',
    'inferred_edges',
    'removed_nodes',
    'removed_edges',
  ];
  for (const key of keys) {
    const values = [...new Set([...(left[key] || []), ...(right[key] || [])])];
    if (values.length > 0) merged[key] = values;
  }
  return merged;
}
