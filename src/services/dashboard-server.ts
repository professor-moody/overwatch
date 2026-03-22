// ============================================================
// Overwatch — Live Dashboard Server
// HTTP + WebSocket server for real-time engagement visualization
// ============================================================

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { GraphEngine } from './graph-engine.js';
import type { GraphUpdateDetail } from './engine-context.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface DashboardStartResult {
  started: boolean;
  error?: string;
}

export interface DashboardEvent {
  type: 'graph_update' | 'agent_update' | 'objective_update' | 'full_state';
  timestamp: string;
  data: any;
}

export class DashboardServer {
  private httpServer: ReturnType<typeof createServer>;
  private wss: WebSocketServer;
  private engine: GraphEngine;
  private port: number;
  private clients: Set<WebSocket> = new Set();
  private dashboardHtml: string | null = null;
  private _running: boolean = false;
  private pendingDetail: GraphUpdateDetail | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private static readonly DEBOUNCE_MS = 500;

  constructor(engine: GraphEngine, port: number = 8384) {
    this.engine = engine;
    this.port = port;

    this.httpServer = createServer((req, res) => this.handleHttp(req, res));
    this.wss = new WebSocketServer({ server: this.httpServer });

    this.wss.on('error', () => {
      // Absorb WSS errors (e.g. from underlying HTTP server EADDRINUSE)
      // — handled by httpServer 'error' listener in start()
    });

    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      // Send full state on connect
      const state = this.engine.getState();
      const graph = this.engine.exportGraph();
      ws.send(JSON.stringify({
        type: 'full_state',
        timestamp: new Date().toISOString(),
        data: { state, graph },
      }));

      ws.on('close', () => {
        this.clients.delete(ws);
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });
    });
  }

  start(): Promise<DashboardStartResult> {
    return new Promise((resolve) => {
      this.httpServer.on('error', (err: NodeJS.ErrnoException) => {
        console.error(`Dashboard failed on port ${this.port}: ${err.code || err.message}`);
        this._running = false;
        resolve({ started: false, error: err.code || err.message });
      });

      this.httpServer.listen(this.port, () => {
        // Read the actual port (supports port 0 for ephemeral)
        const addr = this.httpServer.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        this._running = true;
        console.error(`Dashboard running at http://localhost:${this.port}`);
        resolve({ started: true });
      });
    });
  }

  stop(): Promise<void> {
    this._running = false;
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    this.pendingDetail = null;
    return new Promise((resolve) => {
      for (const ws of this.clients) {
        ws.close();
      }
      this.clients.clear();
      this.wss.close(() => {
        this.httpServer.close(() => resolve());
      });
    });
  }

  broadcast(event: DashboardEvent): void {
    const msg = JSON.stringify(event);
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
      }
    }
  }

  // Called by GraphEngine after persist()
  onGraphUpdate(detail: GraphUpdateDetail): void {
    // Short-circuit: skip expensive work when nobody is listening
    if (this.clients.size === 0) return;

    // Accumulate detail into pending batch
    if (!this.pendingDetail) {
      this.pendingDetail = { new_nodes: [], new_edges: [], updated_nodes: [], updated_edges: [], inferred_edges: [] };
    }
    for (const key of ['new_nodes', 'new_edges', 'updated_nodes', 'updated_edges', 'inferred_edges'] as const) {
      if (detail[key]) {
        this.pendingDetail[key]!.push(...detail[key]!);
      }
    }

    // Reset debounce timer
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => this.flushPendingUpdate(), DashboardServer.DEBOUNCE_MS);
  }

  /** Immediately flush any pending debounced update. Useful for testing. */
  flush(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.flushPendingUpdate();
  }

  private flushPendingUpdate(): void {
    const detail = this.pendingDetail;
    this.pendingDetail = null;
    this.debounceTimer = null;
    if (!detail || this.clients.size === 0) return;

    // Build incremental delta: only the nodes/edges that changed
    const changedNodeIds = new Set([...(detail.new_nodes || []), ...(detail.updated_nodes || [])]);
    const changedEdgeIds = new Set([...(detail.new_edges || []), ...(detail.updated_edges || []), ...(detail.inferred_edges || [])]);

    const fullGraph = this.engine.exportGraph();
    const deltaNodes = fullGraph.nodes.filter(n => changedNodeIds.has(n.id));
    const deltaEdges = fullGraph.edges.filter(e => e.id !== undefined && changedEdgeIds.has(e.id));

    const state = this.engine.getState();

    this.broadcast({
      type: 'graph_update',
      timestamp: new Date().toISOString(),
      data: {
        state,
        detail,
        delta: { nodes: deltaNodes, edges: deltaEdges },
      },
    });
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url || '/';

    // CORS headers for local dev
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');

    if (url === '/' || url === '/index.html') {
      this.serveHtml(res);
    } else if (url === '/api/state') {
      this.serveState(res);
    } else if (url === '/api/graph') {
      this.serveGraph(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  }

  private serveHtml(res: ServerResponse): void {
    if (!this.dashboardHtml) {
      try {
        // In compiled output, dashboard HTML is at dist/dashboard/index.html
        // relative to this file at dist/services/dashboard-server.js
        const htmlPath = join(__dirname, '..', 'dashboard', 'index.html');
        this.dashboardHtml = readFileSync(htmlPath, 'utf-8');
      } catch {
        // Fallback: try source path
        try {
          const htmlPath = join(__dirname, '..', '..', 'src', 'dashboard', 'index.html');
          this.dashboardHtml = readFileSync(htmlPath, 'utf-8');
        } catch {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Dashboard HTML not found');
          return;
        }
      }
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(this.dashboardHtml);
  }

  private serveState(res: ServerResponse): void {
    const state = this.engine.getState();
    const graph = this.engine.exportGraph();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ state, graph }));
  }

  private serveGraph(res: ServerResponse): void {
    const graph = this.engine.exportGraph();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(graph));
  }

  get running(): boolean {
    return this._running;
  }

  get address(): string {
    return `http://localhost:${this.port}`;
  }

  get clientCount(): number {
    return this.clients.size;
  }
}
