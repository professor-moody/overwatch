// ============================================================
// Overwatch — Live Dashboard Server
// HTTP + WebSocket server for real-time engagement visualization
// ============================================================

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { readFileSync, existsSync } from 'fs';
import { join, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import type { GraphEngine } from './graph-engine.js';
import type { GraphUpdateDetail } from './engine-context.js';
import { DeltaAccumulator } from './delta-accumulator.js';

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
  private _running: boolean = false;
  private accumulator = new DeltaAccumulator();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private static readonly DEBOUNCE_MS = 500;

  private host: string;

  constructor(engine: GraphEngine, port: number = 8384, host?: string) {
    this.engine = engine;
    this.port = port;
    this.host = host || process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';

    this.httpServer = createServer((req, res) => this.handleHttp(req, res));
    this.wss = new WebSocketServer({ server: this.httpServer });

    this.wss.on('error', () => {
      // Absorb WSS errors (e.g. from underlying HTTP server EADDRINUSE)
      // — handled by httpServer 'error' listener in start()
    });

    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      // Send full state on connect — getState() first to materialize community_id on nodes
      const state = this.engine.getState();
      const graph = this.engine.exportGraph();
      const historyCount = this.engine.getFullHistory().length;
      ws.send(JSON.stringify({
        type: 'full_state',
        timestamp: new Date().toISOString(),
        data: { state, graph, history_count: historyCount },
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

      this.httpServer.listen(this.port, this.host, () => {
        // Read the actual port (supports port 0 for ephemeral)
        const addr = this.httpServer.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
          this.host = addr.address;
        }
        this._running = true;
        console.error(`Dashboard running at http://${this.host}:${this.port}`);
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
    this.accumulator.drain();
    this.fileCache.clear();
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

    this.accumulator.push(detail);

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
    const detail = this.accumulator.drain();
    this.debounceTimer = null;
    if (!detail || this.clients.size === 0) return;

    // Build incremental delta: only the nodes/edges that changed
    const changedNodeIds = new Set([...(detail.new_nodes || []), ...(detail.updated_nodes || [])]);
    const changedEdgeIds = new Set([...(detail.new_edges || []), ...(detail.updated_edges || []), ...(detail.inferred_edges || [])]);

    // getState() first — materializes community_id on nodes before exportGraph() reads them
    const state = this.engine.getState();
    const historyCount = this.engine.getFullHistory().length;

    const fullGraph = this.engine.exportGraph();
    const deltaNodes = fullGraph.nodes.filter(n => changedNodeIds.has(n.id));
    const deltaEdges = fullGraph.edges.filter(e => e.id !== undefined && changedEdgeIds.has(e.id));

    this.broadcast({
      type: 'graph_update',
      timestamp: new Date().toISOString(),
      data: {
        state: { ...state, history_count: historyCount },
        detail,
        delta: {
          nodes: deltaNodes,
          edges: deltaEdges,
          removed_nodes: detail.removed_nodes || [],
          removed_edges: detail.removed_edges || [],
        },
      },
    });
  }

  private static readonly MIME_TYPES: Record<string, string> = {
    '.html': 'text/html; charset=utf-8',
    '.css':  'text/css; charset=utf-8',
    '.js':   'application/javascript; charset=utf-8',
    '.json': 'application/json',
    '.png':  'image/png',
    '.svg':  'image/svg+xml',
  };

  private dashboardDir: string | null = null;
  private fileCache: Map<string, string | Buffer> = new Map();

  private isTextAsset(ext: string): boolean {
    return ['.html', '.css', '.js', '.json', '.svg'].includes(ext);
  }

  private resolveDashboardDir(): string {
    if (this.dashboardDir) return this.dashboardDir;
    // dist/services/ → dist/dashboard/
    const distPath = join(__dirname, '..', 'dashboard');
    if (existsSync(join(distPath, 'index.html'))) {
      this.dashboardDir = distPath;
      return distPath;
    }
    // Fallback: source path
    const srcPath = join(__dirname, '..', '..', 'src', 'dashboard');
    if (existsSync(join(srcPath, 'index.html'))) {
      this.dashboardDir = srcPath;
      return srcPath;
    }
    throw new Error('Dashboard directory not found');
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url || '/';

    // CORS: restrict to localhost origins (or env override)
    const origin = req.headers.origin || '';
    const allowedHost = process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
    const isLocalOrigin = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    let isAllowedOrigin = isLocalOrigin;
    if (!isAllowedOrigin && origin) {
      try { isAllowedOrigin = new URL(origin).hostname === allowedHost; } catch { /* malformed origin */ }
    }
    if (isAllowedOrigin && origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET');

    const pathname = url.split('?')[0];

    if (pathname === '/api/state') {
      this.serveState(res);
    } else if (pathname === '/api/graph') {
      this.serveGraph(res);
    } else if (pathname === '/api/history') {
      this.serveHistory(url, res);
    } else {
      this.serveStaticFile(url, res);
    }
  }

  private serveStaticFile(url: string, res: ServerResponse): void {
    let filePath = url === '/' ? '/index.html' : url;

    // Security: prevent directory traversal
    if (filePath.includes('..')) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    // Strip leading slash and query string
    const cleanPath = filePath.replace(/^\//, '').split('?')[0];
    const ext = extname(cleanPath);
    const mime = DashboardServer.MIME_TYPES[ext] || 'application/octet-stream';

    // Check cache
    if (this.fileCache.has(cleanPath)) {
      res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
      res.end(this.fileCache.get(cleanPath));
      return;
    }

    try {
      const dashDir = this.resolveDashboardDir();
      const fullPath = join(dashDir, cleanPath);

      // Security: ensure resolved path is within dashboard dir
      if (!fullPath.startsWith(dashDir)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }

      const content = this.isTextAsset(ext)
        ? readFileSync(fullPath, 'utf-8')
        : readFileSync(fullPath);
      this.fileCache.set(cleanPath, content);
      res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
      res.end(content);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  }

  private serveState(res: ServerResponse): void {
    const state = this.engine.getState();
    const graph = this.engine.exportGraph();
    const historyCount = this.engine.getFullHistory().length;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ state, graph, history_count: historyCount }));
  }

  private serveHistory(url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    let limit: number | undefined;
    if (params.has('limit')) {
      const parsed = parseInt(params.get('limit')!, 10);
      limit = Number.isFinite(parsed) && parsed >= 1 ? parsed : undefined;
    }
    const rawAfter = params.get('after') || undefined;
    const after = rawAfter && !isNaN(Date.parse(rawAfter)) ? rawAfter : undefined;
    const rawBefore = params.get('before') || undefined;
    const before = rawBefore && !isNaN(Date.parse(rawBefore)) ? rawBefore : undefined;

    let entries = this.engine.getFullHistory();

    if (after) {
      entries = entries.filter(e => e.timestamp > after);
    }
    if (before) {
      entries = entries.filter(e => e.timestamp < before);
    }

    const total = entries.length;

    if (limit && limit > 0) {
      entries = entries.slice(0, limit);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ entries, total }));
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
    return `http://${this.host}:${this.port}`;
  }

  get boundHost(): string {
    return this.host;
  }

  get clientCount(): number {
    return this.clients.size;
  }
}
