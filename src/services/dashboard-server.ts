// ============================================================
// Overwatch — Live Dashboard Server
// HTTP + WebSocket server for real-time engagement visualization
// ============================================================

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { readFileSync, existsSync } from 'fs';
import { join, dirname, extname, relative, isAbsolute } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import type { GraphEngine } from './graph-engine.js';
import type { GraphUpdateDetail } from './engine-context.js';
import { DeltaAccumulator } from './delta-accumulator.js';
import type { SessionManager } from './session-manager.js';
import { dispatchCampaignAgents } from '../tools/agents.js';
import { listTemplates, loadTemplate, mergeTemplateWithConfig } from '../config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface DashboardStartResult {
  started: boolean;
  error?: string;
}

export interface DashboardEvent {
  type: 'graph_update' | 'agent_update' | 'objective_update' | 'full_state' | 'action_pending' | 'action_resolved';
  timestamp: string;
  data: any;
}

export class DashboardServer {
  private httpServer: ReturnType<typeof createServer>;
  private wss: WebSocketServer;
  private sessionWss: WebSocketServer;
  private engine: GraphEngine;
  private sessionManager: SessionManager | null;
  private port: number;
  private clients: Set<WebSocket> = new Set();
  private sessionPollers: Map<WebSocket, ReturnType<typeof setInterval>> = new Map();
  private _running: boolean = false;
  private accumulator = new DeltaAccumulator();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private static readonly DEBOUNCE_MS = 500;
  private static readonly SESSION_POLL_MS = 50;

  private host: string;

  constructor(engine: GraphEngine, port: number = 8384, host?: string, sessionManager?: SessionManager) {
    this.engine = engine;
    this.port = port;
    this.host = host || process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
    this.sessionManager = sessionManager || null;

    this.httpServer = createServer((req, res) => this.handleHttp(req, res));
    this.wss = new WebSocketServer({ noServer: true });
    this.sessionWss = new WebSocketServer({ noServer: true });

    this.wss.on('error', () => {
      // Absorb WSS errors
    });

    this.sessionWss.on('error', () => {
      // Absorb WSS errors
    });

    // URL-based WebSocket routing
    this.httpServer.on('upgrade', (req, socket, head) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const pathname = url.pathname;

      // Auth check for non-loopback
      if (!this.isLoopback(this.host)) {
        const token = url.searchParams.get('token');
        const expected = process.env.OVERWATCH_DASHBOARD_TOKEN;
        if (!expected || token !== expected) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
          return;
        }
      }

      const sessionMatch = pathname.match(/^\/ws\/session\/([a-f0-9-]{36})$/);
      if (sessionMatch) {
        if (!this.sessionManager) {
          socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
          socket.destroy();
          return;
        }
        this.sessionWss.handleUpgrade(req, socket, head, (ws) => {
          this.sessionWss.emit('connection', ws, req);
          this.handleSessionConnection(ws, sessionMatch[1]);
        });
      } else {
        this.wss.handleUpgrade(req, socket, head, (ws) => {
          this.wss.emit('connection', ws, req);
        });
      }
    });

    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      // Send full state on connect
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

    // Wire PendingActionQueue events to WebSocket broadcasts
    engine.getPendingActionQueue().onEvent((eventType, data) => {
      this.broadcast({
        type: eventType,
        timestamp: new Date().toISOString(),
        data,
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
    // Clean up session pollers
    for (const [ws, interval] of this.sessionPollers) {
      clearInterval(interval);
      ws.close();
    }
    this.sessionPollers.clear();
    return new Promise((resolve) => {
      for (const ws of this.clients) {
        ws.close();
      }
      this.clients.clear();
      this.sessionWss.close(() => {
        this.wss.close(() => {
          this.httpServer.close(() => resolve());
        });
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
        state,
        history_count: historyCount,
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

  // ---- Session terminal bridge ----

  private handleSessionConnection(ws: WebSocket, sessionId: string): void {
    if (!this.sessionManager) {
      ws.close(4503, 'Session manager not available');
      return;
    }

    const meta = this.sessionManager.getSession(sessionId);
    if (!meta) {
      ws.close(4404, 'Session not found');
      return;
    }
    if (meta.state !== 'connected') {
      ws.close(4409, `Session not connected (state: ${meta.state})`);
      return;
    }

    // Send initial state
    ws.send(JSON.stringify({ type: 'session_meta', data: meta }));

    // Read initial buffer tail
    try {
      const initial = this.sessionManager.read(sessionId, undefined, 8192);
      if (initial.text) {
        ws.send(JSON.stringify({ type: 'output', text: initial.text, end_pos: initial.end_pos }));
      }
    } catch { /* session may have closed between check and read */ }

    // Poll buffer for new output
    let cursor = this.sessionManager.read(sessionId, undefined, 0).end_pos;

    const poller = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        clearInterval(poller);
        this.sessionPollers.delete(ws);
        return;
      }

      try {
        const result = this.sessionManager!.read(sessionId, cursor);
        if (result.text) {
          ws.send(JSON.stringify({ type: 'output', text: result.text, end_pos: result.end_pos }));
          cursor = result.end_pos;
        }
      } catch {
        // Session closed or error — notify and stop polling
        ws.send(JSON.stringify({ type: 'session_closed' }));
        clearInterval(poller);
        this.sessionPollers.delete(ws);
        ws.close(4410, 'Session closed');
      }
    }, DashboardServer.SESSION_POLL_MS);

    this.sessionPollers.set(ws, poller);

    // Handle input from client
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === 'input' && typeof msg.data === 'string') {
          this.sessionManager!.write(sessionId, msg.data);
        } else if (msg.type === 'resize' && typeof msg.cols === 'number' && typeof msg.rows === 'number') {
          this.sessionManager!.resize(sessionId, msg.cols, msg.rows);
        }
      } catch { /* ignore malformed messages */ }
    });

    ws.on('close', () => {
      const interval = this.sessionPollers.get(ws);
      if (interval) {
        clearInterval(interval);
        this.sessionPollers.delete(ws);
      }
    });

    ws.on('error', () => {
      const interval = this.sessionPollers.get(ws);
      if (interval) {
        clearInterval(interval);
        this.sessionPollers.delete(ws);
      }
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
    const method = req.method || 'GET';

    // CORS: restrict to localhost origins (or env override)
    const origin = req.headers.origin || '';
    const allowedHost = process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
    const isLocalOrigin = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin);
    let isAllowedOrigin = isLocalOrigin;
    if (!isAllowedOrigin && origin) {
      try { isAllowedOrigin = new URL(origin).hostname === allowedHost; } catch { /* malformed origin */ }
    }
    if (isAllowedOrigin && origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const pathname = url.split('?')[0];

    if (pathname === '/api/state') {
      this.serveState(res);
    } else if (pathname === '/api/graph') {
      this.serveGraph(res);
    } else if (pathname === '/api/history') {
      this.serveHistory(url, res);
    } else if (pathname === '/api/sessions') {
      this.serveSessions(res);
    } else if (pathname === '/api/agents') {
      this.serveAgents(res);
    } else if (pathname === '/api/agents/dispatch' && method === 'POST') {
      this.handleAgentDispatch(req, res);
    } else if (pathname === '/api/templates') {
      this.serveTemplates(res);
    } else if (pathname === '/api/settings' && method === 'GET') {
      this.serveSettings(res);
    } else if (pathname === '/api/settings' && method === 'PATCH') {
      this.handleUpdateSettings(req, res);
    } else if (pathname === '/api/config' && method === 'GET') {
      this.serveConfig(res);
    } else if (pathname === '/api/config' && method === 'PATCH') {
      this.handleUpdateConfig(req, res);
    } else if (pathname === '/api/config/scope' && method === 'PATCH') {
      this.handleUpdateScope(req, res);
    } else if (pathname === '/api/config/objectives' && method === 'POST') {
      this.handleAddObjective(req, res);
    } else if (pathname === '/api/frontier/weights' && method === 'GET') {
      this.serveFrontierWeights(res);
    } else if (pathname === '/api/frontier/weights' && method === 'PATCH') {
      this.handleUpdateFrontierWeights(req, res);
    } else if (pathname === '/api/frontier/weights/reset' && method === 'POST') {
      this.handleResetFrontierWeights(req, res);
    } else if (pathname === '/api/health') {
      this.serveHealth(res);
    } else if (pathname === '/api/engagements/from-template' && method === 'POST') {
      this.handleCreateFromTemplate(req, res);
    } else if (pathname === '/api/campaigns' && method === 'POST') {
      this.handleCampaignCreate(req, res);
    } else if (pathname === '/api/campaigns') {
      this.serveCampaigns(res);
    } else if (pathname === '/api/actions/pending') {
      this.servePendingActions(res);
    } else {
      // Parameterized routes
      const agentCtxMatch = pathname.match(/^\/api\/agents\/([a-f0-9-]+)\/context$/);
      const agentCancelMatch = pathname.match(/^\/api\/agents\/([a-f0-9-]+)\/cancel$/);
      const objectiveMatch = pathname.match(/^\/api\/config\/objectives\/([a-f0-9-]+)$/);
      const campaignDetailMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)$/);
      const campaignActionMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/action$/);
      const campaignDispatchMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/dispatch$/);
      const campaignCloneMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/clone$/);
      const actionApproveMatch = pathname.match(/^\/api\/actions\/([a-f0-9-]+)\/approve$/);
      const actionDenyMatch = pathname.match(/^\/api\/actions\/([a-f0-9-]+)\/deny$/);
      const evidenceChainMatch = pathname.match(/^\/api\/evidence-chains\/([^/]+)$/);
      const pathsMatch = pathname.match(/^\/api\/paths\/([^/]+)$/);

      if (agentCtxMatch) {
        this.serveAgentContext(agentCtxMatch[1], res);
      } else if (agentCancelMatch && method === 'POST') {
        this.handleAgentCancel(agentCancelMatch[1], req, res);
      } else if (objectiveMatch && method === 'PATCH') {
        this.handleUpdateObjective(objectiveMatch[1], req, res);
      } else if (objectiveMatch && method === 'DELETE') {
        this.handleDeleteObjective(objectiveMatch[1], req, res);
      } else if (campaignActionMatch && method === 'POST') {
        this.handleCampaignAction(campaignActionMatch[1], req, res);
      } else if (campaignDispatchMatch && method === 'POST') {
        this.handleCampaignDispatch(campaignDispatchMatch[1], req, res);
      } else if (campaignCloneMatch && method === 'POST') {
        this.handleCampaignClone(campaignCloneMatch[1], req, res);
      } else if (campaignDetailMatch && method === 'PATCH') {
        this.handleCampaignUpdate(campaignDetailMatch[1], req, res);
      } else if (campaignDetailMatch && method === 'DELETE') {
        this.handleCampaignDelete(campaignDetailMatch[1], req, res);
      } else if (campaignDetailMatch) {
        this.serveCampaignDetail(campaignDetailMatch[1], res);
      } else if (actionApproveMatch && method === 'POST') {
        this.handleActionApprove(actionApproveMatch[1], req, res);
      } else if (actionDenyMatch && method === 'POST') {
        this.handleActionDeny(actionDenyMatch[1], req, res);
      } else if (evidenceChainMatch) {
        this.serveEvidenceChains(decodeURIComponent(evidenceChainMatch[1]), res);
      } else if (pathsMatch) {
        this.servePaths(decodeURIComponent(pathsMatch[1]), url, res);
      } else {
        this.serveStaticFile(url, res);
      }
    }
  }

  private serveStaticFile(url: string, res: ServerResponse): void {
    // Multi-page routing: operator dashboard (/) and graph explorer (/graph)
    let filePath: string;
    if (url === '/' || url === '/operator' || url === '/operator.html') {
      filePath = '/operator.html';
    } else if (url === '/graph' || url === '/graph.html') {
      filePath = '/graph.html';
    } else if (url === '/index.html') {
      // Backward compat: redirect old index.html to operator dashboard
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    } else {
      filePath = url;
    }

    // Security: prevent directory traversal (including percent-encoded variants)
    const decoded = decodeURIComponent(filePath);
    if (filePath.includes('..') || decoded.includes('..')) {
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
      const rel = relative(dashDir, fullPath);
      if (rel.startsWith('..') || isAbsolute(rel)) {
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

  // ---- Template endpoints ----

  private serveTemplates(res: ServerResponse): void {
    try {
      const templates = listTemplates();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ templates, total: templates.length }));
    } catch (err: any) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  }

  private handleCreateFromTemplate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body?.template_id || typeof body.template_id !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'template_id (string) is required' }));
        return;
      }
      const template = loadTemplate(body.template_id);
      if (!template) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Template not found: ${body.template_id}` }));
        return;
      }
      const overrides = body.overrides && typeof body.overrides === 'object' ? body.overrides : {};
      if (!overrides.id || typeof overrides.id !== 'string') {
        overrides.id = `eng-${Date.now()}`;
      }
      if (!overrides.name || typeof overrides.name !== 'string') {
        overrides.name = template.name;
      }
      if (!overrides.created_at || typeof overrides.created_at !== 'string') {
        overrides.created_at = new Date().toISOString();
      }
      try {
        const config = mergeTemplateWithConfig(template, overrides as any);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ config }));
      } catch (err: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // ---- Settings endpoints ----

  private serveSettings(res: ServerResponse): void {
    const config = this.engine.getConfig();
    const opsec = config.opsec;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      opsec: {
        max_noise: opsec.max_noise,
        approval_mode: opsec.approval_mode || 'approve-critical',
        approval_timeout_ms: opsec.approval_timeout_ms || 300000,
        blacklisted_techniques: opsec.blacklisted_techniques || [],
        time_window: opsec.time_window || null,
      },
      noise_state: {
        global_noise_spent: this.engine.getOpsecTracker().getGlobalNoise(),
        noise_ceiling_ratio: 0.85,
        per_host_ceiling_ratio: 0.50,
      },
      profile: opsec.name || config.profile || 'custom',
    }));
  }

  private handleUpdateSettings(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      const config = this.engine.getConfig();
      const opsec = config.opsec;
      let changed = false;

      if (typeof body.max_noise === 'number' && body.max_noise >= 0 && body.max_noise <= 2) {
        opsec.max_noise = body.max_noise;
        changed = true;
      }
      if (typeof body.approval_mode === 'string' && ['auto-approve', 'approve-all', 'approve-critical'].includes(body.approval_mode)) {
        opsec.approval_mode = body.approval_mode;
        changed = true;
      }
      if (typeof body.approval_timeout_ms === 'number' && body.approval_timeout_ms >= 10000 && body.approval_timeout_ms <= 3600000) {
        opsec.approval_timeout_ms = body.approval_timeout_ms;
        changed = true;
      }
      if (Array.isArray(body.blacklisted_techniques)) {
        opsec.blacklisted_techniques = body.blacklisted_techniques.filter((t: unknown) => typeof t === 'string');
        changed = true;
      }
      if (body.time_window !== undefined) {
        if (body.time_window === null) {
          opsec.time_window = undefined;
          changed = true;
        } else if (typeof body.time_window === 'object' &&
                   typeof body.time_window.start_hour === 'number' &&
                   typeof body.time_window.end_hour === 'number') {
          opsec.time_window = { start_hour: body.time_window.start_hour, end_hour: body.time_window.end_hour };
          changed = true;
        }
      }

      if (changed) {
        this.engine.persist();
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ updated: changed, opsec }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // ---- Config endpoints ----

  private serveConfig(res: ServerResponse): void {
    const config = this.engine.getConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(config));
  }

  private handleUpdateConfig(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      // Prevent overwriting immutable fields
      delete (body as Record<string, unknown>).id;
      delete (body as Record<string, unknown>).created_at;
      const updated = this.engine.updateConfig(body as Record<string, unknown>);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ updated: true, config: updated }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleUpdateScope(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      const updated = this.engine.updateConfig({ scope: body });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ updated: true, scope: updated.scope }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleAddObjective(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object' || typeof (body as Record<string, unknown>).description !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'description is required' }));
        return;
      }
      const b = body as Record<string, unknown>;
      const objective = this.engine.addObjective({
        description: b.description as string,
        target_node_type: b.target_node_type as string | undefined,
        target_criteria: b.target_criteria as Record<string, unknown> | undefined,
        achievement_edge_types: b.achievement_edge_types as string[] | undefined,
      });
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ created: true, objective }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleUpdateObjective(id: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      const ok = this.engine.updateObjective(id, body as Record<string, unknown>);
      if (!ok) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Objective not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ updated: true }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleDeleteObjective(id: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    const ok = this.engine.removeObjective(id);
    if (!ok) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Objective not found' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ deleted: true }));
  }

  // ---- Agent dispatch endpoint ----

  private handleAgentDispatch(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      const b = body as Record<string, unknown>;
      const targetNodeIds = Array.isArray(b.target_node_ids) ? b.target_node_ids.filter((x: unknown) => typeof x === 'string') as string[] : [];
      const skill = typeof b.skill === 'string' ? b.skill : undefined;
      const campaignId = typeof b.campaign_id === 'string' ? b.campaign_id : undefined;
      const frontierItemId = typeof b.frontier_item_id === 'string' ? b.frontier_item_id : undefined;

      if (targetNodeIds.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'target_node_ids must be a non-empty array of node IDs' }));
        return;
      }

      const taskId = randomUUID();
      const agentId = `dashboard-agent-${taskId.slice(0, 8)}`;

      const task = {
        id: taskId,
        agent_id: agentId,
        assigned_at: new Date().toISOString(),
        status: 'pending' as const,
        subgraph_node_ids: targetNodeIds,
        skill,
        campaign_id: campaignId,
        frontier_item_id: frontierItemId,
      };

      this.engine.registerAgent(task);

      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ dispatched: true, task }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // ---- Frontier weight endpoints ----

  private serveFrontierWeights(res: ServerResponse): void {
    const weights = this.engine.getFrontierWeights();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(weights));
  }

  private handleUpdateFrontierWeights(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object with fan_out and/or noise' }));
        return;
      }
      this.engine.setFrontierWeights({
        fan_out: body.fan_out && typeof body.fan_out === 'object' ? body.fan_out : undefined,
        noise: body.noise && typeof body.noise === 'object' ? body.noise : undefined,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ updated: true, weights: this.engine.getFrontierWeights() }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleResetFrontierWeights(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.engine.resetFrontierWeights();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ reset: true, weights: this.engine.getFrontierWeights() }));
  }

  // ---- Health endpoint ----

  private serveHealth(res: ServerResponse): void {
    try {
      const health = this.engine.getHealthReport();
      const adContext = this.engine.checkADContext();
      const graph = this.engine.exportGraph();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        graph_stats: {
          nodes: graph.nodes.length,
          edges: graph.edges.length,
          node_types: graph.nodes.reduce((acc: Record<string, number>, n: any) => {
            acc[n.properties.type] = (acc[n.properties.type] || 0) + 1;
            return acc;
          }, {}),
        },
        ad_context: adContext,
        health_checks: health,
      }));
    } catch (err: any) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
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

  private serveSessions(res: ServerResponse): void {
    if (!this.sessionManager) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ total: 0, active: 0, sessions: [] }));
      return;
    }
    const all = this.sessionManager.list();
    const active = all.filter(s => s.state === 'connected' || s.state === 'pending');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: all.length, active: active.length, sessions: all }));
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

  // ---- Agent & Campaign REST endpoints ----

  private serveAgents(res: ServerResponse): void {
    const agents = this.engine.getAllAgents();
    const now = Date.now();
    const enriched = agents.map(a => ({
      ...a,
      elapsed_ms: a.status === 'running' ? now - new Date(a.assigned_at).getTime() : undefined,
      campaign: a.campaign_id ? this.engine.getCampaign(a.campaign_id) : undefined,
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ agents: enriched, total: enriched.length }));
  }

  private serveAgentContext(taskId: string, res: ServerResponse): void {
    const task = this.engine.getTask(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent task not found' }));
      return;
    }
    const subgraph = this.engine.getSubgraphForAgent(task.subgraph_node_ids, { hops: 2 });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ task, subgraph }));
  }

  private handleAgentCancel(taskId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    const task = this.engine.getTask(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent task not found' }));
      return;
    }
    if (task.status !== 'running' && task.status !== 'pending') {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Agent is ${task.status} — cannot cancel` }));
      return;
    }
    const ok = this.engine.updateAgentStatus(taskId, 'interrupted', 'Cancelled by operator via dashboard');
    if (!ok) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to cancel agent' }));
      return;
    }
    const updated = this.engine.getTask(taskId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ cancelled: true, task: updated }));
  }

  private serveCampaigns(res: ServerResponse): void {
    const campaigns = this.engine.listCampaigns();
    const allAgents = this.engine.getAllAgents();
    const enriched = campaigns.map(c => {
      const agents = allAgents.filter(a => a.campaign_id === c.id);
      return {
        ...c,
        agent_count: agents.length,
        running_agents: agents.filter(a => a.status === 'running').length,
      };
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ campaigns: enriched, total: enriched.length }));
  }

  private serveCampaignDetail(campaignId: string, res: ServerResponse): void {
    const campaign = this.engine.getCampaign(campaignId);
    if (!campaign) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Campaign not found' }));
      return;
    }
    const allAgents = this.engine.getAllAgents();
    const agents = allAgents.filter(a => a.campaign_id === campaignId);
    const abort_check = this.engine.checkCampaignAbortConditions(campaignId);

    // Enrich findings with node summaries
    const finding_details = (campaign.findings || []).map(nodeId => {
      const node = this.engine.getNode(nodeId);
      return {
        id: nodeId,
        label: node?.label || nodeId,
        type: node?.type || 'unknown',
        created_at: node?.created_at || null,
      };
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ campaign, agents, abort_check, finding_details }));
  }

  private handleCampaignAction(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const action = body?.action;
      const validActions = ['activate', 'pause', 'resume', 'abort'];
      if (!validActions.includes(action)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Invalid action. Must be one of: ${validActions.join(', ')}` }));
        return;
      }
      const campaign = this.engine.getCampaign(campaignId);
      if (!campaign) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Campaign not found' }));
        return;
      }
      let result: import('../types.js').Campaign | null = null;
      switch (action) {
        case 'activate': result = this.engine.activateCampaign(campaignId); break;
        case 'pause': result = this.engine.pauseCampaign(campaignId); break;
        case 'resume': result = this.engine.resumeCampaign(campaignId); break;
        case 'abort': result = this.engine.abortCampaign(campaignId); break;
      }
      if (!result) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Failed to ${action} campaign` }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ action, campaign: result }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleCampaignDispatch(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const result = dispatchCampaignAgents(this.engine, campaignId, {
        max_agents: typeof body?.max_agents === 'number' ? body.max_agents : undefined,
        hops: typeof body?.hops === 'number' ? body.hops : undefined,
        skill: typeof body?.skill === 'string' ? body.skill : undefined,
      });
      if (result.error) {
        res.writeHead(result.error.includes('not found') ? 404 : 409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleCampaignCreate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body?.name || typeof body.name !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'name (string) is required' }));
        return;
      }
      if (!body?.strategy || typeof body.strategy !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'strategy (string) is required' }));
        return;
      }
      if (!Array.isArray(body?.item_ids) || body.item_ids.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'item_ids (non-empty array) is required' }));
        return;
      }
      const validStrategies = ['credential_spray', 'enumeration', 'post_exploitation', 'network_discovery', 'custom'];
      if (!validStrategies.includes(body.strategy)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Invalid strategy. Must be one of: ${validStrategies.join(', ')}` }));
        return;
      }
      try {
        const campaign = this.engine.createCampaign({
          name: body.name,
          strategy: body.strategy as import('../types.js').CampaignStrategy,
          item_ids: body.item_ids,
          abort_conditions: Array.isArray(body.abort_conditions) ? body.abort_conditions : undefined,
        });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ campaign }));
      } catch (err: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleCampaignUpdate(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'JSON body required' }));
        return;
      }
      try {
        const campaign = this.engine.updateCampaign(campaignId, {
          name: typeof body.name === 'string' ? body.name : undefined,
          abort_conditions: Array.isArray(body.abort_conditions) ? body.abort_conditions : undefined,
          add_items: Array.isArray(body.add_items) ? body.add_items : undefined,
          remove_items: Array.isArray(body.remove_items) ? body.remove_items : undefined,
        });
        if (!campaign) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Campaign not found' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ campaign }));
      } catch (err: any) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleCampaignDelete(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const deleted = this.engine.deleteCampaign(campaignId);
      if (!deleted) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Campaign not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ deleted: true }));
    } catch (err: any) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  }

  private handleCampaignClone(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    const campaign = this.engine.cloneCampaign(campaignId);
    if (!campaign) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Campaign not found' }));
      return;
    }
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ campaign }));
  }

  // ---- Mutation auth & body parsing helpers ----

  private checkMutationAuth(req: IncomingMessage, res: ServerResponse): boolean {
    if (this.isLoopback(this.host)) return true;
    const expected = process.env.OVERWATCH_DASHBOARD_TOKEN;
    if (!expected) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token not configured for non-loopback host' }));
      return false;
    }
    // Check Authorization header or query string
    const authHeader = req.headers.authorization;
    const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const urlToken = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`).searchParams.get('token');
    if (headerToken !== expected && urlToken !== expected) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return false;
    }
    return true;
  }

  private readJsonBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const MAX_BODY = 64 * 1024; // 64 KB limit
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          req.destroy();
          reject(new Error('Body too large'));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        try {
          const raw = Buffer.concat(chunks).toString('utf-8');
          resolve(raw ? JSON.parse(raw) : {});
        } catch { reject(new Error('Invalid JSON')); }
      });
      req.on('error', reject);
    });
  }

  private isLoopback(host: string): boolean {
    return host === '127.0.0.1' || host === '::1' || host === 'localhost';
  }

  // =============================================
  // Pending Actions (Approval Gates)
  // =============================================

  private servePendingActions(res: ServerResponse): void {
    const queue = this.engine.getPendingActionQueue();
    const pending = queue.getPending();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ pending, count: pending.length }));
  }

  private handleActionApprove(actionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const queue = this.engine.getPendingActionQueue();
      const result = queue.approve(actionId, body?.notes);
      if (!result) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Action not found or already resolved' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request body' }));
    });
  }

  private handleActionDeny(actionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const queue = this.engine.getPendingActionQueue();
      const result = queue.deny(actionId, body?.reason);
      if (!result) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Action not found or already resolved' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request body' }));
    });
  }

  // =============================================
  // Evidence Chains & Path Visualization
  // =============================================

  private serveEvidenceChains(nodeId: string, res: ServerResponse): void {
    // Build evidence chains for a node from the activity log
    const history = this.engine.getFullHistory();
    const chains: Array<{ action_id?: string; tool?: string; timestamp: string; snippet?: string }> = [];

    for (const entry of history) {
      // Match entries that reference this node
      const entryStr = JSON.stringify(entry);
      if (!entryStr.includes(nodeId)) continue;

      chains.push({
        action_id: (entry as Record<string, unknown>).action_id as string | undefined,
        tool: (entry as Record<string, unknown>).tool_name as string | undefined
          || (entry as Record<string, unknown>).action_type as string | undefined,
        timestamp: entry.timestamp,
        snippet: (entry as Record<string, unknown>).description as string | undefined
          || (entry as Record<string, unknown>).summary as string | undefined,
      });
    }

    // Enrich with node properties and findings from exported graph
    const exported = this.engine.exportGraph();
    let node_props: Record<string, unknown> | undefined;
    let findings: Array<{ finding_type?: string; severity?: string; technique_id?: string; description?: string }> = [];
    const nodeData = exported.nodes.find(n => n.id === nodeId);
    if (nodeData) {
      const attrs = nodeData.properties || {};
      node_props = {
        type: attrs.type,
        label: attrs.label,
        os: attrs.os,
        confidence: attrs.confidence,
        discovered_at: attrs.discovered_at,
        chain_template: attrs.chain_template,
      };

      // Collect findings from connected edges
      for (const edge of exported.edges) {
        if (edge.source !== nodeId && edge.target !== nodeId) continue;
        const ep = edge.properties;
        if (ep.type === 'EXPLOITS' || ep.type === 'AUTH_BYPASS' || ep.finding_type) {
          findings.push({
            finding_type: (ep.finding_type as string) || ep.type,
            severity: ep.severity as string | undefined,
            technique_id: ep.technique_id as string | undefined,
            description: `${edge.source} → ${edge.target} (${ep.type})`,
          });
        }
      }
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ node_id: nodeId, chains, count: chains.length, node_props, findings }));
  }

  private servePaths(objectiveId: string, url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    const optimize = (params.get('optimize') || 'confidence') as 'confidence' | 'stealth' | 'balanced';
    const limitParam = params.get('limit');
    const limit = limitParam ? parseInt(limitParam, 10) : 5;

    try {
      const paths = this.engine.findPathsToObjective(objectiveId, limit, optimize);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ objective_id: objectiveId, paths, count: paths.length }));
    } catch {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Objective not found or no paths available' }));
    }
  }
}
