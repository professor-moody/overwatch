// ============================================================
// Overwatch — Live Dashboard Server
// HTTP + WebSocket server for real-time engagement visualization
// ============================================================

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { readFileSync, existsSync, statSync } from 'fs';
import { join, dirname, extname, relative, isAbsolute } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import type { GraphEngine } from './graph-engine.js';
import { parseAndMaybeIngest } from './parse-ingest.js';
import { getSupportedParsers } from './parsers/index.js';
import type { GraphUpdateDetail } from './engine-context.js';
import { DeltaAccumulator } from './delta-accumulator.js';
import type { SessionEvent, SessionManager } from './session-manager.js';
import { dispatchCampaignAgents } from '../tools/agents.js';
import { interpretCommand, executeOps, buildPlannerObjective, type OperatorOp, type InterpreterState } from './command-interpreter.js';
import { getArchetype, isArchetypeId, listArchetypes, recommendArchetype } from './agent-archetypes.js';
import { listTemplates, loadTemplate, mergeTemplateWithConfig } from '../config.js';
import { opsecPartialUpdateSchema, operatorPolicyUpdateSchema, type Campaign, type AgentDirectiveKind } from '../types.js';
import type { DefensiveSignal, OpsecContext } from './opsec-tracker.js';
import { EngagementManager } from './engagement-manager.js';
import { checkAllTools } from './tool-check.js';
import { getTelemetry } from '../tools/error-boundary.js';
import { assembleReport, type ReportFormat } from './report-assembler.js';
import { prepareBundle, pipeTarGzToStream } from './bundle-builder.js';
import { buildFindings } from './report-generator.js';
import { classifyAllFindings } from './finding-classifier.js';
import type { ReportRecord } from './report-archive.js';
import type { DurableApprovalRecord, PendingAction } from './pending-action-queue.js';
import type { ToolEntry } from './prompt-generator.js';
import { buildTrustSignalsResponse, type TrustSignalSeverity } from './trust-signal-summary.js';
import { activityToAgentConsoleEvent, buildAgentConsoleEvents, type AgentConsoleEvent } from './agent-console.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function categorizeMcpTool(name: string): string {
  if (['get_state', 'next_task', 'get_system_prompt', 'run_lab_preflight', 'run_graph_health'].includes(name)) {
    return 'state-readiness';
  }
  if (
    name.includes('session') ||
    ['validate_action', 'log_action_event', 'run_bash', 'run_tool', 'track_process', 'check_processes'].includes(name)
  ) {
    return 'execution';
  }
  if (
    name.includes('graph') ||
    name.includes('ingest') ||
    ['query_graph', 'find_paths', 'parse_output', 'report_finding', 'get_evidence', 'recompute_objectives', 'correct_graph'].includes(name)
  ) {
    return 'graph-data';
  }
  if (name.includes('agent') || name.includes('campaign')) {
    return 'agents-campaigns';
  }
  if (
    name.includes('credential') ||
    name.includes('token') ||
    name.includes('postgres') ||
    ['expand_aws_credential', 'expand_github_credential', 'expand_oidc_capture', 'expand_entra_credential', 'exchange_refresh_token'].includes(name)
  ) {
    return 'credentials-playbooks';
  }
  if (
    name.includes('report') ||
    name.includes('timeline') ||
    name.includes('decision') ||
    name.includes('retrospective') ||
    name.includes('tape') ||
    ['get_history', 'explain_action', 'verify_activity_chain', 'bundle_engagement'].includes(name)
  ) {
    return 'audit-reporting';
  }
  return 'other';
}

export interface DashboardStartResult {
  started: boolean;
  error?: string;
}

interface CachedStaticAsset {
  content: string | Buffer;
  mtimeMs: number;
  size: number;
}

export interface DashboardEvent {
  type: 'graph_update' | 'agent_update' | 'agent_console_update' | 'objective_update' | 'full_state' | 'action_pending' | 'action_resolved' | 'session_update' | 'agent_query';
  timestamp: string;
  data: any;
}

/** Per-campaign OPSEC budget snapshot — the campaign's own noise contribution
 * measured against the (global) noise budget, plus the global recommended
 * approach. Shaped to feed the same OpsecGauge the Overview uses. */
interface CampaignOpsecBudget {
  global_noise_spent: number;
  noise_budget_remaining: number;
  max_noise: number;
  recommended_approach: OpsecContext['recommended_approach'];
  defensive_signals: DefensiveSignal[];
  time_window_remaining_hours?: number;
  warning?: string;
}

type DashboardCampaign = Campaign & {
  agent_count: number;
  running_agents: number;
  agents_total: number;
  agents_active: number;
  completion_pct: number;
  findings_count: number;
  opsec: CampaignOpsecBudget;
};

export class DashboardServer {
  private httpServer: ReturnType<typeof createServer>;
  private wss: WebSocketServer;
  private sessionWss: WebSocketServer;
  private actionWss: WebSocketServer;
  private engine: GraphEngine;
  private sessionManager: SessionManager | null;
  private port: number;
  private clients: Set<WebSocket> = new Set();
  private sessionPollers: Map<WebSocket, ReturnType<typeof setInterval>> = new Map();
  private actionPollers: Map<WebSocket, ReturnType<typeof setInterval>> = new Map();
  private agentConsoleCursor = 0;
  private _running: boolean = false;
  private accumulator = new DeltaAccumulator();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private static readonly DEBOUNCE_MS = 500;
  private static readonly SESSION_POLL_MS = 50;
  private static readonly ACTION_POLL_MS = 100;

  private host: string;
  private engagementManager: EngagementManager | null = null;
  private configPath?: string;
  /**
   * Optional in-process tape controller. Attached by app bootstrap so the
   * dashboard can expose status + a runtime on/off toggle. The dashboard
   * never owns the controller — toggling here mirrors what env / config
   * achieve at startup.
   */
  private tape: { getStatus(): unknown; enable(opts?: { defaultDir?: string; file?: string; sessionId?: string; startedBy?: 'env' | 'config' | 'dashboard' }): unknown; disable(): Promise<unknown> } | null = null;

  attachTape(controller: { getStatus(): unknown; enable(opts?: { defaultDir?: string; file?: string; sessionId?: string; startedBy?: 'env' | 'config' | 'dashboard' }): unknown; disable(): Promise<unknown> }): void {
    this.tape = controller;
  }

  /**
   * Optional skill index. Required for `/api/reports/render` when
   * `include_retrospective: true`; the retrospective walks loaded
   * skills to flag gaps.
   */
  private skills: import('./skill-index.js').SkillIndex | null = null;
  attachSkills(skills: import('./skill-index.js').SkillIndex): void {
    this.skills = skills;
  }

  private mcpTools: ToolEntry[] = [];
  attachMcpTools(tools: ToolEntry[]): void {
    this.mcpTools = tools.slice();
  }

  /**
   * Optional task-execution service. Required for the cancel endpoint to kill a
   * headless sub-agent's OS process (not just mark its task interrupted).
   */
  private taskExecution: {
    cancelHeadless(task_id: string, reason?: string): boolean;
    isHeadlessAvailable(): boolean;
  } | null = null;
  attachTaskExecution(svc: { cancelHeadless(task_id: string, reason?: string): boolean; isHeadlessAvailable(): boolean }): void {
    this.taskExecution = svc;
  }

  constructor(engine: GraphEngine, port: number = 8384, host?: string, sessionManager?: SessionManager, configPath?: string) {
    this.engine = engine;
    this.port = port;
    this.host = host || process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
    this.sessionManager = sessionManager || null;
    this.configPath = configPath;
    if (configPath) {
      this.engagementManager = new EngagementManager(configPath);
    }

    // Wire engine updates to WS push without requiring external wiring in app.ts.
    engine.onUpdate(detail => this.onGraphUpdate(detail));
    this.agentConsoleCursor = engine.getFullHistory().length;

    // 3D: push the agent-question inbox live when an agent asks or is answered.
    engine.getAgentQueryStore().onChange(() => {
      if (this.clients.size === 0) return;
      this.broadcast({
        type: 'agent_query',
        timestamp: new Date().toISOString(),
        data: { queries: engine.getAgentQueryStore().getOpen() },
      });
    });

    this.httpServer = createServer((req, res) => this.handleHttp(req, res));
    this.wss = new WebSocketServer({ noServer: true });
    this.sessionWss = new WebSocketServer({ noServer: true });
    this.actionWss = new WebSocketServer({ noServer: true });

    this.wss.on('error', () => {
      // Absorb WSS errors
    });

    this.sessionWss.on('error', () => {
      // Absorb WSS errors
    });

    this.actionWss.on('error', () => {
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
      const actionOutputMatch = pathname.match(/^\/ws\/actions\/([A-Za-z0-9_-]+)\/output$/);
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
      } else if (actionOutputMatch) {
        this.actionWss.handleUpgrade(req, socket, head, (ws) => {
          this.actionWss.emit('connection', ws, req);
          this.handleActionOutputConnection(ws, actionOutputMatch[1]);
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
      const state = this.buildFrontendState();
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

    if (typeof this.sessionManager?.onEvent === 'function') {
      this.sessionManager.onEvent((event: SessionEvent) => {
        this.broadcast({
          type: 'session_update',
          timestamp: new Date().toISOString(),
          data: event,
        });
      });
    }
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
    // Clean up action-output pollers
    for (const [ws, interval] of this.actionPollers) {
      clearInterval(interval);
      ws.close();
    }
    this.actionPollers.clear();
    return new Promise((resolve) => {
      for (const ws of this.clients) {
        ws.close();
      }
      this.clients.clear();
      this.actionWss.close(() => {
        this.sessionWss.close(() => {
          this.wss.close(() => {
            this.httpServer.close(() => resolve());
          });
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
    const consoleEvents = this.collectNewAgentConsoleEvents();

    // Short-circuit: skip expensive work when nobody is listening
    if (this.clients.size === 0) return;

    if (consoleEvents.length > 0) {
      this.broadcast({
        type: 'agent_console_update',
        timestamp: new Date().toISOString(),
        data: { events: consoleEvents },
      });
    }

    this.accumulator.push(detail);

    // Reset debounce timer
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => this.flushPendingUpdate(), DashboardServer.DEBOUNCE_MS);
  }

  private collectNewAgentConsoleEvents(): AgentConsoleEvent[] {
    const history = this.engine.getFullHistory();
    if (this.agentConsoleCursor > history.length) {
      this.agentConsoleCursor = history.length;
      return [];
    }
    const entries = history.slice(this.agentConsoleCursor);
    this.agentConsoleCursor = history.length;
    if (entries.length === 0) return [];
    return entries
      .map(entry => activityToAgentConsoleEvent(entry))
      .filter((event): event is AgentConsoleEvent => event !== null);
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
    const state = this.buildFrontendState();
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

    // Handle input from client. Dashboard terminal writes act on behalf of
    // the operator, so always pass force=true — otherwise writes to a
    // session claimed by an agent silently fail (assertOwnership throws,
    // and the catch below would swallow it). Surface any write/resize
    // errors back over the WS so the user sees something change.
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === 'input' && typeof msg.data === 'string') {
          try {
            this.sessionManager!.write(sessionId, msg.data, 'dashboard', true);
          } catch (err) {
            ws.send(JSON.stringify({
              type: 'error',
              op: 'input',
              error: err instanceof Error ? err.message : String(err),
            }));
          }
        } else if (msg.type === 'resize' && typeof msg.cols === 'number' && typeof msg.rows === 'number') {
          try {
            this.sessionManager!.resize(sessionId, msg.cols, msg.rows, 'dashboard', true);
          } catch (err) {
            ws.send(JSON.stringify({
              type: 'error',
              op: 'resize',
              error: err instanceof Error ? err.message : String(err),
            }));
          }
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

  // ---- Live action-output bridge (Analysis workspace) ----

  private handleActionOutputConnection(ws: WebSocket, actionId: string): void {
    const buffer = this.engine.getActionOutputBuffer();
    if (!buffer.has(actionId)) {
      // Not live: never streamed, or already finished + evicted. Tell the
      // client to fall back to the durable evidence route.
      ws.send(JSON.stringify({ type: 'action_done' }));
      ws.close(4404, 'No live output');
      return;
    }

    let outCursor = 0;
    let errCursor = 0;
    const flush = () => {
      for (const stream of ['stdout', 'stderr'] as const) {
        const cursor = stream === 'stdout' ? outCursor : errCursor;
        const r = buffer.read(actionId, stream, cursor);
        if (r && r.text) {
          ws.send(JSON.stringify({ type: 'output', stream, text: r.text, end_pos: r.end_pos, dropped: r.dropped }));
          if (stream === 'stdout') outCursor = r.end_pos; else errCursor = r.end_pos;
        }
      }
    };

    try { flush(); } catch { /* connection may have closed */ }

    const poller = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        clearInterval(poller);
        this.actionPollers.delete(ws);
        return;
      }
      try {
        flush();
        if (buffer.isDone(actionId)) {
          ws.send(JSON.stringify({ type: 'action_done' }));
          clearInterval(poller);
          this.actionPollers.delete(ws);
          ws.close(1000, 'done');
        }
      } catch {
        // Send error: stop polling and tell the client to fall back to the
        // durable route rather than freezing in a live state.
        clearInterval(poller);
        this.actionPollers.delete(ws);
        try { ws.send(JSON.stringify({ type: 'action_done' })); } catch { /* socket gone */ }
        try { ws.close(); } catch { /* already closed */ }
      }
    }, DashboardServer.ACTION_POLL_MS);

    this.actionPollers.set(ws, poller);

    const cleanup = () => {
      const interval = this.actionPollers.get(ws);
      if (interval) {
        clearInterval(interval);
        this.actionPollers.delete(ws);
      }
    };
    ws.on('close', cleanup);
    ws.on('error', cleanup);
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
  private fileCache: Map<string, CachedStaticAsset> = new Map();

  private isTextAsset(ext: string): boolean {
    return ['.html', '.css', '.js', '.json', '.svg'].includes(ext);
  }

  private resolveDashboardDir(): string {
    if (this.dashboardDir) return this.dashboardDir;

    // The dashboard-next (React + Vite) BUILD always has an `assets/`
    // subdirectory; the source tree does not. We use that as the
    // "is-this-a-built-bundle" marker so that demos running via
    // `npx tsx` (where __dirname is src/services/) don't accidentally
    // serve the source `src/dashboard-next/index.html` — which references
    // `/src/main.tsx` and renders blank because no Vite is serving it.

    const candidates = [
      // tsx / source-execution case: __dirname is src/services/, so
      // src/services/../../dist/dashboard-next is the project's built bundle.
      join(__dirname, '..', '..', 'dist', 'dashboard-next'),
      // Compiled-services case: __dirname is dist/services/, sibling dir
      // is dist/dashboard-next/.
      join(__dirname, '..', 'dashboard-next'),
    ];
    // Preferred: a path that has both index.html AND assets/ (a real build).
    for (const dir of candidates) {
      if (existsSync(join(dir, 'index.html')) && existsSync(join(dir, 'assets'))) {
        this.dashboardDir = dir;
        return dir;
      }
    }
    // Fallback: any candidate with at least an index.html. This keeps the
    // unit-tests CI job working (it doesn't build the dashboard before
    // running `npm run test:source`) and tolerates compiled-but-not-Vite-built
    // deployments. The serve path will still surface a useful page.
    for (const dir of candidates) {
      if (existsSync(join(dir, 'index.html'))) {
        this.dashboardDir = dir;
        return dir;
      }
    }
    // Last fallback: the source tree under src/dashboard-next/. Always present
    // in a checkout; never throws "Dashboard build not found" anymore. Demos
    // running from this path will render blank without a Vite dev server, but
    // the routing surface (SPA fallthrough) still works for test purposes.
    const srcDir = join(__dirname, '..', '..', 'src', 'dashboard-next');
    if (existsSync(join(srcDir, 'index.html'))) {
      this.dashboardDir = srcDir;
      return srcDir;
    }
    const compiledSrcDir = join(__dirname, '..', 'dashboard-next');
    if (existsSync(join(compiledSrcDir, 'index.html'))) {
      this.dashboardDir = compiledSrcDir;
      return compiledSrcDir;
    }

    throw new Error(
      'Dashboard build not found. Run `npm run build:dashboard-next` (or `npm run build`) before starting the server.',
    );
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
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const pathname = url.split('?')[0];

    // Require token auth for /api/* reads (and writes) when bound non-loopback.
    // Mutations have their own checkMutationAuth (which also enforces CSRF /
    // Origin); this gate covers GET endpoints that would otherwise leak
    // graph/state/history to anyone able to reach the dashboard host.
    if (pathname.startsWith('/api/') && !this.checkReadAuth(req, res)) {
      return;
    }

    if (pathname === '/api/state') {
      this.serveState(res);
    } else if (pathname === '/api/graph') {
      this.serveGraph(res);
    } else if (pathname === '/api/history') {
      this.serveHistory(url, res);
    } else if (pathname === '/api/decision-log') {
      this.serveDecisionLog(url, res);
    } else if (pathname === '/api/timeline') {
      this.serveTimeline(url, res);
    } else if (pathname === '/api/sessions') {
      this.serveSessions(res);
    } else if (pathname === '/api/agents') {
      this.serveAgents(res);
    } else if (pathname === '/api/agents/dispatch' && method === 'POST') {
      this.handleAgentDispatch(req, res);
    } else if (pathname === '/api/agents/quick-deploy' && method === 'POST') {
      this.handleQuickDeploy(req, res);
    } else if (pathname === '/api/agent-archetypes' && method === 'GET') {
      this.serveAgentArchetypes(res);
    } else if (pathname === '/api/fleet/directive' && method === 'POST') {
      this.handleFleetDirective(req, res);
    } else if (pathname === '/api/commands' && method === 'POST') {
      this.handleCommand(req, res);
    } else if (pathname === '/api/plans' && method === 'GET') {
      this.serveProposedPlans(res);
    } else if (pathname === '/api/agent-queries' && method === 'GET') {
      this.serveAgentQueries(res);
    } else if (pathname === '/api/agent-queries/answer-batch' && method === 'POST') {
      this.handleAnswerAgentQueryBatch(req, res);
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
    } else if (pathname === '/api/config/scope/preview' && method === 'POST') {
      this.handlePreviewScope(req, res);
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
    } else if (pathname === '/api/opsec/budget') {
      this.serveOpsecBudget(res);
    } else if (pathname === '/api/health') {
      this.serveHealth(res);
    } else if (pathname === '/api/engagements' && method === 'GET') {
      this.serveEngagements(res);
    } else if (pathname === '/api/engagements' && method === 'POST') {
      this.handleCreateEngagement(req, res);
    } else if (pathname === '/api/engagements/from-template' && method === 'POST') {
      this.handleCreateFromTemplate(req, res);
    } else if (pathname?.startsWith('/api/engagements/') && !pathname.includes('/from-template') && method === 'GET') {
      const engId = decodeURIComponent(pathname.slice('/api/engagements/'.length));
      this.serveEngagementDetail(engId, res);
    } else if (pathname?.startsWith('/api/engagements/') && !pathname.includes('/from-template') && method === 'PATCH') {
      const engId = decodeURIComponent(pathname.slice('/api/engagements/'.length));
      this.handleUpdateEngagement(engId, req, res);
    } else if (pathname === '/api/campaigns' && method === 'POST') {
      this.handleCampaignCreate(req, res);
    } else if (pathname === '/api/campaigns') {
      this.serveCampaigns(res);
    } else if (pathname === '/api/phases') {
      this.servePhases(res);
    } else if (pathname === '/api/actions/pending') {
      this.servePendingActions(res);
    } else if (pathname === '/api/tools' && method === 'GET') {
      this.serveTools(res);
    } else if (pathname === '/api/parsers' && method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ parsers: getSupportedParsers() }));
    } else if (pathname === '/api/mcp-tools' && method === 'GET') {
      this.serveMcpTools(res);
    } else if (pathname === '/api/readiness' && method === 'GET') {
      this.serveReadiness(res);
    } else if (pathname === '/api/trust-signals' && method === 'GET') {
      this.serveTrustSignals(url, res);
    } else if (pathname === '/api/inference-rules' && method === 'GET') {
      this.serveInferenceRules(res);
    } else if (pathname === '/api/telemetry' && method === 'GET') {
      this.serveTelemetry(res);
    } else if (pathname === '/api/graph/export' && method === 'POST') {
      this.handleGraphExport(res);
    } else if (pathname === '/api/graph/correct' && method === 'POST') {
      this.handleGraphCorrect(req, res);
    } else if (pathname === '/api/tape' && method === 'GET') {
      this.handleTapeStatus(res);
    } else if (pathname === '/api/tape/toggle' && method === 'POST') {
      this.handleTapeToggle(req, res);
    } else if (pathname === '/api/findings' && method === 'GET') {
      this.serveFindings(res);
    } else if (pathname === '/api/reports' && method === 'GET') {
      this.serveReportsList(res);
    } else if (pathname === '/api/reports/render' && method === 'POST') {
      this.handleRenderReport(req, res);
    } else if (pathname === '/api/bundle' && method === 'GET') {
      this.streamBundle(req, res);
    } else {
      // Parameterized routes
      const agentCtxMatch = pathname.match(/^\/api\/agents\/([^/]+)\/context$/);
      const agentHistoryMatch = pathname.match(/^\/api\/agents\/([^/]+)\/history$/);
      const agentConsoleMatch = pathname.match(/^\/api\/agents\/([^/]+)\/console$/);
      const agentCancelMatch = pathname.match(/^\/api\/agents\/([^/]+)\/cancel$/);
      const agentDirectiveMatch = pathname.match(/^\/api\/agents\/([^/]+)\/directive$/);
      const agentQueryAnswerMatch = pathname.match(/^\/api\/agent-queries\/([^/]+)\/answer$/);
      const objectiveMatch = pathname.match(/^\/api\/config\/objectives\/([a-f0-9-]+)$/);
      const campaignDetailMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)$/);
      const campaignActionMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/action$/);
      const campaignDispatchMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/dispatch$/);
      const campaignCloneMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/clone$/);
      const campaignSplitMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/split$/);
      const campaignChildrenMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/children$/);
      const actionExplainMatch = pathname.match(/^\/api\/actions\/([^/]+)\/explain$/);
      // Raw tool-output for the Analysis workspace. Action ids are `act_<hex>`
      // or a uuid (the `act_` underscore falls outside [a-f0-9-]), so match the
      // full id charset — an unknown id is just a 404 in the handler.
      const actionOutputMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/output$/);
      const actionReparseMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/reparse$/);
      const evidenceRawMatch = pathname.match(/^\/api\/evidence\/([^/]+)\/raw$/);
      // Action ids are `act_<hex>` (deterministic, nonce-bearing engagements) or
      // a uuid — both fall outside [a-f0-9-] because of the `act_` underscore, so
      // a hex-only class silently 404s every real action. Match the full id
      // charset (the queue does an exact lookup, so an unknown id is just a 404).
      const actionApproveMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/approve$/);
      const actionDenyMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/deny$/);
      const sessionCloseMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/close$/);
      const sessionBufferMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/buffer$/);
      const sessionDetailMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)$/);
      const evidenceChainMatch = pathname.match(/^\/api\/evidence-chains\/([^/]+)$/);
      const pathsMatch = pathname.match(/^\/api\/paths\/([^/]+)$/);
      const findingContextMatch = pathname.match(/^\/api\/findings\/([^/]+)\/context$/);
      const reportDetailMatch = pathname.match(/^\/api\/reports\/([a-f0-9-]+)$/);

      if (agentCtxMatch) {
        this.serveAgentContext(decodeURIComponent(agentCtxMatch[1]), res);
      } else if (agentHistoryMatch) {
        this.serveAgentHistory(decodeURIComponent(agentHistoryMatch[1]), res);
      } else if (agentConsoleMatch) {
        this.serveAgentConsole(decodeURIComponent(agentConsoleMatch[1]), url, res);
      } else if (agentCancelMatch && method === 'POST') {
        this.handleAgentCancel(decodeURIComponent(agentCancelMatch[1]), req, res);
      } else if (agentDirectiveMatch && method === 'POST') {
        this.handleAgentDirective(decodeURIComponent(agentDirectiveMatch[1]), req, res);
      } else if (agentQueryAnswerMatch && method === 'POST') {
        this.handleAnswerAgentQuery(decodeURIComponent(agentQueryAnswerMatch[1]), req, res);
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
      } else if (campaignSplitMatch && method === 'POST') {
        this.handleCampaignSplit(campaignSplitMatch[1], req, res);
      } else if (campaignChildrenMatch) {
        this.serveCampaignChildren(campaignChildrenMatch[1], res);
      } else if (campaignDetailMatch && method === 'PATCH') {
        this.handleCampaignUpdate(campaignDetailMatch[1], req, res);
      } else if (campaignDetailMatch && method === 'DELETE') {
        this.handleCampaignDelete(campaignDetailMatch[1], req, res);
      } else if (campaignDetailMatch) {
        this.serveCampaignDetail(campaignDetailMatch[1], res);
      } else if (actionExplainMatch && method === 'GET') {
        this.serveActionExplanation(decodeURIComponent(actionExplainMatch[1]), res);
      } else if (actionOutputMatch && method === 'GET') {
        this.serveActionOutput(decodeURIComponent(actionOutputMatch[1]), url, res);
      } else if (actionReparseMatch && method === 'POST') {
        this.handleActionReparse(decodeURIComponent(actionReparseMatch[1]), req, res);
      } else if (evidenceRawMatch && method === 'GET') {
        this.serveEvidenceRaw(decodeURIComponent(evidenceRawMatch[1]), url, res);
      } else if (actionApproveMatch && method === 'POST') {
        this.handleActionApprove(actionApproveMatch[1], req, res);
      } else if (actionDenyMatch && method === 'POST') {
        this.handleActionDeny(actionDenyMatch[1], req, res);
      } else if (sessionCloseMatch && method === 'POST') {
        this.handleSessionClose(sessionCloseMatch[1], req, res);
      } else if (sessionBufferMatch && method === 'GET') {
        this.serveSessionBuffer(sessionBufferMatch[1], url, res);
      } else if (sessionDetailMatch && method === 'PATCH') {
        this.handleSessionUpdate(sessionDetailMatch[1], req, res);
      } else if (evidenceChainMatch) {
        this.serveEvidenceChains(decodeURIComponent(evidenceChainMatch[1]), res);
      } else if (pathsMatch) {
        this.servePaths(decodeURIComponent(pathsMatch[1]), url, res);
      } else if (findingContextMatch && method === 'GET') {
        this.serveFindingContext(decodeURIComponent(findingContextMatch[1]), res);
      } else if (reportDetailMatch && method === 'GET') {
        this.serveReportDownload(reportDetailMatch[1], url, res);
      } else if (reportDetailMatch && method === 'DELETE') {
        this.handleReportDelete(reportDetailMatch[1], res);
      } else {
        this.serveStaticFile(url, res);
      }
    }
  }

  private serveStaticFile(url: string, res: ServerResponse): void {
    // React SPA: serve index.html for all non-asset routes (React Router
    // handles `/`, `/operator`, `/graph`, `/index.html`, `/operator.html`,
    // and any future client routes). Paths with file extensions fall
    // through to disk lookup so static assets (.js, .css, .png, ...) work.
    const pathname = url.split('?')[0];
    const hasExt = extname(pathname) !== '';
    const filePath = hasExt ? pathname : '/index.html';

    // Security: prevent directory traversal (including percent-encoded variants).
    // decodeURIComponent can throw URIError on malformed escapes (e.g. `%E0`),
    // so guard it explicitly rather than letting it crash the request handler.
    let decoded: string;
    try {
      decoded = decodeURIComponent(filePath);
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad request');
      return;
    }
    if (filePath.includes('..') || decoded.includes('..')) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    // Strip leading slash and query string
    const cleanPath = filePath.replace(/^\//, '').split('?')[0];
    const ext = extname(cleanPath);
    const mime = DashboardServer.MIME_TYPES[ext] || 'application/octet-stream';

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

      const stat = statSync(fullPath);
      const cached = this.fileCache.get(cleanPath);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
        res.end(cached.content);
        return;
      }

      const content = this.isTextAsset(ext)
        ? readFileSync(fullPath, 'utf-8')
        : readFileSync(fullPath);
      this.fileCache.set(cleanPath, {
        content,
        mtimeMs: stat.mtimeMs,
        size: stat.size,
      });
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
    const opsecStatus = this.engine.getOpsecStatus();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      opsec: {
        enabled: opsec.enabled === true,
        max_noise: opsec.max_noise,
        approval_mode: opsec.approval_mode || 'approve-critical',
        approval_timeout_ms: opsec.approval_timeout_ms || 300000,
        blacklisted_techniques: opsec.blacklisted_techniques || [],
        time_window: opsec.time_window || null,
      },
      // Phase B: surface configured-but-disabled state so the dashboard can
      // render an "OPSEC INERT" badge instead of letting operators assume
      // the configured ceiling is enforced.
      opsec_status: opsecStatus,
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

      if (typeof body.enabled === 'boolean') {
        opsec.enabled = body.enabled;
        changed = true;
      }
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
    res.end(JSON.stringify({
      ...config,
      config_path: this.configPath,
      state_path: this.engine.getStateFilePath(),
    }));
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
      const b = body as Record<string, unknown>;
      delete b.id;
      delete b.created_at;
      // 0.5: strict zod parse on the OPSEC subtree. Unknown keys (e.g. the
      // historical client drift where SettingsPanel sent
      // `approval_timeout_seconds` and `time_window: {start, end}`) now
      // surface as a 400 instead of being silently dropped.
      if (b.opsec !== undefined && b.opsec !== null) {
        const opsecParse = opsecPartialUpdateSchema.safeParse(b.opsec);
        if (!opsecParse.success) {
          const issues = opsecParse.error.issues.map(i =>
            i.code === 'unrecognized_keys'
              ? `unknown opsec key(s): ${(i as unknown as { keys?: string[] }).keys?.join(', ') ?? ''}`
              : `${i.path.join('.')}: ${i.message}`,
          );
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `OPSEC validation failed: ${issues.join('; ')}`, issues }));
          return;
        }
      }
      // Strict parse on the operator_policy subtree (same rationale as OPSEC):
      // a malformed approval rule or dispatch limit surfaces as a 400 instead of
      // being silently stored and ignored by the engine.
      if (b.operator_policy !== undefined && b.operator_policy !== null) {
        const policyParse = operatorPolicyUpdateSchema.safeParse(b.operator_policy);
        if (!policyParse.success) {
          const issues = policyParse.error.issues.map(i =>
            i.code === 'unrecognized_keys'
              ? `unknown operator_policy key(s): ${(i as unknown as { keys?: string[] }).keys?.join(', ') ?? ''}`
              : `${i.path.join('.')}: ${i.message}`,
          );
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `operator_policy validation failed: ${issues.join('; ')}`, issues }));
          return;
        }
      }
      try {
        const updated = this.engine.updateConfig(b);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ updated: true, config: updated }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
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
      try {
        // 0.4: route cidrs/domains/exclusions through engine.updateScope so
        // the safety pipeline (CIDR/IPv6 validation, cold→hot promotion,
        // inference re-runs, scope_updated audit event) actually fires.
        // The dashboard sends a Partial<ScopeConfig> "replace" payload; we
        // diff it against the current scope to derive the add/remove deltas
        // updateScope expects.
        const incoming = body as Record<string, unknown>;
        const current = this.engine.getConfig().scope;
        const arr = (v: unknown): string[] | undefined =>
          Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : undefined;
        const incomingCidrs = arr(incoming.cidrs);
        const incomingDomains = arr(incoming.domains);
        const incomingExclusions = arr(incoming.exclusions);

        const diff = (next: string[] | undefined, prev: string[]): { add: string[]; remove: string[] } => {
          if (!next) return { add: [], remove: [] };
          const nextSet = new Set(next);
          const prevSet = new Set(prev);
          return {
            add: next.filter(x => !prevSet.has(x)),
            remove: prev.filter(x => !nextSet.has(x)),
          };
        };
        const cidrsDiff = diff(incomingCidrs, current.cidrs);
        const domainsDiff = diff(incomingDomains, current.domains);
        const exclusionsDiff = diff(incomingExclusions, current.exclusions);

        const hasNetworkChanges =
          cidrsDiff.add.length + cidrsDiff.remove.length +
          domainsDiff.add.length + domainsDiff.remove.length +
          exclusionsDiff.add.length + exclusionsDiff.remove.length > 0;

        let scopeResult: ReturnType<typeof this.engine.updateScope> | undefined;
        if (hasNetworkChanges) {
          scopeResult = this.engine.updateScope({
            add_cidrs: cidrsDiff.add,
            remove_cidrs: cidrsDiff.remove,
            add_domains: domainsDiff.add,
            remove_domains: domainsDiff.remove,
            add_exclusions: exclusionsDiff.add,
            remove_exclusions: exclusionsDiff.remove,
            reason: 'dashboard scope update',
          });
          if (!scopeResult.applied) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: scopeResult.errors.join('; '), errors: scopeResult.errors }));
            return;
          }
        }

        // Non-network scope fields (hosts, url_patterns, aws_accounts, etc.)
        // are not handled by updateScope; route them through updateConfig's
        // partial-merge path. Only forward the keys the caller actually sent.
        const passthrough: Record<string, unknown> = {};
        for (const k of ['hosts', 'url_patterns', 'aws_accounts', 'azure_subscriptions', 'gcp_projects'] as const) {
          if (Array.isArray(incoming[k])) passthrough[k] = incoming[k];
        }
        if (Object.keys(passthrough).length > 0) {
          this.engine.updateConfig({ scope: passthrough });
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          updated: true,
          scope: this.engine.getConfig().scope,
          ...(scopeResult ? {
            applied: scopeResult.applied,
            affected_node_count: scopeResult.affected_node_count,
          } : {}),
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // Read-only dry-run for the dashboard "Add Targets" flow: accepts the SAME
  // full-replacement Partial<ScopeConfig> body as PATCH /api/config/scope,
  // diffs it the same way, then reports what WOULD change via
  // engine.previewScopeChange (no persist, no audit, no mutation). Lets the
  // operator see how many graph nodes enter/leave scope before committing.
  private handlePreviewScope(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      try {
        // Same parse + diff as handleUpdateScope so the preview matches the
        // commit exactly (only network fields — cidrs/domains/exclusions —
        // participate in scope analysis; passthrough fields have no preview).
        const incoming = body as Record<string, unknown>;
        const current = this.engine.getConfig().scope;
        const arr = (v: unknown): string[] | undefined =>
          Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : undefined;
        const diff = (next: string[] | undefined, prev: string[]): { add: string[]; remove: string[] } => {
          if (!next) return { add: [], remove: [] };
          const nextSet = new Set(next);
          const prevSet = new Set(prev);
          return { add: next.filter(x => !prevSet.has(x)), remove: prev.filter(x => !nextSet.has(x)) };
        };
        const cidrsDiff = diff(arr(incoming.cidrs), current.cidrs);
        const domainsDiff = diff(arr(incoming.domains), current.domains);
        const exclusionsDiff = diff(arr(incoming.exclusions), current.exclusions);

        const preview = this.engine.previewScopeChange({
          add_cidrs: cidrsDiff.add,
          remove_cidrs: cidrsDiff.remove,
          add_domains: domainsDiff.add,
          remove_domains: domainsDiff.remove,
          add_exclusions: exclusionsDiff.add,
          remove_exclusions: exclusionsDiff.remove,
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ...preview,
          added: { cidrs: cidrsDiff.add, domains: domainsDiff.add, exclusions: exclusionsDiff.add },
          removed: { cidrs: cidrsDiff.remove, domains: domainsDiff.remove, exclusions: exclusionsDiff.remove },
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
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
      const campaignId = typeof b.campaign_id === 'string' ? b.campaign_id : undefined;
      const frontierItemId = typeof b.frontier_item_id === 'string' ? b.frontier_item_id : undefined;
      // Agent type: an explicit archetype expands to {role, backend, skill,
      // objective}; an explicit skill still overrides the archetype default.
      // Fail closed — an unknown explicit archetype must not silently become the
      // full-surface default agent.
      if (typeof b.archetype === 'string' && !isArchetypeId(b.archetype)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Unknown agent type: ${b.archetype}` }));
        return;
      }
      const explicitArch = typeof b.archetype === 'string' ? getArchetype(b.archetype) : undefined;
      // No explicit agent type → auto-select one from the seed node type rather
      // than silently using the full-surface default (mirrors quick-deploy + the
      // dispatch tools). role/backend expansion stays on the explicit path.
      const autoArchetype = recommendArchetype({ nodeType: targetNodeIds[0] ? this.engine.getNode(targetNodeIds[0])?.type : undefined });
      const skill = typeof b.skill === 'string' ? b.skill : explicitArch?.defaultSkill;
      const objective = typeof b.objective === 'string' ? b.objective : undefined;

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
        // 'running' so the runners actually pick it up — both drain loops skip
        // non-running tasks, so a 'pending' dispatch silently never executes
        // (matches the planner/cve self-dispatch precedent).
        status: 'running' as const,
        subgraph_node_ids: targetNodeIds,
        skill,
        campaign_id: campaignId,
        frontier_item_id: frontierItemId,
        ...(explicitArch
          ? { archetype: explicitArch.id, role: explicitArch.role, backend: explicitArch.backend }
          : { archetype: autoArchetype }),
        ...(objective ? { objective } : {}),
      };

      // F2: registerAgent may refuse on frontier-lease conflict.
      // Returning 201 with { dispatched: true } when the task was never
      // inserted left the dashboard claiming work that didn't exist.
      const reg = this.engine.registerAgent(task);
      if (reg.cap_exceeded) {
        // 429 (not 409): the dispatch cap is a deferral — retry when a slot frees.
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          dispatched: false,
          reason: 'dispatch_cap_exceeded',
          cap_scope: reg.cap_exceeded.scope,
          cap_key: reg.cap_exceeded.key,
          limit: reg.cap_exceeded.limit,
          current: reg.cap_exceeded.current,
        }));
        return;
      }
      if (!reg.ok) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          dispatched: false,
          reason: 'frontier_lease_conflict',
          existing_task_id: reg.lease_conflict?.existing_task_id,
          existing_agent_id: reg.lease_conflict?.existing_agent_id,
        }));
        return;
      }

      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ dispatched: true, task }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // ---- Phase 5c: ad-hoc real-time deploy ----
  // Paste an IP/CIDR/domain → add it to scope (canonical updateScope, so
  // target-facing actions stay in-scope) and dispatch the recommended (or a
  // chosen) agent type at it, in one step. No engagement-setup ritual; the
  // active engagement's scope is the substrate.
  private handleQuickDeploy(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      const b = body as Record<string, unknown>;
      const targetRaw = typeof b.target === 'string' ? b.target.trim() : '';
      if (!targetRaw) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'target (IP, CIDR, or domain) is required' }));
        return;
      }
      // Fail closed on an unknown explicit agent type, before touching scope.
      if (typeof b.archetype === 'string' && !isArchetypeId(b.archetype)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Unknown agent type: ${b.archetype}` }));
        return;
      }
      // Same classification as the `scan` command + the dashboard Add-Targets
      // parser (IPv4 CIDR / IP→/32 / domain; IPv6 + junk rejected).
      const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
      const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
      const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i;
      const add_cidrs: string[] = [];
      const add_domains: string[] = [];
      for (const tok of targetRaw.split(/[\s,]+/).filter(Boolean)) {
        if (CIDR_RE.test(tok)) add_cidrs.push(tok);
        else if (IP_RE.test(tok)) add_cidrs.push(`${tok}/32`);
        else if (DOMAIN_RE.test(tok)) add_domains.push(tok.toLowerCase());
      }
      if (add_cidrs.length === 0 && add_domains.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `no valid IPv4/CIDR/domain target in "${targetRaw}"` }));
        return;
      }

      const scopeResult = this.engine.updateScope({ add_cidrs, add_domains, reason: 'quick-deploy' });
      if (!scopeResult.applied) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: scopeResult.errors.join('; ') || 'scope update failed', errors: scopeResult.errors }));
        return;
      }

      // Recommend recon for a raw target unless the operator chose a type.
      const arch = getArchetype(typeof b.archetype === 'string' ? b.archetype : recommendArchetype({ rawTarget: true }));
      const objective = (arch.defaultObjective || 'Investigate {target}.').replace('{target}', targetRaw);
      const taskId = randomUUID();
      const task = {
        id: taskId,
        agent_id: `quick-${taskId.slice(0, 8)}`,
        assigned_at: new Date().toISOString(),
        status: 'running' as const, // so the runner picks it up (see handleAgentDispatch)
        subgraph_node_ids: [] as string[],
        skill: arch.defaultSkill,
        archetype: arch.id,
        role: arch.role,
        backend: arch.backend,
        objective,
      };
      const reg = this.engine.registerAgent(task);
      if (reg.cap_exceeded) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          dispatched: false,
          reason: 'dispatch_cap_exceeded',
          cap_scope: reg.cap_exceeded.scope,
          cap_key: reg.cap_exceeded.key,
          limit: reg.cap_exceeded.limit,
          current: reg.cap_exceeded.current,
        }));
        return;
      }
      if (!reg.ok) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ dispatched: false, reason: 'dispatch_refused' }));
        return;
      }

      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        dispatched: true,
        task,
        archetype: arch.id,
        scope: { added_cidrs: add_cidrs, added_domains: add_domains, affected_node_count: scopeResult.affected_node_count },
      }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // The agent-type catalog for the dashboard Deploy picker (read-only).
  private serveAgentArchetypes(res: ServerResponse): void {
    const archetypes = listArchetypes().map(a => ({
      id: a.id, label: a.label, description: a.description,
      role: a.role, defaultSkill: a.defaultSkill, suitableFor: a.suitableFor,
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ archetypes }));
  }

  // ---- NL operator command (Phase 3A) ----
  // Two-phase, like update_scope: a command is first interpreted into a plan
  // (preview, no mutation); the operator then confirms the plan_id to execute.
  // Nothing mutates without an explicit confirm.
  private commandPlans = new Map<string, { ops: OperatorOp[]; command: string; created_at: number }>();

  private pruneCommandPlans(): void {
    const cutoff = Date.now() - 10 * 60_000; // 10 min TTL
    for (const [id, p] of this.commandPlans) if (p.created_at < cutoff) this.commandPlans.delete(id);
  }

  private buildInterpreterState(): InterpreterState {
    return {
      tasks: this.engine.getAgentTasks().map(t => ({ id: t.id, agent_id: t.agent_id, status: t.status, skill: t.skill })),
      pendingActionIds: this.engine.getPendingActionQueue().getPending().map(a => a.action_id),
    };
  }

  /**
   * 3A.2: register a read-only headless 'planner' sub-agent to translate a
   * free-form command (the grammar couldn't resolve) into a proposed plan. The
   * planner carries the command + a snapshot of steerable state as its objective,
   * reasons over the graph, and submits ops via propose_plan for the operator to
   * confirm. No frontier_item_id → no lease conflict. Returns the task id, or
   * null if the headless runtime isn't available.
   */
  private dispatchPlanner(command: string, state: InterpreterState): string | null {
    // No task-execution service attached (e.g. a dashboard-only deployment) or
    // no /mcp endpoint (stdio mode) → headless is unavailable; report it instead
    // of registering a planner task that can never launch.
    if (!this.taskExecution || !this.taskExecution.isHeadlessAvailable()) return null;
    const taskId = randomUUID();
    const reg = this.engine.registerAgent({
      id: taskId,
      agent_id: `planner-${taskId.slice(0, 8)}`,
      assigned_at: new Date().toISOString(),
      status: 'running',
      subgraph_node_ids: [],
      backend: 'headless_mcp',
      role: 'planner',
      skill: 'operator-planner',
      objective: buildPlannerObjective(command, state),
    });
    return reg.ok ? taskId : null;
  }

  private serveProposedPlans(res: ServerResponse): void {
    const plans = this.engine.getProposedPlanStore().getOpen();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ plans }));
  }

  // ---- Agent→operator question inbox (Phase 3D) ----
  private serveAgentQueries(res: ServerResponse): void {
    const queries = this.engine.getAgentQueryStore().getOpen();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ queries }));
  }

  private handleAnswerAgentQuery(queryId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const b = (body ?? {}) as Record<string, unknown>;
      const answer = typeof b.answer === 'string' ? b.answer.trim() : '';
      if (!answer) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'answer (non-empty string) is required' }));
        return;
      }
      // If the asking agent is already gone (reaped/timed out), don't answer into
      // the void — terminal transitions expire a task's queries, but guard the race.
      const existing = this.engine.getAgentQueryStore().get(queryId);
      if (existing?.task_id) {
        const task = this.engine.getTask(existing.task_id);
        if (!task || task.status !== 'running') {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'the asking agent is no longer running — answer would not be delivered' }));
          return;
        }
      }
      const resolved = this.engine.getAgentQueryStore().answer(queryId, answer);
      if (!resolved) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'question not found or already answered/expired' }));
        return;
      }
      // Surface the answer in the console; the agent picks it up on its next heartbeat.
      this.engine.logActionEvent({
        description: `Operator answered agent question: ${resolved.question}`,
        event_type: 'operator_command',
        category: 'system',
        source_kind: 'dashboard',
        result_classification: 'neutral',
        linked_agent_task_id: resolved.task_id,
        details: { reason: 'agent_query_answered', source: 'dashboard', query_id: queryId, question: resolved.question, answer },
      });
      this.engine.persist();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, query: resolved }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  /**
   * Answer-once fan-out: resolve a cluster of identical questions (asked by
   * multiple agents) with a single answer. Each query is only answered if its
   * asking agent is still running — same guard as the single-answer path,
   * applied per member so a partial fan-out (some agents already gone) is fine.
   */
  private handleAnswerAgentQueryBatch(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const b = (body ?? {}) as Record<string, unknown>;
      const answer = typeof b.answer === 'string' ? b.answer.trim() : '';
      const queryIds = Array.isArray(b.query_ids)
        ? b.query_ids.filter((x): x is string => typeof x === 'string')
        : [];
      if (!answer) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'answer (non-empty string) is required' }));
        return;
      }
      if (queryIds.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'query_ids (non-empty string array) is required' }));
        return;
      }
      const store = this.engine.getAgentQueryStore();
      // Only fan out to queries whose asking agent is still running.
      const deliverable = queryIds.filter(id => {
        const existing = store.get(id);
        if (!existing) return false;
        if (!existing.task_id) return true;
        const task = this.engine.getTask(existing.task_id);
        return !!task && task.status === 'running';
      });
      const resolved = store.answerMany(deliverable, answer);
      if (resolved.length === 0) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'no answerable questions — all unknown, already answered, or their agents are gone' }));
        return;
      }
      this.engine.logActionEvent({
        description: `Operator answered ${resolved.length} clustered agent question(s): ${resolved[0].question}`,
        event_type: 'operator_command',
        category: 'system',
        source_kind: 'dashboard',
        result_classification: 'neutral',
        details: {
          reason: 'agent_query_answered_batch',
          source: 'dashboard',
          query_ids: resolved.map(r => r.query_id),
          question: resolved[0].question,
          answer,
          count: resolved.length,
        },
      });
      this.engine.persist();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, answered: resolved.length, queries: resolved }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleCommand(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const b = (body ?? {}) as Record<string, unknown>;
      this.pruneCommandPlans();

      // Dismiss a planner-proposed plan without executing it.
      if (b.deny === true && typeof b.plan_id === 'string') {
        const denied = this.engine.getProposedPlanStore().resolve(b.plan_id, 'denied');
        res.writeHead(denied ? 200 : 404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(denied ? { denied: true, plan_id: b.plan_id } : { error: 'plan not found or already resolved' }));
        return;
      }

      // Phase 2 of the flow: confirm + execute a previously-previewed plan. The
      // plan_id may be a grammar plan (commandPlans) or a planner-proposed plan
      // (the shared ProposedPlanStore) — both execute through the same path.
      if (b.confirm === true && typeof b.plan_id === 'string') {
        const grammarPlan = this.commandPlans.get(b.plan_id);
        const proposed = grammarPlan ? null : this.engine.getProposedPlanStore().resolve(b.plan_id, 'confirmed');
        const plan = grammarPlan ?? (proposed ? { ops: proposed.ops, command: proposed.command } : null);
        if (!plan) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'plan not found or expired — re-issue the command' }));
          return;
        }
        if (grammarPlan) this.commandPlans.delete(b.plan_id);
        const results = executeOps(this.engine, plan.ops, 'operator');
        this.engine.logActionEvent({
          description: `Operator command executed: ${plan.command || '(planner plan)'}`,
          event_type: 'operator_command',
          category: 'system',
          // source:'dashboard' makes this surface as an operator command card in
          // the console (inferSourceKind), not an anonymous system warning.
          source_kind: 'dashboard',
          result_classification: results.every(r => r.ok) ? 'success' : 'partial',
          details: { reason: 'operator_command', source: 'dashboard', command: plan.command, planner: !!proposed, results },
        });
        this.engine.persist();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ executed: true, results }));
        return;
      }

      // Phase 1 of the flow: interpret → preview plan (no mutation).
      const command = typeof b.command === 'string' ? b.command : '';
      if (!command.trim()) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'command (string) is required' }));
        return;
      }
      const state = this.buildInterpreterState();
      const interp = interpretCommand(command, state);
      let plan_id: string | undefined;
      if (interp.ops.length > 0) {
        plan_id = randomUUID();
        this.commandPlans.set(plan_id, { ops: interp.ops, command, created_at: Date.now() });
      }

      // The grammar punted entirely — hand the free-form command to a headless
      // planner (3A.2). It proposes ops asynchronously; the operator confirms
      // the proposed plan via the same confirm path (polling GET /api/plans).
      const needsPlanner = interp.unresolved.length > 0 && interp.ops.length === 0;
      let planner_task_id: string | undefined;
      let planner_available = true;
      if (needsPlanner) {
        const tid = this.dispatchPlanner(command, state);
        if (tid) planner_task_id = tid;
        else planner_available = false;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        plan_id,
        ops: interp.ops,
        summary: interp.summary,
        unresolved: interp.unresolved,
        needs_planner: needsPlanner,
        // When a planner was dispatched, the UI polls GET /api/plans for the
        // proposed plan. planner_available=false means stdio mode (no daemon).
        planner_task_id,
        planner_available: needsPlanner ? planner_available : undefined,
      }));
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

  /**
   * Build the EngagementState payload that the dashboard frontend
   * consumes via /api/state and the WebSocket full_state / graph_update
   * pushes. Wraps engine.getState() and folds in dashboard-server-owned
   * data (notably the SessionManager's session list) that the engine
   * itself doesn't track. All four frontend-facing call sites must use
   * this helper rather than calling engine.getState() directly so the
   * payload stays consistent.
   */
  private enrichCampaigns(campaigns: Campaign[] = this.engine.listCampaigns()): DashboardCampaign[] {
    const allAgents = this.engine.getAllAgents();
    // The global noise context (budget remaining, recommended approach, time
    // window) is the same for every campaign — compute it once. Only the
    // per-campaign noise contribution differs, via the tracker's accessor.
    const opsecCtx = this.engine.getOpsecContext();
    const maxNoise = this.engine.getConfig().opsec.max_noise;
    const tracker = this.engine.getOpsecTracker();
    return campaigns.map(c => {
      const agents = allAgents.filter(a => a.campaign_id === c.id);
      const completed = c.progress?.completed ?? 0;
      const total = c.progress?.total ?? c.items.length;
      const completionPct = total > 0 ? Math.round((completed / total) * 100) : 0;
      const runningAgents = agents.filter(a => a.status === 'running').length;
      return {
        ...c,
        agent_count: agents.length,
        running_agents: runningAgents,
        agents_total: agents.length,
        agents_active: runningAgents,
        completion_pct: completionPct,
        findings_count: c.findings?.length ?? 0,
        opsec: {
          global_noise_spent: tracker.getCampaignNoise(c.id),
          noise_budget_remaining: opsecCtx.noise_budget_remaining,
          max_noise: maxNoise,
          recommended_approach: opsecCtx.recommended_approach,
          // Defensive signals are tracked globally (and per host/domain), not
          // per campaign — leave empty here so the per-campaign gauge focuses
          // on this campaign's noise contribution, not global alarms.
          defensive_signals: [],
          time_window_remaining_hours: opsecCtx.time_window_remaining_hours,
        },
      };
    });
  }

  private buildFrontendState(): ReturnType<GraphEngine['getState']> & {
    sessions: ReturnType<NonNullable<SessionManager>['list']>;
    pending_actions: PendingAction[];
    campaigns: DashboardCampaign[];
  } {
    const state = this.engine.getState();
    const sessions = this.sessionManager?.list() ?? [];
    const pending_actions = this.getDashboardApprovalRecords()
      .filter(action => action.status === 'pending') as PendingAction[];
    const campaigns = this.enrichCampaigns();
    return { ...state, sessions, pending_actions, campaigns };
  }

  private serveState(res: ServerResponse): void {
    const state = this.buildFrontendState();
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
    // order=asc|desc; default desc so `?limit=N` returns the *most recent* N
    // entries (operators care about latest activity, not oldest).
    const orderParam = (params.get('order') || 'desc').toLowerCase();
    const order: 'asc' | 'desc' = orderParam === 'asc' ? 'asc' : 'desc';

    let entries = this.engine.getFullHistory()
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

    if (after) {
      entries = entries.filter(e => e.timestamp > after);
    }
    if (before) {
      entries = entries.filter(e => e.timestamp < before);
    }

    const total = entries.length;

    if (limit && limit > 0) {
      // Take the last `limit` entries (most recent in ascending order).
      entries = entries.slice(-limit);
    }
    if (order === 'desc') {
      entries = entries.slice().reverse();
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ entries, total, order }));
  }

  private serveGraph(res: ServerResponse): void {
    const graph = this.engine.exportGraph();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(graph));
  }

  private serveDecisionLog(url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    const query: NonNullable<Parameters<GraphEngine['getDecisionLog']>[0]> = {};
    const actionId = params.get('action_id') || undefined;
    const frontierItemId = params.get('frontier_item_id') || undefined;
    const agentId = params.get('agent_id') || undefined;
    const outcome = params.get('outcome') || undefined;
    const rawLimit = params.get('limit') || undefined;

    if (actionId) query.action_id = actionId;
    if (frontierItemId) query.frontier_item_id = frontierItemId;
    if (agentId) query.agent_id = agentId;
    if (outcome && ['completed', 'failed', 'denied', 'dropped', 'open'].includes(outcome)) {
      query.outcome = outcome as NonNullable<typeof query.outcome>;
    }
    if (rawLimit) {
      const limit = parseInt(rawLimit, 10);
      if (Number.isFinite(limit) && limit >= 1) query.limit = limit;
    }

    const decisions = this.engine.getDecisionLog(query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ decisions, total: decisions.length }));
  }

  private serveActionExplanation(actionId: string, res: ServerResponse): void {
    const explanation = this.engine.explainAction(actionId);
    res.writeHead(explanation.found ? 200 : 404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(explanation));
  }

  /** Clamp a `max_bytes` query param to a safe per-request read window. */
  private clampReadBytes(raw: string | null): number {
    const DEFAULT = 64 * 1024;
    const MAX = 1024 * 1024;
    const n = raw !== null ? parseInt(raw, 10) : NaN;
    if (!Number.isFinite(n) || n <= 0) return DEFAULT;
    return Math.min(n, MAX);
  }

  /**
   * Raw stdout/stderr for an action, for the Analysis workspace assessment view.
   * The evidence manifest does not distinguish streams, so the authoritative
   * stdout/stderr evidence ids + capture metadata come from the action's
   * terminal lifecycle event (action_completed / action_failed). Head-by-default:
   * we return a bounded slice and flag `head_truncated` when the blob is larger.
   */
  private serveActionOutput(actionId: string, url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    const maxBytes = this.clampReadBytes(params.get('max_bytes'));
    const store = this.engine.getEvidenceStore();

    const events = this.engine.getFullHistory().filter(e => e.action_id === actionId);
    if (events.length === 0) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `No action found for ${actionId}` }));
      return;
    }
    const terminal = [...events].reverse().find(
      e => e.event_type === 'action_completed' || e.event_type === 'action_failed',
    );
    const started = events.find(e => e.event_type === 'action_started');
    const meta = terminal ?? started ?? events[events.length - 1];
    // Prefer the terminal event's details; fall back to action_started so a
    // still-running action still reports command/binary/invoking_tool.
    const d = ((terminal ?? started)?.details ?? {}) as Record<string, unknown>;

    const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
    const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

    const captureErr = d.evidence_capture_error as { stdout?: string; stderr?: string } | undefined;
    const readStream = (
      evId: unknown, truncatedFlag: unknown, totalBytes: unknown, droppedBytes: unknown, streamErr: string | undefined,
    ) => {
      const id = str(evId);
      const total = num(totalBytes) ?? 0;
      const dropped = num(droppedBytes) ?? 0;
      if (!id) {
        // No evidence id. Distinguish "capture failed but bytes existed" from
        // "genuinely no output" so the UI doesn't render a failure as silence.
        if (streamErr || total > 0) {
          return {
            evidence_id: null, text: '', total_bytes: total,
            truncated: Boolean(truncatedFlag), head_truncated: false,
            dropped_bytes: dropped, missing: true, capture_failed: Boolean(streamErr),
          };
        }
        return null;
      }
      const head = store.getRawOutputHead(id, maxBytes);
      if (!head) {
        return {
          evidence_id: id, text: '', total_bytes: total,
          truncated: Boolean(truncatedFlag), head_truncated: false,
          dropped_bytes: dropped, missing: true, capture_failed: Boolean(streamErr),
        };
      }
      return {
        evidence_id: id, text: head.text, total_bytes: head.total_bytes,
        truncated: Boolean(truncatedFlag), head_truncated: head.truncated,
        dropped_bytes: dropped,
      };
    };

    const findingIds = Array.from(new Set(events.flatMap(e => e.linked_finding_ids ?? [])));
    const payload = {
      action_id: actionId,
      status: terminal
        ? (terminal.result_classification ?? (terminal.event_type === 'action_failed' ? 'failure' : 'success'))
        : 'running',
      event_type: meta.event_type,
      timestamp: meta.timestamp,
      tool_name: meta.tool_name ?? str(d.invoking_tool),
      command_repr: meta.command_repr ?? str(d.command),
      technique: meta.technique,
      invoking_tool: str(d.invoking_tool),
      exit_code: num(d.exit_code),
      signal: str(d.signal),
      duration_ms: num(d.duration_ms),
      timed_out: typeof d.timed_out === 'boolean' ? d.timed_out : undefined,
      target_node_ids: meta.target_node_ids,
      target_ips: meta.target_ips,
      target_cidrs: meta.target_cidrs,
      agent_id: meta.agent_id,
      frontier_item_id: meta.frontier_item_id,
      linked_finding_ids: findingIds,
      max_bytes: maxBytes,
      stdout: readStream(d.stdout_evidence_id, d.stdout_truncated, d.stdout_total_bytes, d.stdout_dropped_bytes, captureErr?.stdout),
      stderr: readStream(d.stderr_evidence_id, d.stderr_truncated, d.stderr_total_bytes, d.stderr_dropped_bytes, captureErr?.stderr),
      capture_error: d.evidence_capture_error ?? undefined,
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  /** Bounded, paged raw-evidence read by evidence_id or content_hash. */
  private serveEvidenceRaw(evidenceId: string, url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    const maxBytes = this.clampReadBytes(params.get('max_bytes'));
    const rawOffset = params.get('offset');
    const offset = rawOffset !== null ? Math.max(0, parseInt(rawOffset, 10) || 0) : 0;
    const store = this.engine.getEvidenceStore();

    const slice = store.getRawOutputSlice(evidenceId, offset, maxBytes);
    if (!slice) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `No evidence found for ${evidenceId}` }));
      return;
    }
    const record = store.getRecord(evidenceId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      evidence_id: store.resolveKey(evidenceId),
      ...slice,
      evidence_type: record?.evidence_type,
      capture_error: record?.capture_error,
      action_id: record?.action_id,
      finding_id: record?.finding_id,
    }));
  }

  /**
   * Re-parse an action's captured output with a chosen parser, then preview
   * (ingest:false, default) or promote (ingest:true) the result into the graph.
   * Routes through the SAME parse→ingest pipeline as the parse_output tool, so
   * validation/event-logging/graph mutation stay identical.
   */
  private handleActionReparse(actionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    const JSON_HEADERS = { 'Content-Type': 'application/json' };
    this.readJsonBody(req).then(body => {
      const toolName = typeof body?.tool_name === 'string' ? body.tool_name.trim()
        : (typeof body?.tool === 'string' ? body.tool.trim() : '');
      if (!toolName) {
        res.writeHead(400, JSON_HEADERS);
        res.end(JSON.stringify({ error: 'tool_name is required' }));
        return;
      }

      const store = this.engine.getEvidenceStore();
      // Resolve which blob to re-parse: explicit evidence_id, else the action's
      // stdout (then stderr) evidence from its terminal lifecycle event.
      let evidenceId: string | undefined = typeof body?.evidence_id === 'string' ? body.evidence_id : undefined;
      if (!evidenceId) {
        const events = this.engine.getFullHistory().filter(e => e.action_id === actionId);
        const terminal = [...events].reverse().find(
          e => e.event_type === 'action_completed' || e.event_type === 'action_failed',
        );
        const d = (terminal?.details ?? {}) as Record<string, unknown>;
        const sid = typeof d.stdout_evidence_id === 'string' ? d.stdout_evidence_id : undefined;
        const eid = typeof d.stderr_evidence_id === 'string' ? d.stderr_evidence_id : undefined;
        evidenceId = sid || eid;
      }
      if (!evidenceId) {
        res.writeHead(404, JSON_HEADERS);
        res.end(JSON.stringify({ error: `No evidence to re-parse for action ${actionId}` }));
        return;
      }

      if (!store.resolveKey(evidenceId)) {
        res.writeHead(404, JSON_HEADERS);
        res.end(JSON.stringify({ error: `Evidence not found: ${evidenceId}` }));
        return;
      }
      const REPARSE_MAX_BYTES = 16 * 1024 * 1024;
      const raw = store.getRawOutput(evidenceId, { max_bytes: REPARSE_MAX_BYTES });
      if (raw === null) {
        // getRawOutput returns null for an oversized blob OR a missing `.raw`
        // file (e.g. content-only evidence). Probe the file size to tell them
        // apart rather than always claiming "too large".
        const head = store.getRawOutputHead(evidenceId, 1);
        if (head && head.total_bytes > REPARSE_MAX_BYTES) {
          res.writeHead(413, JSON_HEADERS);
          res.end(JSON.stringify({ error: `Evidence too large to re-parse (> ${REPARSE_MAX_BYTES} bytes)` }));
          return;
        }
        res.writeHead(404, JSON_HEADERS);
        res.end(JSON.stringify({ error: `Evidence has no raw output to re-parse: ${evidenceId}` }));
        return;
      }

      const ingest = body?.ingest === true; // preview by default — promote is explicit
      const context = (body?.context && typeof body.context === 'object') ? body.context : undefined;
      const result = parseAndMaybeIngest(this.engine, {
        tool_name: toolName,
        outputText: raw,
        action_id: actionId,
        ingest,
        context,
        agent_id: 'operator',
      });
      res.writeHead(200, JSON_HEADERS);
      res.end(JSON.stringify({ ...result, evidence_id: store.resolveKey(evidenceId) }));
    }).catch(err => {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(400, JSON_HEADERS);
      res.end(JSON.stringify({ error: message }));
    });
  }

  private serveTimeline(url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    const query: NonNullable<Parameters<GraphEngine['getTimeline']>[0]> = {};
    const entityId = params.get('entity_id') || undefined;
    const kind = params.get('kind') || undefined;
    const since = params.get('since') || undefined;
    const at = params.get('at') || undefined;
    const rawLimit = params.get('limit') || undefined;

    if (entityId) query.entity_id = entityId;
    if (kind === 'node' || kind === 'edge') query.kind = kind;
    if (since && !isNaN(Date.parse(since))) query.since = since;
    if (at && !isNaN(Date.parse(at))) query.at = at;
    if (rawLimit) {
      const limit = parseInt(rawLimit, 10);
      if (Number.isFinite(limit) && limit >= 1) query.limit = limit;
    }

    const entries = this.engine.getTimeline(query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ entries, total: entries.length }));
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

  private serveSessionBuffer(sessionId: string, url: string, res: ServerResponse): void {
    if (!this.sessionManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session manager not available' }));
      return;
    }

    const params = new URL(url, 'http://localhost').searchParams;
    const rawFrom = params.get('from');
    const rawTail = params.get('tail_bytes');
    const from = rawFrom !== null ? parseInt(rawFrom, 10) : undefined;
    const tailBytes = rawTail !== null ? Math.min(Math.max(parseInt(rawTail, 10) || 4096, 0), 65536) : undefined;

    try {
      const result = this.sessionManager.read(
        sessionId,
        Number.isFinite(from) ? from : undefined,
        tailBytes,
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const notFound = /not found/i.test(message);
      res.writeHead(notFound ? 404 : 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
  }

  private handleSessionClose(sessionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.sessionManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session manager not available' }));
      return;
    }
    try {
      const result = this.sessionManager.close(sessionId, 'dashboard', true);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const notFound = /not found/i.test(message);
      res.writeHead(notFound ? 404 : 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
  }

  private handleSessionUpdate(sessionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.sessionManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session manager not available' }));
      return;
    }
    this.readJsonBody(req).then(body => {
      const updates: { title?: string; notes?: string } = {};
      if (typeof body?.title === 'string') updates.title = body.title;
      if (typeof body?.notes === 'string') updates.notes = body.notes;
      const metadata = this.sessionManager!.update(sessionId, updates, 'dashboard', true);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ metadata }));
    }).catch((err) => {
      const message = err instanceof Error ? err.message : String(err);
      const notFound = /not found/i.test(message);
      res.writeHead(notFound ? 404 : 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    });
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

    // Derive each agent's most recent activity ("current action") + last finding
    // in ONE pass over history, so the roster can show "doing: …" live without
    // N×history scans. 3C / "see everything".
    //   - current_action reflects the agent's WORK, so skip operator/runtime
    //     bookkeeping (directives, launch/exit warnings, registration) and
    //     heartbeats — otherwise "doing:" reads "Operator directive: pause".
    //   - keyed by the precise task id when present; agent_id is a fallback only
    //     when exactly one running task owns that label, so two tasks sharing an
    //     agent_id never cross-bleed each other's activity.
    const latestByKey = new Map<string, { description: string; event_type?: string; timestamp: string }>();
    const lastFindingAtByKey = new Map<string, string>();
    const BOOKKEEPING_EVENTS = new Set(['instrumentation_warning', 'operator_command', 'agent_registered', 'agent_updated', 'heartbeat']);
    for (const e of this.engine.getFullHistory()) {
      const keys = [e.agent_id, e.linked_agent_task_id, (e.details as { task_id?: string } | undefined)?.task_id].filter((k): k is string => !!k);
      const isFinding = e.category === 'finding' || (e.event_type ?? '').startsWith('finding') || e.event_type === 'parse_output';
      const isBookkeeping = e.category === 'system' || BOOKKEEPING_EVENTS.has(e.event_type ?? '');
      for (const k of keys) {
        if (!isBookkeeping) {
          const prev = latestByKey.get(k);
          if (!prev || e.timestamp > prev.timestamp) latestByKey.set(k, { description: e.description, event_type: e.event_type, timestamp: e.timestamp });
        }
        if (isFinding) {
          const pf = lastFindingAtByKey.get(k);
          if (!pf || e.timestamp > pf) lastFindingAtByKey.set(k, e.timestamp);
        }
      }
    }
    // Count running tasks per agent_id so a shared label only attributes activity
    // when it's unambiguous (exactly one running owner).
    const runningPerAgentId = new Map<string, number>();
    for (const a of agents) {
      if (a.status === 'running') runningPerAgentId.set(a.agent_id, (runningPerAgentId.get(a.agent_id) ?? 0) + 1);
    }
    const resolveByKeys = <V>(m: Map<string, V>, a: { id: string; agent_id: string }): V | undefined =>
      m.get(a.id) ?? (runningPerAgentId.get(a.agent_id) === 1 ? m.get(a.agent_id) : undefined);

    const enriched = agents.map(a => {
      const latest = a.status === 'running' ? resolveByKeys(latestByKey, a) : undefined;
      return {
        ...a,
        elapsed_ms: a.status === 'running' ? now - new Date(a.assigned_at).getTime() : undefined,
        campaign: a.campaign_id ? this.engine.getCampaign(a.campaign_id) : undefined,
        // Live "current action" — what this agent most recently did.
        current_action: latest?.description,
        current_action_type: latest?.event_type,
        current_action_at: latest?.timestamp,
        // A finding timestamp bleeding between same-label tasks is low-harm, and
        // completed agents (no running owner) still need it — keep the plain fallback.
        last_finding_at: lastFindingAtByKey.get(a.id) ?? lastFindingAtByKey.get(a.agent_id),
        // pending headless tasks are effectively queued behind the concurrency cap.
        queued: a.status === 'pending',
      };
    });
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

  private serveAgentHistory(taskId: string, res: ServerResponse): void {
    const task = this.engine.getTask(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent task not found' }));
      return;
    }
    const agentId = task.agent_id;
    // Include events tagged with either the human-readable agent_id or the
    // task UUID — submit_agent_transcript / log_action_event events are
    // recorded against linked_agent_task_id, which the simple agent_id filter
    // would miss.
    const entries = this.engine.getFullHistory().filter(e =>
      e.agent_id === agentId || (e as { linked_agent_task_id?: string }).linked_agent_task_id === taskId
    );
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ entries, total: entries.length }));
  }

  private serveAgentConsole(taskId: string, url: string, res: ServerResponse): void {
    const task = this.engine.getTask(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent task not found' }));
      return;
    }

    const params = new URL(url, 'http://localhost').searchParams;
    const rawLimit = params.get('limit') || undefined;
    const limit = rawLimit ? parseInt(rawLimit, 10) : 80;
    const after = params.get('after') || undefined;
    const events = buildAgentConsoleEvents(this.engine.getFullHistory(), task, {
      limit: Number.isFinite(limit) && limit > 0 ? limit : 80,
      after,
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ events, total: events.length }));
  }

  private serveOpsecBudget(res: ServerResponse): void {
    const ctx = this.engine.getOpsecContext();
    const maxNoise = this.engine.getConfig().opsec.max_noise;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      global_noise_spent: ctx.global_noise_spent,
      noise_budget_remaining: ctx.noise_budget_remaining,
      max_noise: maxNoise,
      recommended_approach: ctx.recommended_approach,
      defensive_signals: ctx.defensive_signals,
      time_window_remaining_hours: ctx.time_window_remaining_hours,
      warning: ctx.warning,
    }));
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
    let killed = false;
    if (this.taskExecution) {
      // Kills the headless OS process (if any) AND marks the task interrupted
      // (releases the lease). Non-headless tasks just get the status update.
      killed = this.taskExecution.cancelHeadless(taskId, 'Cancelled by operator via dashboard');
    } else {
      // No execution service attached (e.g. isolated tests): status-only cancel.
      this.engine.updateAgentStatus(taskId, 'interrupted', 'Cancelled by operator via dashboard');
    }
    const updated = this.engine.getTask(taskId);
    if (updated?.status !== 'interrupted') {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to cancel agent' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ cancelled: true, process_killed: killed, task: updated }));
  }

  // ---- Per-agent steering (Phase 3B) ----
  // Single-click directive on one agent. Builds one OperatorOp and runs it
  // through the SAME validated executeOps path the command bar uses — no new
  // mutation surface. Kinds: pause/resume/stop/narrow_scope/skip_types/prioritize
  // (+ free-text 'instruct' once Stage 2 adds it).
  private static DIRECTIVE_KINDS: readonly AgentDirectiveKind[] = [
    'pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct',
  ];

  private handleAgentDirective(taskId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const b = (body ?? {}) as Record<string, unknown>;
      const kind = typeof b.kind === 'string' ? b.kind : '';
      if (!DashboardServer.DIRECTIVE_KINDS.includes(kind as AgentDirectiveKind)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `unknown directive kind "${kind}"` }));
        return;
      }
      const task = this.engine.getTask(taskId);
      if (!task) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Agent task not found' }));
        return;
      }
      if (task.status !== 'running') {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Agent is ${task.status} — directives only apply to running agents` }));
        return;
      }
      const op: OperatorOp = {
        op: 'directive',
        task_id: taskId,
        agent_label: task.agent_id,
        kind: kind as AgentDirectiveKind,
        node_ids: Array.isArray(b.node_ids) ? (b.node_ids as unknown[]).filter(x => typeof x === 'string') as string[] : undefined,
        frontier_types: Array.isArray(b.frontier_types) ? (b.frontier_types as unknown[]).filter(x => typeof x === 'string') as string[] : undefined,
        note: typeof b.note === 'string' ? b.note : undefined,
      };
      const results = executeOps(this.engine, [op], 'operator');
      this.engine.logActionEvent({
        description: `Operator directive: ${kind} → ${task.agent_id}`,
        event_type: 'operator_command',
        category: 'system',
        source_kind: 'dashboard',
        result_classification: results[0]?.ok ? 'success' : 'failure',
        linked_agent_task_id: taskId,
        details: { reason: 'operator_command', source: 'dashboard', command: `${kind} ${task.agent_id}`, results },
      });
      this.engine.persist();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: results[0]?.ok ?? false, results }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // ---- Fleet-level steering (Phase 3C) ----
  // Apply one directive kind to ALL running agents (optionally one campaign).
  // Just a fan-out of the same validated executeOps directive op — the grammar's
  // "pause all" does this in NL; this is the one-click UI equivalent.
  private handleFleetDirective(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const b = (body ?? {}) as Record<string, unknown>;
      const kind = typeof b.kind === 'string' ? b.kind : '';
      // Fleet controls are limited to lifecycle kinds (no arg-taking/free-text).
      if (!['pause', 'resume', 'stop'].includes(kind)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `fleet directive kind must be pause|resume|stop, got "${kind}"` }));
        return;
      }
      const campaignId = typeof b.campaign_id === 'string' ? b.campaign_id : undefined;
      const targets = this.engine.getAgentTasks().filter(t =>
        t.status === 'running' && (!campaignId || t.campaign_id === campaignId));
      const ops: OperatorOp[] = targets.map(t => ({
        op: 'directive', task_id: t.id, agent_label: t.agent_id, kind: kind as AgentDirectiveKind,
      }));
      const results = ops.length ? executeOps(this.engine, ops, 'operator') : [];
      const ok = results.filter(r => r.ok).length;
      this.engine.logActionEvent({
        description: `Operator fleet directive: ${kind} → ${ok}/${targets.length} running agent(s)${campaignId ? ` in campaign ${campaignId}` : ''}`,
        event_type: 'operator_command',
        category: 'system',
        source_kind: 'dashboard',
        result_classification: results.every(r => r.ok) ? 'success' : ok === 0 ? 'failure' : 'partial',
        details: { reason: 'operator_command', source: 'dashboard', command: `${kind} all${campaignId ? ` (campaign ${campaignId})` : ''}`, results },
      });
      this.engine.persist();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, applied: ok, total: targets.length, results }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private serveCampaigns(res: ServerResponse): void {
    const enriched = this.enrichCampaigns();
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

  private async handleCampaignSplit(campaignId: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const body = await this.readJsonBody(req);
      const children = this.engine.splitCampaign(campaignId, body.count);
      if (!children) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Campaign not found or cannot be split' }));
        return;
      }
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ parent_id: campaignId, children, count: children.length }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request body' }));
    }
  }

  private serveCampaignChildren(campaignId: string, res: ServerResponse): void {
    const children = this.engine.getCampaignChildren(campaignId);
    const progress = this.engine.getCampaignParentProgress(campaignId);
    const derivedStatus = this.engine.deriveCampaignParentStatus(campaignId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ parent_id: campaignId, children, derived_status: derivedStatus, aggregated_progress: progress }));
  }

  private servePhases(res: ServerResponse): void {
    const state = this.engine.getState();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ phases: state.phases, current_phase: state.current_phase }));
  }

  // ---- Mutation auth & body parsing helpers ----

  /**
   * Read-side auth gate. On loopback binds we trust the local user (consistent
   * with the rest of the codebase). On any non-loopback bind we require
   * OVERWATCH_DASHBOARD_TOKEN to be set and presented via Authorization
   * header or `?token=` query param. Without this, /api/state, /api/graph,
   * /api/history, /api/sessions, /api/agents, /api/graph/export and friends
   * would expose engagement data to anyone who can reach the host.
   */
  private checkReadAuth(req: IncomingMessage, res: ServerResponse): boolean {
    if (this.isLoopback(this.host)) return true;
    const expected = process.env.OVERWATCH_DASHBOARD_TOKEN;
    if (!expected) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token not configured for non-loopback host' }));
      return false;
    }
    const authHeader = req.headers.authorization;
    const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
    let urlToken: string | null = null;
    try {
      urlToken = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`).searchParams.get('token');
    } catch { /* malformed URL — fall through, header check below decides */ }
    if (headerToken !== expected && urlToken !== expected) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return false;
    }
    return true;
  }

  private checkMutationAuth(req: IncomingMessage, res: ServerResponse): boolean {
    // CSRF: Always check Origin header for mutation requests, even on loopback.
    // Reject cross-origin mutations from untrusted sites that may be open in the browser.
    const origin = req.headers.origin;
    if (origin) {
      const isLocalOrigin = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin);
      let isAllowed = isLocalOrigin;
      if (!isAllowed) {
        try { isAllowed = new URL(origin).hostname === this.host; } catch { /* malformed */ }
      }
      if (!isAllowed) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'CSRF: origin not allowed' }));
        return false;
      }
    }

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

  private readJsonBody(req: IncomingMessage, maxBytes: number = 64 * 1024): Promise<any> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const MAX_BODY = maxBytes;
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

  private getDashboardApprovalRecords(options: { includeResolvedRecent?: boolean } = {}): DurableApprovalRecord[] {
    const includeResolvedRecent = options.includeResolvedRecent ?? false;
    const records = new Map<string, DurableApprovalRecord>();
    const resolvedSinceMs = includeResolvedRecent ? 10 * 60 * 1000 : undefined;

    for (const record of this.readPersistedApprovalRecords()) {
      if (record.status === 'pending' || includeResolvedRecent) {
        if (!resolvedSinceMs || record.status === 'pending' || !record.resolved_at || Date.now() - new Date(record.resolved_at).getTime() <= resolvedSinceMs) {
          records.set(record.action_id, record);
        }
      }
    }

    for (const record of this.engine.getApprovalRequests({ resolvedSinceMs })) {
      if (record.status === 'pending' || includeResolvedRecent) records.set(record.action_id, record);
    }

    for (const action of this.engine.getPendingActionQueue().getPending()) {
      records.set(action.action_id, {
        ...action,
        ...(records.get(action.action_id) || {}),
        status: 'pending',
      });
    }

    return [...records.values()]
      .filter(record => record.status === 'pending' || includeResolvedRecent)
      .sort((a, b) => (b.submitted_at || '').localeCompare(a.submitted_at || ''));
  }

  private readPersistedApprovalRecords(): DurableApprovalRecord[] {
    try {
      const statePath = this.engine.getStateFilePath();
      if (!existsSync(statePath)) return [];
      const raw = JSON.parse(readFileSync(statePath, 'utf-8')) as { approvalRequests?: unknown };
      if (!Array.isArray(raw.approvalRequests)) return [];
      return raw.approvalRequests
        .map(item => Array.isArray(item) ? item[1] : item)
        .filter((item): item is DurableApprovalRecord => (
          !!item
          && typeof item === 'object'
          && typeof (item as DurableApprovalRecord).action_id === 'string'
          && typeof (item as DurableApprovalRecord).status === 'string'
        ));
    } catch {
      return [];
    }
  }

  private buildActionDiagnostics(records: DurableApprovalRecord[]): Record<string, unknown> {
    const state = this.engine.getState({ activityCount: 100, includeReasoning: true, includeSystem: true });
    const recentActivity = state.recent_activity || [];
    const latestActionEvent = [...recentActivity].reverse().find(entry => typeof entry.event_type === 'string' && entry.event_type.startsWith('action_'));
    const latestApproval = records[0];
    const opsec = this.engine.getConfig().opsec;
    return {
      approval_mode: opsec.approval_mode || 'auto-approve',
      opsec_enabled: opsec.enabled === true,
      websocket_connected: this.clients.size > 0,
      latest_action_at: latestActionEvent?.timestamp,
      latest_action_type: latestActionEvent?.event_type,
      latest_approval_at: latestApproval?.submitted_at,
      latest_approval_status: latestApproval?.status,
    };
  }

  private servePendingActions(res: ServerResponse): void {
    const records = this.getDashboardApprovalRecords({ includeResolvedRecent: true });
    const pending = records.filter(record => record.status === 'pending');
    const recent = records.filter(record => record.status !== 'pending');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      pending,
      recent,
      count: pending.length,
      diagnostics: this.buildActionDiagnostics(records),
    }));
  }

  private handleActionApprove(actionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const queue = this.engine.getPendingActionQueue();
      const result = queue.approve(actionId, body?.notes);
      if (!result) {
        const durable = this.getDashboardApprovalRecords({ includeResolvedRecent: true }).find(action => action.action_id === actionId);
        res.writeHead(durable ? 409 : 404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: durable ? 'approval_not_live' : 'Action not found or already resolved' }));
        return;
      }
      this.engine.resolveApprovalRequest(result);
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
        const durable = this.getDashboardApprovalRecords({ includeResolvedRecent: true }).find(action => action.action_id === actionId);
        res.writeHead(durable ? 409 : 404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: durable ? 'approval_not_live' : 'Action not found or already resolved' }));
        return;
      }
      this.engine.resolveApprovalRequest(result);
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

  private buildEvidenceChain(nodeId: string): {
    node_id: string;
    chains: Array<{ action_id?: string; agent_id?: string; event_type?: string; tool?: string; command?: string; timestamp: string; snippet?: string }>;
    count: number;
    node_props?: Record<string, unknown>;
    findings?: Array<{ finding_type?: string; severity?: string; technique_id?: string; description?: string }>;
  } {
    // Build evidence chains for a node from the activity log
    const history = this.engine.getFullHistory();
    const chains: Array<{ action_id?: string; agent_id?: string; event_type?: string; tool?: string; command?: string; timestamp: string; snippet?: string }> = [];

    for (const entry of history) {
      // Match entries that explicitly reference this node via structured fields
      const e = entry as Record<string, unknown>;
      const det = e.details as Record<string, unknown> | undefined;
      const targetNodeIds = Array.isArray(e.target_node_ids) ? e.target_node_ids as string[] : [];
      const ingestedNodeIds = Array.isArray(det?.ingested_node_ids) ? det.ingested_node_ids as string[] : [];
      const nodeIds = Array.isArray(det?.node_ids) ? det.node_ids as string[] : [];
      const referencesNode =
        targetNodeIds.includes(nodeId) ||
        ingestedNodeIds.includes(nodeId) ||
        nodeIds.includes(nodeId) ||
        e.action_id === nodeId ||
        e.node_id === nodeId;
      if (!referencesNode) continue;

      const commandRepr = e.command_repr as string | undefined
        || (typeof det?.command === 'string' ? det.command : undefined);

      chains.push({
        action_id: e.action_id as string | undefined,
        agent_id: e.agent_id as string | undefined,
        event_type: e.event_type as string | undefined,
        tool: e.tool_name as string | undefined || e.action_type as string | undefined,
        command: commandRepr,
        timestamp: entry.timestamp,
        snippet: e.description as string | undefined || e.summary as string | undefined,
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

    return { node_id: nodeId, chains, count: chains.length, node_props, findings };
  }

  private serveEvidenceChains(nodeId: string, res: ServerResponse): void {
    const payload = this.buildEvidenceChain(nodeId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  private resolveAssetToNode(asset: string, graph: ReturnType<GraphEngine['exportGraph']>): { id: string; properties: Record<string, unknown> } | null {
    const needle = asset.trim().toLowerCase();
    if (!needle) return null;
    for (const node of graph.nodes) {
      const props = (node.properties || {}) as Record<string, unknown>;
      const candidates = [
        node.id,
        props.id,
        props.label,
        props.hostname,
        props.ip,
        props.username,
        props.domain,
        props.url,
        props.arn,
        props.provider_resource_id,
        props.cred_user,
      ];
      if (candidates.some(value => typeof value === 'string' && value.toLowerCase() === needle)) {
        return { id: node.id, properties: props };
      }
    }
    return null;
  }

  private serveFindingContext(findingId: string, res: ServerResponse): void {
    const config = this.engine.getConfig();
    const graph = this.engine.exportGraph();
    const history = this.engine.getFullHistory();
    const evidenceLoader = (id: string): string | null => {
      try { return this.engine.getEvidenceStore().getRawOutput(id); } catch { return null; }
    };
    const findings = buildFindings(graph, history, config, { evidenceLoader });
    const classifications = classifyAllFindings(findings, graph);
    const finding = findings.find(f => f.id === findingId);

    if (!finding) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Finding not found: ${findingId}` }));
      return;
    }

    const affectedNodes = finding.affected_assets
      .map(asset => {
        const node = this.resolveAssetToNode(asset, graph);
        return node ? { asset, id: node.id, ...node.properties } : null;
      })
      .filter((node): node is Record<string, unknown> & { asset: string; id: string } => !!node);
    const affectedNodeIds = [...new Set(affectedNodes.map(node => node.id))];
    const evidence_chains = affectedNodeIds.map(nodeId => this.buildEvidenceChain(nodeId));
    const sessions = (this.sessionManager?.list() || []).filter(session =>
      affectedNodeIds.includes(session.target_node || '')
      || affectedNodeIds.includes(session.principal_node || '')
      || affectedNodeIds.includes(session.credential_node || ''),
    );
    const pending_actions = this.getDashboardApprovalRecords().filter(action =>
      affectedNodeIds.includes(action.target_node || '')
      || affectedNodeIds.includes(((action as unknown as { target?: string }).target) || ''),
    );
    const state = this.engine.getState();
    const frontier = state.frontier.filter(item =>
      affectedNodeIds.includes(item.node_id || '')
      || affectedNodeIds.includes(((item as unknown as { target_node?: string }).target_node) || '')
      || affectedNodeIds.includes(item.edge_source || '')
      || affectedNodeIds.includes(item.edge_target || ''),
    );
    const path_impacts = config.objectives.flatMap(objective => {
      if (!objective.id) return [];
      return this.engine.findPathsToObjective(objective.id, 3, 'confidence')
        .filter(path => path.nodes.some(nodeId => affectedNodeIds.includes(nodeId)))
        .map(path => ({ objective_id: objective.id, objective: objective.description, nodes: path.nodes, total_confidence: path.total_confidence, total_opsec_noise: path.total_opsec_noise }));
    });

    const enrichedFinding = {
      ...finding,
      classification: classifications.get(finding.id) ?? finding.classification,
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      finding: enrichedFinding,
      affected_nodes: affectedNodes,
      evidence_chains,
      sessions,
      pending_actions,
      frontier,
      path_impacts,
      report_ready: evidence_chains.some(chain => chain.count > 0) || affectedNodes.length > 0,
    }));
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

  private serveEngagements(res: ServerResponse): void {
    if (!this.engagementManager) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ engagements: [], active_id: null }));
      return;
    }
    const engagements = this.engagementManager.listEngagements();
    const active_id = this.engagementManager.getActiveId();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ engagements, active_id }));
  }

  private async handleCreateEngagement(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.engagementManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Engagement manager not available' }));
      return;
    }
    this.readJsonBody(req, 256 * 1024).then(input => {
      if (!input || !input.name || typeof input.name !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'name is required' }));
        return;
      }
      try {
        const summary = this.engagementManager!.createEngagement({
          name: input.name,
          profile: input.profile,
          cidrs: Array.isArray(input.cidrs) ? input.cidrs : [],
          domains: Array.isArray(input.domains) ? input.domains : [],
          exclusions: Array.isArray(input.exclusions) ? input.exclusions : [],
          hosts: Array.isArray(input.hosts) ? input.hosts : undefined,
          url_patterns: Array.isArray(input.url_patterns) ? input.url_patterns : undefined,
          aws_accounts: Array.isArray(input.aws_accounts) ? input.aws_accounts : undefined,
          azure_subscriptions: Array.isArray(input.azure_subscriptions) ? input.azure_subscriptions : undefined,
          gcp_projects: Array.isArray(input.gcp_projects) ? input.gcp_projects : undefined,
          opsec_profile: input.opsec_profile,
          opsec: input.opsec && typeof input.opsec === 'object' ? input.opsec : undefined,
          objectives: Array.isArray(input.objectives) ? input.objectives : [],
          failure_patterns: Array.isArray(input.failure_patterns) ? input.failure_patterns : undefined,
          phases: Array.isArray(input.phases) ? input.phases : undefined,
          template_id: typeof input.template_id === 'string' ? input.template_id : undefined,
        });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(summary));
      } catch (err: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message ?? 'Internal error' }));
      }
    }).catch(err => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON: ' + err.message }));
    });
  }

  private serveEngagementDetail(id: string, res: ServerResponse): void {
    if (!this.engagementManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Engagement manager not available' }));
      return;
    }
    const detail = this.engagementManager.getEngagement(id);
    if (!detail) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Engagement not found: ${id}` }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(detail));
  }

  private handleUpdateEngagement(id: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.engagementManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Engagement manager not available' }));
      return;
    }
    this.readJsonBody(req, 256 * 1024).then(body => {
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      const updated = this.engagementManager!.updateEngagement(id, body);
      if (!updated) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Engagement not found: ${id}` }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ updated: true }));
    }).catch(err => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON: ' + err.message }));
    });
  }

  // ---- Tools endpoint ----

  private async serveTools(res: ServerResponse): Promise<void> {
    try {
      const results = await checkAllTools();
      const installed = results.filter(t => t.installed);
      const missing = results.filter(t => !t.installed);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        installed_count: installed.length,
        missing_count: missing.length,
        tools: results,
      }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Tool check failed: ' + (err as Error).message }));
    }
  }

  private serveMcpTools(res: ServerResponse): void {
    const tools = this.mcpTools
      .map(tool => ({
        name: tool.name,
        title: tool.title,
        description: tool.description,
        category: tool.category ?? categorizeMcpTool(tool.name),
        read_only: tool.read_only,
        destructive: tool.destructive,
        idempotent: tool.idempotent,
        open_world: tool.open_world,
      }))
      .sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
    const categories = tools.reduce((acc: Record<string, number>, tool) => {
      acc[tool.category] = (acc[tool.category] || 0) + 1;
      return acc;
    }, {});
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: tools.length, categories, tools }));
  }

  private serveReadiness(res: ServerResponse): void {
    try {
      const graph = this.engine.exportGraph();
      const state = this.engine.getState({ activityCount: 5, includeSystem: false });
      const health = this.engine.getHealthReport();
      const pending = this.getDashboardApprovalRecords().filter(action => action.status === 'pending');
      const agents = this.engine.getAllAgents();
      const sessions = this.sessionManager?.list(false) ?? (Array.isArray((state as any).sessions) ? (state as any).sessions : []);
      const tapeStatus = this.tape?.getStatus() ?? { enabled: false, attached: false };
      const persistence = this.engine.getPersistMetrics();
      const activeSessions = sessions.filter((session: any) => session.state === 'connected' || session.state === 'pending').length;
      const runningAgents = agents.filter(agent => agent.status === 'running').length;
      const failedAgents = agents.filter(agent => agent.status === 'failed' || agent.status === 'interrupted').length;
      const issues = [
        ...health.issues.slice(0, 3).map(issue => issue.message),
        ...(failedAgents > 0 ? [`${failedAgents} agent${failedAgents === 1 ? '' : 's'} failed or interrupted`] : []),
      ];
      const status =
        health.status === 'critical' ? 'critical' :
        health.status === 'warning' || failedAgents > 0 ? 'warning' :
        'ready';

      const payload: Record<string, unknown> = {
        status,
        generated_at: new Date().toISOString(),
        graph: {
          status: health.status,
          nodes: graph.nodes.length,
          edges: graph.edges.length,
          counts_by_severity: health.counts_by_severity,
          top_issues: health.issues.slice(0, 5),
        },
        api: {
          dashboard_running: this.running,
          websocket_clients: this.clients.size,
          mcp_tools_registered: this.mcpTools.length,
        },
        tape: tapeStatus,
        sessions: {
          total: sessions.length,
          active: activeSessions,
          closed: sessions.length - activeSessions,
        },
        actions: {
          pending: pending.length,
        },
        agents: {
          total: agents.length,
          running: runningAgents,
          failed: failedAgents,
        },
        persistence: {
          dirty: persistence.dirty,
          last_flush_at: persistence.lastFlushAt,
          flush_count: persistence.flushCount,
          last_flush_ms: persistence.lastFlushMs,
        },
        issues,
      };

      if (process.env.NODE_ENV !== 'production') {
        payload.dev = {
          node_env: process.env.NODE_ENV ?? 'development',
          host: this.host,
          port: this.port,
        };
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Readiness check failed: ' + (err as Error).message }));
    }
  }

  private serveTrustSignals(url: string, res: ServerResponse): void {
    try {
      const params = new URL(url, 'http://localhost').searchParams;
      const limitParam = params.get('limit');
      const limit = limitParam ? parseInt(limitParam, 10) : 100;
      const severityParam = params.get('severity') as TrustSignalSeverity | null;
      const severity: TrustSignalSeverity | undefined = severityParam && ['error', 'warning', 'info'].includes(severityParam)
        ? severityParam
        : undefined;
      const graph = this.engine.exportGraph();
      const history = this.engine.getFullHistory();
      const config = this.engine.getConfig();
      const evidenceLoader = (id: string): string | null => {
        try { return this.engine.getEvidenceStore().getRawOutput(id); } catch { return null; }
      };
      const findings = buildFindings(graph, history, config, { evidenceLoader });
      const payload = buildTrustSignalsResponse({
        history,
        findings,
        limit: Number.isFinite(limit) && limit > 0 ? limit : 100,
        nodeId: params.get('node_id') || undefined,
        findingId: params.get('finding_id') || undefined,
        severity,
        resolveAssetToNode: asset => this.resolveAssetToNode(asset, graph)?.id ?? null,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Trust signal summary failed: ' + (err as Error).message }));
    }
  }

  // ---- Inference rules endpoint ----

  private serveInferenceRules(res: ServerResponse): void {
    const rules = this.engine.getInferenceRules();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ rules, total: rules.length }));
  }

  // ---- Telemetry endpoint ----

  private serveTelemetry(res: ServerResponse): void {
    const telemetry = getTelemetry();
    const toolSummary = telemetry ? telemetry.summarize([]) : null;
    const state = this.engine.getState();
    const inferenceEffectiveness = state.inference_rule_effectiveness || [];
    const healthReport = this.engine.getHealthReport();

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      tool_telemetry: toolSummary,
      inference_effectiveness: inferenceEffectiveness,
      health: {
        status: healthReport.status,
        counts: healthReport.counts_by_severity,
        top_issues: healthReport.issues.slice(0, 10),
      },
      graph_stats: {
        total_nodes: state.graph_summary?.total_nodes ?? 0,
        total_edges: state.graph_summary?.total_edges ?? 0,
        confirmed_edges: state.graph_summary?.confirmed_edges ?? 0,
        inferred_edges: state.graph_summary?.inferred_edges ?? 0,
      },
      credential_coverage: state.credential_coverage ?? null,
    }));
  }

  // ---- Graph export endpoint ----

  private handleGraphExport(res: ServerResponse): void {
    const graph = this.engine.exportGraph();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(graph));
  }

  // ---- Tape recorder status / toggle ----
  // Surfaces the in-process tape controller so operators can flip recording
  // on/off from the dashboard without restarting the server. The controller
  // is optional: when not attached (e.g. in tests) these endpoints return
  // 503 so callers know the feature isn't wired in this build.

  private handleTapeStatus(res: ServerResponse): void {
    if (!this.tape) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'tape_controller_not_attached' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(this.tape.getStatus()));
  }

  private async handleTapeToggle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.tape) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'tape_controller_not_attached' }));
      return;
    }
    try {
      const body = await this.readJsonBody(req).catch(() => ({} as Record<string, unknown>));
      const action = (body as { action?: string }).action;
      const dir = (body as { dir?: string }).dir;
      const file = (body as { file?: string }).file;
      const sessionId = (body as { session_id?: string }).session_id;
      let status;
      if (action === 'enable') {
        status = this.tape.enable({ defaultDir: dir, file, sessionId, startedBy: 'dashboard' });
      } else if (action === 'disable') {
        status = await this.tape.disable();
      } else {
        // Default = toggle: if currently enabled, disable; else enable.
        const cur = this.tape.getStatus() as { enabled?: boolean };
        status = cur.enabled
          ? await this.tape.disable()
          : this.tape.enable({ defaultDir: dir, file, sessionId, startedBy: 'dashboard' });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(status));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
  }

  // ---- B.2/B.3 — Findings + Reports endpoints ----

  /**
   * GET /api/findings — returns the structured Findings array (with
   * compliance classification) that the FindingsPanel renders. Same
   * pipeline `generate_report` uses, just wrapped as JSON for the UI.
   */
  private serveFindings(res: ServerResponse): void {
    const config = this.engine.getConfig();
    const graph = this.engine.exportGraph();
    const history = this.engine.getFullHistory();
    const evidenceLoader = (id: string): string | null => {
      try { return this.engine.getEvidenceStore().getRawOutput(id); } catch { return null; }
    };
    const findings = buildFindings(graph, history, config, { evidenceLoader });
    const classifications = classifyAllFindings(findings, graph);
    const enriched = findings.map(f => ({
      ...f,
      classification: classifications.get(f.id) ?? f.classification,
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      findings: enriched,
      total: enriched.length,
      severity_summary: {
        critical: enriched.filter(f => f.severity === 'critical').length,
        high: enriched.filter(f => f.severity === 'high').length,
        medium: enriched.filter(f => f.severity === 'medium').length,
        low: enriched.filter(f => f.severity === 'low').length,
        info: enriched.filter(f => f.severity === 'info').length,
      },
    }));
  }

  /** GET /api/bundle — stream the engagement archive as a .tar.gz download. */
  private async streamBundle(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    let prepared: ReturnType<typeof prepareBundle> | null = null;
    try {
      prepared = prepareBundle(this.engine, { includeSnapshots: false });
      const cfg = this.engine.getConfig();
      const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
      const filename = `bundle-${cfg.id}-${ts}.tar.gz`;

      res.writeHead(200, {
        'Content-Type': 'application/gzip',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Transfer-Encoding': 'chunked',
        'Cache-Control': 'no-store',
      });

      await pipeTarGzToStream(res, prepared.stateDir, prepared.entries);
      res.end();

      this.engine.logActionEvent({
        description: `Dashboard bundle downloaded: ${filename}`,
        event_type: 'system',
        category: 'system',
      });
      this.engine.flushNow();
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    } finally {
      prepared?.cleanup();
    }
  }

  /** GET /api/reports — list manifest entries newest-first. */
  private serveReportsList(res: ServerResponse): void {
    const archive = this.engine.getReportArchive();
    const records = archive.list();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ reports: records, total: records.length, total_bytes: archive.totalBytes() }));
  }

  /** GET /api/reports/:id — stream the file content. */
  private serveReportDownload(id: string, url: string, res: ServerResponse): void {
    const archive = this.engine.getReportArchive();
    const result = archive.get(id);
    if (!result) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'report not found' }));
      return;
    }
    const { record, content } = result;
    const contentType = record.format === 'html' ? 'text/html'
      : record.format === 'json' ? 'application/json'
      : record.format === 'pdf' ? 'application/pdf'
      : 'text/markdown';
    const ext = record.format === 'markdown' ? 'md' : record.format;
    const downloadName = `report-${record.id.slice(0, 8)}-${record.redaction_mode}.${ext}`;
    const inline = new URL(url, 'http://localhost').searchParams.get('disposition') === 'inline';
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${downloadName}"`,
      'Content-Length': content.byteLength,
    });
    res.end(content);
  }

  /** DELETE /api/reports/:id — remove from manifest + filesystem. */
  private handleReportDelete(id: string, res: ServerResponse): void {
    const archive = this.engine.getReportArchive();
    const ok = archive.delete(id);
    res.writeHead(ok ? 200 : 404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ deleted: ok }));
  }

  /** POST /api/reports/render — assemble + persist a new report. Body shape mirrors generate_report's options. */
  private async handleRenderReport(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const body = await this.readJsonBody(req).catch(() => ({} as Record<string, unknown>));
      const formatRaw = (body as { format?: string }).format ?? 'markdown';
      const format = (formatRaw === 'md' ? 'markdown' : formatRaw) as ReportFormat | 'pdf';
      if (!['markdown', 'html', 'json', 'pdf'].includes(format)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `unsupported format: ${formatRaw}` }));
        return;
      }
      const includeRetrospective = (body as { include_retrospective?: boolean }).include_retrospective === true;
      if (includeRetrospective && !this.skills) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'retrospective requires skill index; pass include_retrospective:false or attach skills via attachSkills()' }));
        return;
      }

      // assembleReport requires a non-null SkillIndex even when retrospective is off
      // (it only reads skills when include_retrospective: true). Provide an empty
      // shim when none is attached so the caller doesn't need to wire skills for
      // the common case.
      const skills = this.skills ?? ({ listSkills: () => [] } as unknown as import('./skill-index.js').SkillIndex);
      // For PDF, assemble HTML internally then pipe through puppeteer.
      const assembleFormat: ReportFormat = format === 'pdf' ? 'html' : format;
      const profile = (body as Record<string, unknown>).profile === 'client' ? 'client' : (body as Record<string, unknown>).profile === 'operator' ? 'operator' : undefined;
      const evidenceStyleRaw = (body as Record<string, unknown>).evidence_style;
      const evidenceStyle = evidenceStyleRaw === 'appendix' || evidenceStyleRaw === 'full_inline' || evidenceStyleRaw === 'proof_cards'
        ? evidenceStyleRaw
        : undefined;
      const assembled = assembleReport(this.engine, skills, {
        format: assembleFormat,
        include_evidence: (body as Record<string, unknown>).include_evidence as boolean | undefined,
        include_narrative: (body as Record<string, unknown>).include_narrative as boolean | undefined,
        include_retrospective: includeRetrospective,
        include_compliance: (body as Record<string, unknown>).include_compliance as boolean | undefined,
        include_attack_navigator: (body as Record<string, unknown>).include_attack_navigator as boolean | undefined,
        include_gap_analysis: (body as Record<string, unknown>).include_gap_analysis as boolean | undefined,
        include_attack_paths: (body as Record<string, unknown>).include_attack_paths as boolean | undefined,
        max_paths_per_objective: (body as Record<string, unknown>).max_paths_per_objective as number | undefined,
        theme: ((body as Record<string, unknown>).theme as 'light' | 'dark' | undefined),
        client_safe: (body as Record<string, unknown>).client_safe === true,
        profile,
        evidence_style: evidenceStyle,
      });

      let stored: Buffer | string = assembled.content;
      if (format === 'pdf') {
        try {
          const { renderReportPdf } = await import('./report-pdf.js');
          stored = await renderReportPdf(assembled.content, { format: 'A4', printBackground: true });
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `PDF rendering failed: ${err instanceof Error ? err.message : String(err)}` }));
          return;
        }
      }

      const archive = this.engine.getReportArchive();
      const record: ReportRecord = archive.add(stored, {
        generated_at: new Date().toISOString(),
        format,
        redaction_mode: assembled.redaction_mode,
        profile: assembled.profile,
        evidence_style: evidenceStyle ?? 'proof_cards',
        findings_count: assembled.findings_count,
        evidence_count: assembled.evidence_count,
        options: {
          include_evidence: (body as Record<string, unknown>).include_evidence as boolean | undefined,
          include_narrative: (body as Record<string, unknown>).include_narrative as boolean | undefined,
          include_retrospective: includeRetrospective,
          include_compliance: (body as Record<string, unknown>).include_compliance as boolean | undefined,
          include_attack_paths: (body as Record<string, unknown>).include_attack_paths as boolean | undefined,
          profile: assembled.profile,
          evidence_style: evidenceStyle ?? 'proof_cards',
          theme: format === 'html' ? ((body as Record<string, unknown>).theme as 'light' | 'dark' | undefined) : undefined,
        },
      });

      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        report: record,
        findings_count: assembled.findings_count,
        evidence_count: assembled.evidence_count,
        severity_summary: assembled.severity_summary,
      }));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
  }

  // ---- Graph correct endpoint ----

  private async handleGraphCorrect(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const body = await this.readJsonBody(req);
      const { reason, operations } = body;
      if (!reason || !Array.isArray(operations) || operations.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'reason (string) and operations (array) are required' }));
        return;
      }
      const result = this.engine.correctGraph(reason, operations, `console-${Date.now()}`);
      // Broadcast full state update to all WS clients
      const state = this.buildFrontendState();
      const graph = this.engine.exportGraph();
      this.broadcast({
        type: 'full_state',
        timestamp: new Date().toISOString(),
        data: { state, graph, history_count: this.engine.getFullHistory().length },
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
  }
}
