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
import { opsecPartialUpdateSchema } from '../types.js';
import { EngagementManager } from './engagement-manager.js';
import { checkAllTools } from './tool-check.js';
import { getTelemetry } from '../tools/error-boundary.js';
import { assembleReport, type ReportFormat } from './report-assembler.js';
import { prepareBundle, pipeTarGzToStream } from './bundle-builder.js';
import { buildFindings } from './report-generator.js';
import { classifyAllFindings } from './finding-classifier.js';
import type { ReportRecord } from './report-archive.js';
import { ScriptedAgentRunner } from './scripted-agent-runner.js';
import type { ToolEntry } from './prompt-generator.js';
import { buildTrustSignalsResponse, type TrustSignalSeverity } from './trust-signal-summary.js';

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
  private engagementManager: EngagementManager | null = null;
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

  private scriptedRunner: ScriptedAgentRunner;

  constructor(engine: GraphEngine, port: number = 8384, host?: string, sessionManager?: SessionManager, configPath?: string) {
    this.engine = engine;
    this.port = port;
    this.host = host || process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
    this.sessionManager = sessionManager || null;
    if (configPath) {
      this.engagementManager = new EngagementManager(configPath);
    }

    // Wire engine updates to WS push without requiring external wiring in app.ts.
    engine.onUpdate(detail => this.onGraphUpdate(detail));

    this.scriptedRunner = new ScriptedAgentRunner(engine);

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
        this.scriptedRunner.start();
        console.error(`Dashboard running at http://${this.host}:${this.port}`);
        resolve({ started: true });
      });
    });
  }

  stop(): Promise<void> {
    this._running = false;
    this.scriptedRunner.stop();
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

    // dashboard-next (React + Vite build) is the only dashboard.
    // dist/services/ → dist/dashboard-next/
    const nextDistPath = join(__dirname, '..', 'dashboard-next');
    if (existsSync(join(nextDistPath, 'index.html'))) {
      this.dashboardDir = nextDistPath;
      return nextDistPath;
    }
    // Fallback: top-level dist output (e.g. when running tsc only)
    const nextSrcPath = join(__dirname, '..', '..', 'dist', 'dashboard-next');
    if (existsSync(join(nextSrcPath, 'index.html'))) {
      this.dashboardDir = nextSrcPath;
      return nextSrcPath;
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
      const agentCtxMatch = pathname.match(/^\/api\/agents\/([a-f0-9-]+)\/context$/);
      const agentHistoryMatch = pathname.match(/^\/api\/agents\/([a-f0-9-]+)\/history$/);
      const agentCancelMatch = pathname.match(/^\/api\/agents\/([a-f0-9-]+)\/cancel$/);
      const objectiveMatch = pathname.match(/^\/api\/config\/objectives\/([a-f0-9-]+)$/);
      const campaignDetailMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)$/);
      const campaignActionMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/action$/);
      const campaignDispatchMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/dispatch$/);
      const campaignCloneMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/clone$/);
      const campaignSplitMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/split$/);
      const campaignChildrenMatch = pathname.match(/^\/api\/campaigns\/([a-f0-9-]+)\/children$/);
      const actionExplainMatch = pathname.match(/^\/api\/actions\/([^/]+)\/explain$/);
      const actionApproveMatch = pathname.match(/^\/api\/actions\/([a-f0-9-]+)\/approve$/);
      const actionDenyMatch = pathname.match(/^\/api\/actions\/([a-f0-9-]+)\/deny$/);
      const sessionCloseMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/close$/);
      const sessionBufferMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/buffer$/);
      const sessionDetailMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)$/);
      const evidenceChainMatch = pathname.match(/^\/api\/evidence-chains\/([^/]+)$/);
      const pathsMatch = pathname.match(/^\/api\/paths\/([^/]+)$/);
      const findingContextMatch = pathname.match(/^\/api\/findings\/([^/]+)\/context$/);
      const reportDetailMatch = pathname.match(/^\/api\/reports\/([a-f0-9-]+)$/);

      if (agentCtxMatch) {
        this.serveAgentContext(agentCtxMatch[1], res);
      } else if (agentHistoryMatch) {
        this.serveAgentHistory(agentHistoryMatch[1], res);
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
        this.serveReportDownload(reportDetailMatch[1], res);
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

      // F2: registerAgent may refuse on frontier-lease conflict.
      // Returning 201 with { dispatched: true } when the task was never
      // inserted left the dashboard claiming work that didn't exist.
      const reg = this.engine.registerAgent(task);
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
  private buildFrontendState(): ReturnType<GraphEngine['getState']> & { sessions: ReturnType<NonNullable<SessionManager>['list']> } {
    const state = this.engine.getState();
    const sessions = this.sessionManager?.list() ?? [];
    return { ...state, sessions };
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
    const pending_actions = this.engine.getPendingActionQueue().getPending().filter(action =>
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
      const pending = this.engine.getPendingActionQueue().getPending();
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
  private serveReportDownload(id: string, res: ServerResponse): void {
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
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Disposition': `attachment; filename="${downloadName}"`,
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
        redaction_mode: (body as Record<string, unknown>).client_safe === true ? 'client_safe' : 'operator',
        options: {
          include_evidence: (body as Record<string, unknown>).include_evidence as boolean | undefined,
          include_narrative: (body as Record<string, unknown>).include_narrative as boolean | undefined,
          include_retrospective: includeRetrospective,
          include_compliance: (body as Record<string, unknown>).include_compliance as boolean | undefined,
          include_attack_paths: (body as Record<string, unknown>).include_attack_paths as boolean | undefined,
          theme: format === 'html' ? ((body as Record<string, unknown>).theme as 'light' | 'dark' | undefined) : undefined,
        },
      });

      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        report: record,
        findings_count: assembled.findings_count,
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
