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
import { z } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandConflictError,
  ApplicationCommandService,
  getApplicationCommandInvocation,
  withApplicationCommandInvocation,
} from './application-command-service.js';
import {
  DispatchCommandError,
  DispatchCommandService,
} from './dispatch-command-service.js';
import {
  OperatorCommandError,
  OperatorCommandService,
} from './operator-command-service.js';
import {
  ApprovalCommandError,
  ApprovalCommandService,
} from './approval-command-service.js';
import {
  AgentLifecycleCommandError,
  AgentLifecycleCommandService,
} from './agent-lifecycle-command-service.js';
import {
  CampaignCommandError,
  CampaignCommandService,
} from './campaign-command-service.js';
import {
  EngagementCommandError,
  EngagementCommandService,
} from './engagement-command-service.js';
import {
  RecoveryCommandError,
  RecoveryCommandService,
} from './recovery-command-service.js';
import {
  GraphCorrectionCommandError,
  GraphCorrectionCommandService,
} from './graph-correction-command-service.js';
import { parseAndMaybeIngest } from './parse-ingest.js';
import {
  ParseCommandService,
  buildParseSourceFingerprint,
} from './parse-command-service.js';
import { getSupportedParsers } from './parsers/index.js';
import type { GraphUpdateDetail } from './engine-context.js';
import { DeltaAccumulator } from './delta-accumulator.js';
import type { SessionEvent, SessionManager } from './session-manager.js';
import { interpretCommand, type InterpreterState } from './command-interpreter.js';
import { interpretQuery, executeQuery, type QueryAnswer } from './query-interpreter.js';
import { listArchetypes } from './agent-archetypes.js';
import { listTemplates, loadTemplate, mergeTemplateWithConfig } from '../config.js';
import {
  opsecPartialUpdateSchema,
  operatorPolicyUpdateSchema,
  type AgentDirectiveKind,
  type Campaign,
} from '../types.js';
import type { DefensiveSignal, OpsecContext } from './opsec-tracker.js';
import {
  EngagementManager,
  EngagementManagerError,
  parseEngagementUpdate,
} from './engagement-manager.js';
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
import { assessPersistenceRecovery } from './lab-preflight.js';
import { projectAgentDtos } from './dashboard-agent-projector.js';
import {
  AgentListResponseSchema,
  CampaignActionRequestSchema,
  CampaignActionResponseSchema,
  CampaignChildrenResponseSchema,
  CampaignCloneResponseSchema,
  CampaignCreateRequestSchema,
  CampaignCreateResponseSchema,
  CampaignDeleteResponseSchema,
  CampaignDetailResponseSchema,
  CampaignDispatchRequestSchema,
  CampaignDispatchResponseSchema,
  CampaignListResponseSchema,
  CampaignSplitRequestSchema,
  CampaignSplitResponseSchema,
  CampaignUpdateRequestSchema,
  CampaignUpdateResponseSchema,
  ConfigDivergenceResolveRequestSchema,
  ConfigDivergenceResolveResponseSchema,
  GraphCorrectionRequestSchema,
  GraphCorrectionResultSchema,
  FrontierWeightsPatchSchema,
  FrontierWeightsResetResultSchema,
  FrontierWeightsUpdateResultSchema,
  HealthDtoSchema,
  ObjectiveCreateRequestSchema,
  ObjectiveCreateResponseSchema,
  ObjectiveDeleteResponseSchema,
  ObjectiveUpdateRequestSchema,
  ObjectiveUpdateResponseSchema,
  RecoveryStatusResponseSchema,
  SettingsDtoSchema,
  SettingsPatchSchema,
  SettingsUpdateResultSchema,
  type AgentDto,
} from '../contracts/dashboard-v1.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function categorizeMcpTool(name: string): string {
  if (['get_state', 'next_task', 'get_system_prompt', 'run_lab_preflight', 'run_graph_health', 'get_recovery_status', 'resolve_config_divergence'].includes(name)) {
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
  child_count?: number;
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
    this.agentLifecycleCommands.setRuntimeController(svc);
  }

  private readonly applicationCommands: ApplicationCommandService;
  private readonly dispatchCommands: DispatchCommandService;
  private readonly operatorCommands: OperatorCommandService;
  private readonly approvalCommands: ApprovalCommandService;
  private readonly agentLifecycleCommands: AgentLifecycleCommandService;
  private readonly campaignCommands: CampaignCommandService;
  private readonly engagementCommands: EngagementCommandService;
  private readonly recoveryCommands: RecoveryCommandService;
  private readonly graphCorrectionCommands: GraphCorrectionCommandService;
  private readonly parseCommands: ParseCommandService;

  constructor(
    engine: GraphEngine,
    port: number = 8384,
    host?: string,
    sessionManager?: SessionManager,
    configPath?: string,
    applicationCommands?: ApplicationCommandService,
  ) {
    this.engine = engine;
    this.applicationCommands = applicationCommands ?? new ApplicationCommandService(engine);
    this.dispatchCommands = new DispatchCommandService(engine, this.applicationCommands);
    this.operatorCommands = new OperatorCommandService(engine, this.applicationCommands);
    this.approvalCommands = new ApprovalCommandService(engine, this.applicationCommands);
    this.agentLifecycleCommands = new AgentLifecycleCommandService(engine, this.applicationCommands);
    this.campaignCommands = new CampaignCommandService(engine, this.applicationCommands);
    this.engagementCommands = new EngagementCommandService(
      engine,
      this.applicationCommands,
    );
    this.recoveryCommands = new RecoveryCommandService(
      engine,
      this.applicationCommands,
    );
    this.graphCorrectionCommands = new GraphCorrectionCommandService(
      engine,
      this.applicationCommands,
    );
    this.parseCommands = new ParseCommandService(
      engine,
      this.applicationCommands,
    );
    this.port = port;
    this.host = host || process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
    this.sessionManager = sessionManager || null;
    this.configPath = configPath;
    if (configPath) {
      this.engagementManager = new EngagementManager(
        configPath,
        undefined,
        {
          readOnly: !engine.isPersistenceWritable(),
          isWritable: () => engine.isPersistenceWritable(),
        },
      );
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
      // Guard: a malformed Host header makes `new URL` throw. This runs before any
      // auth, in an 'upgrade' listener with no outer boundary, so an unhandled throw
      // would crash the daemon. Fail the handshake instead.
      let url: URL;
      try {
        url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      } catch {
        socket.destroy();
        return;
      }
      const pathname = url.pathname;

      // Reject cross-origin WebSocket handshakes (CSWSH). Browsers ALWAYS send an
      // Origin on a WS handshake and cannot spoof it; a malicious page the operator
      // visits could otherwise open ws://127.0.0.1/ws and read the full graph
      // (incl. credential material). Same-origin dashboard connections are allowed;
      // non-browser clients (no Origin) aren't a confused-deputy risk. Applies on
      // loopback too (that's exactly where the drive-by works).
      const origin = req.headers.origin;
      if (origin && !this.isAllowedWsOrigin(origin, req.headers.host)) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }

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
        if (!this.engine.isPersistenceWritable()) {
          socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
          socket.destroy();
          return;
        }
        if (!this.sessionManager) {
          socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
          socket.destroy();
          return;
        }
        this.sessionWss.handleUpgrade(req, socket, head, (ws) => {
          this.sessionWss.emit('connection', ws, req);
          const expectedConnectionId = url.searchParams.get('connection_id') ?? undefined;
          const expectedGenerationRaw = url.searchParams.get('connection_generation');
          const expectedConnectionGeneration = expectedGenerationRaw === null
            ? undefined
            : Number(expectedGenerationRaw);
          this.handleSessionConnection(ws, sessionMatch[1], {
            ...(expectedConnectionId !== undefined
              ? { expected_connection_id: expectedConnectionId }
              : {}),
            ...(expectedGenerationRaw !== null
              ? {
                  expected_connection_generation:
                    Number.isSafeInteger(expectedConnectionGeneration)
                    && (expectedConnectionGeneration ?? -1) >= 0
                      ? expectedConnectionGeneration
                      : Number.NaN,
                }
              : {}),
          });
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
      const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
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
    let detail = this.accumulator.drain();
    this.debounceTimer = null;
    if (!detail || this.clients.size === 0) return;

    // Build state first so graph metrics and the explicitly projected browser
    // communities describe the same topology generation.
    const state = this.buildFrontendState();
    const historyCount = this.engine.getFullHistory().length;

    const fullGraph = this.engine.exportGraph({ includeDerivedCommunities: true });

    // Some state projections perform a deterministic first-use initialization
    // (for example generating campaign records from the frontier). Those
    // writes synchronously call onGraphUpdate while this flush is building its
    // authoritative state. Fold them into this same generation: the state
    // above already contains them, and leaving the nested callback queued
    // would emit a redundant second graph_update.
    const nestedDetail = this.accumulator.drain();
    if (nestedDetail) {
      if (this.debounceTimer) clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
      const keys: Array<keyof GraphUpdateDetail> = [
        'new_nodes',
        'new_edges',
        'updated_nodes',
        'updated_edges',
        'inferred_edges',
        'removed_nodes',
        'removed_edges',
      ];
      detail = { ...detail };
      for (const key of keys) {
        const merged = [...new Set([...(detail[key] || []), ...(nestedDetail[key] || [])])];
        if (merged.length > 0) detail[key] = merged;
      }
    }

    // Build incremental delta: only the nodes/edges that changed.
    const changedNodeIds = new Set([...(detail.new_nodes || []), ...(detail.updated_nodes || [])]);
    const changedEdgeIds = new Set([...(detail.new_edges || []), ...(detail.updated_edges || []), ...(detail.inferred_edges || [])]);
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
          cold_nodes: fullGraph.cold_nodes ?? [],
        },
      },
    });
  }

  // ---- Session terminal bridge ----

  private handleSessionConnection(
    ws: WebSocket,
    sessionId: string,
    expected: {
      expected_connection_id?: string;
      expected_connection_generation?: number;
    } = {},
  ): void {
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
    if (
      (expected.expected_connection_id !== undefined
        && meta.connection_id !== expected.expected_connection_id)
      || (expected.expected_connection_generation !== undefined
        && meta.connection_generation !== expected.expected_connection_generation)
    ) {
      ws.close(4409, 'Session connection generation changed before attachment');
      return;
    }
    const connectionId = meta.connection_id;
    const connectionGeneration = meta.connection_generation;
    const expectedGeneration = {
      ...(connectionId !== undefined ? { connection_id: connectionId } : {}),
      ...(connectionGeneration !== undefined
        ? { connection_generation: connectionGeneration }
        : {}),
    };
    const generationAddressed = connectionId !== undefined || connectionGeneration !== undefined;
    const readGeneration = (from?: number, tail?: number) =>
      generationAddressed
        ? this.sessionManager!.read(sessionId, from, tail, expectedGeneration)
        : this.sessionManager!.read(sessionId, from, tail);

    // Send initial state
    ws.send(JSON.stringify({ type: 'session_meta', data: meta }));

    // Read initial buffer tail
    try {
      const initial = readGeneration(undefined, 8192);
      if (initial.text) {
        ws.send(JSON.stringify({ type: 'output', text: initial.text, end_pos: initial.end_pos }));
      }
    } catch { /* session may have closed between check and read */ }

    // Poll buffer for new output
    let cursor = readGeneration(undefined, 0).end_pos;

    const poller = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        clearInterval(poller);
        this.sessionPollers.delete(ws);
        return;
      }

      try {
        const current = this.sessionManager!.getSession(sessionId);
        if (
          !current
          || current.state !== 'connected'
          || current.connection_id !== connectionId
        ) {
          ws.send(JSON.stringify({
            type: 'session_closed',
            connection_id: connectionId,
          }));
          clearInterval(poller);
          this.sessionPollers.delete(ws);
          ws.close(4410, 'Session generation ended');
          return;
        }
        const result = readGeneration(cursor);
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
        // The persistence gate can close after the WebSocket was upgraded
        // (for example, after a third consecutive snapshot failure). Recheck
        // every command-shaped message so an existing socket cannot outlive
        // the service's writable generation.
        if (!this.engine.isPersistenceWritable()) {
          ws.send(JSON.stringify({
            type: 'error',
            op: 'persistence',
            code: 'PERSISTENCE_READ_ONLY',
            error: 'Durable mutations are disabled while persistence recovery is incomplete.',
            recovery: this.engine.getPersistenceRecoveryStatus(),
          }));
          ws.close(4503, 'Persistence is read-only');
          return;
        }
        const msg = JSON.parse(String(raw));
        const current = this.sessionManager!.getSession(sessionId);
        if (
          !current
          || current.state !== 'connected'
          || current.connection_id !== connectionId
        ) {
          ws.send(JSON.stringify({
            type: 'error',
            op: 'generation',
            code: 'SESSION_GENERATION_ENDED',
            error: 'This terminal is attached to a connection generation that has ended.',
          }));
          ws.close(4410, 'Session generation ended');
          return;
        }
        if (msg.type === 'input' && typeof msg.data === 'string') {
          try {
            if (generationAddressed) {
              this.sessionManager!.write(
                sessionId,
                msg.data,
                'dashboard',
                true,
                expectedGeneration,
              );
            } else {
              this.sessionManager!.write(sessionId, msg.data, 'dashboard', true);
            }
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

  /** True when an Origin header matches the request Host.
   *  Shared by the HTTP CORS gate and the WebSocket upgrade CSWSH check. */
  private isAllowedWsOrigin(origin: string, requestHost?: string): boolean {
    try {
      const originUrl = new URL(origin);
      if (originUrl.protocol !== 'http:' && originUrl.protocol !== 'https:') return false;
      const effectiveRequestHost = requestHost || `${this.host}:${this.port}`;
      // Interpret Host using the Origin scheme so default ports normalize
      // correctly (https://host and Host: host:443 are the same authority).
      const requestUrl = new URL(`${originUrl.protocol}//${effectiveRequestHost}`);
      const effectivePort = (url: URL): string => url.port || (url.protocol === 'https:' ? '443' : '80');
      if (
        originUrl.hostname.toLowerCase() === requestUrl.hostname.toLowerCase()
        && effectivePort(originUrl) === effectivePort(requestUrl)
      ) return true;
      return this.isLoopback(originUrl.hostname) && this.isLoopback(requestUrl.hostname);
    } catch {
      return false;
    }
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    // Top-level boundary: a synchronous throw in routing (e.g. a URIError from
    // decodeURIComponent on a malformed %-escape path) must not crash the daemon.
    const client = req.headers['x-overwatch-client'];
    const commandId = req.headers['x-overwatch-command-id'];
    const idempotencyKey = req.headers['idempotency-key'];
    const actorTaskId = req.headers['x-overwatch-actor-task-id'];
    withApplicationCommandInvocation(
      {
        transport: client === 'cli' ? 'cli' : 'dashboard',
        actor_task_id: typeof actorTaskId === 'string' && actorTaskId.trim()
          ? actorTaskId.trim()
          : null,
        request_id: `${req.method ?? 'GET'}:${req.url ?? '/'}:${randomUUID()}`,
        ...(typeof commandId === 'string' && commandId.trim()
          ? { command_id: commandId.trim() }
          : {}),
        ...(typeof idempotencyKey === 'string' && idempotencyKey.trim()
          ? { idempotency_key: idempotencyKey.trim() }
          : {}),
      },
      () => {
        try {
          this.handleHttpRoute(req, res);
        } catch {
          if (!res.headersSent) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Bad request' }));
          }
        }
      }
    );
  }

  private handleHttpRoute(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url || '/';
    const method = req.method || 'GET';

    // CORS: restrict to localhost origins (or env override)
    const origin = req.headers.origin || '';
    if (origin && this.isAllowedWsOrigin(origin, req.headers.host)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Idempotency-Key, X-Overwatch-Command-Id, X-Overwatch-Actor-Task-Id, X-Overwatch-Client',
    );

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

    // A partial WAL recovery remains inspectable, but no dashboard command may
    // start target work or create a new durable mutation until recovery is
    // complete.  Keep the two POST-shaped pure-read operations available.
    const readOnlyPost = pathname === '/api/config/scope/preview' || pathname === '/api/graph/export';
    const recoveryResolution = pathname === '/api/recovery/config/resolve' && method === 'POST';
    // Bundle generation records a durable audit event after streaming, so it
    // is a mutating operation even though its historical route uses GET.
    const mutatingGet = method === 'GET' && pathname === '/api/bundle';
    if (
      pathname.startsWith('/api/')
      && ((['POST', 'PATCH', 'DELETE'].includes(method) && !readOnlyPost && !recoveryResolution) || mutatingGet)
      && !this.engine.isPersistenceWritable()
    ) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Durable mutations are disabled while persistence recovery is incomplete.',
        code: 'PERSISTENCE_READ_ONLY',
        recovery: this.engine.getPersistenceRecoveryStatus(),
      }));
      return;
    }

    if (pathname === '/api/recovery' && method === 'GET') {
      this.serveRecovery(res);
    } else if (pathname === '/api/recovery/config/resolve' && method === 'POST') {
      this.handleResolveConfigDivergence(req, res);
    } else if (pathname === '/api/state') {
      this.serveState(res);
    } else if (pathname === '/api/graph') {
      this.serveGraph(res);
    } else if (pathname === '/api/history') {
      this.serveHistory(url, res);
    } else if (pathname === '/api/decision-log') {
      this.serveDecisionLog(url, res);
    } else if (pathname === '/api/timeline') {
      this.serveTimeline(url, res);
    } else if (pathname === '/api/find-paths') {
      this.serveFindPaths(url, res);
    } else if (pathname === '/api/sessions') {
      this.serveSessions(res);
    } else if (pathname === '/api/agents') {
      this.serveAgents(res);
    } else if (pathname === '/api/agents/dispatch' && method === 'POST') {
      this.handleAgentDispatch(req, res);
    } else if (pathname === '/api/agents/dispatch-batch' && method === 'POST') {
      this.handleAgentDispatchBatch(req, res);
    } else if (pathname === '/api/agents/quick-deploy' && method === 'POST') {
      this.handleQuickDeploy(req, res);
    } else if (pathname === '/api/agent-archetypes' && method === 'GET') {
      this.serveAgentArchetypes(res);
    } else if (pathname === '/api/fleet/directive' && method === 'POST') {
      this.handleFleetDirective(req, res);
    } else if (pathname === '/api/fleet/dismiss' && method === 'POST') {
      this.handleFleetDismiss(req, res);
    } else if (pathname === '/api/actions/approve-batch' && method === 'POST') {
      this.handleActionApproveBatch(req, res);
    } else if (pathname === '/api/actions/deny-batch' && method === 'POST') {
      this.handleActionDenyBatch(req, res);
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
      const agentDismissMatch = pathname.match(/^\/api\/agents\/([^/]+)\/dismiss$/);
      const agentDirectiveMatch = pathname.match(/^\/api\/agents\/([^/]+)\/directive$/);
      const applicationCommandMatch = pathname.match(/^\/api\/commands\/([^/]+)$/);
      const agentQueryAnswerMatch = pathname.match(/^\/api\/agent-queries\/([^/]+)\/answer$/);
      const objectiveMatch = pathname.match(/^\/api\/config\/objectives\/([^/]+)$/);
      const campaignDetailMatch = pathname.match(/^\/api\/campaigns\/([^/]+)$/);
      const campaignActionMatch = pathname.match(/^\/api\/campaigns\/([^/]+)\/action$/);
      const campaignDispatchMatch = pathname.match(/^\/api\/campaigns\/([^/]+)\/dispatch$/);
      const campaignCloneMatch = pathname.match(/^\/api\/campaigns\/([^/]+)\/clone$/);
      const campaignSplitMatch = pathname.match(/^\/api\/campaigns\/([^/]+)\/split$/);
      const campaignChildrenMatch = pathname.match(/^\/api\/campaigns\/([^/]+)\/children$/);
      const actionExplainMatch = pathname.match(/^\/api\/actions\/([^/]+)\/explain$/);
      // Raw tool-output for the Analysis workspace. Action ids are `act_<hex>`
      // or a uuid (the `act_` underscore falls outside [a-f0-9-]), so match the
      // full id charset — an unknown id is just a 404 in the handler.
      const actionOutputMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/output$/);
      const actionReparseMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/reparse$/);
      const evidenceRawMatch = pathname.match(/^\/api\/evidence\/([^/]+)\/raw$/);
      const evidenceImageMatch = pathname.match(/^\/api\/evidence\/([^/]+)\/image$/);
      // Action ids are `act_<hex>` (deterministic, nonce-bearing engagements) or
      // a uuid — both fall outside [a-f0-9-] because of the `act_` underscore, so
      // a hex-only class silently 404s every real action. Match the full id
      // charset (the queue does an exact lookup, so an unknown id is just a 404).
      const actionApproveMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/approve$/);
      const actionDenyMatch = pathname.match(/^\/api\/actions\/([A-Za-z0-9_-]+)\/deny$/);
      const sessionCloseMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/close$/);
      const sessionResumeMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/resume$/);
      const sessionBufferMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)\/buffer$/);
      const sessionDetailMatch = pathname.match(/^\/api\/sessions\/([a-f0-9-]+)$/);
      const evidenceChainMatch = pathname.match(/^\/api\/evidence-chains\/([^/]+)$/);
      const pathsMatch = pathname.match(/^\/api\/paths\/([^/]+)$/);
      const findingContextMatch = pathname.match(/^\/api\/findings\/([^/]+)\/context$/);
      const reportDetailMatch = pathname.match(/^\/api\/reports\/([a-f0-9-]+)$/);

      if (applicationCommandMatch && method === 'GET') {
        this.serveApplicationCommand(decodeURIComponent(applicationCommandMatch[1]), res);
      } else if (agentCtxMatch) {
        this.serveAgentContext(decodeURIComponent(agentCtxMatch[1]), res);
      } else if (agentHistoryMatch) {
        this.serveAgentHistory(decodeURIComponent(agentHistoryMatch[1]), res);
      } else if (agentConsoleMatch) {
        this.serveAgentConsole(decodeURIComponent(agentConsoleMatch[1]), url, res);
      } else if (agentCancelMatch && method === 'POST') {
        this.handleAgentCancel(decodeURIComponent(agentCancelMatch[1]), req, res);
      } else if (agentDismissMatch && method === 'POST') {
        this.handleAgentDismiss(decodeURIComponent(agentDismissMatch[1]), req, res);
      } else if (agentDirectiveMatch && method === 'POST') {
        this.handleAgentDirective(decodeURIComponent(agentDirectiveMatch[1]), req, res);
      } else if (agentQueryAnswerMatch && method === 'POST') {
        this.handleAnswerAgentQuery(decodeURIComponent(agentQueryAnswerMatch[1]), req, res);
      } else if (objectiveMatch && method === 'PATCH') {
        this.handleUpdateObjective(decodeURIComponent(objectiveMatch[1]), req, res);
      } else if (objectiveMatch && method === 'DELETE') {
        this.handleDeleteObjective(decodeURIComponent(objectiveMatch[1]), req, res);
      } else if (campaignActionMatch && method === 'POST') {
        this.handleCampaignAction(decodeURIComponent(campaignActionMatch[1]), req, res);
      } else if (campaignDispatchMatch && method === 'POST') {
        this.handleCampaignDispatch(decodeURIComponent(campaignDispatchMatch[1]), req, res);
      } else if (campaignCloneMatch && method === 'POST') {
        this.handleCampaignClone(decodeURIComponent(campaignCloneMatch[1]), req, res);
      } else if (campaignSplitMatch && method === 'POST') {
        this.handleCampaignSplit(decodeURIComponent(campaignSplitMatch[1]), req, res);
      } else if (campaignChildrenMatch) {
        this.serveCampaignChildren(decodeURIComponent(campaignChildrenMatch[1]), res);
      } else if (campaignDetailMatch && method === 'PATCH') {
        this.handleCampaignUpdate(decodeURIComponent(campaignDetailMatch[1]), req, res);
      } else if (campaignDetailMatch && method === 'DELETE') {
        this.handleCampaignDelete(decodeURIComponent(campaignDetailMatch[1]), req, res);
      } else if (campaignDetailMatch) {
        this.serveCampaignDetail(decodeURIComponent(campaignDetailMatch[1]), res);
      } else if (actionExplainMatch && method === 'GET') {
        this.serveActionExplanation(decodeURIComponent(actionExplainMatch[1]), res);
      } else if (actionOutputMatch && method === 'GET') {
        this.serveActionOutput(decodeURIComponent(actionOutputMatch[1]), url, res);
      } else if (actionReparseMatch && method === 'POST') {
        this.handleActionReparse(decodeURIComponent(actionReparseMatch[1]), req, res);
      } else if (evidenceRawMatch && method === 'GET') {
        this.serveEvidenceRaw(decodeURIComponent(evidenceRawMatch[1]), url, res);
      } else if (evidenceImageMatch && method === 'GET') {
        this.serveEvidenceImage(decodeURIComponent(evidenceImageMatch[1]), res);
      } else if (actionApproveMatch && method === 'POST') {
        this.handleActionApprove(actionApproveMatch[1], req, res);
      } else if (actionDenyMatch && method === 'POST') {
        this.handleActionDeny(actionDenyMatch[1], req, res);
      } else if (sessionCloseMatch && method === 'POST') {
        this.handleSessionClose(sessionCloseMatch[1], req, res);
      } else if (sessionResumeMatch && method === 'POST') {
        this.handleSessionResume(sessionResumeMatch[1], req, res);
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
        this.handleReportDelete(reportDetailMatch[1], req, res);
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
      if (!this.requireWritablePersistence(res)) return;
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
      if (!this.engagementManager) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Engagement manager not available' }));
        return;
      }
      try {
        if (!this.requireWritablePersistence(res)) return;
        let config;
        try {
          config = mergeTemplateWithConfig(template, overrides as any);
        } catch (error) {
          throw new EngagementManagerError(
            'ENGAGEMENT_VALIDATION_FAILED',
            `Template overrides are invalid: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
        // Persist so a created-from-template engagement actually lands on disk
        // (it previously only returned the config). persistConfig is the shared
        // write gateway — it enforces id-safety, nonce minting, and no-overwrite.
        const engagement = this.engagementManager.persistConfig(config);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ config, persisted: true, engagement }));
      } catch (error) {
        this.respondEngagementManagerFailure(res, error);
      }
    }).catch(() => {
      if (!this.engine.isPersistenceWritable()) {
        this.requireWritablePersistence(res);
        return;
      }
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  // ---- Settings endpoints ----

  private serveSettings(res: ServerResponse): void {
    const config = this.engine.getConfig();
    const opsec = config.opsec;
    const opsecStatus = this.engine.getOpsecStatus();
    const payload = SettingsDtoSchema.parse({
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
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  private handleUpdateSettings(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const parsed = SettingsPatchSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid settings patch', issues: parsed.error.issues }));
        return;
      }
      const execution = this.engagementCommands.updateSettings(parsed.data, {
        transport: 'dashboard',
      });
      const payload = SettingsUpdateResultSchema.parse({
        ...execution.result,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    }).catch(error => {
      if (error instanceof Error && error.message === 'Invalid JSON') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        return;
      }
      this.respondEngagementCommandFailure(res, error);
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
      if (!this.requireWritablePersistence(res)) return;
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
        const execution = this.engagementCommands.patchConfig(b, {
          transport: 'dashboard',
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ...execution.result,
          command_id: execution.command_id,
          idempotency_key: execution.idempotency_key,
          replayed: execution.replayed,
        }));
      } catch (err) {
        this.respondEngagementCommandFailure(res, err);
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleUpdateScope(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      try {
        const execution = this.engagementCommands.replaceScope(body, {
          transport: 'dashboard',
        });
        const scopeResult = execution.result!;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          updated: scopeResult.updated,
          scope: scopeResult.scope,
          applied: scopeResult.applied,
          affected_node_count: scopeResult.affected_node_count,
          command_id: execution.command_id,
          idempotency_key: execution.idempotency_key,
          replayed: execution.replayed,
        }));
      } catch (err) {
        this.respondEngagementCommandFailure(res, err);
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
        const preview = this.engagementCommands.previewScope(body);
        const diff = (next: string[], current: string[]) => ({
          add: next.filter(value => !current.includes(value)),
          remove: current.filter(value => !next.includes(value)),
        });
        const cidrsDiff = diff(preview.after.cidrs, preview.before.cidrs);
        const domainsDiff = diff(
          preview.after.domains,
          preview.before.domains,
        );
        const exclusionsDiff = diff(
          preview.after.exclusions,
          preview.before.exclusions,
        );

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ...preview,
          added: { cidrs: cidrsDiff.add, domains: domainsDiff.add, exclusions: exclusionsDiff.add },
          removed: { cidrs: cidrsDiff.remove, domains: domainsDiff.remove, exclusions: exclusionsDiff.remove },
          changed_fields: Object.keys(preview.after).filter(key =>
            JSON.stringify(
              (preview.before as unknown as Record<string, unknown>)[key],
            ) !== JSON.stringify(
              (preview.after as unknown as Record<string, unknown>)[key],
            )),
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
      if (!this.requireWritablePersistence(res)) return;
      const parsed = ObjectiveCreateRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid objective create request', issues: parsed.error.issues }));
        return;
      }
      const execution = this.engagementCommands.addObjective(parsed.data, {
        transport: 'dashboard',
      });
      const payload = ObjectiveCreateResponseSchema.parse({
        ...execution.result,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    }).catch(error => {
      if (error instanceof Error && (error.message === 'Invalid JSON' || error.message === 'Body too large')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        return;
      }
      this.respondEngagementCommandFailure(res, error);
    });
  }

  private handleUpdateObjective(id: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const parsed = ObjectiveUpdateRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid objective update request', issues: parsed.error.issues }));
        return;
      }
      const execution = this.engagementCommands.updateObjective(
        id,
        parsed.data,
        { transport: 'dashboard' },
      );
      const payload = ObjectiveUpdateResponseSchema.parse({
        updated: true,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    }).catch(error => {
      if (error instanceof Error && (error.message === 'Invalid JSON' || error.message === 'Body too large')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        return;
      }
      this.respondEngagementCommandFailure(res, error);
    });
  }

  private handleDeleteObjective(id: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.requireWritablePersistence(res)) return;
    try {
      const execution = this.engagementCommands.deleteObjective(id, {
        transport: 'dashboard',
      });
      const payload = ObjectiveDeleteResponseSchema.parse({
        deleted: true,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (error) {
      this.respondEngagementCommandFailure(res, error);
    }
  }

  // ---- Agent dispatch endpoint ----

  private handleAgentDispatch(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const execution = this.dispatchCommands.dispatch(body);
      const result = execution.result!;
      res.writeHead(result.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...result.body,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondDispatchCommandFailure(res, error);
    });
  }

  // ---- Fan-out dispatch ----
  // Deploy N agents across a selection of nodes in one call, WITHOUT overlap.
  // Node-scoped dispatch has no frontier lease (leases key on frontier_item_id),
  // so non-overlap is enforced here: input ids are de-duped, and any node already
  // covered by a RUNNING task (or claimed earlier in this same batch) is skipped
  // — so re-running a fan-out over the same selection cleanly no-ops instead of
  // stacking redundant agents on the same asset.
  //   Body: { target_node_ids: string[], mode?: 'per-node'|'per-batch',
  //           batch_size?, archetype?, skill?, model?, objective? }
  //   'per-node' (default): one agent per distinct node (distinct lanes).
  //   'per-batch': group up to batch_size nodes per agent.
  // Returns 200 with aggregated { dispatched, skipped, deferred, summary }.
  private handleAgentDispatchBatch(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const execution = this.dispatchCommands.dispatchBatch(body);
      const result = execution.result!;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...result,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondDispatchCommandFailure(res, error);
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
      if (!this.requireWritablePersistence(res)) return;
      const execution = this.dispatchCommands.quickDeploy(body);
      const result = execution.result!;
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...result,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondDispatchCommandFailure(res, error);
    });
  }

  // The agent-type catalog for the dashboard Deploy picker (read-only).
  private serveAgentArchetypes(res: ServerResponse): void {
    const archetypes = listArchetypes().map(a => ({
      id: a.id, label: a.label, description: a.description,
      role: a.role, defaultSkill: a.defaultSkill, suitableFor: a.suitableFor,
    }));
    // Models the Deploy picker offers: the operator's configured list, or a
    // sensible default set. When available_models is set, dispatch validation
    // (resolveDispatchModel) also restricts to it — so an org that lacks a model
    // simply omits it from engagement.json.
    const config = this.engine.getConfig();
    const DEFAULT_MODELS = ['claude-opus-4-8', 'claude-sonnet-5', 'claude-haiku-4-5'];
    const available = config.available_models && config.available_models.length > 0
      ? config.available_models
      : DEFAULT_MODELS;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ archetypes, models: { available, default: config.default_agent_model } }));
  }

  // ---- NL operator command (Phase 3A) ----
  // Two-phase, like update_scope: a command is first interpreted into a plan
  // (preview, no mutation); the operator then confirms the plan_id to execute.
  // Nothing mutates without an explicit confirm.
  private buildInterpreterState(): InterpreterState {
    return {
      tasks: this.engine.getAgentTasks().map(t => ({
        task_id: t.task_id ?? t.id,
        agent_label: t.agent_label ?? t.agent_id,
        id: t.id,
        agent_id: t.agent_id,
        status: t.status,
        skill: t.skill,
      })),
      pendingActionIds: this.engine.getPendingActionQueue().getPending().map(a => a.action_id),
    };
  }

  private serveProposedPlans(res: ServerResponse): void {
    const plans = this.engine.getProposedPlanStore().getOpen();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ plans }));
  }

  private serveApplicationCommand(commandId: string, res: ServerResponse): void {
    const command = this.engine.getApplicationCommandById(commandId);
    if (!command) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'command not found', command_id: commandId }));
      return;
    }
    const existingResult = command.result
      && typeof command.result === 'object'
      && !Array.isArray(command.result)
      ? command.result as Record<string, unknown>
      : {};
    const linkedPlan = command.plan_id
      && !existingResult.plan
      ? this.engine.getProposedPlanStore().get(command.plan_id)
      : undefined;
    const projectedCommand = linkedPlan
      ? {
          ...command,
          result: {
            ...existingResult,
            phase: 'plan_ready',
            command_id: command.command_id,
            planner_task_id:
              existingResult.planner_task_id
              ?? command.entity_refs?.planner_task_id,
            plan_id: linkedPlan.plan_id,
            plan: linkedPlan,
          },
        }
      : command;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ command: projectedCommand }));
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
      if (!this.requireWritablePersistence(res)) return;
      const b = (body ?? {}) as Record<string, unknown>;
      const answer = typeof b.answer === 'string' ? b.answer.trim() : '';
      if (!answer) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'answer (non-empty string) is required' }));
        return;
      }
      const execution = this.agentLifecycleCommands.answerQuestions({
        query_ids: [queryId],
        answer,
      }, { transport: 'dashboard' });
      const resolved = execution.result!.queries[0];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        query: resolved,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondAgentLifecycleCommandFailure(res, error);
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
      if (!this.requireWritablePersistence(res)) return;
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
      const execution = this.agentLifecycleCommands.answerQuestions({
        query_ids: queryIds,
        answer,
      }, { transport: 'dashboard' });
      const resolved = execution.result!.queries;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        answered: resolved.length,
        queries: resolved,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondAgentLifecycleCommandFailure(res, error);
    });
  }

  private handleCommand(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const b = (body ?? {}) as Record<string, unknown>;
      // Dismiss a planner-proposed plan without executing it.
      if (b.deny === true && typeof b.plan_id === 'string') {
        try {
          const execution = this.operatorCommands.denyPlan(b.plan_id, {
            transport: 'dashboard',
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            idempotency_key: execution.idempotency_key,
            replayed: execution.replayed,
          }));
        } catch (error) {
          this.respondOperatorCommandFailure(res, error);
        }
        return;
      }

      // Phase 2 of the flow: confirm + execute a previously-previewed plan. The
      // plan_id may be a grammar plan (commandPlans) or a planner-proposed plan
      // (the shared ProposedPlanStore) — both execute through the same path.
      if (b.confirm === true && typeof b.plan_id === 'string') {
        try {
          const execution = this.operatorCommands.confirmPlan(b.plan_id, {
            transport: 'dashboard',
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            idempotency_key: execution.idempotency_key,
            replayed: execution.replayed,
          }));
        } catch (error) {
          this.respondOperatorCommandFailure(res, error);
        }
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

      // Read-only QUERY fast path: runs BEFORE the mutation grammar and
      // short-circuits on a hit. Queries execute immediately (no confirm gate,
      // nothing mutates) and never reach interpretCommand or the planner. A
      // null result means it's not a query → fall through unchanged.
      const queryOp = interpretQuery(command);
      if (queryOp) {
        let query_answer: QueryAnswer;
        try {
          query_answer = executeQuery(this.engine, queryOp, { skills: this.skills });
        } catch (err) {
          query_answer = { kind: 'unanswerable', summary: err instanceof Error ? err.message : String(err) };
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ops: [], summary: query_answer.summary, unresolved: [], needs_planner: false, query_answer }));
        return;
      }

      const interp = interpretCommand(command, state);
      let plan_id: string | undefined;
      let preview_command_id: string | undefined;
      if (interp.ops.length > 0) {
        const execution = this.operatorCommands.createGrammarPlan(
          command,
          interp.ops,
          { transport: 'dashboard' },
        );
        plan_id = execution.result!.plan_id;
        preview_command_id = execution.command_id;
      }

      // The grammar punted entirely — hand the free-form command to a headless
      // planner (3A.2). It proposes ops asynchronously; the operator confirms
      // the proposed plan via the same confirm path (polling GET /api/plans).
      const needsPlanner = interp.unresolved.length > 0 && interp.ops.length === 0;
      let planner_task_id: string | undefined;
      let planner_command_id: string | undefined;
      let planner_status: string | undefined;
      let planner_available = true;
      let planner_plan: unknown;
      if (needsPlanner) {
        const execution = this.operatorCommands.requestPlanner(
          command,
          state,
          {
            runtime_available:
              this.taskExecution?.isHeadlessAvailable() === true,
          },
          { transport: 'dashboard' },
        );
        planner_command_id = execution.command_id;
        planner_status = execution.status;
        if (typeof execution.result?.planner_task_id === 'string') {
          planner_task_id = execution.result.planner_task_id;
        } else if (
          typeof execution.record.entity_refs?.planner_task_id === 'string'
        ) {
          planner_task_id = execution.record.entity_refs.planner_task_id;
        }
        planner_plan = execution.result?.plan;
        if (!planner_plan && execution.record.plan_id) {
          planner_plan = this.engine.getProposedPlanStore()
            .get(execution.record.plan_id);
        }
        if (
          execution.status === 'failed'
          || execution.status === 'interrupted'
        ) {
          planner_available = false;
        }
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
        command_id: planner_command_id ?? preview_command_id,
        planner_status,
        planner_available: needsPlanner ? planner_available : undefined,
        planner_plan,
      }));
    }).catch(error => {
      if (
        error instanceof Error
        && (error.message === 'Invalid JSON' || error.message === 'Body too large')
      ) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        return;
      }
      this.respondOperatorCommandFailure(res, error);
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
      if (!this.requireWritablePersistence(res)) return;
      const parsed = FrontierWeightsPatchSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid frontier weight patch', issues: parsed.error.issues }));
        return;
      }
      this.engine.setFrontierWeights({
        fan_out: parsed.data.fan_out,
        noise: parsed.data.noise,
      });
      const payload = FrontierWeightsUpdateResultSchema.parse({ updated: true, weights: this.engine.getFrontierWeights() });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
  }

  private handleResetFrontierWeights(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.engine.resetFrontierWeights();
    const payload = FrontierWeightsResetResultSchema.parse({ reset: true, weights: this.engine.getFrontierWeights() });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  // ---- Health endpoint ----

  private serveHealth(res: ServerResponse): void {
    try {
      const health = this.engine.getHealthReport();
      const adContext = this.engine.checkADContext();
      const graph = this.engine.exportGraph();
      const payload = HealthDtoSchema.parse({
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
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
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
    const allCampaigns = this.engine.listCampaigns();
    const allAgents = this.engine.getAllAgents();
    // The global noise context (budget remaining, recommended approach, time
    // window) is the same for every campaign — compute it once. Only the
    // per-campaign noise contribution differs, via the tracker's accessor.
    const opsecCtx = this.engine.getOpsecContext();
    const maxNoise = this.engine.getConfig().opsec.max_noise;
    const tracker = this.engine.getOpsecTracker();
    return campaigns.map(c => {
      const children = allCampaigns.filter(candidate => candidate.parent_id === c.id);
      const aggregateProgress = children.length > 0 ? this.engine.getCampaignParentProgress(c.id) : null;
      const derivedStatus = children.length > 0 ? this.engine.deriveCampaignParentStatus(c.id) : null;
      const projectedFindings = [...new Set([
        ...(c.findings ?? []),
        ...children.flatMap(child => child.findings ?? []),
      ])];
      const campaignIds = new Set([c.id, ...children.map(child => child.id)]);
      const agents = allAgents.filter(a => a.campaign_id && campaignIds.has(a.campaign_id));
      const progress = aggregateProgress ?? c.progress;
      const completed = progress?.completed ?? 0;
      const total = progress?.total ?? c.items.length;
      const completionPct = total > 0 ? Math.round((completed / total) * 100) : 0;
      const runningAgents = agents.filter(a => a.status === 'running').length;
      return {
        ...c,
        status: derivedStatus ?? c.status,
        progress,
        findings: projectedFindings,
        agent_count: agents.length,
        running_agents: runningAgents,
        agents_total: agents.length,
        agents_active: runningAgents,
        completion_pct: completionPct,
        findings_count: projectedFindings.length,
        child_count: children.length || undefined,
        opsec: {
          global_noise_spent: [...campaignIds].reduce((totalNoise, id) => totalNoise + tracker.getCampaignNoise(id), 0),
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

  private buildFrontendState(): Omit<ReturnType<GraphEngine['getState']>, 'agents'> & {
    agents: AgentDto[];
    sessions: ReturnType<NonNullable<SessionManager>['list']>;
    pending_actions: PendingAction[];
    campaigns: DashboardCampaign[];
  } {
    const state = this.engine.getState();
    const sessions = this.sessionManager?.list() ?? [];
    const pending_actions = this.getDashboardApprovalRecords()
      .filter(action => action.status === 'pending') as PendingAction[];
    const campaigns = this.enrichCampaigns();
    const agents = projectAgentDtos(state.agents, this.engine.getFullHistory(), campaigns);
    return { ...state, agents, sessions, pending_actions, campaigns };
  }

  private serveState(res: ServerResponse): void {
    const state = this.buildFrontendState();
    const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
    const historyCount = this.engine.getFullHistory().length;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ state, graph, history_count: historyCount }));
  }

  private serveRecovery(res: ServerResponse): void {
    const payload = RecoveryStatusResponseSchema.parse({
      recovery: this.engine.getPersistenceRecoveryStatus(),
    });
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify(payload));
  }

  private handleResolveConfigDivergence(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      const parsed = ConfigDivergenceResolveRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Invalid configuration reconciliation request',
          issues: parsed.error.issues,
        }));
        return;
      }
      try {
        const execution = this.recoveryCommands.resolveConfig({
          mode: parsed.data.resolution,
          expected_file_hash: parsed.data.expected_file_hash,
          expected_state_hash: parsed.data.expected_state_hash,
        }, { transport: 'dashboard' });
        const payload = ConfigDivergenceResolveResponseSchema.parse({
          ...execution.result,
          command_id: execution.command_id,
          idempotency_key: execution.idempotency_key,
          replayed: execution.replayed,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      } catch (error) {
        this.respondRecoveryCommandFailure(res, error);
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
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
    // event_types=a,b,c restricts to those event types BEFORE the limit slice. Without
    // it, `?limit=N` returns the most-recent N of the WHOLE stream — heartbeats,
    // thoughts, agent updates and all — so a chatty engagement crowds tool runs out of
    // the window (the Analysis view then shows only a fraction of the runs that exist).
    // Filtering first means `limit=N&event_types=action_started,...` yields the most
    // recent N ACTION events, undiluted.
    const rawTypes = params.get('event_types') || undefined;
    const typeFilter = rawTypes
      ? new Set(rawTypes.split(',').map(s => s.trim()).filter(Boolean))
      : undefined;
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
    if (typeFilter && typeFilter.size > 0) {
      entries = entries.filter(e => e.event_type !== undefined && typeFilter.has(e.event_type));
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
    const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
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
  // Raster image types the evidence-image route will serve. Deliberately EXCLUDES
  // SVG (which can carry scripts) — screenshots are raster.
  private static readonly IMAGE_MIME_TYPES: Record<string, string> = {
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  };
  private static readonly MAX_IMAGE_BYTES = 25 * 1024 * 1024;

  /** Serve a `screenshot` evidence blob as raw image bytes (binary-safe). */
  private serveEvidenceImage(evidenceId: string, res: ServerResponse): void {
    const store = this.engine.getEvidenceStore();
    const record = store.getRecord(evidenceId);
    if (!record) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `No evidence found for ${evidenceId}` }));
      return;
    }
    const ext = extname(record.filename || '').toLowerCase();
    // Only serve screenshot-typed evidence as an image; derive the content-type
    // from the filename, defaulting a screenshot with no/unknown ext to PNG.
    const mime = DashboardServer.IMAGE_MIME_TYPES[ext] || (record.evidence_type === 'screenshot' ? 'image/png' : '');
    if (record.evidence_type !== 'screenshot' || !mime) {
      res.writeHead(415, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Evidence ${evidenceId} is not a viewable image` }));
      return;
    }
    // Bound the read before loading the whole blob into memory (a screenshot-typed
    // record can be planted with arbitrary size via report_finding). The paired
    // /raw route caps reads too; keep this route from OOMing the process.
    if ((record.content_length ?? 0) > DashboardServer.MAX_IMAGE_BYTES) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Evidence ${evidenceId} exceeds the ${DashboardServer.MAX_IMAGE_BYTES}-byte image cap` }));
      return;
    }
    const buf = store.getContentBuffer(evidenceId);
    if (!buf) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `No image bytes for ${evidenceId}` }));
      return;
    }
    // `nosniff` + inline disposition: the bytes are operator-controlled, so serve
    // them as an inert declared image and never let a browser sniff them as HTML.
    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': 'no-cache',
      'Content-Length': buf.length,
      'X-Content-Type-Options': 'nosniff',
      'Content-Disposition': 'inline',
    });
    res.end(buf);
  }

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
      if (!this.requireWritablePersistence(res)) return;
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
      const storedParserContext = [...this.engine.getFullHistory()].reverse()
        .filter(event => event.action_id === actionId && event.event_type === 'parse_output')
        .map(event => (event.details as Record<string, unknown> | undefined)?.parser_context)
        .find((value): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value));
      const parserContext = body?.context ?? storedParserContext;
      const contextKeys = parserContext && typeof parserContext === 'object'
        && !Array.isArray(parserContext)
        ? Object.keys(parserContext).sort()
        : [];
      const resolvedEvidenceId = store.resolveKey(evidenceId)!;
      return this.parseCommands.execute(
        {
          tool_name: toolName,
          source_kind: 'evidence',
          source_reference: resolvedEvidenceId,
          source_length: Buffer.byteLength(raw),
          source_fingerprint: buildParseSourceFingerprint({
            source_kind: 'evidence',
            source_reference: resolvedEvidenceId,
            output: raw,
            tool_name: toolName,
            context: parserContext ?? {},
            ingest,
          }),
          context_keys: contextKeys,
          agent_id: 'operator',
          action_id: actionId,
          ingest,
        },
        commandCompletion => parseAndMaybeIngest(this.engine, {
          tool_name: toolName,
          outputText: raw,
          action_id: actionId,
          ingest,
          context: parserContext,
          agent_id: 'operator',
          command_completion: commandCompletion,
        }),
        { action_id: actionId },
      ).then(result => {
        res.writeHead(200, JSON_HEADERS);
        res.end(JSON.stringify({
          ...result,
          evidence_id: resolvedEvidenceId,
        }));
      });
    }).catch(err => {
      const message = err instanceof Error ? err.message : String(err);
      const conflict = err instanceof ApplicationCommandConflictError;
      res.writeHead(conflict ? 409 : 400, JSON_HEADERS);
      res.end(JSON.stringify({
        error: message,
        ...(conflict ? { code: err.code } : {}),
      }));
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
    const expectedConnectionId = params.get('connection_id') ?? undefined;
    const expectedConnectionGenerationRaw = params.get('connection_generation');
    const from = rawFrom !== null ? parseInt(rawFrom, 10) : undefined;
    const tailBytes = rawTail !== null ? Math.min(Math.max(parseInt(rawTail, 10) || 4096, 0), 65536) : undefined;
    const expectedConnectionGeneration = expectedConnectionGenerationRaw === null
      ? undefined
      : Number(expectedConnectionGenerationRaw);

    try {
      const expectedGeneration = {
        ...(expectedConnectionId !== undefined
          ? { connection_id: expectedConnectionId }
          : {}),
        ...(expectedConnectionGenerationRaw !== null
          ? {
              connection_generation:
                Number.isSafeInteger(expectedConnectionGeneration)
                && (expectedConnectionGeneration ?? -1) >= 0
                  ? expectedConnectionGeneration
                  : Number.NaN,
            }
          : {}),
      };
      const result = expectedConnectionId !== undefined
        || expectedConnectionGenerationRaw !== null
        ? this.sessionManager.read(
            sessionId,
            Number.isFinite(from) ? from : undefined,
            tailBytes,
            expectedGeneration,
          )
        : this.sessionManager.read(
            sessionId,
            Number.isFinite(from) ? from : undefined,
            tailBytes,
          );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const code = err && typeof err === 'object' && 'code' in err
        ? String((err as { code?: unknown }).code ?? '')
        : '';
      const notFound = /not found/i.test(message);
      const generationConflict = code === 'SESSION_GENERATION_CHANGED';
      res.writeHead(notFound ? 404 : generationConflict ? 409 : 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message, ...(code ? { code } : {}) }));
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

  private handleSessionResume(sessionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.sessionManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session manager not available' }));
      return;
    }
    if (!this.requireWritablePersistence(res)) return;
    this.sessionManager.resume(sessionId, 'dashboard', true).then(result => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ resumed: true, metadata: result.metadata }));
    }).catch(err => {
      if (!this.engine.isPersistenceWritable()) {
        this.requireWritablePersistence(res);
        return;
      }
      const message = err instanceof Error ? err.message : String(err);
      const code = err && typeof err === 'object' && 'code' in err
        ? String((err as { code?: unknown }).code ?? '')
        : '';
      const notFound = /not found/i.test(message);
      const conflict = code === 'SESSION_NOT_RESUMABLE'
        || code === 'SESSION_RESUME_CONFLICT'
        || /not an explicitly resumable|already has a runtime listener/i.test(message);
      res.writeHead(notFound ? 404 : conflict ? 409 : 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message, ...(code ? { code } : {}) }));
    });
  }

  private handleSessionUpdate(sessionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.sessionManager) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session manager not available' }));
      return;
    }
    this.readJsonBody(req).then(body => {
      // Request routing checked the gate before body I/O. Recheck after the
      // await and immediately before touching SessionManager metadata.
      if (!this.requireWritablePersistence(res)) return;
      const updates: { title?: string; notes?: string } = {};
      if (typeof body?.title === 'string') updates.title = body.title;
      if (typeof body?.notes === 'string') updates.notes = body.notes;
      const metadata = this.sessionManager!.update(sessionId, updates, 'dashboard', true);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ metadata }));
    }).catch((err) => {
      if (!this.engine.isPersistenceWritable()) {
        this.requireWritablePersistence(res);
        return;
      }
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
    const enriched = projectAgentDtos(
      this.engine.getAllAgents(),
      this.engine.getFullHistory(),
      this.engine.listCampaigns(),
    );
    const payload = AgentListResponseSchema.parse({ agents: enriched, total: enriched.length });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
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
    const agentId = task.agent_label ?? task.agent_id;
    const uniqueLabel = this.engine.getAgentTasks()
      .filter(candidate => (candidate.agent_label ?? candidate.agent_id) === agentId).length === 1;
    // Include events tagged with either the human-readable agent_id or the
    // task UUID — submit_agent_transcript / log_action_event events are
    // recorded against linked_agent_task_id, which the simple agent_id filter
    // would miss.
    const entries = this.engine.getFullHistory().filter(e =>
      (e as { linked_agent_task_id?: string }).linked_agent_task_id === taskId
      || (uniqueLabel && e.agent_id === agentId)
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
    const agentLabel = task.agent_label ?? task.agent_id;
    const allowLegacyLabel = this.engine.getAgentTasks()
      .filter(candidate => (candidate.agent_label ?? candidate.agent_id) === agentLabel).length === 1;
    const events = buildAgentConsoleEvents(this.engine.getFullHistory(), task, {
      limit: Number.isFinite(limit) && limit > 0 ? limit : 80,
      after,
      allowLegacyLabel,
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
    const REASON = 'Cancelled by operator via dashboard';
    try {
      const execution = this.agentLifecycleCommands.cancel(
        taskId,
        REASON,
        { transport: 'dashboard' },
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...execution.result,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    } catch (error) {
      this.respondAgentLifecycleCommandFailure(res, error);
    }
  }

  // Remove a terminal agent from the roster. Gated to terminal statuses — a live
  // agent must be cancelled first (which kills the process + releases the lease).
  private handleAgentDismiss(taskId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    // Optional `{ force: true }` body: force-terminate a live agent and remove it in
    // one step, so a wedged sub-agent can always be cleared without a cancel→dismiss
    // dance that can dead-end. No body → legacy behavior (terminal-only).
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      try {
        const force = !!(body && typeof body === 'object' && (body as Record<string, unknown>).force === true);
        const execution = this.agentLifecycleCommands.dismiss(
          taskId,
          force,
          { transport: 'dashboard' },
        );
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ...execution.result,
          command_id: execution.command_id,
          replayed: execution.replayed,
        }));
      } catch (error) {
        this.respondAgentLifecycleCommandFailure(res, error);
      }
    }).catch(error => {
      this.respondAgentLifecycleCommandFailure(res, error);
    });
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
      if (!this.requireWritablePersistence(res)) return;
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
      // Allow a directive to a running agent (acts live) or a pending one
      // (queued — the agent acknowledges it on its first heartbeat once it
      // launches). Terminal agents can't act on anything, so reject those.
      if (task.status !== 'running' && task.status !== 'pending') {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Agent is ${task.status} — directives only apply to running or pending agents` }));
        return;
      }
      const execution = this.agentLifecycleCommands.issueDirective({
        task_id: taskId,
        kind: kind as AgentDirectiveKind,
        node_ids: Array.isArray(b.node_ids) ? (b.node_ids as unknown[]).filter(x => typeof x === 'string') as string[] : undefined,
        frontier_types: Array.isArray(b.frontier_types) ? (b.frontier_types as unknown[]).filter(x => typeof x === 'string') as string[] : undefined,
        note: typeof b.note === 'string' ? b.note : undefined,
        issued_by: 'operator',
      }, { transport: 'dashboard' });
      const results = [{
        op: {
          op: 'directive',
          task_id: taskId,
          agent_label: task.agent_label ?? task.agent_id,
          kind,
        },
        ok: true,
        message: `Directive ${kind} issued to ${task.agent_label ?? task.agent_id}`,
      }];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        results,
        directive: execution.result?.directive,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondAgentLifecycleCommandFailure(res, error);
    });
  }

  // ---- Fleet-level steering (Phase 3C) ----
  // Apply one directive kind to ALL running agents (optionally one campaign).
  // Just a fan-out of the same validated executeOps directive op — the grammar's
  // "pause all" does this in NL; this is the one-click UI equivalent.
  private handleFleetDirective(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const b = (body ?? {}) as Record<string, unknown>;
      const kind = typeof b.kind === 'string' ? b.kind : '';
      // Lifecycle kinds fan out with no argument; 'instruct' broadcasts a
      // free-text note to every running agent (the "All agents" command scope).
      if (!['pause', 'resume', 'stop', 'instruct'].includes(kind)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `fleet directive kind must be pause|resume|stop|instruct, got "${kind}"` }));
        return;
      }
      const note = typeof b.note === 'string' ? b.note.trim() : '';
      if (kind === 'instruct' && !note) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'fleet instruct requires a non-empty note' }));
        return;
      }
      const execution = this.agentLifecycleCommands.issueDirectiveBatch({
        kind,
        note: kind === 'instruct' ? note : undefined,
        campaign_id: typeof b.campaign_id === 'string'
          ? b.campaign_id
          : undefined,
      }, { transport: 'dashboard' });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...execution.result,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondAgentLifecycleCommandFailure(res, error);
    });
  }

  // Bulk "Clear finished": dismiss every terminal (completed/failed/interrupted)
  // agent from the roster (optionally scoped to one campaign). Running/pending
  // agents are left untouched.
  private handleFleetDismiss(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const b = (body ?? {}) as Record<string, unknown>;
      const execution = this.agentLifecycleCommands.dismissBatch({
        campaign_id: typeof b.campaign_id === 'string'
          ? b.campaign_id
          : undefined,
      }, { transport: 'dashboard' });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...execution.result,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondAgentLifecycleCommandFailure(res, error);
    });
  }

  private serveCampaigns(res: ServerResponse): void {
    const enriched = this.enrichCampaigns();
    const payload = CampaignListResponseSchema.parse({ campaigns: enriched, total: enriched.length });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  private serveCampaignDetail(campaignId: string, res: ServerResponse): void {
    const campaign = this.engine.getCampaign(campaignId);
    if (!campaign) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Campaign not found' }));
      return;
    }
    const projectedCampaign = this.enrichCampaigns([campaign])[0];
    const childIds = new Set(this.engine.getCampaignChildren(campaignId).map(child => child.id));
    const matchingTasks = this.engine.getAllAgents().filter(a => a.campaign_id === campaignId || (a.campaign_id ? childIds.has(a.campaign_id) : false));
    const agents = projectAgentDtos(matchingTasks, this.engine.getFullHistory(), this.engine.listCampaigns());
    const childAbortChecks = this.engine.getCampaignChildren(campaignId)
      .map(child => ({ campaign_id: child.id, ...this.engine.checkCampaignAbortConditions(child.id) }));
    const abort_check = childAbortChecks.find(check => check.should_abort)
      ?? { campaign_id: campaignId, ...this.engine.checkCampaignAbortConditions(campaignId) };

    // Campaigns store durable Finding IDs, not graph-node IDs. Resolve their
    // presentation from the activity event that recorded the finding, then use
    // its ingested node references for an operator-friendly summary.
    const history = this.engine.getFullHistory();
    const finding_details = (projectedCampaign.findings || []).map(findingId => {
      const linkedEntries = history.filter(candidate => candidate.linked_finding_ids?.includes(findingId));
      // parse_output is intentionally logged after finding_ingested, but its
      // summary may not carry the concrete node ids. Prefer the newest linked
      // event with graph references so campaign detail does not regress to a
      // generic parser message merely because it was logged later.
      const entry = [...linkedEntries].reverse().find(candidate => {
        const candidateDetails = (candidate.details ?? {}) as Record<string, unknown>;
        return (Array.isArray(candidateDetails.ingested_node_ids) && candidateDetails.ingested_node_ids.length > 0)
          || (candidate.target_node_ids?.length ?? 0) > 0;
      }) ?? linkedEntries.at(-1);
      const details = (entry?.details ?? {}) as Record<string, unknown>;
      const ingestedIds = Array.isArray(details.ingested_node_ids)
        ? details.ingested_node_ids.filter((id): id is string => typeof id === 'string')
        : [];
      const nodeIds = ingestedIds.length > 0 ? ingestedIds : (entry?.target_node_ids ?? []);
      const nodes = nodeIds.map(id => this.engine.getNode(id)).filter((node): node is NonNullable<typeof node> => Boolean(node));
      return {
        id: findingId,
        label: nodes.length > 0 ? nodes.map(node => node.label).join(', ') : (entry?.description ?? findingId),
        type: nodes[0]?.type ?? entry?.event_type ?? 'finding',
        created_at: entry?.timestamp ?? null,
        node_ids: nodeIds,
      };
    });

    const payload = CampaignDetailResponseSchema.parse({ campaign: projectedCampaign, agents, abort_check, finding_details });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  private handleCampaignAction(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const parsed = CampaignActionRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid campaign action', issues: parsed.error.issues }));
        return;
      }
      const execution = this.campaignCommands.action(
        campaignId,
        parsed.data,
        { transport: 'dashboard' },
      );
      const payload = CampaignActionResponseSchema.parse(execution.result);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondCampaignCommandFailure(res, error);
    });
  }

  private handleCampaignDispatch(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const parsed = CampaignDispatchRequestSchema.safeParse(body ?? {});
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid campaign dispatch request', issues: parsed.error.issues }));
        return;
      }
      const execution = this.dispatchCommands.dispatchCampaign({
        campaign_id: campaignId,
        max_agents: parsed.data.max_agents,
        hops: parsed.data.hops,
        skill: parsed.data.skill,
      }, { transport: 'dashboard' });
      const payload = CampaignDispatchResponseSchema.parse(execution.result);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondDispatchCommandFailure(res, error);
    });
  }

  private handleCampaignCreate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const parsed = CampaignCreateRequestSchema.safeParse(body);
      if (!parsed.success) {
        const invalidStrategy = parsed.error.issues.some(issue => issue.path[0] === 'strategy');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: invalidStrategy ? 'Invalid strategy' : 'Invalid campaign create request',
          issues: parsed.error.issues,
        }));
        return;
      }
      const execution = this.campaignCommands.create(
        parsed.data,
        { transport: 'dashboard' },
      );
      const payload = CampaignCreateResponseSchema.parse(execution.result);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondCampaignCommandFailure(res, error);
    });
  }

  private handleCampaignUpdate(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const parsed = CampaignUpdateRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid campaign update request', issues: parsed.error.issues }));
        return;
      }
      const execution = this.campaignCommands.update(
        campaignId,
        parsed.data,
        { transport: 'dashboard' },
      );
      const payload = CampaignUpdateResponseSchema.parse(execution.result);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondCampaignCommandFailure(res, error);
    });
  }

  private handleCampaignDelete(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const execution = this.campaignCommands.delete(
        campaignId,
        { transport: 'dashboard' },
      );
      const payload = CampaignDeleteResponseSchema.parse(execution.result);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    } catch (error) {
      this.respondCampaignCommandFailure(res, error);
    }
  }

  private handleCampaignClone(campaignId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const execution = this.campaignCommands.clone(
        campaignId,
        { transport: 'dashboard' },
      );
      const payload = CampaignCloneResponseSchema.parse(execution.result);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    } catch (error) {
      this.respondCampaignCommandFailure(res, error);
    }
  }

  private async handleCampaignSplit(campaignId: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.checkMutationAuth(req, res)) return;
    try {
      const body = await this.readJsonBody(req);
      if (!this.requireWritablePersistence(res)) return;
      const parsed = CampaignSplitRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid campaign split request', issues: parsed.error.issues }));
        return;
      }
      const execution = this.campaignCommands.split(
        campaignId,
        parsed.data.count,
        { transport: 'dashboard' },
      );
      const payload = CampaignSplitResponseSchema.parse(execution.result);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...payload,
        command_id: execution.command_id,
        replayed: execution.replayed,
      }));
    } catch (error) {
      this.respondCampaignCommandFailure(res, error);
    }
  }

  private serveCampaignChildren(campaignId: string, res: ServerResponse): void {
    if (!this.engine.getCampaign(campaignId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Campaign not found' }));
      return;
    }
    const children = this.enrichCampaigns(this.engine.getCampaignChildren(campaignId));
    const progress = this.engine.getCampaignParentProgress(campaignId);
    const derivedStatus = this.engine.deriveCampaignParentStatus(campaignId);
    const payload = CampaignChildrenResponseSchema.parse({ parent_id: campaignId, children, derived_status: derivedStatus, aggregated_progress: progress });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
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
      if (!this.isAllowedWsOrigin(origin, req.headers.host)) {
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

  /** Recheck at the actual mutation boundary. Request authentication happens
   *  before body/PDF/process awaits, while persistence can become read-only
   *  during those waits after repeated storage failures. */
  private requireWritablePersistence(res: ServerResponse): boolean {
    if (this.engine.isPersistenceWritable()) return true;
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'Durable mutations are disabled while persistence recovery is incomplete.',
      code: 'PERSISTENCE_READ_ONLY',
      recovery: this.engine.getPersistenceRecoveryStatus(),
    }));
    return false;
  }

  /** Map the inactive-engagement file store's stable failure classes to HTTP. */
  private respondEngagementManagerFailure(res: ServerResponse, error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    if (!(error instanceof EngagementManagerError)) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: message,
        code: 'ENGAGEMENT_INTERNAL_ERROR',
      }));
      return;
    }

    const status = error.code === 'ENGAGEMENT_NOT_FOUND'
      ? 404
      : error.code === 'ENGAGEMENT_VALIDATION_FAILED'
        ? 400
        : error.code === 'ENGAGEMENT_CONFLICT'
          ? 409
          : 503;
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: message, code: error.code }));
  }

  private respondDispatchCommandFailure(res: ServerResponse, error: unknown): void {
    if (
      error instanceof Error
      && (error.message === 'Invalid JSON' || error.message === 'Body too large')
    ) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof DispatchCommandError) {
      const { http_status: _status, ...details } = error.details;
      const reason = error.code.toLowerCase();
      const refusal = error.code === 'DISPATCH_CAP_EXCEEDED'
        || error.code === 'DISPATCH_REFUSED';
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...(refusal ? { dispatched: false } : { error: error.message }),
        reason,
        code: error.code,
        ...details,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  private respondOperatorCommandFailure(res: ServerResponse, error: unknown): void {
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof OperatorCommandError) {
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        ...error.details,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  private respondEngagementCommandFailure(
    res: ServerResponse,
    error: unknown,
  ): void {
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof EngagementCommandError) {
      const recovery = this.engine.getPersistenceRecoveryStatus();
      if (
        error.http_status === 503
        || recovery.config_recovery?.status === 'write_incomplete'
        || recovery.config_recovery?.intent_present === true
      ) {
        this.respondMutationFailure(res, error);
        return;
      }
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        ...error.details,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  private respondRecoveryCommandFailure(
    res: ServerResponse,
    error: unknown,
  ): void {
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof RecoveryCommandError) {
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
      }));
      return;
    }
    console.error(
      `[recovery] configuration reconciliation command failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}`,
    );
    this.respondMutationFailure(res, error, {
      conflictWhen: message =>
        /No active configuration divergence/i.test(message),
    });
  }

  private respondGraphCorrectionCommandFailure(
    res: ServerResponse,
    error: unknown,
  ): void {
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof GraphCorrectionCommandError) {
      if (error.http_status === 503) {
        this.respondMutationFailure(res, error);
        return;
      }
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  private respondApprovalCommandFailure(res: ServerResponse, error: unknown): void {
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof ApprovalCommandError) {
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.code === 'APPROVAL_NOT_LIVE'
          ? 'approval_not_live'
          : error.message,
        code: error.code,
        ...error.details,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  private respondAgentLifecycleCommandFailure(
    res: ServerResponse,
    error: unknown,
  ): void {
    if (
      error instanceof Error
      && (error.message === 'Invalid JSON' || error.message === 'Body too large')
    ) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }
    if (error instanceof z.ZodError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.issues.map(issue => issue.message).join('; '),
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof AgentLifecycleCommandError) {
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        ...error.details,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  private respondCampaignCommandFailure(
    res: ServerResponse,
    error: unknown,
  ): void {
    if (
      error instanceof Error
      && (error.message === 'Invalid JSON' || error.message === 'Body too large')
    ) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }
    if (error instanceof z.ZodError) {
      const invalidStrategy = error.issues.some(issue =>
        issue.path.includes('strategy'));
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: invalidStrategy
          ? 'Invalid strategy'
          : 'Invalid campaign request',
        issues: error.issues,
        code: 'VALIDATION_ERROR',
      }));
      return;
    }
    if (error instanceof ApplicationCommandConflictError) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        command_id: error.existing.command_id,
      }));
      return;
    }
    if (error instanceof CampaignCommandError) {
      res.writeHead(error.http_status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: error.message,
        code: error.code,
        ...error.details,
      }));
      return;
    }
    this.respondMutationFailure(res, error);
  }

  /**
   * Map an error thrown at a durable dashboard mutation boundary without
   * disguising storage failure as bad operator input. Configuration writes
   * can fail after the initial writable check and may rethrow the underlying
   * filesystem error (for example ENOSPC) rather than a persistence-specific
   * error class, so classification also consults the combined recovery state
   * installed by the failed write.
   */
  private respondMutationFailure(
    res: ServerResponse,
    error: unknown,
    options: { conflictWhen?: (message: string) => boolean } = {},
  ): void {
    const message = error instanceof Error ? error.message : String(error);
    const rawCode = typeof (error as { code?: unknown } | null)?.code === 'string'
      ? (error as { code: string }).code
      : undefined;

    const recovery = this.engine.getPersistenceRecoveryStatus();
    const configRecovery = recovery.config_recovery;
    const recoveryShowsIncompleteWrite = configRecovery?.status === 'write_incomplete'
      || configRecovery?.intent_present === true;
    const conflict = rawCode === 'CONFIG_HASH_CONFLICT'
      || options.conflictWhen?.(message) === true;
    // A late file race can first surface as CONFIG_HASH_CONFLICT after the
    // config service has already made a durable write intent authoritative.
    // In that state this is no longer an ordinary optimistic conflict: the
    // operator must see the recovery envelope and stop issuing mutations.
    if (conflict && !recoveryShowsIncompleteWrite) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: message,
        code: rawCode ?? 'CONFIG_HASH_CONFLICT',
      }));
      return;
    }

    const storageErrorCode = rawCode !== undefined && [
      'EACCES',
      'EBUSY',
      'EDQUOT',
      'EIO',
      'EMFILE',
      'ENFILE',
      'ENOSPC',
      'EPERM',
      'EROFS',
      'PERSISTENCE_READ_ONLY',
      'CONFIG_WRITE_INCOMPLETE',
    ].includes(rawCode);
    const persistenceMessage = /\b(?:persistence|persist(?:ed|ence|ing)?|durab(?:le|ly|ility)|fsync|journal|snapshot|WAL|read[- ]only)\b|write (?:did not complete|is incomplete)/i.test(message);
    const persistenceFailure = storageErrorCode
      || recoveryShowsIncompleteWrite
      || (!recovery.writable && persistenceMessage)
      || persistenceMessage;

    if (persistenceFailure) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: message,
        code: 'PERSISTENCE_READ_ONLY',
        recovery,
      }));
      return;
    }

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: message }));
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
    const normalized = host.toLowerCase().replace(/^\[|\]$/g, '');
    return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
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
      if (!this.requireWritablePersistence(res)) return;
      const execution = this.approvalCommands.approve(
        actionId,
        typeof body?.notes === 'string' ? body.notes : undefined,
        { transport: 'dashboard' },
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...execution.result?.approval,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondApprovalCommandFailure(res, error);
    });
  }

  private handleActionDeny(actionId: string, req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const execution = this.approvalCommands.deny(
        actionId,
        typeof body?.reason === 'string' ? body.reason : undefined,
        { transport: 'dashboard' },
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...execution.result?.approval,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      }));
    }).catch(error => {
      this.respondApprovalCommandFailure(res, error);
    });
  }

  // Bulk approve — each id routes through the SAME canonical resolve as the single
  // handler (queue.approve → resolveApprovalRequest, which fires the per-action WS
  // event). An id already gone from the live queue is skipped, not an error, so a
  // stale selection resolves the still-live subset cleanly.
  private handleActionApproveBatch(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const b = (body ?? {}) as Record<string, unknown>;
      const ids = Array.isArray(b.action_ids) ? (b.action_ids as unknown[]).filter(x => typeof x === 'string') as string[] : [];
      if (ids.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'action_ids (non-empty string[]) is required' }));
        return;
      }
      const notes = typeof b.notes === 'string' ? b.notes : undefined;
      const invocation = getApplicationCommandInvocation();
      const batchIdentity = invocation?.idempotency_key
        ?? invocation?.request_id
        ?? invocation?.command_id
        ?? randomUUID();
      let resolved = 0;
      for (const [index, id] of ids.entries()) {
        try {
          this.approvalCommands.approve(id, notes, {
            transport: 'dashboard',
            command_id: randomUUID(),
            idempotency_key: `${batchIdentity}:approve:${index}:${id}`,
          });
          resolved++;
        } catch (error) {
          if (!(error instanceof ApprovalCommandError)) throw error;
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, resolved, total: ids.length }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request body' }));
    });
  }

  // Bulk deny — a single shared reason applies to all (audit parity with the single
  // deny: a reason is required, no silent bulk-deny).
  private handleActionDenyBatch(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkMutationAuth(req, res)) return;
    this.readJsonBody(req).then(body => {
      if (!this.requireWritablePersistence(res)) return;
      const b = (body ?? {}) as Record<string, unknown>;
      const ids = Array.isArray(b.action_ids) ? (b.action_ids as unknown[]).filter(x => typeof x === 'string') as string[] : [];
      const reason = typeof b.reason === 'string' ? b.reason.trim() : '';
      if (ids.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'action_ids (non-empty string[]) is required' }));
        return;
      }
      if (!reason) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'reason (non-empty) is required to deny' }));
        return;
      }
      const invocation = getApplicationCommandInvocation();
      const batchIdentity = invocation?.idempotency_key
        ?? invocation?.request_id
        ?? invocation?.command_id
        ?? randomUUID();
      let resolved = 0;
      for (const [index, id] of ids.entries()) {
        try {
          this.approvalCommands.deny(id, reason, {
            transport: 'dashboard',
            command_id: randomUUID(),
            idempotency_key: `${batchIdentity}:deny:${index}:${id}`,
          });
          resolved++;
        } catch (error) {
          if (!(error instanceof ApprovalCommandError)) throw error;
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, resolved, total: ids.length }));
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

  // Read-only structured path finder backing the Attack Paths "Custom path"
  // picker. Unlike /api/paths/:objectiveId (objective-only, 404 on miss), this
  // accepts arbitrary from/to or an objective and returns 200 with the engine's
  // analysis_status (found|no_path|missing_endpoint|analysis_failed) + human
  // warnings, so the picker renders a directed empty state instead of throwing.
  private serveFindPaths(url: string, res: ServerResponse): void {
    const params = new URL(url, 'http://localhost').searchParams;
    const from = params.get('from') || undefined;
    const to = params.get('to') || undefined;
    const objective = params.get('objective') || undefined;
    const optimize = (['confidence', 'stealth', 'balanced'].includes(params.get('optimize') || '')
      ? params.get('optimize') : 'confidence') as 'confidence' | 'stealth' | 'balanced';
    const maxParam = parseInt(params.get('max') || '', 10);
    const max = Number.isFinite(maxParam) ? Math.min(25, Math.max(1, maxParam)) : 5;

    const ok = (body: unknown) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    try {
      if (objective) {
        const paths = this.engine.findPathsToObjective(objective, max, optimize);
        ok({ paths, analysis_status: paths.length ? 'found' : 'no_path', warnings: [], count: paths.length });
      } else if (from && to) {
        const detailed = this.engine.findPathsDetailed(from, to, max, optimize);
        ok({ paths: detailed.paths, analysis_status: detailed.analysis_status, warnings: detailed.warnings ?? [], count: detailed.paths.length });
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'provide from+to, or objective' }));
      }
    } catch (err) {
      ok({ paths: [], analysis_status: 'analysis_failed', warnings: [err instanceof Error ? err.message : String(err)], count: 0 });
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
      if (!this.requireWritablePersistence(res)) return;
      if (!input || !input.name || typeof input.name !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'name is required' }));
        return;
      }
      try {
        if (!this.requireWritablePersistence(res)) return;
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
      } catch (error) {
        this.respondEngagementManagerFailure(res, error);
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
      if (!this.requireWritablePersistence(res)) return;
      if (!body || typeof body !== 'object') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Expected JSON object' }));
        return;
      }
      let update: ReturnType<typeof parseEngagementUpdate>;
      try {
        update = parseEngagementUpdate(body, id);
      } catch (error) {
        this.respondEngagementManagerFailure(res, error);
        return;
      }
      try {
        if (!this.requireWritablePersistence(res)) return;
        const activeEngagement = id === this.engine.getConfig().id;
        const execution = activeEngagement
          ? this.engagementCommands.patchConfig(update, {
              transport: 'dashboard',
            })
          : undefined;
        if (!activeEngagement) {
          this.engagementManager!.updateEngagement(id, update);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          updated: true,
          ...(execution
            ? {
                command_id: execution.command_id,
                idempotency_key: execution.idempotency_key,
                replayed: execution.replayed,
              }
            : {}),
        }));
      } catch (error) {
        if (id === this.engine.getConfig().id) {
          this.respondEngagementCommandFailure(res, error);
        }
        else this.respondEngagementManagerFailure(res, error);
      }
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
      const recovery = state.persistence_recovery;
      const recoveryReadiness = recovery ? assessPersistenceRecovery(recovery) : undefined;
      const sessionCounts = {
        connected: sessions.filter((session: any) => session.state === 'connected').length,
        waiting: sessions.filter((session: any) => session.state === 'pending').length,
        resume_available: sessions.filter((session: any) => session.state === 'resume_available').length,
        interrupted: sessions.filter((session: any) => session.state === 'interrupted').length,
        error: sessions.filter((session: any) => session.state === 'error').length,
        closed_exact: sessions.filter((session: any) => session.state === 'closed').length,
      };
      const activeSessions = sessionCounts.connected + sessionCounts.waiting;
      const runningAgents = agents.filter(agent => agent.status === 'running').length;
      const failedAgents = agents.filter(agent => agent.status === 'failed' || agent.status === 'interrupted').length;
      const issues = [
        ...(recoveryReadiness && recoveryReadiness.status !== 'pass' ? [recoveryReadiness.message] : []),
        ...health.issues.slice(0, 3).map(issue => issue.message),
        ...(failedAgents > 0 ? [`${failedAgents} agent${failedAgents === 1 ? '' : 's'} failed or interrupted`] : []),
      ];
      const status =
        health.status === 'critical' || recoveryReadiness?.status === 'fail' ? 'critical' :
        health.status === 'warning' || recoveryReadiness?.status === 'warning' || failedAgents > 0 ? 'warning' :
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
          // Compatibility v1: `closed` historically meant every inactive
          // lifecycle, not only the literal closed state.
          closed: sessions.length - activeSessions,
          ...sessionCounts,
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
          recovery,
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
    // Explicit export for downstream tooling / reports — include source_trust
    // (observed/asserted/inferred) so consumers can distinguish confirmed from
    // hypothesized graph elements.
    const graph = this.engine.exportGraph({ sourceTrust: true });
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
      if (!this.requireWritablePersistence(res)) return;
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
  private handleReportDelete(id: string, req: IncomingMessage, res: ServerResponse): void {
    // DELETE is a mutation — enforce the same CSRF/Origin + token gate every
    // other mutation does (this endpoint previously skipped it).
    if (!this.checkMutationAuth(req, res)) return;
    if (!this.requireWritablePersistence(res)) return;
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

      // Rendering can take seconds. Persistence may have crossed the failure
      // threshold while Chromium was running, so gate the actual archive write
      // rather than trusting the request-entry check.
      if (!this.requireWritablePersistence(res)) return;
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
      if (!this.requireWritablePersistence(res)) return;
      const parsed = GraphCorrectionRequestSchema.safeParse(body);
      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Invalid graph correction request',
          issues: parsed.error.issues,
        }));
        return;
      }
      const execution = this.graphCorrectionCommands.correct(parsed.data, {
        transport: 'dashboard',
      });
      // Broadcast full state update to all WS clients
      const state = this.buildFrontendState();
      const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
      this.broadcast({
        type: 'full_state',
        timestamp: new Date().toISOString(),
        data: { state, graph, history_count: this.engine.getFullHistory().length },
      });
      const payload = GraphCorrectionResultSchema.parse({
        ...execution.result,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (error: unknown) {
      this.respondGraphCorrectionCommandFailure(res, error);
    }
  }
}
