// ============================================================
// Overwatch — App Bootstrap
// Core app construction separated from transport startup.
// ============================================================

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { randomUUID, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolCallback, RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ZodRawShapeCompat, AnySchema } from '@modelcontextprotocol/sdk/server/zod-compat.js';
import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { Express, Request, Response } from 'express';
import type { Server } from 'http';
import { GraphEngine } from './services/graph-engine.js';
import { SkillIndex } from './services/skill-index.js';
import { ProcessTracker } from './services/process-tracker.js';
import { DashboardServer } from './services/dashboard-server.js';
import { SessionManager } from './services/session-manager.js';
import { LocalPtyAdapter, SshAdapter, SocketAdapter } from './services/session-adapters.js';
import { createMcpAuthMiddleware } from './services/mcp-auth.js';
import { TaskExecutionService, type TaskExecutionServiceOptions } from './services/task-execution-service.js';
import type { EngagementConfig } from './types.js';
import { engagementConfigSchema } from './types.js';
import { formatConfigError, parseEngagementConfig } from './config.js';
import { registerStateTools } from './tools/state.js';
import { registerOpsecTools } from './tools/opsec.js';
import { registerFindingReadinessTools } from './tools/finding-readiness.js';
import { registerFindingTools } from './tools/findings.js';
import { registerScoringTools } from './tools/scoring.js';
import { registerExplorationTools } from './tools/exploration.js';
import { registerResearchCveTools } from './tools/research-cve.js';
import { registerProposePlanTools } from './tools/propose-plan.js';
import { registerAgentTools } from './tools/agents.js';
import { registerSkillTools } from './tools/skills.js';
import { registerBloodHoundTools } from './tools/bloodhound.js';
import { registerAzureHoundTools } from './tools/azurehound.js';
import { registerToolCheckTools } from './tools/toolcheck.js';
import { registerProcessTools } from './tools/processes.js';
import { registerInferenceTools } from './tools/inference.js';
import { registerParseOutputTools } from './tools/parse-output.js';
import { registerLoggingTools } from './tools/logging.js';
import { registerRetrospectiveTools } from './tools/retrospective.js';
import { registerReportingTools } from './tools/reporting.js';
import { registerRemediationTools } from './tools/remediation.js';
import { registerSessionTools } from './tools/sessions.js';
import { registerScopeTools } from './tools/scope.js';
import { registerEngagementTools } from './tools/engagement.js';
import { EngagementManager } from './services/engagement-manager.js';
import { registerRunBashTool } from './tools/run-bash.js';
import { registerRunToolTool } from './tools/run-tool.js';
import { registerTokenReplayTool } from './tools/token-replay.js';
import { registerAwsPlaybookTool } from './tools/aws-playbook.js';
import { registerGithubPlaybookTool } from './tools/github-playbook.js';
import { registerCicdOidcPlaybookTool } from './tools/cicd-oidc-playbook.js';
import { registerEntraPlaybookTools } from './tools/entra-playbook.js';
import { registerLogThoughtTool } from './tools/log-thought.js';
import { registerDecisionLogTools } from './tools/decision-log.js';
import { registerIntrospectionTools } from './tools/introspection.js';
import { registerTimelineTools } from './tools/timeline.js';
import { registerTranscriptTools } from './tools/transcripts.js';
import { registerTapeTools } from './tools/tapes.js';
import { registerOperatorInfraTools } from './tools/operator-infra.js';
import { registerPostgresTools } from './tools/postgres.js';
import { registerIngestJsonTools } from './tools/ingest-json.js';
import { registerBundleTools } from './tools/bundle.js';
import { registerInstructionTools } from './tools/instructions.js';
import type { ToolEntry } from './services/prompt-generator.js';
import { ToolTelemetry } from './services/tool-telemetry.js';
import { setTelemetry, getTelemetry } from './tools/error-boundary.js';
import { InProcessTapeController, type TapeStartSource } from './services/in-process-tape.js';

type DashboardStatusProvider = () => {
  enabled: boolean;
  running: boolean;
  address?: string;
};

export type OverwatchToolRegistrar = Pick<McpServer, 'registerTool'>;

/**
 * Wrapper around McpServer that intercepts registerTool calls to collect
 * tool metadata (name + description) without monkey-patching the server.
 */
export class ToolRegistrar implements OverwatchToolRegistrar {
  private entries: ToolEntry[] = [];
  constructor(private server: McpServer) {}
  registerTool<OutputArgs extends ZodRawShapeCompat | AnySchema, InputArgs extends undefined | ZodRawShapeCompat | AnySchema = undefined>(
    name: string,
    config: { title?: string; description?: string; inputSchema?: InputArgs; outputSchema?: OutputArgs; annotations?: ToolAnnotations; _meta?: Record<string, unknown> },
    cb: ToolCallback<InputArgs>,
  ): RegisteredTool {
    this.entries.push({
      name,
      title: config?.title,
      description: config?.description || '',
      read_only: config?.annotations?.readOnlyHint,
      destructive: config?.annotations?.destructiveHint,
      idempotent: config?.annotations?.idempotentHint,
      open_world: config?.annotations?.openWorldHint,
    });
    return this.server.registerTool(name, config, cb);
  }
  getEntries(): ToolEntry[] { return this.entries; }
}

export type OverwatchApp = {
  config: EngagementConfig;
  engine: GraphEngine;
  skills: SkillIndex;
  processTracker: ProcessTracker;
  sessionManager: SessionManager;
  engagementManager: EngagementManager;
  server: McpServer;
  dashboard: DashboardServer | null;
  taskExecution: TaskExecutionService;
  telemetry: ToolTelemetry;
  tape: InProcessTapeController;
  httpTransports?: Record<string, StreamableHTTPServerTransport>;
  httpServer?: Server;
};

export type CreateOverwatchAppOptions = {
  config?: EngagementConfig;
  configPath?: string;
  skillDir?: string;
  dashboardPort?: number;
  stateFilePath?: string;
  /** Forwarded to TaskExecutionService — lets the eval harness set the headless
   *  claude binary / model (extraArgs) / max-turns / log dir for sub-agents. */
  taskExecution?: TaskExecutionServiceOptions;
};

export function loadConfig(configPath: string = process.env.OVERWATCH_CONFIG || './engagement.json'): EngagementConfig {
  if (!existsSync(configPath)) {
    if (process.env.OVERWATCH_BOOTSTRAP === '1') {
      console.warn(`Config not found at ${configPath}. OVERWATCH_BOOTSTRAP=1 — creating default config.`);
      return engagementConfigSchema.parse({
        id: uuidv4(),
        name: 'default-engagement',
        created_at: new Date().toISOString(),
        scope: { cidrs: [], domains: [], exclusions: [] },
        objectives: [],
        opsec: { name: 'pentest', max_noise: 0.7 },
      });
    }
    throw new Error(
      `Engagement config not found at ${configPath}. ` +
      `Create a config file or set OVERWATCH_BOOTSTRAP=1 to start with an empty engagement.`
    );
  }

  return parseEngagementConfig(readFileSync(configPath, 'utf-8'));
}

export function registerAllTools(
  server: OverwatchToolRegistrar,
  deps: {
    engine: GraphEngine;
    skills: SkillIndex;
    processTracker: ProcessTracker;
    sessionManager: SessionManager;
    engagementManager: EngagementManager;
    getDashboardStatus: DashboardStatusProvider;
  },
): ToolEntry[] {
  // Initialize shared telemetry (idempotent — first caller wins)
  if (!getTelemetry()) {
    setTelemetry(new ToolTelemetry());
  }

  const registrar = new ToolRegistrar(server as McpServer);
  const s = registrar as unknown as McpServer;

  registerStateTools(s, deps.engine, {
    getDashboardStatus: deps.getDashboardStatus,
  });
  registerFindingTools(s, deps.engine);
  registerFindingReadinessTools(s, deps.engine);
  registerScoringTools(s, deps.engine);
  registerOpsecTools(s, deps.engine);
  registerExplorationTools(s, deps.engine);
  registerResearchCveTools(s, deps.engine);
  registerProposePlanTools(s, deps.engine);
  registerAgentTools(s, deps.engine);
  registerSkillTools(s, deps.skills, deps.engine.getKB());
  registerBloodHoundTools(s, deps.engine);
  registerAzureHoundTools(s, deps.engine);
  registerToolCheckTools(s);
  registerProcessTools(s, deps.processTracker, deps.engine);
  registerInferenceTools(s, deps.engine);
  registerParseOutputTools(s, deps.engine);
  registerLoggingTools(s, deps.engine);
  registerRetrospectiveTools(s, deps.engine, deps.skills, () => registrar.getEntries().map(e => e.name));
  registerReportingTools(s, deps.engine, deps.skills);
  registerRemediationTools(s, deps.engine);
  registerSessionTools(s, deps.sessionManager, deps.engine);
  registerScopeTools(s, deps.engine);
  registerEngagementTools(s, deps.engine, deps.engagementManager);
  registerRunBashTool(s, deps.engine);
  registerRunToolTool(s, deps.engine);
  registerTokenReplayTool(s, deps.engine);
  registerAwsPlaybookTool(s, deps.engine);
  registerGithubPlaybookTool(s, deps.engine);
  registerCicdOidcPlaybookTool(s, deps.engine);
  registerEntraPlaybookTools(s, deps.engine);
  registerLogThoughtTool(s, deps.engine);
  registerDecisionLogTools(s, deps.engine);
  registerIntrospectionTools(s, deps.engine);
  registerTimelineTools(s, deps.engine);
  registerTranscriptTools(s, deps.engine);
  registerTapeTools(s, deps.engine);
  registerOperatorInfraTools(s, deps.engine);
  registerPostgresTools(s, deps.engine);
  registerIngestJsonTools(s, deps.engine);
  registerBundleTools(s, deps.engine);

  // Register instruction tools last (needs the collected tool list)
  registerInstructionTools(s, deps.engine, () => registrar.getEntries());

  return registrar.getEntries();
}

export function createOverwatchApp(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  const configPath = options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json';
  const config = options.config || loadConfig(configPath);
  // Keep config and live state separate. By default, the mutable state file
  // lives beside the operator-authored config so launching from a different
  // cwd cannot silently create or load the wrong engagement state.
  const resolvedConfigPath = resolve(configPath);
  const defaultStateFilePath = join(dirname(resolvedConfigPath), `state-${config.id}.json`);
  const stateFilePath = options.stateFilePath || process.env.OVERWATCH_STATE_FILE || defaultStateFilePath;
  const engine = new GraphEngine(config, stateFilePath);
  const skillDir = options.skillDir || process.env.OVERWATCH_SKILLS || './skills';
  const skills = new SkillIndex(skillDir);
  console.error(`Loaded ${skills.count} skills from ${skillDir}`);
  // Share the index with the engine so prompt generation + the headless runner
  // inline archetype methodology from the SAME loaded skills (not a per-call
  // `new SkillIndex()` that depends on cwd).
  engine.setSkillIndex(skills);

  const savedProcesses = engine.getTrackedProcesses();
  const processTracker = savedProcesses.length > 0
    ? ProcessTracker.deserialize(savedProcesses)
    : new ProcessTracker();

  // Reconcile tracked process liveness on startup — dead PIDs are marked completed
  if (savedProcesses.length > 0) {
    processTracker.refreshStatuses();
  }

  const sessionManager = new SessionManager(engine);
  sessionManager.registerAdapter(new LocalPtyAdapter());
  sessionManager.registerAdapter(new SshAdapter());
  sessionManager.registerAdapter(new SocketAdapter());

  const server = new McpServer({
    name: 'overwatch-mcp-server',
    version: '0.1.0',
  });

  const dashboardPort = options.dashboardPort ?? parseInt(process.env.OVERWATCH_DASHBOARD_PORT || '8384', 10);
  const dashboard = dashboardPort > 0 ? new DashboardServer(engine, dashboardPort, undefined, sessionManager, configPath) : null;

  // In-process tape controller. Always constructed; only opens a writer when
  // explicitly enabled via env, engagement config, or dashboard toggle.
  const tape = new InProcessTapeController(engine, {
    defaultDir: process.env.OVERWATCH_TAPE_DIR ?? config.tape?.dir,
    file: process.env.OVERWATCH_TAPE_FILE ?? config.tape?.file,
  });
  if (dashboard) {
    dashboard.attachTape(tape);
    dashboard.attachSkills(skills);
  }

  // File-backed engagement manager for the create_engagement / list_engagements
  // tools. Stateless over engagements/ (no in-memory cache), so this instance is
  // equivalent to the dashboard's own — no need to share a single object.
  const engagementManager = new EngagementManager(configPath);

  const registeredTools = registerAllTools(server, {
    engine,
    skills,
    processTracker,
    sessionManager,
    engagementManager,
    getDashboardStatus: () => ({
      enabled: dashboard !== null,
      running: dashboard?.running ?? false,
      address: dashboard?.address,
    }),
  });
  if (dashboard) {
    dashboard.attachMcpTools(registeredTools);
  }

  // App-level agent-task execution (scripted + headless backends + watchdog).
  // Owned here, not by the dashboard, so agent execution runs whether or not the
  // dashboard is enabled. Started in startStdioApp/startHttpApp; the HTTP
  // endpoint for headless sub-agents is supplied later via setHttpEndpoint.
  const taskExecution = new TaskExecutionService(engine, processTracker, options.taskExecution);
  // Let the dashboard's cancel endpoint kill headless sub-agent processes.
  dashboard?.attachTaskExecution(taskExecution);

  return {
    config,
    engine,
    skills,
    processTracker,
    sessionManager,
    engagementManager,
    server,
    dashboard,
    taskExecution,
    telemetry: getTelemetry()!,
    tape,
  };
}

export async function startStdioApp(app: OverwatchApp): Promise<void> {
  if (app.dashboard) {
    await app.dashboard.start();
  }
  app.taskExecution.start();

  maybeAutoEnableTape(app);

  const baseTransport = new StdioServerTransport();
  // Wrap unconditionally so the dashboard can flip recording on/off without
  // restarting the transport.
  const transport = app.tape.wrapTransport(baseTransport);
  await app.server.connect(transport);
  console.error('Overwatch MCP server running on stdio');
}

/**
 * Decide whether to auto-enable the in-process tape at startup. Env wins over
 * engagement config (operator override). `OVERWATCH_TAPE=0` forces off even
 * when the config says on, so a single shell prefix can disable it.
 */
export function getAutoTapeStartDecision(config: EngagementConfig): { enabled: boolean; startedBy?: TapeStartSource } {
  const env = process.env.OVERWATCH_TAPE;
  if (env === '0' || env === 'false' || env === 'off') return { enabled: false };
  if (env === '1' || env === 'true' || env === 'on') return { enabled: true, startedBy: 'env' };
  if (config.tape?.enabled === true) return { enabled: true, startedBy: 'config' };
  return { enabled: false };
}

export function maybeAutoEnableTape(app: OverwatchApp): void {
  const decision = getAutoTapeStartDecision(app.config);
  if (!decision.enabled || app.tape.isEnabled()) return;
  const status = app.tape.enable({ startedBy: decision.startedBy });
  const suffix = status.started_by ? ` (started_by=${status.started_by})` : '';
  console.error(`Overwatch tape recording to ${status.path}${suffix}`);
}

export const MAX_HTTP_SESSIONS = 50;

// Default fallback when no engagement-specific approval timeout is configured.
// Mirrors DEFAULT_TIMEOUT_MS in pending-action-queue.ts.
export const DEFAULT_APPROVAL_TIMEOUT_MS = 300_000; // 5 minutes
// The HTTP socket must outlive the approval window by a margin, otherwise Node's
// default requestTimeout (~5 min) tears down the connection mid-approval and
// orphans the pending action. We add headroom on top of the approval timeout.
export const MCP_REQUEST_TIMEOUT_MARGIN_MS = 60_000; // 1 minute

export type StartHttpAppOptions = {
  port?: number;
  host?: string;
  maxSessions?: number;
};

export async function startHttpApp(app: OverwatchApp, options: StartHttpAppOptions = {}): Promise<Express> {
  const port = options.port ?? parseInt(process.env.OVERWATCH_HTTP_PORT || '3000', 10);
  const host = options.host ?? process.env.OVERWATCH_HTTP_HOST ?? '127.0.0.1';

  maybeAutoEnableTape(app);

  const expressApp = createMcpExpressApp({ host });

  // Guard /mcp with bearer-token auth before any route handlers run. The HTTP
  // daemon exposes the full Overwatch tool surface — including target-facing
  // run_bash/run_tool — to every connecting client (the primary + headless
  // sub-agents). Any local process could otherwise drive those tools, so we
  // FAIL CLOSED: a token is required by default, even on loopback. If none is
  // configured we generate one and log it (zero-config but secure). Explicit
  // opt-out (e.g. trusted single-user dev or test harnesses) via
  // OVERWATCH_MCP_REQUIRE_TOKEN=0.
  const requireDisabled = process.env.OVERWATCH_MCP_REQUIRE_TOKEN === '0'
    || process.env.OVERWATCH_MCP_REQUIRE_TOKEN === 'false';
  const requireMcpToken = !requireDisabled;
  if (requireMcpToken && !process.env.OVERWATCH_MCP_TOKEN) {
    const generated = randomUUID().replace(/-/g, '');
    process.env.OVERWATCH_MCP_TOKEN = generated;
    // Do NOT print the secret to stderr — it persists in logs / terminal
    // scrollback / log aggregation. Write it to a 0600 file beside the engagement
    // state and log only the path + a non-reversible fingerprint. Headless
    // sub-agents read the env var in-process; an operator wiring .mcp.http.json
    // reads the file.
    const fingerprint = createHash('sha256').update(generated).digest('hex').slice(0, 12);
    let tokenPath: string;
    try {
      tokenPath = join(dirname(app.engine.getStateFilePath()), '.overwatch-mcp-token');
      writeFileSync(tokenPath, generated, { mode: 0o600 });
    } catch {
      tokenPath = '(could not write token file — set OVERWATCH_MCP_TOKEN yourself)';
    }
    console.error(`[overwatch] /mcp auth required — generated a token (sha256:${fingerprint}…), written 0600 to ${tokenPath}`);
    console.error('[overwatch] set OVERWATCH_MCP_TOKEN yourself for a stable token (used by .mcp.http.example.json and headless sub-agents).');
  }
  expressApp.use('/mcp', createMcpAuthMiddleware({ host, requireToken: requireMcpToken }));

  const transports: Record<string, StreamableHTTPServerTransport> = {};
  app.httpTransports = transports;

  // Each HTTP session needs its own McpServer (SDK limitation: one connect() per server).
  // All sessions share the same engine, skills, and services.
  function createSessionServer(): McpServer {
    const server = new McpServer({
      name: 'overwatch-mcp-server',
      version: '0.1.0',
    });
    registerAllTools(server, {
      engine: app.engine,
      skills: app.skills,
      processTracker: app.processTracker,
      sessionManager: app.sessionManager,
      engagementManager: app.engagementManager,
      getDashboardStatus: () => ({
        enabled: app.dashboard !== null,
        running: app.dashboard?.running ?? false,
        address: app.dashboard?.address,
      }),
    });
    return server;
  }

  // MCP POST — initialize new session or route to existing
  expressApp.post('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    if (sessionId && transports[sessionId]) {
      await transports[sessionId].handleRequest(req, res, req.body);
      return;
    }

    if (!sessionId && isInitializeRequest(req.body)) {
      const maxSessions = options.maxSessions ?? MAX_HTTP_SESSIONS;
      if (Object.keys(transports).length >= maxSessions) {
        res.status(503).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: `Too many active sessions (limit: ${maxSessions}). Close existing sessions before opening new ones.` },
          id: null,
        });
        return;
      }
      const baseTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid: string) => {
          // Store the *base* transport — handleRequest() is HTTP-specific
          // and lives on StreamableHTTPServerTransport, not on the generic
          // wrapper. The wrapper is only used for the MCP Server connect
          // path so its send/recv hooks can mirror frames into the tape.
          transports[sid] = baseTransport;
        },
      });
      baseTransport.onclose = () => {
        const sid = baseTransport.sessionId;
        if (sid) {
          delete transports[sid];
        }
      };
      const wrappedTransport = app.tape.wrapTransport(baseTransport);
      const server = createSessionServer();
      await server.connect(wrappedTransport);
      await baseTransport.handleRequest(req, res, req.body);
      return;
    }

    res.status(400).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
      id: null,
    });
  });

  // MCP GET — SSE stream for server-initiated messages
  expressApp.get('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  });

  // MCP DELETE — session termination
  expressApp.delete('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  });

  // Start dashboard (on its own port as before)
  if (app.dashboard) {
    await app.dashboard.start();
  }
  app.taskExecution.start();

  // Start HTTP server — use http.createServer so server.address() is
  // reliable even with ephemeral port 0.
  const { createServer: createHttpServer } = await import('http');
  const server = createHttpServer(expressApp);

  // Approvals over HTTP block the tool-call request for up to approval_timeout_ms.
  // Node's default server.requestTimeout (~5 min) would close the socket mid-wait
  // and orphan the pending approval, so we set an explicit timeout that always
  // outlives the approval window by MCP_REQUEST_TIMEOUT_MARGIN_MS. We deliberately
  // do NOT set requestTimeout = 0 (unbounded): a finite ceiling keeps a hung
  // request from leaking a socket forever, while the queue's own approval-timeout
  // auto-resolve remains the functional pressure valve for un-answered approvals.
  const approvalTimeoutMs = app.config.opsec?.approval_timeout_ms ?? DEFAULT_APPROVAL_TIMEOUT_MS;
  const mcpRequestTimeoutMs = approvalTimeoutMs + MCP_REQUEST_TIMEOUT_MARGIN_MS;
  server.requestTimeout = mcpRequestTimeoutMs;
  // keepAliveTimeout/headersTimeout must exceed requestTimeout to avoid Node
  // racing the socket closed before the request timeout fires.
  server.keepAliveTimeout = mcpRequestTimeoutMs + 5_000;
  server.headersTimeout = mcpRequestTimeoutMs + 10_000;

  app.httpServer = server;

  return new Promise<Express>((resolve, reject) => {
    server.on('error', (err: Error) => reject(err));
    server.listen(port, host, () => {
      const addr = server.address();
      const boundPort = (addr && typeof addr === 'object') ? addr.port : port;
      // Tell the task-execution service where headless sub-agents should connect.
      // This enables the headless_mcp backend (only available in daemon mode).
      app.taskExecution.setHttpEndpoint({
        url: `http://${host}:${boundPort}/mcp`,
        token: process.env.OVERWATCH_MCP_TOKEN,
      });
      console.error(`Overwatch MCP HTTP transport at http://${host}:${boundPort}/mcp`);
      if (app.dashboard?.running) {
        console.error(`Dashboard at ${app.dashboard.address}`);
      }
      resolve(expressApp);
    });
  });
}

export async function shutdownOverwatchApp(app: OverwatchApp): Promise<void> {
  // Stop agent-task execution and AWAIT headless children exiting (SIGTERM→
  // SIGKILL) so none outlive the daemon.
  await app.taskExecution.shutdown();
  // Close HTTP transport sessions. (In-flight tool calls are aborted per-request
  // via the MCP SDK's extra.signal, which the process runner already honors;
  // there is no separate per-session abort controller to fire.)
  if (app.httpTransports) {
    for (const [sid, transport] of Object.entries(app.httpTransports)) {
      try {
        await transport.close();
      } catch { /* best effort */ }
      delete app.httpTransports[sid];
    }
  }
  if (app.httpServer) {
    await new Promise<void>((resolve) => app.httpServer!.close(() => resolve()));
  }
  await app.sessionManager.shutdown().catch(() => {});
  if (app.dashboard) {
    await app.dashboard.stop().catch(() => {});
  }
  await app.tape.disable().catch(() => {});
  app.engine.setTrackedProcesses(app.processTracker.serialize());
  app.engine.persist();
  app.engine.flushNow();
  app.engine.dispose();
}

export function createAppOrExit(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  try {
    return createOverwatchApp(options);
  } catch (error) {
    console.error(formatConfigError(error, options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json'));
    process.exit(1);
  }
}
