// ============================================================
// Overwatch — App Bootstrap
// Core app construction separated from transport startup.
// ============================================================

import { readFileSync, existsSync } from 'fs';
import { randomUUID } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { Express } from 'express';
import type { Server } from 'http';
import { GraphEngine } from './services/graph-engine.js';
import { SkillIndex } from './services/skill-index.js';
import { ProcessTracker } from './services/process-tracker.js';
import { DashboardServer } from './services/dashboard-server.js';
import { SessionManager } from './services/session-manager.js';
import { LocalPtyAdapter, SshAdapter, SocketAdapter } from './services/session-adapters.js';
import type { EngagementConfig } from './types.js';
import { engagementConfigSchema } from './types.js';
import { formatConfigError, parseEngagementConfig } from './config.js';
import { registerStateTools } from './tools/state.js';
import { registerFindingTools } from './tools/findings.js';
import { registerScoringTools } from './tools/scoring.js';
import { registerExplorationTools } from './tools/exploration.js';
import { registerAgentTools } from './tools/agents.js';
import { registerSkillTools } from './tools/skills.js';
import { registerBloodHoundTools } from './tools/bloodhound.js';
import { registerToolCheckTools } from './tools/toolcheck.js';
import { registerProcessTools } from './tools/processes.js';
import { registerInferenceTools } from './tools/inference.js';
import { registerParseOutputTools } from './tools/parse-output.js';
import { registerLoggingTools } from './tools/logging.js';
import { registerRetrospectiveTools } from './tools/retrospective.js';
import { registerRemediationTools } from './tools/remediation.js';
import { registerSessionTools } from './tools/sessions.js';
import { registerScopeTools } from './tools/scope.js';
import { registerInstructionTools } from './tools/instructions.js';
import type { ToolEntry } from './services/prompt-generator.js';

type DashboardStatusProvider = () => {
  enabled: boolean;
  running: boolean;
  address?: string;
};

export type OverwatchToolRegistrar = Pick<McpServer, 'registerTool'>;

export type OverwatchApp = {
  config: EngagementConfig;
  engine: GraphEngine;
  skills: SkillIndex;
  processTracker: ProcessTracker;
  sessionManager: SessionManager;
  server: McpServer;
  dashboard: DashboardServer | null;
  httpTransports?: Record<string, StreamableHTTPServerTransport>;
  httpServer?: Server;
};

export type CreateOverwatchAppOptions = {
  config?: EngagementConfig;
  configPath?: string;
  skillDir?: string;
  dashboardPort?: number;
  stateFilePath?: string;
};

export function loadConfig(configPath: string = process.env.OVERWATCH_CONFIG || './engagement.json'): EngagementConfig {
  if (!existsSync(configPath)) {
    console.error(`Config not found at ${configPath}. Creating default config.`);
    return engagementConfigSchema.parse({
      id: uuidv4(),
      name: 'default-engagement',
      created_at: new Date().toISOString(),
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 },
    });
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
    getDashboardStatus: DashboardStatusProvider;
  },
): ToolEntry[] {
  const toolEntries: ToolEntry[] = [];

  // Wrap registerTool to collect name+description for the prompt generator
  const originalRegisterTool = (server as McpServer).registerTool.bind(server as McpServer);
  (server as McpServer).registerTool = function (name: string, config: any, cb: any) {
    toolEntries.push({ name, description: config?.description || '' });
    return originalRegisterTool(name, config, cb);
  };

  registerStateTools(server as McpServer, deps.engine, {
    getDashboardStatus: deps.getDashboardStatus,
  });
  registerFindingTools(server as McpServer, deps.engine);
  registerScoringTools(server as McpServer, deps.engine);
  registerExplorationTools(server as McpServer, deps.engine);
  registerAgentTools(server as McpServer, deps.engine);
  registerSkillTools(server as McpServer, deps.skills);
  registerBloodHoundTools(server as McpServer, deps.engine);
  registerToolCheckTools(server as McpServer);
  registerProcessTools(server as McpServer, deps.processTracker, deps.engine);
  registerInferenceTools(server as McpServer, deps.engine);
  registerParseOutputTools(server as McpServer, deps.engine);
  registerLoggingTools(server as McpServer, deps.engine);
  registerRetrospectiveTools(server as McpServer, deps.engine, deps.skills);
  registerRemediationTools(server as McpServer, deps.engine);
  registerSessionTools(server as McpServer, deps.sessionManager, deps.engine);
  registerScopeTools(server as McpServer, deps.engine);

  // Register instruction tools last (needs the collected tool list)
  registerInstructionTools(server as McpServer, deps.engine, () => toolEntries);

  // Restore original registerTool
  (server as McpServer).registerTool = originalRegisterTool;

  return toolEntries;
}

export function createOverwatchApp(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  const configPath = options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json';
  const config = options.config || loadConfig(configPath);
  const engine = new GraphEngine(config, options.stateFilePath);
  const skillDir = options.skillDir || process.env.OVERWATCH_SKILLS || './skills';
  const skills = new SkillIndex(skillDir);
  console.error(`Loaded ${skills.count} skills from ${skillDir}`);

  const savedProcesses = engine.getTrackedProcesses();
  const processTracker = savedProcesses.length > 0
    ? ProcessTracker.deserialize(savedProcesses)
    : new ProcessTracker();

  const sessionManager = new SessionManager(engine);
  sessionManager.registerAdapter(new LocalPtyAdapter());
  sessionManager.registerAdapter(new SshAdapter());
  sessionManager.registerAdapter(new SocketAdapter());

  const server = new McpServer({
    name: 'overwatch-mcp-server',
    version: '0.1.0',
  });

  const dashboardPort = options.dashboardPort ?? parseInt(process.env.OVERWATCH_DASHBOARD_PORT || '8384', 10);
  const dashboard = dashboardPort > 0 ? new DashboardServer(engine, dashboardPort) : null;

  registerAllTools(server, {
    engine,
    skills,
    processTracker,
    sessionManager,
    getDashboardStatus: () => ({
      enabled: dashboard !== null,
      running: dashboard?.running ?? false,
      address: dashboard?.address,
    }),
  });

  return {
    config,
    engine,
    skills,
    processTracker,
    sessionManager,
    server,
    dashboard,
  };
}

export async function startStdioApp(app: OverwatchApp): Promise<void> {
  if (app.dashboard) {
    const result = await app.dashboard.start();
    if (result.started) {
      app.engine.onUpdate((detail) => app.dashboard?.onGraphUpdate(detail));
    }
  }

  const transport = new StdioServerTransport();
  await app.server.connect(transport);
  console.error('Overwatch MCP server running on stdio');
}

export type StartHttpAppOptions = {
  port?: number;
  host?: string;
};

export async function startHttpApp(app: OverwatchApp, options: StartHttpAppOptions = {}): Promise<Express> {
  const port = options.port ?? parseInt(process.env.OVERWATCH_HTTP_PORT || '3000', 10);
  const host = options.host ?? process.env.OVERWATCH_HTTP_HOST ?? '127.0.0.1';

  const expressApp = createMcpExpressApp({ host });
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
      getDashboardStatus: () => ({
        enabled: app.dashboard !== null,
        running: app.dashboard?.running ?? false,
        address: app.dashboard?.address,
      }),
    });
    return server;
  }

  // MCP POST — initialize new session or route to existing
  expressApp.post('/mcp', async (req: any, res: any) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    if (sessionId && transports[sessionId]) {
      await transports[sessionId].handleRequest(req, res, req.body);
      return;
    }

    if (!sessionId && isInitializeRequest(req.body)) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid: string) => {
          transports[sid] = transport;
        },
      });
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid && transports[sid]) {
          delete transports[sid];
        }
      };
      const server = createSessionServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    res.status(400).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
      id: null,
    });
  });

  // MCP GET — SSE stream for server-initiated messages
  expressApp.get('/mcp', async (req: any, res: any) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  });

  // MCP DELETE — session termination
  expressApp.delete('/mcp', async (req: any, res: any) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  });

  // Start dashboard (on its own port as before)
  if (app.dashboard) {
    const result = await app.dashboard.start();
    if (result.started) {
      app.engine.onUpdate((detail) => app.dashboard?.onGraphUpdate(detail));
    }
  }

  // Start HTTP server
  return new Promise<Express>((resolve, reject) => {
    const server = expressApp.listen(port, host, () => {
      console.error(`Overwatch MCP HTTP transport at http://${host}:${port}/mcp`);
      if (app.dashboard?.running) {
        console.error(`Dashboard at ${app.dashboard.address}`);
      }
      app.httpServer = server;
      resolve(expressApp);
    });
    server.on('error', (err: Error) => {
      reject(err);
    });
  });
}

export async function shutdownOverwatchApp(app: OverwatchApp): Promise<void> {
  // Close all HTTP transport sessions
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
  app.engine.setTrackedProcesses(app.processTracker.serialize());
  app.engine.persist();
}

export function createAppOrExit(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  try {
    return createOverwatchApp(options);
  } catch (error) {
    console.error(formatConfigError(error, options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json'));
    process.exit(1);
  }
}
