// ============================================================
// Overwatch — App Bootstrap
// Core app construction separated from transport startup.
// ============================================================

import { readFileSync, existsSync } from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
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
};

export type CreateOverwatchAppOptions = {
  config?: EngagementConfig;
  configPath?: string;
  skillDir?: string;
  dashboardPort?: number;
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
): void {
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
}

export function createOverwatchApp(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  const configPath = options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json';
  const config = options.config || loadConfig(configPath);
  const engine = new GraphEngine(config);
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

export async function shutdownOverwatchApp(app: OverwatchApp): Promise<void> {
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
