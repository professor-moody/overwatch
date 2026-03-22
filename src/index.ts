// ============================================================
// Overwatch — MCP Orchestrator Server
// ============================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { v4 as uuidv4 } from 'uuid';
import { readFileSync, existsSync } from 'fs';
import { GraphEngine } from './services/graph-engine.js';
import { SkillIndex } from './services/skill-index.js';
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
import { ProcessTracker } from './services/process-tracker.js';
import { DashboardServer } from './services/dashboard-server.js';
import { registerRetrospectiveTools } from './tools/retrospective.js';

// --- Load engagement config ---
function loadConfig(): EngagementConfig {
  const configPath = process.env.OVERWATCH_CONFIG || './engagement.json';
  if (!existsSync(configPath)) {
    console.error(`Config not found at ${configPath}. Creating default config.`);
    return engagementConfigSchema.parse({
      id: uuidv4(),
      name: 'default-engagement',
      created_at: new Date().toISOString(),
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 }
    });
  }
  return parseEngagementConfig(readFileSync(configPath, 'utf-8'));
}

// --- Initialize ---
let config: EngagementConfig;
try {
  config = loadConfig();
} catch (error) {
  console.error(formatConfigError(error, process.env.OVERWATCH_CONFIG || './engagement.json'));
  process.exit(1);
}
const engine = new GraphEngine(config);
const skillDir = process.env.OVERWATCH_SKILLS || './skills';
const skills = new SkillIndex(skillDir);
console.error(`Loaded ${skills.count} skills from ${skillDir}`);

// Restore ProcessTracker from persisted state if available
const savedProcesses = engine.getTrackedProcesses();
const processTracker = savedProcesses.length > 0
  ? ProcessTracker.deserialize(savedProcesses)
  : new ProcessTracker();

const server = new McpServer({
  name: 'overwatch-mcp-server',
  version: '0.1.0'
});

// ============================================================
// Dashboard (HTTP + WebSocket)
// ============================================================
const dashboardPort = parseInt(process.env.OVERWATCH_DASHBOARD_PORT || '8384', 10);
const dashboard = dashboardPort > 0 ? new DashboardServer(engine, dashboardPort) : null;

// --- Register all tools ---
registerStateTools(server, engine, {
  getDashboardStatus: () => ({
    enabled: dashboard !== null,
    running: dashboard?.running ?? false,
    address: dashboard?.address,
  }),
});
registerFindingTools(server, engine);
registerScoringTools(server, engine);
registerExplorationTools(server, engine);
registerAgentTools(server, engine);
registerSkillTools(server, skills);
registerBloodHoundTools(server, engine);
registerToolCheckTools(server);
registerProcessTools(server, processTracker, engine);
registerInferenceTools(server, engine);
registerParseOutputTools(server, engine);
registerRetrospectiveTools(server, engine, skills);

// ============================================================
// Start Server
// ============================================================
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Overwatch MCP server running on stdio');

  // Dashboard starts fire-and-forget — never blocks MCP transport
  // Only register the graph-update callback if the server actually binds
  if (dashboard) {
    const result = await dashboard.start();
    if (result.started) {
      engine.onUpdate((detail) => dashboard.onGraphUpdate(detail));
    }
  }
}

// Graceful shutdown
function shutdown() {
  console.error('Shutting down Overwatch...');
  if (dashboard) {
    dashboard.stop().catch(() => {});
  }
  // Sync ProcessTracker state into engine before final persist
  engine.setTrackedProcesses(processTracker.serialize());
  engine.persist();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

main().catch(error => {
  console.error('Server error:', error);
  process.exit(1);
});
