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

// --- Load engagement config ---
function loadConfig(): EngagementConfig {
  const configPath = process.env.OVERWATCH_CONFIG || './engagement.json';
  if (!existsSync(configPath)) {
    console.error(`Config not found at ${configPath}. Creating default config.`);
    return {
      id: uuidv4(),
      name: 'default-engagement',
      created_at: new Date().toISOString(),
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 }
    };
  }
  return JSON.parse(readFileSync(configPath, 'utf-8'));
}

// --- Initialize ---
const config = loadConfig();
const engine = new GraphEngine(config);
const skillDir = process.env.OVERWATCH_SKILLS || './skills';
const skills = new SkillIndex(skillDir);
console.error(`Loaded ${skills.count} skills from ${skillDir}`);

const processTracker = new ProcessTracker();

const server = new McpServer({
  name: 'overwatch-mcp-server',
  version: '0.1.0'
});

// --- Register all tools ---
registerStateTools(server, engine);
registerFindingTools(server, engine);
registerScoringTools(server, engine);
registerExplorationTools(server, engine);
registerAgentTools(server, engine);
registerSkillTools(server, skills);
registerBloodHoundTools(server, engine);
registerToolCheckTools(server);
registerProcessTools(server, processTracker);
registerInferenceTools(server, engine);
registerParseOutputTools(server, engine);

// ============================================================
// Start Server
// ============================================================
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Overwatch MCP server running on stdio');
}

main().catch(error => {
  console.error('Server error:', error);
  process.exit(1);
});
