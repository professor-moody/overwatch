import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { DispatchCommandService } from '../services/dispatch-command-service.js';
import { AgentLifecycleCommandService } from '../services/agent-lifecycle-command-service.js';
import { AgentWorkCommandService } from '../services/agent-work-command-service.js';
import {
  registerDispatchAgentsTool,
  registerDispatchCampaignAgentsTool,
  registerDispatchSubnetAgentsTool,
  registerSingleAgentTool,
} from './agent-dispatch-tools.js';
import { registerAgentContextTool } from './agent-context-tools.js';
import { registerAgentTranscriptTool } from './agent-transcript-tools.js';
import {
  registerAgentHeartbeatTool,
  registerUpdateAgentTool,
} from './agent-lifecycle-tools.js';
import {
  registerAcknowledgeAgentDirectiveTool,
  registerAskOperatorTool,
  registerManageAgentDirectiveTool,
} from './agent-steering-tools.js';
import { registerAgentWorkTools } from './agent-work-tools.js';

export {
  dispatchCampaignAgents,
  type DispatchResult,
} from './agent-dispatch-tools.js';

/** Compatibility facade. Keep the historical public entry point and exact tool
 * registration order while focused modules own each adapter family. */
export function registerAgentTools(server: McpServer, engine: GraphEngine): void {
  const dispatchCommands = new DispatchCommandService(engine);
  const lifecycleCommands = new AgentLifecycleCommandService(engine);
  const workCommands = new AgentWorkCommandService(engine);

  registerSingleAgentTool(server, dispatchCommands);
  registerDispatchAgentsTool(server, dispatchCommands);
  registerAgentContextTool(server, engine);
  registerAgentTranscriptTool(server, lifecycleCommands);
  registerUpdateAgentTool(server, lifecycleCommands);
  registerDispatchSubnetAgentsTool(server, dispatchCommands);
  registerDispatchCampaignAgentsTool(server, dispatchCommands);
  registerAgentHeartbeatTool(server, lifecycleCommands);
  registerAskOperatorTool(server, lifecycleCommands);
  registerManageAgentDirectiveTool(server, lifecycleCommands);
  registerAcknowledgeAgentDirectiveTool(server, lifecycleCommands);
  registerAgentWorkTools(server, workCommands);
}
