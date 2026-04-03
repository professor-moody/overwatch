import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { generateSystemPrompt, type ToolEntry } from '../services/prompt-generator.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerInstructionTools(
  server: McpServer,
  engine: GraphEngine,
  getRegisteredTools: () => ToolEntry[],
): void {

  // ============================================================
  // Tool: get_system_prompt
  // Generates dynamic agent instructions from current engagement state.
  // ============================================================
  server.registerTool(
    'get_system_prompt',
    {
      title: 'Get System Prompt',
      description: `Generate a dynamic system prompt for an MCP consumer based on the current engagement state.

Returns a markdown system prompt tailored to the specified role, including engagement briefing,
tool reference table, state snapshot, and OPSEC constraints. Use this instead of static AGENTS.md
instructions for session initialization.

- role=primary: Full orchestrator instructions with core loop and all tools
- role=sub_agent: Scoped worker instructions with subset of tools and agent context`,
      inputSchema: {
        role: z.enum(['primary', 'sub_agent']).describe('Consumer role: primary orchestrator or scoped sub-agent'),
        agent_id: z.string().optional().describe('For sub_agent role: the agent ID to scope the instructions'),
        include_state: z.boolean().default(true).describe('Include current state snapshot in the prompt'),
        include_tools: z.boolean().default(true).describe('Include tool reference table in the prompt'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('get_system_prompt', async ({ role, agent_id, include_state, include_tools }) => {
      const tools = getRegisteredTools();
      const prompt = generateSystemPrompt(engine, tools, {
        role,
        agent_id,
        include_state,
        include_tools,
      });

      return {
        content: [{
          type: 'text',
          text: prompt,
        }],
      };
    }),
  );
}
