import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { FRONTIER_TYPES } from '../contracts/dashboard-v1.js';
import type { GraphEngine } from '../services/graph-engine.js';
import {
  DispatchCommandError,
  DispatchCommandService,
} from '../services/dispatch-command-service.js';
import type { AgentTask } from '../types.js';
import { taskWireIdentity } from './_agent-tool-shared.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerSingleAgentTool(
  server: McpServer,
  dispatchCommands: DispatchCommandService,
): void {
  server.registerTool(
    'register_agent',
    {
      title: 'Register Agent',
      description: `Register a new sub-agent task. Called by the primary session when dispatching agents.

Provide the frontier item the agent should work on and the relevant node IDs for its scoped subgraph view.
The agent can then call get_agent_context with its task ID to receive its scoped view.`,
      inputSchema: {
        agent_label: z.string().optional().describe('Canonical human-readable label for the agent'),
        agent_id: z.string().optional().describe('Legacy alias for agent_label (retained for one minor release)'),
        frontier_item_id: z.string().optional().describe('ID of the frontier item this agent should work on (recommended for attribution)'),
        subgraph_node_ids: z.array(z.string()).default([]).describe('Optional node IDs relevant to this agent\'s task. Leave empty to auto-compute from the frontier item.'),
        skill: z.string().optional().describe('Skill/methodology to apply'),
        archetype: z.string().optional().describe('Optional agent-type override (e.g. recon_scanner, web_tester, credential_operator, post_exploit, cve_researcher). When omitted, the archetype is auto-selected from the frontier item type + node type.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('register_agent', async ({
      agent_label,
      agent_id: legacyAgentId,
      frontier_item_id,
      subgraph_node_ids,
      skill,
      archetype,
    }) => {
      if (!agent_label && !legacyAgentId) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'agent_label is required' }) }],
          isError: true,
        };
      }
      if (agent_label && legacyAgentId && agent_label !== legacyAgentId) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'agent_label and legacy agent_id must match when both are supplied',
            }),
          }],
          isError: true,
        };
      }
      const agentLabel = agent_label ?? legacyAgentId!;
      const execution = dispatchCommands.register({
        agent_label: agentLabel,
        frontier_item_id,
        target_node_ids: subgraph_node_ids,
        skill,
        archetype,
      }, { transport: 'mcp' });
      const body = execution.result!.body;
      const task = body.task as AgentTask | undefined;
      if (body.dispatched !== true || !task) {
        return {
          content: [{ type: 'text', text: JSON.stringify(body, null, 2) }],
          isError: true,
        };
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...taskWireIdentity(task),
            status: task.status,
            archetype: task.archetype,
            scope_node_count: task.subgraph_node_ids.length,
            ...(body.skipped_existing === true ? { skipped_existing: true } : {}),
            command_id: execution.command_id,
            replayed: execution.replayed,
            message: `Agent ${task.agent_label ?? task.agent_id} registered${frontier_item_id ? ` for task ${frontier_item_id}` : ''} as ${task.archetype}`,
          }, null, 2),
        }],
      };
    }),
  );
}

export function registerDispatchAgentsTool(
  server: McpServer,
  dispatchCommands: DispatchCommandService,
): void {
  server.registerTool(
    'dispatch_agents',
    {
      title: 'Dispatch Agents',
      description: `Batch-register sub-agent tasks from the current filtered frontier.

Uses the same frontier computation and deterministic filtering path as next_task,
then registers up to count running agent tasks with auto-computed subgraph scopes.
Skips frontier items that already have a running agent or cannot be scoped.`,
      inputSchema: {
        count: z.number().int().min(1).max(20).default(3).describe('Maximum number of agents to dispatch'),
        strategy: z.enum(['top_priority', 'by_type']).default('top_priority').describe('How to choose frontier items'),
        types: z.array(z.enum(FRONTIER_TYPES)).optional().describe('Optional frontier types to include when dispatching'),
        skill: z.string().optional().describe('Optional skill override applied to each dispatched agent'),
        archetype: z.string().optional().describe('Optional agent-type override applied to every dispatched agent. When omitted, each agent\'s archetype is auto-selected from its frontier item type + node type.'),
        hops: z.number().int().min(1).max(5).default(2).describe('Hops to use when auto-computing subgraph scope'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('dispatch_agents', async ({ count, strategy, types, skill, archetype, hops }) => {
      const execution = dispatchCommands.dispatchFrontierBatch({
        count,
        strategy,
        types,
        skill,
        archetype,
        hops,
      }, { transport: 'mcp' });
      const result: Record<string, unknown> = {
        ...execution.result,
        command_id: execution.command_id,
        replayed: execution.replayed,
      };
      if (execution.result?.dispatched.length === 0) {
        result.warning = 'No agents dispatched — all candidates were skipped or filtered';
      }
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }),
  );
}

export function registerDispatchSubnetAgentsTool(
  server: McpServer,
  dispatchCommands: DispatchCommandService,
): void {
  server.registerTool(
    'dispatch_subnet_agents',
    {
      title: 'Dispatch Subnet Agents',
      description: `Dispatch one sub-agent per scope CIDR for parallel network enumeration.

For each CIDR in the engagement scope, registers a sub-agent whose task is to
sweep and enumerate that subnet. Skips CIDRs that already have a running agent
or are fully discovered. Each agent receives the already-discovered nodes in
its CIDR as its scoped subgraph.`,
      inputSchema: {
        max_agents: z.number().int().min(1).max(20).default(8).describe('Maximum number of agents to dispatch'),
        skill: z.string().default('subnet-enumeration').describe('Skill/methodology to assign to each agent'),
        hops: z.number().int().min(1).max(5).default(2).describe('Hops for subgraph scope computation'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('dispatch_subnet_agents', async ({ max_agents, skill, hops }) => {
      try {
        const execution = dispatchCommands.dispatchSubnets({
          max_agents,
          skill,
          hops,
        }, { transport: 'mcp' });
        return {
          content: [{ type: 'text', text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
          }, null, 2) }],
        };
      } catch (error) {
        if (!(error instanceof DispatchCommandError)) throw error;
        return {
          content: [{ type: 'text', text: JSON.stringify({
            error: error.message,
            code: error.code,
          }, null, 2) }],
          isError: true,
        };
      }
    }),
  );
}

export function registerDispatchCampaignAgentsTool(
  server: McpServer,
  dispatchCommands: DispatchCommandService,
): void {
  server.registerTool(
    'dispatch_campaign_agents',
    {
      title: 'Dispatch Campaign Agents',
      description: `Dispatch sub-agents for each item in a campaign, using campaign-aware scoping.

Activates the campaign if it is in draft status, then registers one agent per
frontier item (up to max_agents). Scope computation is strategy-aware:
- credential_spray: credential + target services + parent hosts
- post_exploitation: host + all connected nodes
- enumeration/network_discovery/custom: N-hop subgraph from frontier seeds

Skips items that already have a running agent.`,
      inputSchema: {
        campaign_id: z.string().describe('ID of the campaign to dispatch agents for'),
        max_agents: z.number().int().min(1).max(20).default(8).describe('Maximum number of agents to dispatch'),
        hops: z.number().int().min(1).max(5).default(2).describe('Hops for subgraph scope computation'),
        skill: z.string().optional().describe('Optional skill override applied to each dispatched agent'),
        archetype: z.string().optional().describe('Optional agent-type override applied to every dispatched agent. When omitted, the archetype is derived from the campaign strategy (e.g. credential_spray → credential_operator).'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('dispatch_campaign_agents', async ({ campaign_id, max_agents, hops, skill, archetype }) => {
      try {
        const execution = dispatchCommands.dispatchCampaign({
          campaign_id,
          max_agents,
          hops,
          skill,
          archetype,
        }, { transport: 'mcp' });
        return {
          content: [{ type: 'text', text: JSON.stringify({
            ...execution.result,
            command_id: execution.command_id,
            replayed: execution.replayed,
          }, null, 2) }],
        };
      } catch (error) {
        if (!(error instanceof DispatchCommandError)) throw error;
        return {
          content: [{ type: 'text', text: JSON.stringify({
            error: error.message,
            campaign_id,
            code: error.code,
          }, null, 2) }],
          isError: true,
        };
      }
    }),
  );
}

export type DispatchResult = import('../services/dispatch-command-service.js').CampaignAgentDispatchResponse & {
  error?: string;
};

export function dispatchCampaignAgents(
  engine: GraphEngine,
  campaign_id: string,
  options: { max_agents?: number; hops?: number; skill?: string; archetype?: string } = {},
): DispatchResult {
  try {
    return new DispatchCommandService(engine).dispatchCampaign({
      campaign_id,
      max_agents: options.max_agents,
      hops: options.hops,
      skill: options.skill,
      archetype: options.archetype,
    }, { transport: 'system' }).result!;
  } catch (error) {
    const campaign = engine.getCampaign(campaign_id);
    return {
      campaign_id,
      strategy: campaign?.strategy ?? '',
      requested: options.max_agents ?? 8,
      total_items: campaign?.items.length ?? 0,
      dispatched: [],
      skipped: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
