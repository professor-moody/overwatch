import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerStateTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: get_state
  // Full engagement state briefing from the graph.
  // This is the primary recovery mechanism after compaction.
  // ============================================================
  server.registerTool(
    'get_state',
    {
      title: 'Get Engagement State',
      description: `Returns the complete current state of the engagement, synthesized from the graph.
Use this as your first call in any new or compacted session to understand:
- What targets are in scope
- What has been discovered (nodes and edges)
- What credentials and access you have
- What objectives remain
- What frontier items (next actions) are available
- What agents are currently running

The frontier items are pre-filtered by the deterministic layer (scope, dedup, hard OPSEC vetoes)
but NOT scored — that is your job. You have full access to reason about priorities.

Returns: EngagementState object with graph_summary, objectives, frontier, active_agents, recent_activity, access_summary, and structured warnings from graph health checks.`,
      inputSchema: {
        include_full_frontier: z.boolean()
          .default(true)
          .describe('Include all frontier items. Set false for summary only.'),
        activity_count: z.number()
          .int().min(1).max(100)
          .default(20)
          .describe('Number of recent activity entries to include')
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('get_state', async ({ include_full_frontier, activity_count }) => {
      const state = engine.getState();
      if (!include_full_frontier) {
        state.frontier = state.frontier.slice(0, 10);
      }
      state.recent_activity = state.recent_activity.slice(-activity_count);
      return {
        content: [{ type: 'text', text: JSON.stringify(state, null, 2) }]
      };
    })
  );

  // ============================================================
  // Tool: run_graph_health
  // Full graph integrity report
  // ============================================================
  server.registerTool(
    'run_graph_health',
    {
      title: 'Run Graph Health Checks',
      description: `Run read-only graph integrity checks across the current engagement graph.

Returns categorized issues such as:
- split host identities across multiple node IDs
- unresolved BloodHound fallback identities
- edge type/source/target violations
- stale inferred edges whose trigger conditions no longer hold

Use this when you want the full health report instead of the summarized warnings included in get_state.`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('run_graph_health', async () => {
      const report = engine.getHealthReport();
      return {
        content: [{ type: 'text', text: JSON.stringify(report, null, 2) }]
      };
    })
  );

  // ============================================================
  // Tool: get_history
  // Full engagement activity log for retrospectives.
  // ============================================================
  server.registerTool(
    'get_history',
    {
      title: 'Get Engagement History',
      description: `Returns the full activity log for the engagement.
Use during retrospectives to review all actions taken, findings reported,
inference rules fired, and objectives achieved — with timestamps and agent IDs.`,
      inputSchema: {
        limit: z.number().int().min(1).max(1000).default(100),
        agent_id: z.string().optional().describe('Filter by specific agent')
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('get_history', async ({ limit, agent_id }) => {
      let history = engine.getFullHistory();
      if (agent_id) {
        history = history.filter(h => h.agent_id === agent_id);
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            total_entries: history.length,
            entries: history.slice(-limit)
          }, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: export_graph
  // Full graph export for reporting and analysis.
  // ============================================================
  server.registerTool(
    'export_graph',
    {
      title: 'Export Full Graph',
      description: 'Export the complete engagement graph with all nodes, edges, and properties. Used for retrospectives and reporting.',
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('export_graph', async () => {
      const graph = engine.exportGraph();
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(graph, null, 2)
        }]
      };
    })
  );
}
