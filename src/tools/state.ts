import { z } from 'zod';
import { createHash } from 'crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { checkAllTools } from '../services/tool-check.js';
import { runLabPreflight } from '../services/lab-preflight.js';
import { withErrorBoundary } from './error-boundary.js';

type StateToolOptions = {
  getDashboardStatus?: () => { enabled: boolean; running: boolean; address?: string };
};

// Per-engine snapshot dedup. Skip writing a fresh evidence blob when the
// returned state body matches the last snapshot AND less than this many
// milliseconds have elapsed. Re-emit a lightweight system event pointing
// at the previous evidence_id so the chain isn't broken.
const SNAPSHOT_DEDUP_WINDOW_MS = 5_000;
const lastSnapshotByEngine = new WeakMap<GraphEngine, { hash: string; evidence_id: string; ts: number }>();

export function registerStateTools(server: McpServer, engine: GraphEngine, options: StateToolOptions = {}): void {

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
          .describe('Number of recent activity entries to include'),
        include_reasoning: z.boolean()
          .default(false)
          .describe('Include `event_type=thought` / `category=reasoning` entries in recent_activity. Default false to keep volume manageable; thoughts are still queryable via get_history / query_graph.'),
        include_system: z.boolean()
          .default(true)
          .describe('Include `category=system` entries in recent_activity (snapshots, ingested transcript turns, instrumentation warnings). Set false to focus on operational events only.'),
        snapshot: z.boolean()
          .default(true)
          .describe('Persist a copy of the returned state to the evidence store and log a `system` event so the retrospective can reconstruct exactly what the agent saw when it made each decision. De-duplicated within a 5s window when the state body is unchanged.'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('get_state', async ({ include_full_frontier, activity_count, include_reasoning, include_system, snapshot }) => {
      const state = engine.getState({
        activityCount: activity_count,
        includeReasoning: include_reasoning,
        includeSystem: include_system,
      });
      if (!include_full_frontier) {
        state.frontier = state.frontier.slice(0, 10);
      }
      const stateText = JSON.stringify(state, null, 2);
      if (snapshot !== false) {
        // Hash a stable view that excludes `recent_activity`. The snapshot itself
        // appends a system event to the activity log, which would otherwise force
        // every back-to-back call to look "different" and defeat dedup.
        const { recent_activity: _ra, ...stateForHash } = state as any;
        const hash = createHash('sha256').update(JSON.stringify(stateForHash)).digest('hex');
        const now = Date.now();
        const prev = lastSnapshotByEngine.get(engine);
        const dedup = prev && prev.hash === hash && (now - prev.ts) < SNAPSHOT_DEDUP_WINDOW_MS;
        if (dedup) {
          // Lightweight breadcrumb pointing at the previous evidence — no new blob written.
          engine.logActionEvent({
            description: 'State snapshot deduplicated (unchanged within window)',
            event_type: 'system',
            category: 'system',
            tool_name: 'get_state',
            provenance: 'system',
            result_classification: 'neutral',
            details: {
              evidence_id: prev!.evidence_id,
              evidence_type: 'log',
              dedup: true,
              frontier_size: state.frontier.length,
              activity_count,
            },
          });
        } else {
          const evidence_id = engine.getEvidenceStore().store({
            evidence_type: 'log',
            filename: 'get_state.json',
            content: stateText,
          });
          lastSnapshotByEngine.set(engine, { hash, evidence_id, ts: now });
          engine.logActionEvent({
            description: 'State snapshot returned to caller',
            event_type: 'system',
            category: 'system',
            tool_name: 'get_state',
            provenance: 'system',
            result_classification: 'neutral',
            details: {
              evidence_id,
              evidence_type: 'log',
              frontier_size: state.frontier.length,
              activity_count,
            },
          });
        }
        engine.persist();
      }
      return {
        content: [{ type: 'text', text: stateText }]
      };
    })
  );

  // ============================================================
  // Tool: run_lab_preflight
  // Aggregate lab-readiness checks for GOAD/HTB-style workflows
  // ============================================================
  server.registerTool(
    'run_lab_preflight',
    {
      title: 'Run Lab Preflight',
      description: `Run a read-only lab-readiness check for the current engagement.

This aggregates:
- engagement config validity and scope shape
- offensive tool availability for the selected profile
- graph health summary
- persistence and restart-safety checks
- dashboard readiness
- current graph stage (empty, seeded, or mid-run)

Profiles:
- **goad_ad**: GOAD-style multi-host AD lab validation (requires scoped domains)
- **network**: Multi-host CIDR-scoped lab (HTB ProLabs, etc.) — domains discovered organically
- **single_host**: Standalone single-target host validation
- **web_app**: Web application assessment (URL-scoped, checks for web tooling)
- **cloud**: Cloud environment assessment (AWS/Azure/GCP resource-scoped)
- **hybrid**: Combined network + cloud + web assessment

Use this before your first lab run, after major ingestion, or after restart to confirm the environment is trustworthy enough for operator testing.`,
      inputSchema: {
        profile: z.enum(['goad_ad', 'single_host', 'network', 'web_app', 'cloud', 'hybrid'])
          .optional()
          .describe('Lab profile to validate against. If omitted, inferred from engagement config. Set explicitly for web_app, cloud, or hybrid engagements.'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      }
    },
    withErrorBoundary('run_lab_preflight', async ({ profile }) => {
      const toolStatuses = await checkAllTools();
      const report = runLabPreflight(engine, {
        profile,
        toolStatuses,
        dashboard: options.getDashboardStatus?.(),
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(report, null, 2) }]
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

  server.registerTool(
    'recompute_objectives',
    {
      title: 'Recompute Objective Status',
      description: `Re-evaluate all engagement objectives from the current graph state.

Use this after graph correction or when objective status appears stale. Objective truth
is derived from the graph and engagement config, not from PATH_TO_OBJECTIVE edges.`,
      inputSchema: {},
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('recompute_objectives', async () => {
      const result = engine.recomputeObjectives();
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }),
  );

  // ============================================================
  // Tool: get_history
  // Paginated engagement activity log for retrospectives.
  // ============================================================
  server.registerTool(
    'get_history',
    {
      title: 'Get Engagement History',
      description: `Returns paginated activity log entries for the engagement.

Use during retrospectives to review actions taken, findings reported,
inference rules fired, and objectives achieved — with timestamps and agent IDs.

Pagination: use \`cursor\` (an event_id) to fetch the next page. The response
includes \`next_cursor\` when more entries exist. Omit \`cursor\` to start from
the oldest retained entry. Set \`direction\` to "newest_first" to start from
the most recent entry instead.`,
      inputSchema: {
        limit: z.number().int().min(1).max(1000).default(100),
        agent_id: z.string().optional().describe('Filter by specific agent'),
        event_type: z.string().optional().describe('Filter by event_type (e.g. action_validated, finding_reported)'),
        cursor: z.string().optional().describe('event_id cursor — fetch entries after this event'),
        direction: z.enum(['oldest_first', 'newest_first']).default('oldest_first').describe('Traversal direction'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('get_history', async ({ limit, agent_id, event_type, cursor, direction }) => {
      let history = engine.getFullHistory();

      if (agent_id) {
        history = history.filter(h => h.agent_id === agent_id);
      }
      if (event_type) {
        history = history.filter(h => h.event_type === event_type);
      }

      if (direction === 'newest_first') {
        history = [...history].reverse();
      }

      let startIdx = 0;
      if (cursor) {
        const cursorIdx = history.findIndex(h => h.event_id === cursor);
        if (cursorIdx >= 0) {
          startIdx = cursorIdx + 1;
        }
      }

      const page = history.slice(startIdx, startIdx + limit);
      const hasMore = startIdx + limit < history.length;
      const nextCursor = hasMore && page.length > 0 ? page[page.length - 1].event_id : undefined;

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            total_entries: history.length,
            returned: page.length,
            has_more: hasMore,
            next_cursor: nextCursor,
            direction,
            entries: page,
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
