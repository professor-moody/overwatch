import { z } from 'zod';
import { createHash } from 'crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { checkAllTools } from '../services/tool-check.js';
import { runLabPreflight } from '../services/lab-preflight.js';
import { withErrorBoundary } from './error-boundary.js';
import { verifyChain, verifyCheckpointSignatures, loadCheckpointKeyring } from '../services/activity-chain.js';
import { computeChangesSince } from '../services/changes-since.js';
import { toolText, COMPACT_PARAM_DESCRIPTION } from './_tool-output.js';

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
          .default(false)
          .describe('Persist a copy of the returned state to the evidence store and log a `system` event so the retrospective can reconstruct exactly what the agent saw when it made each decision. De-duplicated within a 5s window when the state body is unchanged. **Phase H**: defaults to false so the tool is genuinely read-only; pass true at session bootstrap or when you want the snapshot for retrospective fidelity.'),
        since: z.string().optional()
          .describe('ISO timestamp of your last get_state call. When set, the response adds a `changes_since` summary — new findings + which sub-agents completed since then + a recommendation — so a dispatching primary sees at a glance whether to re-synthesize without scanning recent_activity. Unparseable values are ignored.'),
        compact: z.boolean().default(false).describe(COMPACT_PARAM_DESCRIPTION),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('get_state', async ({ include_full_frontier, activity_count, include_reasoning, include_system, snapshot, since, compact }) => {
      const state = engine.getState({
        activityCount: activity_count,
        includeReasoning: include_reasoning,
        includeSystem: include_system,
      });
      if (!include_full_frontier) {
        state.frontier = state.frontier.slice(0, 10);
      }

      // changes_since: a stateless "what happened since you last looked?" digest
      // so a dispatching primary re-synthesizes instead of sitting blind — these
      // signals (completions especially) can scroll out of the capped
      // recent_activity before the next poll. The caller passes its last
      // get_state timestamp; unparseable values are ignored.
      if (since) {
        const digest = computeChangesSince(engine.getFullHistory(), since);
        if (digest) (state as unknown as { changes_since: unknown }).changes_since = digest;
      }

      const stateText = JSON.stringify(state, null, 2);
      // Phase H: snapshot is opt-in. Only the explicit true value triggers
      // evidence persistence + the system event; anything else (including
      // undefined when the test harness bypasses the zod default) keeps
      // get_state truly read-only.
      if (snapshot === true) {
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
      // Evidence snapshot above stays pretty (stateText); only the model-facing
      // response compacts when requested.
      return toolText(state, { compact });
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
      const report = engine.getHealthReport() as unknown as Record<string, unknown>;
      // Phase 6: when hash chain is enabled, surface chain breaks alongside graph health.
      const config = engine.getState().config;
      if (config.hash_chain_enabled) {
        const chain = verifyChain(engine.getFullHistory());
        report.activity_chain = {
          enabled: true,
          valid: chain.valid,
          chained_count: chain.chained_count,
          excluded_count: chain.excluded_count,
          breaks: chain.breaks,
        };
      } else {
        report.activity_chain = { enabled: false };
      }
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
the most recent entry instead.

To close the synthesis loop after dispatching sub-agents, poll with
\`since\` (your last-seen timestamp) + \`event_types: ["agent_transcript_submitted"]\`
to pull just the completions you haven't acted on — these never scroll out of
\`get_state\`'s capped \`recent_activity\` this way.`,
      inputSchema: {
        limit: z.number().int().min(1).max(1000).default(100),
        agent_id: z.string().optional().describe('Filter by specific agent'),
        event_type: z.string().optional().describe('Filter by a single event_type (e.g. action_validated, finding_reported)'),
        event_types: z.array(z.string()).optional().describe('Filter by ANY of these event_types (OR). Combined with event_type if both are given.'),
        since: z.string().optional().describe('ISO timestamp — return only entries strictly newer than this (e.g. your last poll time). Invalid/unparseable values are ignored.'),
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
    withErrorBoundary('get_history', async ({ limit, agent_id, event_type, event_types, since, cursor, direction }) => {
      let history = engine.getFullHistory();

      if (agent_id) {
        history = history.filter(h => h.agent_id === agent_id);
      }
      const typeFilter = new Set([...(event_types ?? []), ...(event_type ? [event_type] : [])]);
      if (typeFilter.size > 0) {
        history = history.filter(h => typeFilter.has(h.event_type ?? ''));
      }
      if (since) {
        const sinceMs = Date.parse(since);
        if (!Number.isNaN(sinceMs)) {
          history = history.filter(h => Date.parse(h.timestamp) > sinceMs);
        }
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

  // ============================================================
  // Tool: verify_activity_chain
  // Walk the activity log and verify the tamper-evident hash chain.
  // Excluded entries (ingested/inferred/thought) are counted but never
  // break the chain. Returns { valid, chained_count, excluded_count, breaks }.
  // ============================================================
  server.registerTool(
    'verify_activity_chain',
    {
      title: 'Verify Activity Chain',
      description: `Verify the tamper-evident hash chain over the engagement's live activity log.

Only events with provenance ∈ {agent, system} and event_type !== 'thought' participate
in the chain. Ingested/inferred/thought entries are counted as \`excluded_count\` and
never break the chain.

When \`hash_chain_enabled\` is false in the engagement config, returns valid:true with
\`chain_disabled: true\` so callers can distinguish "no chain" from "chain ok".`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('verify_activity_chain', async () => {
      const config = engine.getState().config;
      if (!config.hash_chain_enabled) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              valid: true,
              chain_disabled: true,
              chained_count: 0,
              excluded_count: engine.getFullHistory().length,
              breaks: [],
            }, null, 2),
          }],
        };
      }
      const result = verifyChain(engine.getFullHistory());
      // When a verifier public key is configured, also verify checkpoint signatures
      // (attribution on top of the hash-chain tamper-evidence). A signed checkpoint
      // whose signature fails is a hard error; unsigned/unverifiable ones are reported
      // but don't fail the chain (the hash chain already covers tamper-evidence).
      const keyring = loadCheckpointKeyring();
      const checkpoints = engine.getChainCheckpoints();
      let signatures: ReturnType<typeof verifyCheckpointSignatures> | undefined;
      if (Object.keys(keyring).length > 0 && checkpoints.length > 0) {
        signatures = verifyCheckpointSignatures(checkpoints, keyring);
      }
      const sigFailed = !!signatures && signatures.failed.length > 0;
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ ...result, chain_disabled: false, checkpoint_signatures: signatures ?? null }, null, 2),
        }],
        isError: !result.valid || sigFailed,
      };
    }),
  );
}
