// ============================================================
// Overwatch — get_timeline MCP tool (P3.3 — backend)
//
// "What was true at time T?" Returns per-node and per-edge timeline
// entries: when each entity became true, when (if ever) it became false,
// last observation, and the activity-log events that touch it.
//
// Read-only; derives from graph + activity log on every call. No new
// persistence introduced. Dashboard timeline panel will consume this
// tool in a follow-up; for now it's a structured introspection surface.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerTimelineTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'get_timeline',
    {
      title: 'Get Engagement Timeline',
      description: `Returns per-node and per-edge timeline entries. Each entry says when the entity became true, when (if ever) it became false, when it was last observed, and which activity-log events reference it.

Use \`at\` to ask "what was true at time T" — the result is filtered to entries that were known-true at that timestamp. Use \`since\` to scope to recent additions. Combine with \`entity_id\` to drill into a single node/edge across its full lifetime.

Invalidation today comes from existing graph signals: \`credential_status\` ∈ {expired, rotated, stale}, \`valid_until\` in the past, \`session_live: false\` on HAS_SESSION edges, and \`identity_status: superseded\`. Future passes will add explicit invalidation events for richer scrubbing.`,
      inputSchema: {
        entity_id: z.string().optional().describe('Filter to a specific node_id or edge_id'),
        kind: z.enum(['node', 'edge']).optional().describe('Filter to nodes or edges only'),
        at: z.string().optional().describe('ISO timestamp — return only entries known-true at this moment'),
        since: z.string().optional().describe('ISO timestamp — return only entries that became true at or after this moment'),
        limit: z.number().int().min(1).max(2000).default(200)
          .describe('Maximum entries (newest first by became_true_at)'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('get_timeline', async ({ entity_id, kind, at, since, limit }) => {
      const entries = engine.getTimeline({ entity_id, kind, at, since, limit });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ count: entries.length, entries }, null, 2),
        }],
      };
    }),
  );
}
