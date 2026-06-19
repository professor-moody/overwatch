import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { buildFindingReadiness } from '../services/finding-readiness.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerFindingReadinessTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: get_finding_readiness
  // Read-only proof-readiness rollup for the evidence_auditor archetype.
  // ============================================================
  server.registerTool(
    'get_finding_readiness',
    {
      title: 'Get Finding Readiness',
      description: `Audit findings for proof readiness before reporting. For each finding returns a readiness label — **client_ready** (backed by captured evidence / proof cards), **needs_validation** (a claim with no captured evidence yet), or **draft** (thin) — plus the concrete gaps to close. Derived from the same finding builder + classifier the report uses. Read-only; optionally scope to one finding_id.`,
      inputSchema: {
        finding_id: z.string().optional().describe('Audit a single finding by id (default: all findings)'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('get_finding_readiness', async ({ finding_id }) => {
      const { summary, findings } = buildFindingReadiness(engine, finding_id);
      return { content: [{ type: 'text', text: JSON.stringify({ summary, findings }, null, 2) }] };
    }),
  );
}
