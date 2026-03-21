import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerScoringTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: next_task
  // Returns the filtered frontier for LLM scoring.
  // ============================================================
  server.registerTool(
    'next_task',
    {
      title: 'Get Next Tasks',
      description: `Returns frontier items (candidate next actions) with graph context attached.

The deterministic layer has already filtered out:
- Out-of-scope targets
- Duplicate/already-tested actions
- Actions exceeding OPSEC hard noise limits
- Dead hosts

Everything else passes through for YOUR analysis. Each item includes graph metrics
(hops to objective, fan-out estimate, node degree, confidence, OPSEC noise rating).

YOUR job is to:
1. Score and rank these by overall value
2. Spot multi-step attack chains across items
3. Consider sequencing (what should happen first)
4. Assess likely defenses and risks
5. Recommend specific actions for the top items

Returns: Array of FrontierItem objects with graph metrics, plus any items that were filtered and why.`,
      inputSchema: {
        max_items: z.number().int().min(1).max(50)
          .default(20)
          .describe('Maximum frontier items to return'),
        include_filtered: z.boolean()
          .default(false)
          .describe('Also return items that were filtered out, with reasons')
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('next_task', async ({ max_items, include_filtered }) => {
      const frontier = engine.computeFrontier();
      const { passed, filtered } = engine.filterFrontier(frontier);

      const result: Record<string, unknown> = {
        candidate_count: passed.length,
        candidates: passed.slice(0, max_items)
      };

      if (include_filtered) {
        result.filtered_count = filtered.length;
        result.filtered = filtered.slice(0, 20);
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    })
  );

  // ============================================================
  // Tool: validate_action
  // Pre-execution sanity check against graph + OPSEC policy.
  // ============================================================
  server.registerTool(
    'validate_action',
    {
      title: 'Validate Action',
      description: `Validate a proposed action against the graph state and OPSEC policy BEFORE executing it.

Checks:
- Do referenced nodes actually exist in the graph?
- Is the target in scope (not excluded)?
- Is the technique blacklisted by OPSEC profile?
- Is the action within the approved time window?

Call this before every significant action. Returns valid/invalid with specific errors and warnings.`,
      inputSchema: {
        target_node: z.string().optional().describe('Node ID being targeted'),
        edge_source: z.string().optional().describe('Source node of the edge being tested'),
        edge_target: z.string().optional().describe('Target node of the edge being tested'),
        technique: z.string().optional().describe('Technique name (e.g. kerberoast, ntlmrelay, portscan)'),
        description: z.string().describe('Human-readable description of the planned action')
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('validate_action', async ({ target_node, edge_source, edge_target, technique, description }) => {
      const result = engine.validateAction({ target_node, edge_source, edge_target, technique });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action: description,
            ...result
          }, null, 2)
        }]
      };
    })
  );
}
