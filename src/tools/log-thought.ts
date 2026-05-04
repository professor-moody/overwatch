// ============================================================
// Overwatch — log_thought tool
// Captures the agent's reasoning into the activity log so the
// graph retains a record of *why* decisions were made — not just
// what happened. Cheap, append-only, no side effects on the graph.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

const thoughtKindSchema = z.enum([
  'plan',           // upcoming intent / strategy
  'hypothesis',     // belief about the environment to be tested
  'observation',    // noticed something but not yet a finding
  'decision',       // chose action X over Y, optionally with rationale
  'rejection',      // explicitly chose NOT to pursue something (counterfactual)
  'reflection',     // post-hoc analysis of what happened
  'note',           // miscellaneous
]);

export function registerLogThoughtTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'log_thought',
    {
      title: 'Log Reasoning',
      description: `Persist a piece of the agent's reasoning into the engagement activity log.

Use this BEFORE you act, to record *why* you chose a particular frontier item, *what* hypothesis you're testing, or *which* candidates you considered and rejected. Use it AFTER, to capture reflection on outcomes.

This is the primary mechanism for retaining decision-rationale across compaction and for making post-engagement retrospective meaningful. Cheap to call — no graph mutations, no validation gate, no approval gate. Just a structured log entry.

Recommended usage:
- \`kind="plan"\` — "Going to attempt kerberoast against the 3 SPN-bearing accounts; expecting at least one cleartext crack against rc4 hashes."
- \`kind="hypothesis"\` — "DC02 likely runs unconstrained delegation based on the SPN pattern."
- \`kind="decision"\` — "Picked frontier item X over Y because Y is on a noisy host and we're at 0.6 noise budget."
- \`kind="rejection"\` — "Skipped LDAP relay candidate; signing is enforced per earlier nmap result."
- \`kind="reflection"\` — "Spray succeeded but produced no admin creds; pivoting to BloodHound path analysis."

Always include \`frontier_item_id\` if the thought is about a specific candidate from \`next_task()\`.`,
      inputSchema: {
        thought: z.string().min(1).describe('The reasoning content. Write it in first person, concrete and specific.'),
        kind: thoughtKindSchema.default('note').describe('What kind of thought this is.'),
        agent_id: z.string().optional().describe('Agent or session producing the thought.'),
        frontier_item_id: z.string().optional().describe('Frontier item the thought concerns, if any.'),
        action_id: z.string().optional().describe('Action this thought is associated with (for grouping plan→decision→reflection around one execution).'),
        related_action_ids: z.array(z.string()).optional().describe('Other related action IDs (e.g. predecessors that informed this decision).'),
        target_node_ids: z.array(z.string()).optional().describe('Graph nodes this thought concerns.'),
        considered_alternatives: z.array(z.string()).optional().describe('For decisions/rejections: the other options you weighed.'),
        confidence: z.number().min(0).max(1).optional().describe('Subjective confidence in the thought (0.0–1.0).'),
        tags: z.array(z.string()).optional().describe('Free-form tags for downstream filtering.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('log_thought', async ({
      thought,
      kind,
      agent_id,
      frontier_item_id,
      action_id,
      related_action_ids,
      target_node_ids,
      considered_alternatives,
      confidence,
      tags,
    }) => {
      const resolvedKind = kind || 'note';
      const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;

      const event = engine.logActionEvent({
        description: thought,
        agent_id,
        action_id,
        event_type: 'thought',
        category: 'reasoning',
        frontier_item_id,
        frontier_type: frontierType,
        target_node_ids: target_node_ids && target_node_ids.length > 0 ? target_node_ids : undefined,
        result_classification: 'neutral',
        details: {
          kind: resolvedKind,
          considered_alternatives,
          related_action_ids,
          confidence,
          tags,
        },
      });
      engine.persist();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            event_id: event.event_id,
            kind: resolvedKind,
            recorded: true,
            frontier_item_id,
            action_id,
          }, null, 2),
        }],
      };
    }),
  );
}
