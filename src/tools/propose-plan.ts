// ============================================================
// Overwatch — propose_plan (Phase 3A.2 — NL operator cockpit)
//
// The headless 'planner' role translates a free-form operator command into a
// list of OperatorOps and submits it with this tool. The planner PROPOSES; the
// operator CONFIRMS; the dashboard EXECUTES (via the same executeOps path the
// deterministic grammar uses). This tool never mutates engagement state — it
// only records a plan for the operator to confirm, and it REJECTS any plan whose
// ops don't resolve against live state (so a confirmed plan can never silently
// no-op).
//
// The planner role is read-only at the allowlist boundary (no run_bash/run_tool/
// sessions/validate_action) — see allowedToolsFor('planner') in
// headless-mcp-runner.ts. propose_plan is the planner's only write.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { OperatorOp } from '../services/command-interpreter.js';
import { withErrorBoundary } from './error-boundary.js';
import { OperatorOpSchema } from '../services/operator-op-schema.js';
import {
  OperatorCommandService,
  computeScopePreview,
  validateProposedOps,
  type PlannerProposalInput,
  type PlannerProposalResult,
} from '../services/operator-command-service.js';

/**
 * Core recording logic, extracted from the tool handler so it's unit-testable
 * without an MCP server. Validates the ops, rejects the whole plan if any op is
 * unexecutable, otherwise stores it in the engine's ProposedPlanStore and emits
 * a `plan_proposed` activity event.
 */
export type ProposePlanArgs = PlannerProposalInput;
export type ProposePlanResult = PlannerProposalResult;
export { computeScopePreview, validateProposedOps };

export function recordProposedPlan(
  engine: GraphEngine,
  args: ProposePlanArgs,
): ProposePlanResult {
  return new OperatorCommandService(engine).submitProposal(args);
}

export function registerProposePlanTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'propose_plan',
    {
      title: 'Propose Operator Plan',
      description: `Submit a plan of operator operations for the human operator to confirm. Use this (planner role) to translate a free-form operator command into structured ops.

You PROPOSE; the operator CONFIRMS; the dashboard EXECUTES. This tool does NOT mutate engagement state — it records a plan for confirmation. Reference ONLY the exact task_ids / action_ids given in your objective; a plan with any op that can't be resolved against live state is rejected so you can revise it.

Valid ops: directive (pause/resume/stop/narrow_scope/skip_types/prioritize a running task), scope (add cidrs/domains/exclusions), approve/deny (a pending action), and dispatch (deploy an agent at existing graph node id(s) — this is how you turn "port-scan X" / "dig into host Y" into a confirmable action; find the node ids with query_graph). If the command still can't be expressed as these ops, do NOT propose — finish with submit_agent_transcript explaining why.`,
      inputSchema: {
        agent_id: z.string().optional().describe('Your agent id (for attribution)'),
        task_id: z.string().optional().describe('Your planner task id (for correlation)'),
        command: z.string().optional().describe('The operator command this plan answers'),
        summary: z.string().describe('One-line human-readable summary of the plan'),
        rationale: z.string().optional().describe('Why these ops accomplish the command'),
        ops: z.array(OperatorOpSchema).min(1).describe('The ops to propose (at least one)'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('propose_plan', async ({ agent_id, task_id, command, summary, rationale, ops }) => {
      const result = recordProposedPlan(engine, { agent_id, task_id, command, summary, rationale, ops: ops as OperatorOp[] });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        ...(result.ok ? {} : { isError: true }),
      };
    }),
  );
}
