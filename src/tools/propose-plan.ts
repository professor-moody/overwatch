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
import type { AgentDirectiveKind } from '../types.js';
import { previewScopeChange, mergeScopeAdds, type ScopePreview } from '../services/scope-preview.js';
import { isArchetypeId, recommendExploreArchetype } from '../services/agent-archetypes.js';
import { withErrorBoundary } from './error-boundary.js';

const DIRECTIVE_KINDS: readonly AgentDirectiveKind[] = [
  'pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct',
];

export interface ProposePlanArgs {
  agent_id?: string;
  task_id?: string;
  command?: string;
  summary: string;
  rationale?: string;
  ops: OperatorOp[];
}

export type ProposePlanResult =
  | { ok: true; plan_id: string; ops_count: number; summary: string; scope_preview?: ScopePreview }
  | { ok: false; error: string; rejected?: { op: OperatorOp; reason: string }[] };

/** Dry-run scope-impact preview for a plan's scope op(s) — which existing nodes
 *  transition in/out of scope if the plan is confirmed. Null when the plan has no
 *  scope ops. Pure read of current scope + the live graph; never mutates. */
export function computeScopePreview(engine: GraphEngine, ops: OperatorOp[]): ScopePreview | undefined {
  const adds = mergeScopeAdds(ops);
  if (!adds) return undefined;
  const scope = engine.getConfig().scope;
  const exported = engine.exportGraph();
  // Include COLD-store hosts (alive ping-sweep responders with no services/edges live
  // outside the graphology graph) — they're part of the inventory + exactly what a scope
  // change moves in/out.
  const cold = (exported.cold_nodes ?? []).map(c => ({ id: c.id, properties: { ip: c.ip, hostname: c.hostname, label: c.label } }));
  return previewScopeChange(
    [...exported.nodes, ...cold],
    { cidrs: scope.cidrs, domains: scope.domains, exclusions: scope.exclusions },
    adds,
  );
}

/**
 * Validate every op against live engine state. Returns the list of rejections
 * (empty = all ops are executable). A directive must target a real running
 * task; approve/deny must reference a still-pending action; scope must add
 * something. This is the gate that keeps a confirmed plan from no-op'ing.
 */
export function validateProposedOps(engine: GraphEngine, ops: OperatorOp[]): { op: OperatorOp; reason: string }[] {
  const rejected: { op: OperatorOp; reason: string }[] = [];
  const pendingIds = new Set(engine.getPendingActionQueue().getPending().map(a => a.action_id));
  for (const op of ops) {
    if (op.op === 'directive') {
      if (!DIRECTIVE_KINDS.includes(op.kind)) {
        rejected.push({ op, reason: `unknown directive kind "${op.kind}"` });
        continue;
      }
      const task = op.task_id ? engine.getTask(op.task_id) : undefined;
      if (!task) rejected.push({ op, reason: `no agent task with id "${op.task_id}"` });
      else if (task.status !== 'running') rejected.push({ op, reason: `task "${op.task_id}" is ${task.status}, not running` });
    } else if (op.op === 'scope') {
      const adds = (op.add_cidrs?.length ?? 0) + (op.add_domains?.length ?? 0) + (op.add_exclusions?.length ?? 0);
      if (adds === 0) rejected.push({ op, reason: 'scope op adds nothing (no cidrs/domains/exclusions)' });
    } else if (op.op === 'approve' || op.op === 'deny') {
      if (!pendingIds.has(op.action_id)) rejected.push({ op, reason: `no pending action with id "${op.action_id}"` });
    } else if (op.op === 'dispatch') {
      if (!op.target_node_ids?.length) {
        rejected.push({ op, reason: 'dispatch op has no target_node_ids' });
      } else {
        const missing = op.target_node_ids.filter(id => !engine.getNode(id));
        if (missing.length) rejected.push({ op, reason: `unknown node id(s): ${missing.join(', ')}` });
        else if (op.archetype && !isArchetypeId(op.archetype)) rejected.push({ op, reason: `unknown agent type "${op.archetype}"` });
      }
    } else {
      rejected.push({ op: op as OperatorOp, reason: `unsupported op type "${(op as { op: string }).op}"` });
    }
  }
  return rejected;
}

/**
 * Core recording logic, extracted from the tool handler so it's unit-testable
 * without an MCP server. Validates the ops, rejects the whole plan if any op is
 * unexecutable, otherwise stores it in the engine's ProposedPlanStore and emits
 * a `plan_proposed` activity event.
 */
export function recordProposedPlan(engine: GraphEngine, args: ProposePlanArgs): ProposePlanResult {
  const { agent_id, task_id, command, summary, rationale, ops } = args;
  if (!ops.length) {
    return { ok: false, error: 'a plan must contain at least one op' };
  }
  const rejected = validateProposedOps(engine, ops);
  if (rejected.length) {
    return { ok: false, error: `${rejected.length} op(s) could not be resolved against live state`, rejected };
  }

  // Resolve each dispatch op's archetype to a concrete type NOW (post-validation) so the
  // operator confirms exactly what will deploy — never a hidden full-surface 'default'.
  for (const op of ops) {
    if (op.op === 'dispatch' && op.target_node_ids.length) {
      op.archetype = recommendExploreArchetype(op.archetype, engine.getNode(op.target_node_ids[0])?.type);
    }
  }

  const scope_preview = computeScopePreview(engine, ops);
  const plan = engine.getProposedPlanStore().add({
    command: command ?? '',
    ops,
    summary,
    rationale,
    source_task_id: task_id,
    source_agent_id: agent_id,
    scope_preview,
  });

  engine.logActionEvent({
    description: `Planner proposed a ${ops.length}-op plan: ${summary}`,
    event_type: 'plan_proposed',
    category: 'agent',
    result_classification: 'neutral',
    agent_id,
    linked_agent_task_id: task_id,
    details: { reason: 'plan_proposed', plan_id: plan.plan_id, command: command ?? '', summary, ops },
  });

  return { ok: true, plan_id: plan.plan_id, ops_count: ops.length, summary, ...(scope_preview ? { scope_preview } : {}) };
}

const opSchema = z.discriminatedUnion('op', [
  z.object({
    op: z.literal('directive'),
    task_id: z.string().describe('The EXACT id of a running agent task to steer'),
    agent_label: z.string().optional().describe('Display name for the agent (cosmetic)'),
    kind: z.enum(['pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct']),
    node_ids: z.array(z.string()).optional().describe('narrow_scope: node ids to restrict to'),
    frontier_types: z.array(z.string()).optional().describe('skip_types/prioritize: frontier item types'),
    note: z.string().optional(),
  }),
  z.object({
    op: z.literal('scope'),
    add_cidrs: z.array(z.string()).optional(),
    add_domains: z.array(z.string()).optional(),
    add_exclusions: z.array(z.string()).optional(),
  }),
  z.object({
    op: z.literal('approve'),
    action_id: z.string().describe('The EXACT id of a pending action to approve'),
    notes: z.string().optional(),
  }),
  z.object({
    op: z.literal('deny'),
    action_id: z.string().describe('The EXACT id of a pending action to deny'),
    reason: z.string().optional(),
  }),
  z.object({
    op: z.literal('dispatch'),
    target_node_ids: z.array(z.string()).min(1).describe('EXISTING graph node id(s) to deploy the agent at (from your objective/query_graph)'),
    archetype: z.string().optional().describe('Agent type: recon_scanner, web_tester, credential_operator, post_exploit, cve_researcher, osint_recon, pathfinder, … — omit to auto-select from the node type'),
    skill: z.string().optional(),
    objective: z.string().optional().describe('What the agent should accomplish at these nodes'),
  }),
]);

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
        ops: z.array(opSchema).min(1).describe('The ops to propose (at least one)'),
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
