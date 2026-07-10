// ============================================================
// Overwatch — Operator Command Interpreter (Phase 3A)
//
// Turns a natural-language operator command into a list of structured
// OperatorOps that map 1:1 onto EXISTING validated engine methods (directives,
// scope, approvals). The deterministic grammar here handles the high-frequency,
// unambiguous verbs instantly; anything it can't resolve is returned in
// `unresolved` for the headless planner fallback (3A.2) to handle.
//
// Safety: this module never mutates. `executeOps` is the single execution path,
// and it only calls existing engine methods — so OPSEC/scope/lease/approval
// guards still apply. Nothing executes without an explicit operator confirm
// (enforced by the /api/commands endpoint).
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type { GraphEngine } from './graph-engine.js';
import type { AgentDirectiveKind } from '../types.js';
import { getArchetype, recommendExploreArchetype } from './agent-archetypes.js';

export type OperatorOp =
  | { op: 'directive'; task_id: string; agent_label: string; kind: AgentDirectiveKind; node_ids?: string[]; frontier_types?: string[]; note?: string }
  | { op: 'scope'; add_cidrs?: string[]; add_domains?: string[]; add_exclusions?: string[] }
  | { op: 'approve'; action_id: string; notes?: string }
  | { op: 'deny'; action_id: string; reason?: string }
  // Deploy an agent at existing graph node(s). Lets the planner answer "port-scan X"
  // / "dig into host Y" with a confirmable action instead of dead-ending as advice.
  // The operator confirms before it runs; archetype is resolved to a concrete type at
  // propose time so the confirm card shows exactly what will deploy.
  | { op: 'dispatch'; target_node_ids: string[]; archetype?: string; skill?: string; objective?: string };

export interface InterpreterTask {
  id: string;
  agent_id: string;
  status: string;
  skill?: string;
}

export interface InterpreterState {
  tasks: InterpreterTask[];
  pendingActionIds: string[];
}

export interface InterpretResult {
  ops: OperatorOp[];
  summary: string;
  unresolved: { text: string; reason: string }[];
}

const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i;

function resolveTasks(ref: string, tasks: InterpreterTask[]): InterpreterTask[] {
  const exact = tasks.filter(t => t.id === ref || t.agent_id === ref);
  if (exact.length) return exact;
  const needle = ref.toLowerCase();
  return tasks.filter(t =>
    t.agent_id.toLowerCase().includes(needle) || (t.skill ?? '').toLowerCase().includes(needle));
}

function resolveActionId(ref: string, ids: string[]): string | null {
  if (ids.includes(ref)) return ref;
  const prefix = ids.filter(id => id.startsWith(ref));
  return prefix.length === 1 ? prefix[0] : null;
}

/** Deterministic NL → ops. Pure. Unrecognized input lands in `unresolved`. */
export function interpretCommand(text: string, state: InterpreterState): InterpretResult {
  const raw = text.trim();
  const ops: OperatorOp[] = [];
  const unresolved: InterpretResult['unresolved'] = [];

  // --- directive verbs (pause / resume / stop / halt) ---
  const dir = raw.match(/^(pause|resume|stop|halt)\s+(.+)$/i);
  if (dir) {
    const kind: AgentDirectiveKind = dir[1].toLowerCase() === 'halt' ? 'stop' : (dir[1].toLowerCase() as AgentDirectiveKind);
    const ref = dir[2].trim();
    const running = state.tasks.filter(t => t.status === 'running');
    if (/^(all|everything|all agents)$/i.test(ref)) {
      if (running.length === 0) unresolved.push({ text: raw, reason: `no running agents to ${kind}` });
      for (const t of running) ops.push({ op: 'directive', task_id: t.id, agent_label: t.agent_id, kind });
    } else {
      const matches = resolveTasks(ref, running);
      if (matches.length === 1) ops.push({ op: 'directive', task_id: matches[0].id, agent_label: matches[0].agent_id, kind });
      else if (matches.length === 0) unresolved.push({ text: raw, reason: `no running agent matches "${ref}"` });
      else unresolved.push({ text: raw, reason: `"${ref}" matches ${matches.length} agents — be specific (agent id)` });
    }
    return finalize(ops, unresolved);
  }

  // --- free-text instruction: "tell|instruct <agent> [to] <text>" ---
  const tell = raw.match(/^(?:tell|instruct)\s+(\S+)\s+(?:to\s+)?(.+)$/i);
  if (tell) {
    const ref = tell[1].trim();
    const note = tell[2].trim();
    const running = state.tasks.filter(t => t.status === 'running');
    const matches = resolveTasks(ref, running);
    if (matches.length === 1) ops.push({ op: 'directive', task_id: matches[0].id, agent_label: matches[0].agent_id, kind: 'instruct', note });
    else if (matches.length === 0) unresolved.push({ text: raw, reason: `no running agent matches "${ref}"` });
    else unresolved.push({ text: raw, reason: `"${ref}" matches ${matches.length} agents — be specific (agent id)` });
    return finalize(ops, unresolved);
  }

  // --- scope (scan / add scope / target / exclude) ---
  // Supports an exclusion tail ("add scope 10.0.0.0/24 except 10.0.0.5") and
  // dedicated exclude verbs. Without this, an "except/not/exclude" qualifier was
  // silently dropped and the intended-excluded IP was ADDED to scope — a
  // scope-broadening authorization bug.
  const scope = raw.match(/^(scan|add scope|add to scope|target|exclude|unscope|descope|remove scope|remove from scope)\s+(.+)$/i);
  if (scope) {
    const isExcludeVerb = /^(exclude|unscope|descope|remove scope|remove from scope)$/i.test(scope[1].trim());
    // Split on an exclusion keyword anchored at START-of-arg OR whitespace, so a
    // LEADING keyword ("add scope except 10.0.0.5") is honored too — otherwise
    // the excluded target would fall through to add_cidrs (scope-broadening).
    // Everything before the first keyword is added; everything after is excluded.
    const halves = scope[2].split(/(?:^|\s+)(?:except(?:\s+for)?|excluding|exclude|but\s+not|not|minus|without|omit(?:ting)?|drop|skip|apart\s+from|other\s+than)\s+/i);
    const addSpec = isExcludeVerb ? '' : halves[0];
    // For an exclude verb the whole arg is exclusions (keywords already dropped
    // by the split above); otherwise exclusions are everything after the keyword.
    const exclSpec = isExcludeVerb ? halves.join(' ') : halves.slice(1).join(' ');

    const add_cidrs: string[] = [];
    const add_domains: string[] = [];
    const add_exclusions: string[] = [];
    for (const tok of addSpec.split(/[\s,]+/).filter(Boolean)) {
      if (CIDR_RE.test(tok)) add_cidrs.push(tok);
      else if (IP_RE.test(tok)) add_cidrs.push(`${tok}/32`);
      else if (DOMAIN_RE.test(tok)) add_domains.push(tok.toLowerCase());
      else unresolved.push({ text: tok, reason: 'not a CIDR/IP/domain' });
    }
    for (const tok of exclSpec.split(/[\s,]+/).filter(Boolean)) {
      // Exclusions are stored verbatim (bare IP or CIDR) — isIpInScope matches a
      // bare exclusion by equality and a `/`-form by CIDR containment.
      if (CIDR_RE.test(tok) || IP_RE.test(tok)) add_exclusions.push(tok);
      else if (DOMAIN_RE.test(tok)) add_exclusions.push(tok.toLowerCase());
      else unresolved.push({ text: tok, reason: 'not a CIDR/IP/domain' });
    }
    if (add_cidrs.length || add_domains.length || add_exclusions.length) {
      ops.push({
        op: 'scope',
        add_cidrs: add_cidrs.length ? add_cidrs : undefined,
        add_domains: add_domains.length ? add_domains : undefined,
        add_exclusions: add_exclusions.length ? add_exclusions : undefined,
      });
    }
    return finalize(ops, unresolved);
  }

  // --- approve / deny <action> [reason] ---
  const ap = raw.match(/^(approve|deny)\s+(?:action\s+)?(\S+)\s*(.*)$/i);
  if (ap) {
    const verb = ap[1].toLowerCase();
    const actionId = resolveActionId(ap[2], state.pendingActionIds);
    const extra = ap[3].trim() || undefined;
    if (!actionId) {
      unresolved.push({ text: raw, reason: `no pending action matches "${ap[2]}"` });
    } else if (verb === 'approve') {
      ops.push({ op: 'approve', action_id: actionId, notes: extra });
    } else {
      ops.push({ op: 'deny', action_id: actionId, reason: extra });
    }
    return finalize(ops, unresolved);
  }

  unresolved.push({ text: raw, reason: 'not recognized by the command grammar' });
  return finalize(ops, unresolved);
}

/**
 * Build the objective handed to a headless 'planner' sub-agent (3A.2) for a
 * command the deterministic grammar couldn't resolve. Embeds the operator's
 * free-form command, a snapshot of the steerable state (running task ids +
 * pending action ids — so the planner references REAL ids), and the OperatorOp
 * vocabulary it must produce via propose_plan. Pure; co-located with the op
 * union it documents.
 */
export function buildPlannerObjective(command: string, state: InterpreterState): string {
  const running = state.tasks.filter(t => t.status === 'running');
  const agentLines = running.length
    ? running.map(t => `  - task_id="${t.id}" agent="${t.agent_id}"${t.skill ? ` skill="${t.skill}"` : ''}`).join('\n')
    : '  (none running)';
  const actionLines = state.pendingActionIds.length
    ? state.pendingActionIds.map(id => `  - action_id="${id}"`).join('\n')
    : '  (none pending)';
  return [
    `OPERATOR COMMAND (free-form): "${command}"`,
    ``,
    `Running agent tasks you may steer (use the EXACT task_id):`,
    agentLines,
    `Pending actions you may approve/deny (use the EXACT action_id):`,
    actionLines,
    ``,
    `Produce a plan as an array of ops and submit via propose_plan. Allowed ops:`,
    `  { "op":"directive", "task_id":"<id>", "agent_label":"<agent>", "kind":"pause|resume|stop|narrow_scope|skip_types|prioritize", "node_ids?":["n1"], "frontier_types?":["network_discovery"], "note?":"" }`,
    `  { "op":"scope", "add_cidrs?":["10.0.0.0/24"], "add_domains?":["example.com"], "add_exclusions?":["10.0.0.5/32"] }`,
    `  { "op":"approve", "action_id":"<id>", "notes?":"" }`,
    `  { "op":"deny", "action_id":"<id>", "reason?":"" }`,
    `Only reference task_ids/action_ids from the lists above. Pass the operator command back as \`command\` so it's logged with the plan.`,
  ].join('\n');
}

function describeOp(op: OperatorOp): string {
  switch (op.op) {
    case 'directive': return `${op.kind} → ${op.agent_label}`;
    case 'scope': {
      const adds = [...(op.add_cidrs ?? []), ...(op.add_domains ?? [])];
      const excls = op.add_exclusions ?? [];
      return [
        adds.length ? `add scope: ${adds.join(', ')}` : '',
        excls.length ? `exclude: ${excls.join(', ')}` : '',
      ].filter(Boolean).join('; ') || 'scope: (none)';
    }
    case 'approve': return `approve ${op.action_id}`;
    case 'deny': return `deny ${op.action_id}`;
    case 'dispatch': return `deploy ${op.archetype ?? 'agent'} → ${op.target_node_ids.length} node(s)`;
  }
}

function finalize(ops: OperatorOp[], unresolved: InterpretResult['unresolved']): InterpretResult {
  const summary = ops.length ? ops.map(describeOp).join('; ') : 'no operations';
  return { ops, summary, unresolved };
}

export interface OpResult { op: OperatorOp; ok: boolean; detail?: string; error?: string }

/**
 * The single dashboard-side execution path. Each op routes through an existing
 * validated engine method — no new mutation surface.
 */
export function executeOps(engine: GraphEngine, ops: OperatorOp[], issuedBy = 'operator'): OpResult[] {
  const results: OpResult[] = [];
  for (const op of ops) {
    try {
      if (op.op === 'directive') {
        engine.issueAgentDirective({ task_id: op.task_id, kind: op.kind, node_ids: op.node_ids, frontier_types: op.frontier_types, note: op.note, issued_by: issuedBy });
        // A directive is only actioned by a LIVE headless agent (which polls it via
        // acknowledge_agent_directive). For any other backend (manual/scripted) or a
        // missing task, it's advisory — recorded, not auto-applied — so say so.
        const target = engine.getTask(op.task_id);
        const advisory = !target || target.backend !== 'headless_mcp';
        results.push({ op, ok: true, detail: advisory ? `directive ${op.kind} recorded for ${op.agent_label} (advisory — no live agent)` : `directive ${op.kind} issued to ${op.agent_label}` });
      } else if (op.op === 'scope') {
        const r = engine.updateScope({ add_cidrs: op.add_cidrs, add_domains: op.add_domains, add_exclusions: op.add_exclusions, reason: `operator command (${issuedBy})` });
        if (r.applied) results.push({ op, ok: true, detail: `scope updated (${r.affected_node_count} nodes affected)` });
        else results.push({ op, ok: false, error: r.errors.join('; ') });
      } else if (op.op === 'approve' || op.op === 'deny') {
        const queue = engine.getPendingActionQueue();
        const r = op.op === 'approve' ? queue.approve(op.action_id, op.notes) : queue.deny(op.action_id, op.reason);
        if (!r) results.push({ op, ok: false, error: 'action not found or already resolved' });
        else { engine.resolveApprovalRequest(r); results.push({ op, ok: true, detail: `${op.op}d ${op.action_id}` }); }
      } else if (op.op === 'dispatch') {
        // Deploy at the node(s). Resolve a CONCRETE archetype (recommendExploreArchetype
        // never yields the hidden full-surface 'default' — an unmapped node type falls
        // back to recon_scanner), expand its role+backend, and register status:'running'
        // so a drain loop launches it. No model → CLI default (the planner doesn't pick
        // models). A node-scoped dispatch carries no frontier_item_id, so it can't take a
        // frontier lease; registerAgent instead node-dedups it against a running/pending
        // agent of the same archetype+role already at the node (see AgentManager.register).
        const taskId = uuidv4();
        const seedType = op.target_node_ids[0] ? engine.getNode(op.target_node_ids[0])?.type : undefined;
        const arch = getArchetype(recommendExploreArchetype(op.archetype, seedType));
        const reg = engine.registerAgent({
          id: taskId,
          agent_id: `planner-dispatch-${taskId.slice(0, 8)}`,
          assigned_at: new Date().toISOString(),
          status: 'running',
          subgraph_node_ids: op.target_node_ids,
          skill: op.skill ?? arch.defaultSkill,
          archetype: arch.id, role: arch.role, backend: arch.backend,
          ...(op.objective ? { objective: op.objective } : {}),
        });
        if (reg.cap_exceeded) results.push({ op, ok: false, error: `dispatch cap exceeded (${reg.cap_exceeded.current}/${reg.cap_exceeded.limit}) — retry when a slot frees` });
        else if (reg.node_conflict) results.push({ op, ok: false, error: `already being worked at ${reg.node_conflict.node_id} by ${reg.node_conflict.existing_agent_id} — not dispatching a duplicate` });
        else if (!reg.ok) results.push({ op, ok: false, error: reg.lease_conflict ? `already being worked by ${reg.lease_conflict.existing_agent_id}` : 'dispatch refused' });
        else results.push({ op, ok: true, detail: describeOp({ ...op, archetype: arch.id }) });
      }
    } catch (err) {
      results.push({ op, ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return results;
}
