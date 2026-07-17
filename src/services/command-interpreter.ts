// ============================================================
// Overwatch — Operator Command Interpreter (Phase 3A)
//
// Turns a natural-language operator command into a list of structured
// OperatorOps that map 1:1 onto EXISTING validated engine methods (directives,
// scope, approvals). The deterministic grammar here handles the high-frequency,
// unambiguous verbs instantly; anything it can't resolve is returned in
// `unresolved` for the headless planner fallback (3A.2) to handle.
//
// Safety: this module never mutates. Confirmed operations execute through
// OperatorCommandService and the application-command boundary.
// ============================================================

import type { AgentDirectiveKind } from '../types.js';

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
  task_id?: string;
  agent_label?: string;
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
  const exactTask = tasks.filter(t => (t.task_id ?? t.id) === ref || t.id === ref);
  if (exactTask.length) return exactTask;
  const exactLabel = tasks.filter(t => (t.agent_label ?? t.agent_id) === ref || t.agent_id === ref);
  if (exactLabel.length) return exactLabel;
  const needle = ref.toLowerCase();
  return tasks.filter(t =>
    (t.agent_label ?? t.agent_id).toLowerCase().includes(needle)
    || (t.skill ?? '').toLowerCase().includes(needle));
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
      for (const t of running) ops.push({
        op: 'directive',
        task_id: t.task_id ?? t.id,
        agent_label: t.agent_label ?? t.agent_id,
        kind,
      });
    } else {
      const matches = resolveTasks(ref, running);
      if (matches.length === 1) ops.push({
        op: 'directive',
        task_id: matches[0].task_id ?? matches[0].id,
        agent_label: matches[0].agent_label ?? matches[0].agent_id,
        kind,
      });
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
    if (matches.length === 1) ops.push({
      op: 'directive',
      task_id: matches[0].task_id ?? matches[0].id,
      agent_label: matches[0].agent_label ?? matches[0].agent_id,
      kind: 'instruct',
      note,
    });
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
    ? running.map(t => {
        const taskId = t.task_id ?? t.id;
        const agentLabel = t.agent_label ?? t.agent_id ?? taskId;
        return `  - task_id="${taskId}" agent="${agentLabel}"${t.skill ? ` skill="${t.skill}"` : ''}`;
      }).join('\n')
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
    `  { "op":"dispatch", "target_node_ids":["<existing graph node id>"], "archetype?":"recon_scanner", "skill?":"", "objective?":"" }`,
    `Use \`dispatch\` to turn "port-scan X" / "dig into host Y" into a confirmable action — deploy an agent at EXISTING graph node id(s) you found via query_graph.`,
    `Only reference task_ids/action_ids from the lists above (and dispatch node ids you confirmed exist). Pass the operator command back as \`command\` so it's logged with the plan.`,
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

export interface DispatchedTaskRef {
  task_id: string;
  agent_label: string;
  id: string;
  agent_id: string;
}

export interface OpResult {
  op: OperatorOp;
  ok: boolean;
  detail?: string;
  error?: string;
  task?: DispatchedTaskRef;
}
