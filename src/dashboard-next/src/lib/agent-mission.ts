import type { AgentInfo, PendingAction, SessionInfo } from './types';
import type { AgentQuery } from './api';
import { sessionsForAgent } from './session-workspace';

// Phase 5 (Mission Control) — project the scattered per-agent signals the
// dashboard already receives (status, current_action, campaign, frontier item,
// owned sessions, pending approvals, open questions) into a single operator-
// shaped "mission card". Pure surfacing: no new engine state. The card answers
// "is this agent productive, blocked, or done?" at a glance.

export type MissionTone = 'running' | 'blocked' | 'stuck' | 'failed' | 'done' | 'idle';

// A running agent that keeps heartbeating (so the watchdog won't reap it) but
// makes no progress is "stuck". Threshold sits above the mission card's
// RECENT_MS (5m) — so an agent is already visually "quiet" first — and well clear
// of the 120s heartbeat TTL / 30s watchdog tick, so there's no overlap with
// reaping. Tunable; conservative by default to avoid false positives.
export const STUCK_IDLE_MS = 8 * 60_000;
export type HeartbeatFreshness = 'fresh' | 'recent' | 'quiet' | 'none';

export interface MissionCard {
  id: string;
  label: string;
  status: AgentInfo['status'];
  /** Skill stands in as the agent's role until a real role field exists. */
  role?: string;
  campaignId?: string;
  campaignName?: string;
  frontierItemId?: string;
  currentAction?: string;
  /** Liveness derived from current_action_at (the freshest client-visible signal). */
  freshness: HeartbeatFreshness;
  ownedSessionIds: string[];
  findingsCount: number;
  /** True when a pending action is attributed to this agent. */
  pendingApproval: boolean;
  /** True when an open agent question is attributed to this agent. */
  awaitingAnswer: boolean;
  /** Short human reason the agent needs the operator (or why it ended badly). */
  blocker?: string;
  tone: MissionTone;
  scopeNodeCount: number;
}

export interface MissionContext {
  agents?: AgentInfo[];
  sessions?: SessionInfo[];
  pendingActions?: PendingAction[];
  agentQueries?: AgentQuery[];
  now?: number;
}

const FRESH_MS = 60_000;
const RECENT_MS = 5 * 60_000;

function freshnessFor(agent: AgentInfo, now: number): HeartbeatFreshness {
  if (agent.status !== 'running') return 'none';
  const at = agent.current_action_at || agent.assigned_at;
  if (!at) return 'quiet';
  const age = now - new Date(at).getTime();
  if (!Number.isFinite(age) || age < 0) return 'recent';
  if (age <= FRESH_MS) return 'fresh';
  if (age <= RECENT_MS) return 'recent';
  return 'quiet';
}

/** Does an open agent question belong to this agent (by task id or label)? */
export function awaitingAnswerFor(agent: AgentInfo, queries: AgentQuery[]): boolean {
  const taskIds = new Set([agent.task_id, agent.id].filter((v): v is string => !!v));
  return queries.some(q =>
    q.status === 'open'
    && !!(q.owner_task_id ?? q.task_id)
    && taskIds.has((q.owner_task_id ?? q.task_id)!));
}

/**
 * Is a pending action attributed to this agent? Matches on agent_id when the
 * approval carries it (the run_bash/run_tool path), and falls back to a shared
 * frontier_item_id — `validate_action`-gated approvals don't set agent_id today
 * but do carry the frontier item the agent is working, so this still flips the
 * card to "waiting on approval". (A real agent_id on validate_action is tracked
 * as backend work in Phase 2.)
 */
export function pendingApprovalFor(
  agent: AgentInfo,
  actions: PendingAction[],
  agents: AgentInfo[] = [],
): boolean {
  const taskId = agent.task_id ?? agent.id;
  const agentLabel = agent.agent_label ?? agent.agent_id;
  const uniqueLabel = agents.filter(candidate =>
    (candidate.agent_label ?? candidate.agent_id) === agentLabel).length === 1;
  const frontier = agent.frontier_item_id;
  return actions.some(a => {
    const actionLabel = a.agent_label ?? a.agent_id;
    return a.task_id === taskId
      || (!a.task_id && a.agent_id === taskId)
      || (!a.task_id && uniqueLabel && actionLabel === agentLabel)
      || (!!frontier && !!a.frontier_item_id && a.frontier_item_id === frontier);
  });
}

/**
 * A running agent is "stuck" when it's still heartbeating (status stays 'running'
 * — a stale heartbeat would have been reaped to 'interrupted') but has made no
 * progress for STUCK_IDLE_MS and is NOT blocked on the operator (no pending
 * approval / open question — that's "blocked", a different, already-surfaced
 * state). The assigned_at age gate suppresses just-dispatched agents and any task
 * with an unparseable/missing timestamp (legacy non-heartbeating runs). Pure;
 * shared by the mission card tone and the attention queue so they never diverge.
 */
export function isStuck(
  agent: AgentInfo,
  now: number,
  ctx: {
    agents?: AgentInfo[];
    pendingActions?: PendingAction[];
    agentQueries?: AgentQuery[];
  } = {},
): boolean {
  if (agent.status !== 'running') return false;
  if (
    awaitingAnswerFor(agent, ctx.agentQueries ?? [])
    || pendingApprovalFor(agent, ctx.pendingActions ?? [], ctx.agents ?? [])
  ) return false;
  const assignedAge = agent.assigned_at ? now - new Date(agent.assigned_at).getTime() : NaN;
  if (!Number.isFinite(assignedAge) || assignedAge <= STUCK_IDLE_MS) return false;
  // Require a REAL last-action timestamp — don't fall back to assigned_at. The
  // server leaves current_action_at undefined when it can't attribute activity
  // (e.g. two running tasks sharing one agent_id label), and an active agent must
  // not be flagged stuck just because its action couldn't be keyed to the task.
  if (!agent.current_action_at) return false;
  const idleAge = now - new Date(agent.current_action_at).getTime();
  return Number.isFinite(idleAge) && idleAge > STUCK_IDLE_MS;
}

/** Whole minutes an agent has been idle (last action, or dispatch if none). */
export function stuckIdleMinutes(agent: AgentInfo, now: number): number {
  const lastAt = agent.current_action_at || agent.assigned_at;
  const age = lastAt ? now - new Date(lastAt).getTime() : 0;
  return Math.max(0, Math.floor(age / 60_000));
}

export function buildMissionCard(agent: AgentInfo, ctx: MissionContext = {}): MissionCard {
  const now = ctx.now ?? Date.now();
  const queries = ctx.agentQueries ?? [];
  const actions = ctx.pendingActions ?? [];
  const ownedSessionIds = sessionsForAgent(ctx.sessions ?? [], agent).map(s => s.id);

  const awaitingAnswer = awaitingAnswerFor(agent, queries);
  const pendingApproval = pendingApprovalFor(agent, actions, ctx.agents ?? []);
  const terminalBad = agent.status === 'failed' || agent.status === 'interrupted';
  // isStuck already excludes blocked agents, so the tone ladder's blocked check
  // (above stuck) keeps blocked winning — an agent waiting on you is "blocked".
  const stuck = isStuck(agent, now, {
    agents: ctx.agents,
    pendingActions: actions,
    agentQueries: queries,
  });

  let blocker: string | undefined;
  if (awaitingAnswer) blocker = 'waiting on your answer';
  else if (pendingApproval) blocker = 'waiting on approval';
  else if (terminalBad) blocker = agent.result_summary || agent.status;
  else if (stuck) blocker = `idle ${stuckIdleMinutes(agent, now)}m — may be stuck`;

  let tone: MissionTone;
  if (terminalBad) tone = 'failed';
  else if (agent.status === 'completed') tone = 'done';
  else if (agent.status === 'pending') tone = 'idle';
  else if (awaitingAnswer || pendingApproval) tone = 'blocked';
  else if (stuck) tone = 'stuck';
  else tone = 'running';

  return {
    id: agent.id,
    label: agent.agent_id || agent.id,
    status: agent.status,
    role: agent.skill,
    campaignId: agent.campaign_id || agent.campaign?.id,
    campaignName: agent.campaign?.name,
    frontierItemId: agent.frontier_item_id,
    currentAction: agent.status === 'running' ? agent.current_action : undefined,
    freshness: freshnessFor(agent, now),
    ownedSessionIds,
    findingsCount: agent.findings_count ?? 0,
    pendingApproval,
    awaitingAnswer,
    blocker,
    tone,
    scopeNodeCount: (agent.subgraph_node_ids || agent.scope_node_ids || []).length,
  };
}

export interface MissionGroup {
  key: string;
  name: string;
  cards: MissionCard[];
}

const TONE_ORDER: Record<MissionTone, number> = {
  blocked: 0, stuck: 1, running: 2, failed: 3, idle: 4, done: 5,
};

/** Sort so the agents that need attention float up. */
export function sortMissionCards(cards: MissionCard[]): MissionCard[] {
  return [...cards].sort((a, b) => {
    const t = TONE_ORDER[a.tone] - TONE_ORDER[b.tone];
    if (t !== 0) return t;
    return a.label.localeCompare(b.label);
  });
}

/** Group cards by campaign (ungrouped last), each group's cards attention-sorted. */
export function groupMissionCards(cards: MissionCard[]): MissionGroup[] {
  const groups = new Map<string, MissionGroup>();
  const UNGROUPED = '__ungrouped__';
  for (const card of cards) {
    const key = card.campaignId || UNGROUPED;
    if (!groups.has(key)) {
      groups.set(key, { key, name: card.campaignName || (key === UNGROUPED ? 'Ungrouped' : key), cards: [] });
    }
    groups.get(key)!.cards.push(card);
  }
  const ordered = [...groups.values()].map(g => ({ ...g, cards: sortMissionCards(g.cards) }));
  // Ungrouped sinks to the bottom; named campaigns alphabetical.
  return ordered.sort((a, b) => {
    if (a.key === UNGROUPED) return 1;
    if (b.key === UNGROUPED) return -1;
    return a.name.localeCompare(b.name);
  });
}
