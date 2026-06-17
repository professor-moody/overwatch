// ============================================================
// Overwatch — Agent Query Store (Phase 3D — agent→operator escalation)
//
// A running sub-agent that hits a decision point can ask the operator a question
// via the `ask_operator` tool and WAIT for an answer. There is no new blocking
// transport: the agent waits by heartbeating, and the answer is delivered on the
// `agent_heartbeat` response as `pending_answer` (alongside `pending_directive`).
// This store is the shared hand-off point — the tool writes here, the dashboard
// reads/answers here, and the heartbeat path drains answers back to the agent.
//
// In-memory only (a question is meaningless after the agent times out) with a
// TTL, mirroring ProposedPlanStore / the command-plan store.
// ============================================================

import { randomUUID } from 'crypto';

export type AgentQueryStatus = 'open' | 'answered' | 'expired';

export interface AgentQuery {
  query_id: string;
  task_id?: string;
  agent_id?: string;
  question: string;
  /** Optional suggested answers the operator can pick from. */
  options?: string[];
  status: AgentQueryStatus;
  answer?: string;
  created_at: number;
  answered_at?: number;
}

export interface AddAgentQueryArgs {
  task_id?: string;
  agent_id?: string;
  question: string;
  options?: string[];
  now?: number;
}

// 30 min — matches the headless wall-clock timeout; a question outliving the
// agent that asked it is dead weight.
const DEFAULT_TTL_MS = 30 * 60_000;

export class AgentQueryStore {
  private queries = new Map<string, AgentQuery>();
  private onChangeCb: (() => void) | null = null;

  constructor(private ttlMs: number = DEFAULT_TTL_MS) {}

  /** Register a change listener (the dashboard uses this to broadcast). */
  onChange(cb: () => void): void {
    this.onChangeCb = cb;
  }

  /** Record a new question. Returns the stored record (with its query_id). */
  add(args: AddAgentQueryArgs): AgentQuery {
    const now = args.now ?? Date.now();
    this.prune(now);
    const query: AgentQuery = {
      query_id: randomUUID(),
      task_id: args.task_id,
      agent_id: args.agent_id,
      question: args.question,
      options: args.options,
      status: 'open',
      created_at: now,
    };
    this.queries.set(query.query_id, query);
    this.onChangeCb?.();
    return query;
  }

  get(query_id: string): AgentQuery | undefined {
    return this.queries.get(query_id);
  }

  /** All still-open questions, oldest first (FIFO for the operator inbox). */
  getOpen(now: number = Date.now()): AgentQuery[] {
    this.prune(now);
    return [...this.queries.values()]
      .filter(q => q.status === 'open')
      .sort((a, b) => a.created_at - b.created_at);
  }

  /**
   * Answer an open question. Returns the updated record, or null if the query
   * is unknown / already answered / expired.
   */
  answer(query_id: string, answer: string, now: number = Date.now()): AgentQuery | null {
    // Prune first so an expired-but-unswept question can't be answered (matches
    // ProposedPlanStore.resolve). getOpen already prunes, but the answer path
    // must not rely on a prior poll having run.
    this.prune(now);
    const query = this.queries.get(query_id);
    if (!query || query.status !== 'open') return null;
    query.status = 'answered';
    query.answer = answer;
    query.answered_at = now;
    this.onChangeCb?.();
    return query;
  }

  /**
   * Heartbeat delivery: the most-recently-answered question for a task. This
   * PEEKS (does not consume) so delivery is at-least-once — a dropped heartbeat
   * response is self-healing on the next beat, mirroring how pending_directive
   * keeps being returned until acknowledged. The agent dedups by query_id and
   * acts on a given answer once. The record is cleared when the task goes
   * terminal (expireForTask) or by TTL.
   */
  getAnswerForTask(task_id: string): AgentQuery | null {
    const answered = [...this.queries.values()]
      .filter(q => q.task_id === task_id && q.status === 'answered')
      .sort((a, b) => (b.answered_at ?? 0) - (a.answered_at ?? 0));
    return answered[0] ?? null;
  }

  /**
   * Drop every question for a task — called when the task reaches a terminal
   * state so a dead agent's question can't linger in the operator inbox (or be
   * answered into the void).
   */
  expireForTask(task_id: string): void {
    let changed = false;
    for (const [id, q] of this.queries) {
      if (q.task_id === task_id) { this.queries.delete(id); changed = true; }
    }
    if (changed) this.onChangeCb?.();
  }

  /** Sweep questions older than the TTL (open ones effectively expire). */
  prune(now: number = Date.now()): void {
    const cutoff = now - this.ttlMs;
    for (const [id, q] of this.queries) {
      if (q.created_at < cutoff) this.queries.delete(id);
    }
  }

  size(): number {
    return this.queries.size;
  }
}
