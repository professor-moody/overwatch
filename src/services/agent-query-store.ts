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
// Serialized with an absolute TTL, so restart preserves a live operator
// decision without extending it past the asking agent's original window.
// ============================================================

import { randomUUID } from 'crypto';

export type AgentQueryStatus = 'open' | 'answered' | 'expired';

export interface AgentQuery {
  query_id: string;
  owner_task_id?: string;
  owner_agent_label?: string;
  /** Legacy ownership aliases retained for one minor release. */
  task_id?: string;
  agent_id?: string;
  question: string;
  /** Optional suggested answers the operator can pick from. */
  options?: string[];
  status: AgentQueryStatus;
  answer?: string;
  created_at: number;
  /** Absolute expiry; restart must not extend this deadline. */
  expires_at: number;
  answered_at?: number;
  delivered_at?: number;
  acknowledged_at?: number;
  expired_at?: number;
  recovery_warning?: string;
}

export interface AddAgentQueryArgs {
  owner_task_id?: string;
  owner_agent_label?: string;
  task_id?: string;
  agent_id?: string;
  question: string;
  options?: string[];
  now?: number;
}

// 30 min — matches the headless wall-clock timeout; a question outliving the
// agent that asked it is dead weight.
const DEFAULT_TTL_MS = 30 * 60_000;
const RECORD_CAP = 500;

export interface SerializedAgentQueryStore {
  queries: AgentQuery[];
}

export class AgentQueryStore {
  private queries = new Map<string, AgentQuery>();
  private listeners = new Set<() => void>();
  private mutationGuard: (() => void) | undefined;
  private mutationRunner:
    | (<T>(reason: string, mutation: () => T) => T)
    | undefined;

  constructor(private ttlMs: number = DEFAULT_TTL_MS) {}

  private trimRecords(): void {
    if (this.queries.size <= RECORD_CAP) return;
    const removable = [...this.queries.values()]
      .filter(query => query.status !== 'open')
      .sort((a, b) =>
        (a.acknowledged_at ?? a.expired_at ?? a.answered_at ?? a.expires_at)
        - (b.acknowledged_at ?? b.expired_at ?? b.answered_at ?? b.expires_at));
    for (const query of removable) {
      if (this.queries.size <= RECORD_CAP) break;
      this.queries.delete(query.query_id);
    }
  }

  /** Register a change listener (dashboard broadcast + persistence coexist). */
  onChange(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  setMutationGuard(guard: (() => void) | undefined): void {
    this.mutationGuard = guard;
  }

  setMutationRunner(
    runner: (<T>(reason: string, mutation: () => T) => T) | undefined,
  ): void {
    this.mutationRunner = runner;
  }

  private runMutation<T>(reason: string, mutation: () => T): T {
    this.mutationGuard?.();
    return this.mutationRunner
      ? this.mutationRunner(reason, mutation)
      : mutation();
  }

  private notifyChange(): void {
    let firstError: unknown;
    for (const listener of this.listeners) {
      try { listener(); } catch (error) { firstError ??= error; }
    }
    if (firstError !== undefined) throw firstError;
  }

  /** Record a new question. Returns the stored record (with its query_id). */
  add(args: AddAgentQueryArgs): AgentQuery {
    return this.runMutation('add agent query', () => {
      const now = args.now ?? Date.now();
      this.pruneInternal(now, false);
      const query: AgentQuery = {
        query_id: randomUUID(),
        owner_task_id: args.owner_task_id ?? args.task_id,
        owner_agent_label: args.owner_agent_label ?? args.agent_id,
        task_id: args.owner_task_id ?? args.task_id,
        agent_id: args.owner_agent_label ?? args.agent_id,
        question: args.question,
        options: args.options,
        status: 'open',
        created_at: now,
        expires_at: now + this.ttlMs,
      };
      this.queries.set(query.query_id, query);
      this.trimRecords();
      this.notifyChange();
      return query;
    });
  }

  get(query_id: string): AgentQuery | undefined {
    return this.queries.get(query_id);
  }

  /** All still-open questions, oldest first (FIFO for the operator inbox). */
  getOpen(now: number = Date.now()): AgentQuery[] {
    try { this.prune(now); } catch { /* degraded reads filter without mutating */ }
    return [...this.queries.values()]
      .filter(q => q.status === 'open' && q.expires_at > now)
      .sort((a, b) => a.created_at - b.created_at);
  }

  /**
   * Answer an open question. Returns the updated record, or null if the query
   * is unknown / already answered / expired.
   */
  answer(query_id: string, answer: string, now: number = Date.now()): AgentQuery | null {
    return this.runMutation('answer agent query', () => {
      // Prune first so an expired-but-unswept question can't be answered (matches
      // ProposedPlanStore.resolve). getOpen already prunes, but the answer path
      // must not rely on a prior poll having run.
      this.pruneInternal(now, false);
      const query = this.queries.get(query_id);
      if (!query || query.status !== 'open') return null;
      this.resolveQuery(query, answer, now);
      this.notifyChange();
      return query;
    });
  }

  /**
   * Answer-once fan-out: resolve every still-open query in `query_ids` with the
   * same answer. The operator answers one clustered question (identical text
   * asked by multiple agents) and it fans out to all of them — each agent picks
   * up its answer on its next heartbeat via getAnswerForTask. Unknown / already-
   * answered / expired ids are skipped; returns the records actually answered.
   * Fires onChange once (not per member).
   */
  answerMany(query_ids: string[], answer: string, now: number = Date.now()): AgentQuery[] {
    return this.runMutation('answer agent queries', () => {
      this.pruneInternal(now, false);
      const resolved: AgentQuery[] = [];
      for (const id of query_ids) {
        const query = this.queries.get(id);
        if (!query || query.status !== 'open') continue;
        this.resolveQuery(query, answer, now);
        resolved.push(query);
      }
      if (resolved.length > 0) this.notifyChange();
      return resolved;
    });
  }

  private resolveQuery(query: AgentQuery, answer: string, now: number): void {
    query.status = 'answered';
    query.answer = answer;
    query.answered_at = now;
  }

  markDelivered(query_id: string, task_id: string, now: number = Date.now()): AgentQuery | null {
    return this.runMutation('mark agent query answer delivered', () => {
      const query = this.queries.get(query_id);
      if (
        !query
        || query.status !== 'answered'
        || (query.owner_task_id ?? query.task_id) !== task_id
        || query.acknowledged_at !== undefined
      ) {
        return null;
      }
      if (query.delivered_at === undefined) {
        query.delivered_at = now;
        this.notifyChange();
      }
      return query;
    });
  }

  acknowledge(query_id: string, task_id: string, now: number = Date.now()): AgentQuery | null {
    return this.runMutation('acknowledge agent query answer', () => {
      const query = this.queries.get(query_id);
      if (
        !query
        || query.status !== 'answered'
        || (query.owner_task_id ?? query.task_id) !== task_id
      ) {
        return null;
      }
      if (query.acknowledged_at === undefined) {
        query.acknowledged_at = now;
        this.notifyChange();
      }
      return query;
    });
  }

  /**
   * Heartbeat delivery: the most-recently-answered question for a task. This
   * PEEKS (does not consume) so delivery is at-least-once — a dropped heartbeat
   * response is self-healing on the next beat, mirroring how pending_directive
   * keeps being returned until acknowledged. The agent dedups by query_id and
   * acts on a given answer once. The record is cleared when the task goes
   * terminal (expireForTask) or by TTL.
   */
  getAnswerForTask(task_id: string, now: number = Date.now()): AgentQuery | null {
    try { this.prune(now); } catch { /* degraded reads filter without mutating */ }
    const answered = [...this.queries.values()]
      .filter(q =>
        (q.owner_task_id ?? q.task_id) === task_id
        && q.status === 'answered'
        && q.acknowledged_at === undefined
        && q.expires_at > now)
      .sort((a, b) => (b.answered_at ?? 0) - (a.answered_at ?? 0));
    return answered[0] ?? null;
  }

  /** Mark every still-actionable question for a terminal task as expired. */
  expireForTask(task_id: string, now: number = Date.now()): void {
    this.runMutation('expire agent queries for task', () => {
      let changed = false;
      for (const q of this.queries.values()) {
        if (
          (q.owner_task_id ?? q.task_id) === task_id
          && q.status !== 'expired'
          && q.acknowledged_at === undefined
        ) {
          q.status = 'expired';
          q.expired_at = now;
          changed = true;
        }
      }
      this.trimRecords();
      if (changed) this.notifyChange();
    });
  }

  /** Mark questions older than their original absolute TTL as expired. */
  prune(now: number = Date.now()): void {
    this.runMutation('prune agent queries', () => this.pruneInternal(now, false));
  }

  private pruneInternal(now: number, guard: boolean, notify = true): void {
    const expired = [...this.queries.values()]
      .map(query => {
        const expiresAt = Number.isFinite(query.expires_at)
          ? query.expires_at
          : query.created_at + this.ttlMs;
        return { query, expiresAt };
      })
      .filter(({ query, expiresAt }) => query.status !== 'expired' && expiresAt <= now);
    if (expired.length === 0) return;
    if (guard) this.mutationGuard?.();
    for (const { query, expiresAt } of expired) {
      query.status = 'expired';
      query.expired_at = expiresAt;
    }
    this.trimRecords();
    if (notify) this.notifyChange();
  }

  serialize(): SerializedAgentQueryStore {
    return JSON.parse(JSON.stringify({
      queries: [...this.queries.values()],
    })) as SerializedAgentQueryStore;
  }

  /** Restore in place so dashboard/persistence listeners remain attached. */
  restore(data: unknown, now: number = Date.now()): void {
    const record = data && typeof data === 'object' && !Array.isArray(data)
      ? data as Partial<SerializedAgentQueryStore>
      : {};
    this.queries.clear();
    for (const candidate of Array.isArray(record.queries) ? record.queries : []) {
      if (!candidate || typeof candidate !== 'object') continue;
      const query = candidate as AgentQuery;
      if (typeof query.query_id !== 'string' || typeof query.created_at !== 'number') continue;
      const ownerTaskId = query.owner_task_id ?? query.task_id;
      const ownerAgentLabel = query.owner_agent_label ?? query.agent_id;
      this.queries.set(query.query_id, {
        ...(JSON.parse(JSON.stringify(query)) as AgentQuery),
        owner_task_id: ownerTaskId,
        owner_agent_label: ownerAgentLabel,
        task_id: ownerTaskId,
        agent_id: ownerAgentLabel,
        expires_at: Number.isFinite(query.expires_at)
          ? query.expires_at
          : query.created_at + this.ttlMs,
      });
    }
    this.pruneInternal(now, false, false);
    this.trimRecords();
  }

  static deserialize(data: unknown, ttlMs: number = DEFAULT_TTL_MS, now: number = Date.now()): AgentQueryStore {
    const store = new AgentQueryStore(ttlMs);
    store.restore(data, now);
    return store;
  }

  size(): number {
    return this.queries.size;
  }

  getAll(): AgentQuery[] {
    return [...this.queries.values()];
  }
}
