import { describe, it, expect, vi, afterEach } from 'vitest';
import Graph from 'graphology';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { PendingActionQueue } from '../pending-action-queue.js';
import type { PendingAction, ActionResolution } from '../pending-action-queue.js';
import type { OpsecContext } from '../opsec-tracker.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: {
      name: 'pentest',
      max_noise: 1.0,
      blacklisted_techniques: ['T1003'],
      approval_mode: 'auto-approve',
      ...(overrides.opsec as Record<string, unknown> ?? {}),
    },
    ...overrides,
    // Re-apply opsec after spread so it merges correctly
  } as any;
}

// Ensure opsec overrides are applied properly
function makeConfigWithOpsec(opsecOverrides: Record<string, unknown> = {}, configOverrides: Record<string, unknown> = {}) {
  const base = makeConfig(configOverrides);
  base.opsec = { ...base.opsec, ...opsecOverrides };
  return base;
}

function makeQueue(opsecOverrides: Record<string, unknown> = {}): { queue: PendingActionQueue; ctx: EngineContext } {
  const graph = makeGraph();
  const config = makeConfigWithOpsec(opsecOverrides);
  const ctx = new EngineContext(graph, config, './test-state.json');
  const queue = ctx.pendingActionQueue;
  return { queue, ctx };
}

function makeOpsecContext(overrides: Partial<OpsecContext> = {}): OpsecContext {
  return {
    global_noise_spent: 0.1,
    noise_budget_remaining: 0.9,
    recommended_approach: 'normal' as const,
    defensive_signals: [],
    ...overrides,
  };
}

function makeSubmitPayload(overrides: Partial<Omit<PendingAction, 'status' | 'submitted_at' | 'timeout_at'>> = {}) {
  return {
    action_id: overrides.action_id ?? 'act-1',
    description: overrides.description ?? 'Test action',
    opsec_context: overrides.opsec_context ?? makeOpsecContext(),
    validation_result: overrides.validation_result ?? ('valid' as const),
    technique: overrides.technique,
    target_node: overrides.target_node,
    target_ip: overrides.target_ip,
    frontier_item_id: overrides.frontier_item_id,
    task_id: overrides.task_id,
    agent_label: overrides.agent_label,
    agent_id: overrides.agent_id,
  };
}

describe('PendingActionQueue', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // ==== needsApproval ====

  describe('needsApproval', () => {
    it('returns false when mode is auto-approve', () => {
      const { queue } = makeQueue({ approval_mode: 'auto-approve' });
      expect(queue.needsApproval(makeOpsecContext())).toBe(false);
    });

    it('returns true when mode is approve-all', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      expect(queue.needsApproval(makeOpsecContext())).toBe(true);
    });

    it('returns true for approve-critical when noise is high', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-critical', max_noise: 1.0, enabled: true });
      // global_noise_spent + threshold(0.5) >= max_noise(1.0)
      const ctx = makeOpsecContext({ global_noise_spent: 0.6 });
      expect(queue.needsApproval(ctx)).toBe(true);
    });

    it('returns false for approve-critical when noise is low', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-critical', max_noise: 1.0, enabled: true });
      const ctx = makeOpsecContext({ global_noise_spent: 0.1, defensive_signals: [] });
      expect(queue.needsApproval(ctx)).toBe(false);
    });

    it('returns true for approve-critical when technique is blacklisted', () => {
      const { queue } = makeQueue({
        approval_mode: 'approve-critical',
        max_noise: 1.0,
        enabled: true,
        blacklisted_techniques: ['T1003'],
      });
      const ctx = makeOpsecContext({ global_noise_spent: 0.0 });
      expect(queue.needsApproval(ctx, 'T1003')).toBe(true);
    });

    it('returns false for approve-critical when technique is not blacklisted', () => {
      const { queue } = makeQueue({
        approval_mode: 'approve-critical',
        max_noise: 1.0,
        enabled: true,
        blacklisted_techniques: ['T1003'],
      });
      const ctx = makeOpsecContext({ global_noise_spent: 0.0, defensive_signals: [] });
      expect(queue.needsApproval(ctx, 'T1110')).toBe(false);
    });

    it('returns true for approve-critical when defensive signals present', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-critical', max_noise: 1.0, enabled: true });
      const ctx = makeOpsecContext({
        global_noise_spent: 0.0,
        defensive_signals: [{ type: 'lockout', detected_at: new Date().toISOString(), description: 'Alert fired' }],
      });
      expect(queue.needsApproval(ctx)).toBe(true);
    });

    it('returns true for approve-critical when noise budget exhausted', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-critical', max_noise: 1.0, enabled: true });
      const ctx = makeOpsecContext({ noise_budget_remaining: 0, global_noise_spent: 1.0, defensive_signals: [] });
      expect(queue.needsApproval(ctx)).toBe(true);
    });

    it('does NOT escalate on noise/blacklist/signals under approve-critical when OPSEC is DISABLED (inert)', () => {
      const { queue } = makeQueue({
        approval_mode: 'approve-critical', max_noise: 1.0, enabled: false, blacklisted_techniques: ['T1003'],
      });
      // Exhausted budget + defensive signals + a blacklisted technique — all would
      // escalate if OPSEC were on; with OPSEC inert none of them force approval.
      const ctx = makeOpsecContext({
        noise_budget_remaining: 0, global_noise_spent: 1.0,
        defensive_signals: [{ type: 'lockout', detected_at: new Date().toISOString(), description: 'Alert' }],
      });
      expect(queue.needsApproval(ctx, 'T1003')).toBe(false);
    });

    it('escalates when a PHASE enables OPSEC even though base config is disabled', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-critical', max_noise: 1.0, enabled: false });
      const ctx = makeOpsecContext({ noise_budget_remaining: 0, global_noise_spent: 1.0 });
      // Phase-effective flag (folds opsec_overrides) is the authority — must escalate.
      expect(queue.needsApproval(ctx, undefined, { mode: 'approve-critical', blacklisted_techniques: [], opsec_enabled: true })).toBe(true);
    });

    it('does NOT escalate when a PHASE disables OPSEC even though base config is enabled', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-critical', max_noise: 1.0, enabled: true });
      const ctx = makeOpsecContext({
        noise_budget_remaining: 0, global_noise_spent: 1.0,
        defensive_signals: [{ type: 'lockout', detected_at: new Date().toISOString(), description: 'x' }],
      });
      expect(queue.needsApproval(ctx, undefined, { mode: 'approve-critical', blacklisted_techniques: [], opsec_enabled: false })).toBe(false);
    });

    it('defaults to auto-approve when approval_mode not set', () => {
      const graph = makeGraph();
      const config = makeConfig();
      delete config.opsec.approval_mode;
      const ctx = new EngineContext(graph, config, './test-state.json');
      const queue = ctx.pendingActionQueue;
      expect(queue.needsApproval(makeOpsecContext())).toBe(false);
    });
  });

  // ==== submit + approve ====

  describe('submit and approve', () => {
    it('creates a pending action and resolves on approve', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      const promise = queue.submit(makeSubmitPayload({ action_id: 'act-1' }));

      expect(queue.getPendingCount()).toBe(1);
      expect(queue.getAction('act-1')).toBeDefined();
      expect(queue.getAction('act-1')!.status).toBe('pending');

      const result = queue.approve('act-1', 'Looks good');
      expect(result).not.toBeNull();
      expect(result!.status).toBe('approved');
      expect(result!.operator_notes).toBe('Looks good');

      const resolution = await promise;
      expect(resolution.status).toBe('approved');
      expect(resolution.action_id).toBe('act-1');
      expect(queue.getPendingCount()).toBe(0);
    });

    it('stores resolution in resolved history', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      queue.submit(makeSubmitPayload({ action_id: 'act-1' }));
      queue.approve('act-1');

      const res = queue.getResolution('act-1');
      expect(res).toBeDefined();
      expect(res!.status).toBe('approved');
    });
  });

  // ==== submit + deny ====

  describe('submit and deny', () => {
    it('resolves with denied status', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      const promise = queue.submit(makeSubmitPayload({ action_id: 'act-2' }));

      const result = queue.deny('act-2', 'Too risky');
      expect(result).not.toBeNull();
      expect(result!.status).toBe('denied');
      expect(result!.reason).toBe('Too risky');

      const resolution = await promise;
      expect(resolution.status).toBe('denied');
      expect(resolution.action_id).toBe('act-2');
      expect(queue.getPendingCount()).toBe(0);
    });
  });

  // ==== timeout ====

  describe('timeout auto-approve', () => {
    it('auto-approves after timeout, tagged unattended_execute (loud)', async () => {
      vi.useFakeTimers();
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 5000 });
      const promise = queue.submit(makeSubmitPayload({ action_id: 'act-t' }));

      expect(queue.getPendingCount()).toBe(1);

      vi.advanceTimersByTime(5000);

      const resolution = await promise;
      expect(resolution.status).toBe('timeout');
      // Loud reason: surfaces "unattended-execute" rather than the old quiet
      // "Auto-approved after Ns timeout" wording. Operators / retros / OPSEC
      // logs filter on this.
      expect(resolution.reason).toContain('unattended-execute');
      expect(resolution.reason).toContain('5s');
      expect(resolution.auto_approved).toBe(true);
      expect(resolution.unattended_execute).toBe(true);
      expect(queue.getPendingCount()).toBe(0);
    });

    it('does not auto-approve if resolved before timeout', async () => {
      vi.useFakeTimers();
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 5000 });
      const promise = queue.submit(makeSubmitPayload({ action_id: 'act-e' }));

      queue.approve('act-e');

      const resolution = await promise;
      expect(resolution.status).toBe('approved');

      // Advance past timeout — should not throw or change state
      vi.advanceTimersByTime(10000);
      expect(queue.getPendingCount()).toBe(0);
    });

    it('uses default timeout when not configured', async () => {
      vi.useFakeTimers();
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      // Remove approval_timeout_ms — will use DEFAULT_TIMEOUT_MS (300_000)
      const promise = queue.submit(makeSubmitPayload({ action_id: 'act-d' }));

      const action = queue.getAction('act-d');
      expect(action).toBeDefined();
      const submitted = new Date(action!.submitted_at).getTime();
      const timeout = new Date(action!.timeout_at).getTime();
      expect(timeout - submitted).toBe(300_000);

      // Clean up
      queue.dispose();
      await promise; // resolves via dispose
    });
  });

  // ==== Multiple concurrent actions ====

  describe('multiple concurrent actions', () => {
    it('tracks multiple pending actions independently', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      const p1 = queue.submit(makeSubmitPayload({ action_id: 'a1' }));
      const p2 = queue.submit(makeSubmitPayload({ action_id: 'a2' }));
      const p3 = queue.submit(makeSubmitPayload({ action_id: 'a3' }));

      expect(queue.getPendingCount()).toBe(3);
      expect(queue.getPending().map(a => a.action_id).sort()).toEqual(['a1', 'a2', 'a3']);

      queue.approve('a2');
      expect(queue.getPendingCount()).toBe(2);

      queue.deny('a1', 'nah');
      expect(queue.getPendingCount()).toBe(1);

      queue.approve('a3');
      expect(queue.getPendingCount()).toBe(0);

      const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
      expect(r1.status).toBe('denied');
      expect(r2.status).toBe('approved');
      expect(r3.status).toBe('approved');
    });
  });

  // ==== Non-existent action ====

  describe('non-existent action', () => {
    it('approve returns null for unknown action_id', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      expect(queue.approve('no-such-id')).toBeNull();
    });

    it('deny returns null for unknown action_id', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      expect(queue.deny('no-such-id')).toBeNull();
    });

    it('getAction returns undefined for unknown action_id', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      expect(queue.getAction('nope')).toBeUndefined();
    });
  });

  // ==== dispose ====

  describe('dispose', () => {
    it('clears all pending actions and resolves promises as aborted (not timeout)', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      const p1 = queue.submit(makeSubmitPayload({ action_id: 'disp-1' }));
      const p2 = queue.submit(makeSubmitPayload({ action_id: 'disp-2' }));

      expect(queue.getPendingCount()).toBe(2);

      queue.dispose();

      expect(queue.getPendingCount()).toBe(0);

      const [r1, r2] = await Promise.all([p1, p2]);
      // Shutdown is an abort, NOT an unattended-execute timeout (a 'timeout'
      // resolution carries auto_approved and would run the command).
      expect(r1.status).toBe('aborted');
      expect(r1.reason).toContain('disposed');
      expect(r1.auto_approved).toBeFalsy();
      expect(r2.status).toBe('aborted');
      // Resolutions are recorded in the resolved map (getResolution stays correct).
      expect(queue.getResolution('disp-1')?.status).toBe('aborted');
    });

    it('clears timeout timers on dispose', async () => {
      vi.useFakeTimers();
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 60000 });
      const promise = queue.submit(makeSubmitPayload({ action_id: 'disp-t' }));
      queue.dispose();
      const resolution = await promise;
      expect(resolution.status).toBe('aborted');
      // Advancing timers should not cause errors
      vi.advanceTimersByTime(120000);
    });

    it('detaches abort listeners on dispose (no leak / late fire)', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 60000 });
      const controller = new AbortController();
      const removeSpy = vi.spyOn(controller.signal, 'removeEventListener');
      const promise = queue.submit(makeSubmitPayload({ action_id: 'disp-sig' }), { signal: controller.signal });

      queue.dispose();
      expect((await promise).status).toBe('aborted');
      expect(removeSpy).toHaveBeenCalled();
      // A late abort after dispose must not throw or re-resolve.
      controller.abort();
      expect(queue.getPendingCount()).toBe(0);
    });
  });

  // ==== Event callback ====

  describe('event callback', () => {
    it('fires action_pending event on submit', () => {
      const events: { type: string; data: unknown }[] = [];
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      queue.onEvent((type, data) => events.push({ type, data }));

      queue.submit(makeSubmitPayload({ action_id: 'ev-1' }));

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('action_pending');
      expect((events[0].data as PendingAction).action_id).toBe('ev-1');
      expect((events[0].data as PendingAction).status).toBe('pending');

      // Clean up
      queue.dispose();
    });

    it('fires action_resolved event on approve', async () => {
      const events: { type: string; data: unknown }[] = [];
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      queue.onEvent((type, data) => events.push({ type, data }));

      const promise = queue.submit(makeSubmitPayload({ action_id: 'ev-2' }));
      queue.approve('ev-2');
      await promise;

      expect(events).toHaveLength(2); // pending + resolved
      expect(events[1].type).toBe('action_resolved');
      expect((events[1].data as ActionResolution).status).toBe('approved');
    });

    it('fires action_resolved event on deny', async () => {
      const events: { type: string; data: unknown }[] = [];
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      queue.onEvent((type, data) => events.push({ type, data }));

      const promise = queue.submit(makeSubmitPayload({ action_id: 'ev-3' }));
      queue.deny('ev-3', 'bad idea');
      await promise;

      const resolvedEvent = events.find(e => e.type === 'action_resolved');
      expect(resolvedEvent).toBeDefined();
      expect((resolvedEvent!.data as ActionResolution).status).toBe('denied');
      expect((resolvedEvent!.data as ActionResolution).reason).toBe('bad idea');
    });

    it('fires action_resolved event on timeout', async () => {
      vi.useFakeTimers();
      const events: { type: string; data: unknown }[] = [];
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 1000 });
      queue.onEvent((type, data) => events.push({ type, data }));

      const promise = queue.submit(makeSubmitPayload({ action_id: 'ev-to' }));
      vi.advanceTimersByTime(1000);
      const resolution = await promise;

      expect(resolution.status).toBe('timeout');
      const resolvedEvent = events.find(e => e.type === 'action_resolved');
      expect(resolvedEvent).toBeDefined();
      expect((resolvedEvent!.data as ActionResolution).status).toBe('timeout');
    });
  });

  // ==== Submitted action fields ====

  describe('submitted action fields', () => {
    it('populates submitted_at and timeout_at correctly', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 10000 });
      queue.submit(makeSubmitPayload({ action_id: 'fields-1' }));
      const action = queue.getAction('fields-1');

      expect(action).toBeDefined();
      expect(action!.status).toBe('pending');
      expect(action!.submitted_at).toBeDefined();
      expect(action!.timeout_at).toBeDefined();

      const submitted = new Date(action!.submitted_at).getTime();
      const timeout = new Date(action!.timeout_at).getTime();
      expect(timeout - submitted).toBe(10000);

      queue.dispose();
    });

    it('preserves technique and target fields', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      queue.submit(makeSubmitPayload({
        action_id: 'fields-2',
        technique: 'T1046',
        target_node: 'host-1',
        target_ip: '10.10.10.1',
      }));
      const action = queue.getAction('fields-2');

      expect(action!.technique).toBe('T1046');
      expect(action!.target_node).toBe('host-1');
      expect(action!.target_ip).toBe('10.10.10.1');

      queue.dispose();
    });
  });

  // ==== getPending ====

  describe('getPending', () => {
    it('returns snapshot array (not live reference)', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      queue.submit(makeSubmitPayload({ action_id: 'snap-1' }));
      const list = queue.getPending();

      expect(list).toHaveLength(1);
      // Mutating returned array should not affect queue
      list.length = 0;
      expect(queue.getPendingCount()).toBe(1);

      queue.dispose();
    });
  });

  // ==== abort via AbortSignal (HTTP client disconnect / cancel) ====

  describe('abort via AbortSignal', () => {
    it('resolves immediately as aborted when the signal is already aborted', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      const controller = new AbortController();
      controller.abort();

      const resolution = await queue.submit(
        makeSubmitPayload({ action_id: 'act-pre-abort' }),
        { signal: controller.signal },
      );

      expect(resolution.status).toBe('aborted');
      // Never queued — nothing to drain.
      expect(queue.getPendingCount()).toBe(0);
    });

    it('resolves as aborted when the signal fires mid-wait, and reclaims the slot', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 60000 });
      const controller = new AbortController();
      const promise = queue.submit(
        makeSubmitPayload({ action_id: 'act-mid-abort' }),
        { signal: controller.signal },
      );

      expect(queue.getPendingCount()).toBe(1);
      controller.abort();

      const resolution = await promise;
      expect(resolution.status).toBe('aborted');
      expect(resolution.reason).toContain('client disconnected');
      // Slot reclaimed, not left pending until the (60s) timeout.
      expect(queue.getPendingCount()).toBe(0);
    });

    it('clears the timeout timer and detaches the abort listener on abort (no leaks, no double-resolve)', async () => {
      vi.useFakeTimers();
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 5000 });
      const controller = new AbortController();
      const removeSpy = vi.spyOn(controller.signal, 'removeEventListener');

      const promise = queue.submit(
        makeSubmitPayload({ action_id: 'act-leak' }),
        { signal: controller.signal },
      );
      controller.abort();
      const resolution = await promise;
      expect(resolution.status).toBe('aborted');
      // The abort listener must be detached so it can't fire again.
      expect(removeSpy).toHaveBeenCalled();

      // Advancing past the timeout must NOT change the already-resolved state.
      vi.advanceTimersByTime(10000);
      expect(queue.getPendingCount()).toBe(0);
      expect(queue.getResolution('act-leak')?.status).toBe('aborted');
    });

    it('does not abort if the action is approved before the signal fires', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 60000 });
      const controller = new AbortController();
      const promise = queue.submit(
        makeSubmitPayload({ action_id: 'act-approve-first' }),
        { signal: controller.signal },
      );

      queue.approve('act-approve-first', 'ok');
      const resolution = await promise;
      expect(resolution.status).toBe('approved');

      // A late abort must not resurrect or re-resolve the action.
      controller.abort();
      expect(queue.getPendingCount()).toBe(0);
      expect(queue.getResolution('act-approve-first')?.status).toBe('approved');
    });

    it('submit() without a signal behaves exactly as before (backward-compatible)', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all' });
      const promise = queue.submit(makeSubmitPayload({ action_id: 'act-no-signal' }));
      expect(queue.getPendingCount()).toBe(1);
      queue.approve('act-no-signal');
      const resolution = await promise;
      expect(resolution.status).toBe('approved');
    });
  });

  // ==== abortByAgent (owning agent terminated: reap / cancel / timeout) ====

  describe('abortByAgent', () => {
    it('aborts only the matching agent’s pending actions and unblocks their promises', async () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 60000 });
      const pa = queue.submit(makeSubmitPayload({ action_id: 'a-doomed', agent_id: 'agent-dead' }));
      const pb = queue.submit(makeSubmitPayload({ action_id: 'b-survives', agent_id: 'agent-live' }));
      expect(queue.getPendingCount()).toBe(2);

      const aborted = queue.abortByAgent('agent-dead', 'requesting agent terminated');
      expect(aborted).toHaveLength(1);
      expect(aborted[0].action_id).toBe('a-doomed');
      expect(aborted[0].status).toBe('aborted');

      const ra = await pa;
      expect(ra.status).toBe('aborted');           // NOT executed
      expect(ra.reason).toContain('terminated');
      // The other agent's action is untouched and still pending.
      expect(queue.getPendingCount()).toBe(1);
      expect(queue.getAction('b-survives')?.status).toBe('pending');
      queue.approve('b-survives');
      expect((await pb).status).toBe('approved');
    });

    it('abortByTask isolates duplicate labels by canonical task_id', async () => {
      const { queue } = makeQueue();
      const a = queue.submit(makeSubmitPayload({
        action_id: 'task-a-action',
        task_id: 'task-a',
        agent_label: 'shared-label',
        agent_id: 'shared-label',
      }));
      const b = queue.submit(makeSubmitPayload({
        action_id: 'task-b-action',
        task_id: 'task-b',
        agent_label: 'shared-label',
        agent_id: 'shared-label',
      }));

      expect(queue.abortByTask('task-a', undefined)).toHaveLength(1);
      await expect(a).resolves.toMatchObject({ status: 'aborted' });
      expect(queue.getAction('task-b-action')).toBeDefined();
      queue.abortByTask('task-b', undefined);
      await expect(b).resolves.toMatchObject({ status: 'aborted' });
    });

    it('aborted action does NOT auto-fire on a later timeout (the key safety property)', async () => {
      vi.useFakeTimers();
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 5000 });
      const p = queue.submit(makeSubmitPayload({ action_id: 'a-race', agent_id: 'agent-x' }));

      queue.abortByAgent('agent-x');
      const resolution = await p;
      expect(resolution.status).toBe('aborted');

      // Advancing past the original timeout must not re-resolve it as 'timeout'
      // (which carries auto_approved/unattended_execute → would execute).
      vi.advanceTimersByTime(10000);
      expect(queue.getResolution('a-race')?.status).toBe('aborted');
      expect(queue.getPendingCount()).toBe(0);
    });

    it('no-ops for a falsy agentId (never sweeps up agent_id-less primary actions)', () => {
      const { queue } = makeQueue({ approval_mode: 'approve-all', approval_timeout_ms: 60000 });
      queue.submit(makeSubmitPayload({ action_id: 'no-agent' })); // agent_id undefined
      expect(queue.abortByAgent(undefined)).toEqual([]);
      expect(queue.abortByAgent('')).toEqual([]);
      expect(queue.getPendingCount()).toBe(1);
      queue.dispose();
    });
  });
});
