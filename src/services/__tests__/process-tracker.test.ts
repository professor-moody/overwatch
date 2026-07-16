import { describe, it, expect, beforeEach } from 'vitest';
import { ProcessTracker } from '../process-tracker.js';

describe('ProcessTracker', () => {
  let tracker: ProcessTracker;

  beforeEach(() => {
    tracker = new ProcessTracker();
  });

  describe('register', () => {
    it('registers a process with running status', () => {
      const proc = tracker.register({ id: 'p1', pid: 1234, command: 'nmap -sS 10.0.0.0/24', description: 'Nmap scan' });
      expect(proc.status).toBe('running');
      expect(proc.started_at).toBeDefined();
      expect(proc.pid).toBe(1234);
    });

    it('get returns registered process', () => {
      tracker.register({ id: 'p1', pid: 1234, command: 'nmap', description: 'scan' });
      const proc = tracker.get('p1');
      expect(proc).not.toBeNull();
      expect(proc!.id).toBe('p1');
    });

    it('get returns null for unknown id', () => {
      expect(tracker.get('nonexistent')).toBeNull();
    });
  });

  describe('update', () => {
    it('updates status to completed', () => {
      tracker.register({ id: 'p1', pid: 1234, command: 'nmap', description: 'scan' });
      const ok = tracker.update('p1', 'completed');
      expect(ok).toBe(true);
      const proc = tracker.get('p1');
      expect(proc!.status).toBe('completed');
      expect(proc!.completed_at).toBeDefined();
    });

    it('returns false for unknown id', () => {
      expect(tracker.update('nonexistent', 'failed')).toBe(false);
    });
  });

  describe('remove', () => {
    it('removes an abandoned process reservation and notifies durability listeners', () => {
      tracker.register({ id: 'p1', pid: 1234, command: 'nmap', description: 'scan' });
      let calls = 0;
      tracker.onChange(() => { calls++; });

      expect(tracker.remove('p1')).toBe(true);
      expect(tracker.get('p1')).toBeNull();
      expect(calls).toBe(1);
      expect(tracker.remove('p1')).toBe(false);
    });

    it('rolls back removal when durable notification fails', () => {
      tracker.register({ id: 'p1', pid: 1234, command: 'nmap', description: 'scan' });
      tracker.onChange(() => { throw new Error('journal unavailable'); });

      expect(() => tracker.remove('p1')).toThrow('journal unavailable');
      expect(tracker.get('p1')).not.toBeNull();
    });
  });

  describe('pruneCompleted via update()', () => {
    it('prunes oldest completed processes beyond cap of 50', () => {
      // Register 55 processes and complete them
      for (let i = 0; i < 55; i++) {
        tracker.register({ id: `p${i}`, pid: 10000 + i, command: 'cmd', description: `proc ${i}` });
        tracker.update(`p${i}`, 'completed');
      }
      const all = tracker.listAll();
      const completed = all.filter(p => p.status === 'completed');
      expect(completed.length).toBeLessThanOrEqual(50);
    });
  });

  describe('refreshStatuses', () => {
    it('transitions running process to unknown when PID is dead (P4.1)', () => {
      // Use a PID that definitely does not exist. P4.1: this used to mark
      // the process as "completed" (implying clean exit), but from outside
      // we can't tell a clean exit from a crash — the honest status is
      // "unknown." Callers with actual lifecycle visibility should use
      // update(id, 'completed' | 'failed').
      tracker.register({ id: 'p-dead', pid: 999999999, command: 'nmap', description: 'dead scan' });
      tracker.refreshStatuses();
      const proc = tracker.get('p-dead');
      expect(proc!.status).toBe('unknown');
      expect(proc!.completed_at).toBeDefined();
    });

    it('prunes after transitioning processes (P2b fix)', () => {
      // Fill up to 55 completed via refreshStatuses (not update)
      for (let i = 0; i < 55; i++) {
        tracker.register({ id: `p${i}`, pid: 999999900 + i, command: 'cmd', description: `proc ${i}` });
      }
      // All PIDs are dead — refreshStatuses should transition all and then prune
      tracker.refreshStatuses();
      const all = tracker.listAll();
      const completed = all.filter(p => p.status === 'completed');
      expect(completed.length).toBeLessThanOrEqual(50);
    });

    it('does not touch already completed processes', () => {
      tracker.register({ id: 'p1', pid: 999999999, command: 'cmd', description: 'test' });
      tracker.update('p1', 'completed');
      const before = tracker.get('p1')!.completed_at;
      tracker.refreshStatuses();
      expect(tracker.get('p1')!.completed_at).toBe(before);
    });
  });

  describe('listAll / listActive', () => {
    it('listAll returns all processes', () => {
      tracker.register({ id: 'p1', pid: 1, command: 'a', description: 'a' });
      tracker.register({ id: 'p2', pid: 2, command: 'b', description: 'b' });
      expect(tracker.listAll().length).toBe(2);
    });

    it('listActive returns only running processes', () => {
      tracker.register({ id: 'p1', pid: 1, command: 'a', description: 'a' });
      tracker.register({ id: 'p2', pid: 2, command: 'b', description: 'b' });
      tracker.update('p1', 'completed');
      expect(tracker.listActive().length).toBe(1);
      expect(tracker.listActive()[0].id).toBe('p2');
    });
  });

  describe('toSummary', () => {
    it('returns counts and processes', () => {
      tracker.register({ id: 'p1', pid: 999999999, command: 'a', description: 'a' });
      // PID is dead, so toSummary (which calls refreshStatuses) will transition it
      const summary = tracker.toSummary();
      expect(summary.active).toBe(0);
      expect(summary.completed).toBe(1);
      expect(summary.processes.length).toBe(1);
    });
  });

  describe('serialize / deserialize', () => {
    it('round-trips all processes', () => {
      tracker.register({ id: 'p1', pid: 1, command: 'nmap', description: 'scan' });
      tracker.register({ id: 'p2', pid: 2, command: 'responder', description: 'relay' });
      tracker.update('p1', 'completed');

      const serialized = tracker.serialize();
      const restored = ProcessTracker.deserialize(serialized);

      expect(restored.listAll().length).toBe(2);
      expect(restored.get('p1')!.status).toBe('completed');
      expect(restored.get('p1')!.completed_at).toBeDefined();
      expect(restored.get('p2')!.status).toBe('running');
    });

    it('deserialize with empty array creates empty tracker', () => {
      const restored = ProcessTracker.deserialize([]);
      expect(restored.listAll().length).toBe(0);
    });

    it('refreshStatuses after deserialize marks dead PIDs as unknown (startup reconciliation, P4.1)', () => {
      // Simulate persisted state with a "running" process whose PID is dead.
      // P4.1: a missing PID is reported as "unknown," not "completed" — we
      // can't tell from outside whether the process exited cleanly or
      // crashed. Status flips to "unknown" so retros stay honest.
      const serialized = [
        { id: 'p-stale', pid: 999999999, command: 'nmap -sV 10.0.0.0/24', description: 'Long scan', started_at: '2025-01-01T00:00:00Z', status: 'running' as const },
        { id: 'p-done', pid: 888888888, command: 'nikto -h 10.0.0.1', description: 'Web scan', started_at: '2025-01-01T00:00:00Z', completed_at: '2025-01-01T01:00:00Z', status: 'completed' as const },
      ];
      const restored = ProcessTracker.deserialize(serialized);

      // Before refresh, the stale process still appears running
      expect(restored.listActive()).toHaveLength(1);
      expect(restored.get('p-stale')!.status).toBe('running');

      // Refresh marks the dead PID as unknown
      restored.refreshStatuses();
      expect(restored.listActive()).toHaveLength(0);
      expect(restored.get('p-stale')!.status).toBe('unknown');
      expect(restored.get('p-stale')!.completed_at).toBeDefined();

      // Already-completed processes are untouched
      expect(restored.get('p-done')!.completed_at).toBe('2025-01-01T01:00:00Z');
    });

    it('restore replaces stale runtime state and notifies once', () => {
      tracker.register({ id: 'stale', pid: 1, command: 'old', description: 'old' });
      let calls = 0;
      tracker.onChange(() => { calls++; });
      const authoritative = [{
        id: 'restored',
        pid: 2,
        command: 'new',
        description: 'new',
        started_at: '2026-01-01T00:00:00.000Z',
        status: 'unknown' as const,
      }];

      tracker.restore(authoritative);
      authoritative[0].description = 'mutated by caller';

      expect(calls).toBe(1);
      expect(tracker.get('stale')).toBeNull();
      expect(tracker.get('restored')).toMatchObject({
        description: 'new',
        status: 'unknown',
      });
    });

    it('reset clears all runtime state', () => {
      tracker.register({ id: 'stale', pid: 1, command: 'old', description: 'old' });
      tracker.reset();
      expect(tracker.listAll()).toEqual([]);
    });
  });

  describe('change listeners', () => {
    it('fires for register, update, and startup status reconciliation', () => {
      let calls = 0;
      tracker.onChange(() => { calls++; });

      tracker.register({ id: 'p1', pid: process.pid, command: 'live', description: 'live process' });
      tracker.update('p1', 'completed');
      tracker.register({ id: 'p-dead', pid: 999999999, command: 'dead', description: 'dead process' });
      tracker.refreshStatuses();

      expect(calls).toBe(4);
      expect(tracker.get('p-dead')?.status).toBe('unknown');
    });

    it('supports multiple listeners and listener removal', () => {
      let first = 0;
      let second = 0;
      const removeFirst = tracker.onChange(() => { first++; });
      tracker.onChange(() => { second++; });

      tracker.register({ id: 'p1', pid: process.pid, command: 'live', description: 'live process' });
      removeFirst();
      tracker.update('p1', 'completed');

      expect(first).toBe(1);
      expect(second).toBe(2);
    });

    it('rolls back register when durable notification fails', () => {
      tracker.onChange(() => { throw new Error('journal unavailable'); });

      expect(() => tracker.register({
        id: 'not-durable',
        pid: process.pid,
        command: 'scan',
        description: 'must roll back',
      })).toThrow('journal unavailable');

      expect(tracker.listAll()).toEqual([]);
    });

    it('rolls back an ordinary update when durable notification fails', () => {
      tracker.register({
        id: 'running',
        pid: process.pid,
        command: 'scan',
        description: 'still running',
      });
      const before = tracker.serialize().map(proc => ({ ...proc }));
      tracker.onChange(() => { throw new Error('journal unavailable'); });

      expect(() => tracker.update('running', 'failed')).toThrow('journal unavailable');

      expect(tracker.serialize()).toEqual(before);
      expect(tracker.get('running')?.completed_at).toBeUndefined();
    });

    it('restores processes pruned by an update when durable notification fails', () => {
      const completed = Array.from({ length: 50 }, (_, index) => ({
        id: `completed-${index}`,
        pid: 10_000 + index,
        command: 'scan',
        description: `completed ${index}`,
        started_at: `2026-01-01T00:00:${String(index).padStart(2, '0')}.000Z`,
        completed_at: `2026-01-01T00:01:${String(index).padStart(2, '0')}.000Z`,
        status: 'completed' as const,
      }));
      tracker = ProcessTracker.deserialize([
        ...completed,
        {
          id: 'finishing',
          pid: process.pid,
          command: 'scan',
          description: 'finishing',
          started_at: '2026-01-01T01:00:00.000Z',
          status: 'running',
        },
      ]);
      const before = tracker.serialize().map(proc => ({ ...proc }));
      tracker.onChange(() => { throw new Error('journal unavailable'); });

      expect(() => tracker.update('finishing', 'completed')).toThrow('journal unavailable');

      expect(tracker.serialize()).toEqual(before);
      expect(tracker.get('completed-0')).not.toBeNull();
      expect(tracker.get('finishing')?.status).toBe('running');
    });

    it('rolls back refresh transitions and pruning when durable notification fails', () => {
      tracker.register({
        id: 'dead',
        pid: 999999999,
        command: 'scan',
        description: 'dead process',
      });
      const before = tracker.serialize().map(proc => ({ ...proc }));
      tracker.onChange(() => { throw new Error('journal unavailable'); });

      expect(() => tracker.refreshStatuses()).toThrow('journal unavailable');

      expect(tracker.serialize()).toEqual(before);
      expect(tracker.get('dead')?.status).toBe('running');
      expect(tracker.get('dead')?.completed_at).toBeUndefined();
    });

    it('rolls back an authoritative restore when durable notification fails', () => {
      tracker.register({
        id: 'current',
        pid: process.pid,
        command: 'scan',
        description: 'current',
      });
      const before = tracker.serialize().map(proc => ({ ...proc }));
      tracker.onChange(() => { throw new Error('journal unavailable'); });

      expect(() => tracker.restore([])).toThrow('journal unavailable');

      expect(tracker.serialize()).toEqual(before);
    });
  });

  describe('read isolation', () => {
    it('does not expose mutable internal process records', () => {
      const registered = tracker.register({
        id: 'isolated',
        pid: process.pid,
        command: 'scan',
        description: 'immutable projection',
      });
      registered.status = 'failed';
      tracker.get('isolated')!.description = 'mutated getter';
      tracker.listAll()[0]!.command = 'mutated list';
      tracker.serialize()[0]!.pid = 1;

      expect(tracker.get('isolated')).toMatchObject({
        pid: process.pid,
        command: 'scan',
        description: 'immutable projection',
        status: 'running',
      });
    });
  });

  describe('mutation guard', () => {
    it('blocks register, update, refresh, and restore before changing memory', () => {
      tracker.register({
        id: 'live',
        pid: process.pid,
        command: 'live',
        description: 'live process',
      });
      tracker.register({
        id: 'dead',
        pid: 999999999,
        command: 'dead',
        description: 'dead process',
      });
      const before = tracker.serialize().map(proc => ({ ...proc }));
      tracker.setMutationGuard(() => { throw new Error('read-only'); });

      expect(() => tracker.register({
        id: 'blocked',
        pid: 1,
        command: 'blocked',
        description: 'blocked',
      })).toThrow('read-only');
      expect(() => tracker.update('live', 'completed')).toThrow('read-only');
      expect(() => tracker.refreshStatuses()).toThrow('read-only');
      expect(() => tracker.restore([])).toThrow('read-only');
      expect(() => tracker.remove('live')).toThrow('read-only');

      expect(tracker.serialize()).toEqual(before);
      expect(tracker.get('blocked')).toBeNull();
    });

    it('does not invoke the guard for read-only/no-op operations', () => {
      let calls = 0;
      tracker.setMutationGuard(() => { calls++; });

      expect(tracker.update('missing', 'failed')).toBe(false);
      expect(tracker.remove('missing')).toBe(false);
      expect(tracker.refreshStatuses()).toBe(false);
      expect(tracker.listAll()).toEqual([]);
      expect(calls).toBe(0);
    });
  });
});
