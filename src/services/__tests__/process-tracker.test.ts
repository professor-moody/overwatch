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
    it('transitions running process to completed when PID is dead', () => {
      // Use a PID that definitely does not exist
      tracker.register({ id: 'p-dead', pid: 999999999, command: 'nmap', description: 'dead scan' });
      tracker.refreshStatuses();
      const proc = tracker.get('p-dead');
      expect(proc!.status).toBe('completed');
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
  });
});
