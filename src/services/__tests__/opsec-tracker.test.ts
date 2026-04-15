import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { OpsecTracker } from '../opsec-tracker.js';
import type { OpsecTrackerState, DefensiveSignal } from '../opsec-tracker.js';

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
    opsec: { name: 'pentest', max_noise: 1.0, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

function makeTracker(configOverrides: Record<string, unknown> = {}): { tracker: OpsecTracker; ctx: EngineContext } {
  const graph = makeGraph();
  const ctx = new EngineContext(graph, makeConfig(configOverrides), './test-state.json');
  const tracker = new OpsecTracker(ctx);
  return { tracker, ctx };
}

describe('OpsecTracker', () => {
  describe('noise recording', () => {
    it('tracks global cumulative noise', () => {
      const { tracker } = makeTracker();
      tracker.recordNoise({ noise_estimate: 0.3 });
      tracker.recordNoise({ noise_estimate: 0.2 });
      expect(tracker.getGlobalNoise()).toBeCloseTo(0.5, 4);
    });

    it('tracks per-host noise', () => {
      const { tracker } = makeTracker();
      tracker.recordNoise({ host_id: 'host-1', noise_estimate: 0.3 });
      tracker.recordNoise({ host_id: 'host-1', noise_estimate: 0.1 });
      tracker.recordNoise({ host_id: 'host-2', noise_estimate: 0.5 });
      expect(tracker.getHostNoise('host-1')).toBeCloseTo(0.4, 4);
      expect(tracker.getHostNoise('host-2')).toBeCloseTo(0.5, 4);
      expect(tracker.getHostNoise('host-3')).toBe(0);
    });

    it('tracks per-domain noise', () => {
      const { tracker } = makeTracker();
      tracker.recordNoise({ domain: 'corp.local', noise_estimate: 0.2 });
      tracker.recordNoise({ domain: 'corp.local', noise_estimate: 0.3 });
      expect(tracker.getDomainNoise('corp.local')).toBeCloseTo(0.5, 4);
    });

    it('uses noise_actual over noise_estimate when provided', () => {
      const { tracker } = makeTracker();
      tracker.recordNoise({ noise_estimate: 0.5, noise_actual: 0.1 });
      expect(tracker.getGlobalNoise()).toBeCloseTo(0.1, 4);
    });

    it('ignores zero or negative noise', () => {
      const { tracker } = makeTracker();
      tracker.recordNoise({ noise_estimate: 0 });
      tracker.recordNoise({ noise_estimate: -0.3 });
      expect(tracker.getGlobalNoise()).toBe(0);
    });
  });

  describe('getNoiseContext', () => {
    it('returns noise budget remaining', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.3 });
      const ctx = tracker.getNoiseContext();
      expect(ctx.noise_budget_remaining).toBeCloseTo(0.7, 4);
      expect(ctx.global_noise_spent).toBeCloseTo(0.3, 4);
    });

    it('returns host/domain noise when requested', () => {
      const { tracker } = makeTracker();
      tracker.recordNoise({ host_id: 'h1', domain: 'd1', noise_estimate: 0.2 });
      const ctx = tracker.getNoiseContext({ host_id: 'h1', domain: 'd1' });
      expect(ctx.host_noise_spent).toBeCloseTo(0.2, 4);
      expect(ctx.domain_noise_spent).toBeCloseTo(0.2, 4);
    });

    it('recommends loud when >60% budget remaining', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.2 });
      expect(tracker.getNoiseContext().recommended_approach).toBe('loud');
    });

    it('recommends normal when 30-60% budget remaining', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.55 });
      expect(tracker.getNoiseContext().recommended_approach).toBe('normal');
    });

    it('recommends quiet when <30% budget remaining', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.8 });
      expect(tracker.getNoiseContext().recommended_approach).toBe('quiet');
    });

    it('warns when budget exhausted', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 0.5 } });
      tracker.recordNoise({ noise_estimate: 0.5 });
      const ctx = tracker.getNoiseContext();
      expect(ctx.noise_budget_remaining).toBe(0);
      expect(ctx.warning).toContain('exhausted');
    });

    it('warns when budget critically low', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.9 });
      const ctx = tracker.getNoiseContext();
      expect(ctx.warning).toContain('critically low');
    });

    it('forces quiet when >=3 defensive signals', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      // Budget is high (>60%), but 3 signals should force quiet
      for (let i = 0; i < 3; i++) {
        tracker.recordDefensiveSignal({
          type: 'lockout',
          detected_at: new Date().toISOString(),
          description: `lockout ${i}`,
        });
      }
      expect(tracker.getNoiseContext().recommended_approach).toBe('quiet');
    });
  });

  describe('defensive signals', () => {
    it('records and retrieves signals', () => {
      const { tracker } = makeTracker();
      const signal: DefensiveSignal = {
        type: 'lockout',
        host_id: 'h1',
        detected_at: new Date().toISOString(),
        description: 'Account locked out after 5 attempts',
      };
      tracker.recordDefensiveSignal(signal);
      const all = tracker.getAllDefensiveSignals();
      expect(all).toHaveLength(1);
      expect(all[0].type).toBe('lockout');
    });

    it('filters stale signals from context', () => {
      const { tracker } = makeTracker();
      const staleDate = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(); // 25h ago
      tracker.recordDefensiveSignal({
        type: 'lockout',
        detected_at: staleDate,
        description: 'old lockout',
      });
      tracker.recordDefensiveSignal({
        type: 'connection_reset',
        detected_at: new Date().toISOString(),
        description: 'recent reset',
      });
      const ctx = tracker.getNoiseContext();
      expect(ctx.defensive_signals).toHaveLength(1);
      expect(ctx.defensive_signals[0].type).toBe('connection_reset');
    });

    it('warns when defensive signals present', () => {
      const { tracker } = makeTracker();
      tracker.recordDefensiveSignal({
        type: 'honeypot',
        detected_at: new Date().toISOString(),
        description: 'Honeypot detected',
      });
      const ctx = tracker.getNoiseContext();
      expect(ctx.warning).toContain('defensive signal');
    });
  });

  describe('isApproachingCeiling', () => {
    it('returns true when global noise >= 85% of max', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.86 });
      expect(tracker.isApproachingCeiling()).toBe(true);
    });

    it('returns false when global noise < 85% of max', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ noise_estimate: 0.5 });
      expect(tracker.isApproachingCeiling()).toBe(false);
    });

    it('returns true when single host exceeds 50% of global budget', () => {
      const { tracker } = makeTracker({ opsec: { name: 'pentest', max_noise: 1.0 } });
      tracker.recordNoise({ host_id: 'h1', noise_estimate: 0.51 });
      expect(tracker.isApproachingCeiling('h1')).toBe(true);
    });

    it('returns true when max_noise is 0', () => {
      const { tracker } = makeTracker({ opsec: { name: 'stealth', max_noise: 0 } });
      expect(tracker.isApproachingCeiling()).toBe(true);
    });
  });

  describe('time window', () => {
    it('returns undefined when no time_window configured', () => {
      const { tracker } = makeTracker();
      const ctx = tracker.getNoiseContext();
      expect(ctx.time_window_remaining_hours).toBeUndefined();
    });

    it('returns 0 when outside time window', () => {
      const hour = new Date().getHours();
      // Set window to an hour range that doesn't include now
      const start = (hour + 2) % 24;
      const end = (hour + 4) % 24;
      const { tracker } = makeTracker({
        opsec: { name: 'pentest', max_noise: 1.0, time_window: { start_hour: start, end_hour: end } },
      });
      const ctx = tracker.getNoiseContext();
      expect(ctx.time_window_remaining_hours).toBe(0);
    });

    it('returns positive hours when inside time window', () => {
      const hour = new Date().getHours();
      // Set window to include current hour with 3 hours remaining
      const start = hour;
      const end = (hour + 3) % 24;
      const { tracker } = makeTracker({
        opsec: { name: 'pentest', max_noise: 1.0, time_window: { start_hour: start, end_hour: end } },
      });
      const ctx = tracker.getNoiseContext();
      expect(ctx.time_window_remaining_hours).toBeGreaterThan(0);
      expect(ctx.time_window_remaining_hours!).toBeLessThanOrEqual(3);
    });
  });

  describe('serialization', () => {
    it('round-trips through serialize/deserialize', () => {
      const { tracker, ctx } = makeTracker();
      tracker.recordNoise({ host_id: 'h1', domain: 'corp.local', noise_estimate: 0.3 });
      tracker.recordNoise({ host_id: 'h2', noise_estimate: 0.2 });
      tracker.recordDefensiveSignal({
        type: 'lockout',
        host_id: 'h1',
        detected_at: new Date().toISOString(),
        description: 'test lockout',
      });

      const state = tracker.serialize();
      const restored = OpsecTracker.deserialize(state, ctx);

      expect(restored.getGlobalNoise()).toBeCloseTo(0.5, 4);
      expect(restored.getHostNoise('h1')).toBeCloseTo(0.3, 4);
      expect(restored.getHostNoise('h2')).toBeCloseTo(0.2, 4);
      expect(restored.getDomainNoise('corp.local')).toBeCloseTo(0.3, 4);
      expect(restored.getAllDefensiveSignals()).toHaveLength(1);
    });

    it('handles empty state', () => {
      const { ctx } = makeTracker();
      const emptyState: OpsecTrackerState = {
        noise_by_host: {},
        noise_by_domain: {},
        global_noise: 0,
        defensive_signals: [],
      };
      const restored = OpsecTracker.deserialize(emptyState, ctx);
      expect(restored.getGlobalNoise()).toBe(0);
      expect(restored.getAllDefensiveSignals()).toHaveLength(0);
    });

    it('handles partial state (backward compat)', () => {
      const { ctx } = makeTracker();
      const partial = { noise_by_host: {}, noise_by_domain: {} } as any;
      const restored = OpsecTracker.deserialize(partial, ctx);
      expect(restored.getGlobalNoise()).toBe(0);
      expect(restored.getAllDefensiveSignals()).toHaveLength(0);
    });
  });

  describe('integration with EngineContext', () => {
    it('EngineContext initializes with fresh OpsecTracker', () => {
      const graph = makeGraph();
      const config = makeConfig();
      const ctx = new EngineContext(graph, config, './test-state.json');
      expect(ctx.opsecTracker).toBeInstanceOf(OpsecTracker);
      expect(ctx.opsecTracker.getGlobalNoise()).toBe(0);
    });
  });
});
