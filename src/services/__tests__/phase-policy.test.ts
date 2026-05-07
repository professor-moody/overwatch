import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig, EngagementPhase } from '../../types.js';

const TEST_STATE = './state-test-phase-policy.json';

function makeConfig(opts: { phases?: EngagementPhase[]; opsec?: any } = {}): EngagementConfig {
  return {
    id: 'phase-test',
    name: 'phase test',
    created_at: '2026-01-01T00:00:00.000Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: opts.opsec ?? { name: 'pentest', max_noise: 0.7, enabled: true, approval_mode: 'auto-approve' },
    phases: opts.phases,
  };
}

function cleanup(): void {
  for (const f of [TEST_STATE, TEST_STATE + '.journal.jsonl']) {
    try { if (existsSync(f)) unlinkSync(f); } catch {}
  }
}

describe('Phase-aware OPSEC + approval (P4.1)', () => {
  afterEach(() => cleanup());

  it('returns engagement-level OPSEC when no phases are defined', () => {
    cleanup();
    const eng = new GraphEngine(makeConfig({ opsec: { name: 'p', max_noise: 0.5, enabled: true } }), TEST_STATE);
    const eff = eng.getEffectiveOpsec();
    expect(eff.max_noise).toBe(0.5);
    expect(eff.enabled).toBe(true);
  });

  it('returns engagement-level OPSEC when no phase is currently active', () => {
    cleanup();
    // Phase exists but its entry_criteria are unmet (no objectives achieved).
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      exit_criteria: [{ type: 'always' }],
      opsec_overrides: { max_noise: 0.1 },
    }];
    const eng = new GraphEngine(makeConfig({
      opsec: { name: 'p', max_noise: 0.7, enabled: true },
      phases,
    }), TEST_STATE);
    expect(eng.getEffectiveOpsec().max_noise).toBe(0.7);
  });

  it('phase override merges over engagement-level OPSEC when phase is active', () => {
    cleanup();
    // 'always' entry + un-met exit → status 'active'.
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      opsec_overrides: { max_noise: 0.1, enabled: true },
    }];
    const eng = new GraphEngine(makeConfig({
      opsec: { name: 'p', max_noise: 0.7, enabled: true },
      phases,
    }), TEST_STATE);
    const eff = eng.getEffectiveOpsec();
    expect(eff.max_noise).toBe(0.1);
    // Non-overridden fields preserved.
    expect(eff.name).toBe('p');
  });

  it('phase blacklist EXTENDS engagement-level blacklist (does not replace)', () => {
    cleanup();
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      approval_overrides: {
        blacklisted_techniques: ['T1003'], // dangerous in this phase
      },
    }];
    const eng = new GraphEngine(makeConfig({
      opsec: {
        name: 'p', max_noise: 1.0, enabled: true,
        approval_mode: 'approve-critical',
        blacklisted_techniques: ['T1059'], // already blacklisted globally
      },
      phases,
    }), TEST_STATE);
    const cfg = eng.getEffectiveApprovalConfig();
    expect(cfg.blacklisted_techniques.sort()).toEqual(['T1003', 'T1059']);
  });

  it('phase approval mode override wins over engagement-level mode', () => {
    cleanup();
    const phases: EngagementPhase[] = [{
      id: 'exploit', name: 'Exploit', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      approval_overrides: { mode: 'approve-all' },
    }];
    const eng = new GraphEngine(makeConfig({
      opsec: { name: 'p', max_noise: 1.0, enabled: true, approval_mode: 'auto-approve' },
      phases,
    }), TEST_STATE);
    expect(eng.getEffectiveApprovalConfig().mode).toBe('approve-all');
  });

  it('emits phase_entered when a phase becomes active for the first time', () => {
    cleanup();
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
    }];
    const eng = new GraphEngine(makeConfig({ phases }), TEST_STATE);
    // Trigger evaluateObjectives via a small ingest. Use ingestFinding so
    // the engine's normal post-ingest pipeline runs (which calls
    // evaluateObjectives → recordPhaseTransitionsIfAny).
    eng.ingestFinding({
      id: 'finding-1', agent_id: 'test-agent',
      timestamp: '2026-01-01T00:00:01.000Z',
      nodes: [{
        id: 'host-1', type: 'host', label: 'h1', ip: '10.10.10.1',
        discovered_at: '2026-01-01T00:00:01.000Z', confidence: 1,
      }],
      edges: [],
    });
    const transitions = eng.getFullHistory().filter(e => e.event_type === 'phase_entered');
    expect(transitions.length).toBeGreaterThan(0);
    expect((transitions[0].details as any).phase_id).toBe('recon');
  });

  it('does NOT re-emit phase_entered when phase is unchanged', () => {
    cleanup();
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
    }];
    const eng = new GraphEngine(makeConfig({ phases }), TEST_STATE);
    eng.ingestFinding({
      id: 'f1', agent_id: 'a', timestamp: '2026-01-01T00:00:01.000Z',
      nodes: [{ id: 'h1', type: 'host', label: 'h1', ip: '10.10.10.1',
        discovered_at: '2026-01-01T00:00:01.000Z', confidence: 1 }],
      edges: [],
    });
    const before = eng.getFullHistory().filter(e => e.event_type === 'phase_entered').length;
    eng.ingestFinding({
      id: 'f2', agent_id: 'a', timestamp: '2026-01-01T00:00:02.000Z',
      nodes: [{ id: 'h2', type: 'host', label: 'h2', ip: '10.10.10.2',
        discovered_at: '2026-01-01T00:00:02.000Z', confidence: 1 }],
      edges: [],
    });
    const after = eng.getFullHistory().filter(e => e.event_type === 'phase_entered').length;
    expect(after).toBe(before);
  });
});
