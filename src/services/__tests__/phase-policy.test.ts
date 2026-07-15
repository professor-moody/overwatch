import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig, EngagementPhase } from '../../types.js';

function makeConfig(opts: { phases?: EngagementPhase[]; opsec?: any; operator_policy?: any } = {}): EngagementConfig {
  return {
    id: 'phase-test',
    name: 'phase test',
    created_at: '2026-01-01T00:00:00.000Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: opts.opsec ?? { name: 'pentest', max_noise: 0.7, enabled: true, approval_mode: 'auto-approve' },
    phases: opts.phases,
    operator_policy: opts.operator_policy,
  };
}

let testDir: string;
const engines = new Set<GraphEngine>();

function createEngine(config: EngagementConfig): GraphEngine {
  const engine = new GraphEngine(config, join(testDir, 'state.json'));
  engines.add(engine);
  return engine;
}

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'overwatch-phase-policy-'));
});

afterEach(() => {
  for (const engine of engines) engine.dispose();
  engines.clear();
  rmSync(testDir, { recursive: true, force: true });
});

describe('Phase-aware OPSEC + approval (P4.1)', () => {
  it('returns engagement-level OPSEC when no phases are defined', () => {
    const eng = createEngine(makeConfig({ opsec: { name: 'p', max_noise: 0.5, enabled: true } }));
    const eff = eng.getEffectiveOpsec();
    expect(eff.max_noise).toBe(0.5);
    expect(eff.enabled).toBe(true);
  });

  it('returns engagement-level OPSEC when no phase is currently active', () => {
    // Phase exists but its entry_criteria are unmet (no objectives achieved).
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      exit_criteria: [{ type: 'always' }],
      opsec_overrides: { max_noise: 0.1 },
    }];
    const eng = createEngine(makeConfig({
      opsec: { name: 'p', max_noise: 0.7, enabled: true },
      phases,
    }));
    expect(eng.getEffectiveOpsec().max_noise).toBe(0.7);
  });

  it('phase override merges over engagement-level OPSEC when phase is active', () => {
    // 'always' entry + un-met exit → status 'active'.
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      opsec_overrides: { max_noise: 0.1, enabled: true },
    }];
    const eng = createEngine(makeConfig({
      opsec: { name: 'p', max_noise: 0.7, enabled: true },
      phases,
    }));
    const eff = eng.getEffectiveOpsec();
    expect(eff.max_noise).toBe(0.1);
    // Non-overridden fields preserved.
    expect(eff.name).toBe('p');
  });

  it('phase blacklist EXTENDS engagement-level blacklist (does not replace)', () => {
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      approval_overrides: {
        blacklisted_techniques: ['T1003'], // dangerous in this phase
      },
    }];
    const eng = createEngine(makeConfig({
      opsec: {
        name: 'p', max_noise: 1.0, enabled: true,
        approval_mode: 'approve-critical',
        blacklisted_techniques: ['T1059'], // already blacklisted globally
      },
      phases,
    }));
    const cfg = eng.getEffectiveApprovalConfig();
    expect(cfg.blacklisted_techniques.sort()).toEqual(['T1003', 'T1059']);
  });

  it('phase approval mode override wins over engagement-level mode', () => {
    const phases: EngagementPhase[] = [{
      id: 'exploit', name: 'Exploit', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
      approval_overrides: { mode: 'approve-all' },
    }];
    const eng = createEngine(makeConfig({
      opsec: { name: 'p', max_noise: 1.0, enabled: true, approval_mode: 'auto-approve' },
      phases,
    }));
    expect(eng.getEffectiveApprovalConfig().mode).toBe('approve-all');
  });

  it('emits phase_entered when a phase becomes active for the first time', () => {
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
    }];
    const eng = createEngine(makeConfig({ phases }));
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
    const phases: EngagementPhase[] = [{
      id: 'recon', name: 'Recon', order: 1,
      strategies: [],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
    }];
    const eng = createEngine(makeConfig({ phases }));
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

describe('operator-policy approval rules (T3 — tightening-only)', () => {
  it('a network rule escalates the mode for a matching target IP', () => {
    const eng = createEngine(makeConfig({
      operator_policy: { version: 1, approval_rules: [{ match: { network: '10.10.10.0/24' }, require: 'approve-all' }] },
    }));
    // base is auto-approve; the rule escalates for an in-network target.
    expect(eng.getEffectiveApprovalConfig({ ip: '10.10.10.5' }).mode).toBe('approve-all');
    // a target outside the rule's network is unaffected.
    expect(eng.getEffectiveApprovalConfig({ ip: '192.168.1.5' }).mode).toBe('auto-approve');
    // no action context → no rule application.
    expect(eng.getEffectiveApprovalConfig().mode).toBe('auto-approve');
  });

  it('a technique rule escalates for the matching technique only', () => {
    const eng = createEngine(makeConfig({
      operator_policy: { version: 1, approval_rules: [{ match: { technique: 'rdp_lateral_movement' }, require: 'approve-critical' }] },
    }));
    expect(eng.getEffectiveApprovalConfig({ technique: 'rdp_lateral_movement' }).mode).toBe('approve-critical');
    expect(eng.getEffectiveApprovalConfig({ technique: 'port_scan' }).mode).toBe('auto-approve');
  });

  it('NEVER weakens: a looser rule cannot downgrade the base mode', () => {
    const eng = createEngine(makeConfig({
      opsec: { name: 'pentest', max_noise: 0.7, enabled: true, approval_mode: 'approve-all' },
      operator_policy: { version: 1, approval_rules: [{ match: {}, require: 'auto-approve' }] },
    }));
    // base approve-all + a match-everything auto-approve rule → stays approve-all.
    expect(eng.getEffectiveApprovalConfig({ ip: '10.10.10.5' }).mode).toBe('approve-all');
  });

  it('a host_class rule matches the target node\'s scope status', () => {
    const eng = createEngine(makeConfig({
      operator_policy: { version: 1, approval_rules: [{ match: { host_class: 'in_scope' }, require: 'approve-all' }] },
    }));
    eng.addNode({ id: 'h-inscope', type: 'host', label: 'h', ip: '10.10.10.20', discovered_at: '2026-01-01T00:00:00.000Z', confidence: 1 } as never);
    expect(eng.getEffectiveApprovalConfig({ nodeId: 'h-inscope' }).mode).toBe('approve-all');
    // no node context → host_class rule can't match → base mode.
    expect(eng.getEffectiveApprovalConfig({ ip: '10.10.10.20' }).mode).toBe('auto-approve');
  });
});
