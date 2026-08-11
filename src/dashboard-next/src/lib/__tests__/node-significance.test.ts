import { describe, expect, it } from 'vitest';
import { nodeProvenance, nodeSignificance } from '../node-significance';

describe('nodeSignificance', () => {
  it('flags an objective by its description or achieved flag, not just the rare type', () => {
    const byType = nodeSignificance({ type: 'objective', objective_description: 'Own the DC' }, 'objective');
    expect(byType.role).toBe('objective');
    expect(byType.roleLabel).toBe('Objective');
    expect(byType.roleDetail).toBe('Own the DC');
    expect(byType.achieved).toBe(false);

    // An ordinary host flagged as the goal is still an objective.
    const byFlag = nodeSignificance({ objective_achieved: true }, 'host');
    expect(byFlag.role).toBe('objective');
    expect(byFlag.achieved).toBe(true);
    expect(byFlag.tier).toBe('network');
  });

  it('flags a high-value target with its reason', () => {
    const sig = nodeSignificance({ hvt: true, hvt_reason: 'Domain admin group' }, 'group');
    expect(sig.role).toBe('hvt');
    expect(sig.roleLabel).toBe('High-value target');
    expect(sig.roleDetail).toBe('Domain admin group');
  });

  it('describes a routine node by its friendly type and trust tier', () => {
    const sig = nodeSignificance({}, 'host');
    expect(sig.role).toBe('standard');
    expect(sig.roleLabel).toBe('Host');
    expect(sig.tier).toBe('network');
    expect(sig.roleDetail).toBeUndefined();
  });

  it('prefers objective over high-value target when a node is both', () => {
    const sig = nodeSignificance({ hvt: true, objective_achieved: true }, 'cloud_identity');
    expect(sig.role).toBe('objective');
    expect(sig.tier).toBe('cloud');
  });
});

describe('nodeProvenance', () => {
  it('lifts source trust, confidence, discovery time/actor, and traceability', () => {
    const prov = nodeProvenance({
      source_trust: 'observed',
      confidence: 0.92,
      discovered_at: '2020-01-01T00:00:00Z',
      discovered_by: 'recon-agent',
      discovered_by_action_id: 'act-1',
    });
    expect(prov.sourceTrust).toBe('observed');
    expect(prov.confidencePct).toBe(92);
    expect(prov.discoveredBy).toBe('recon-agent');
    expect(prov.discoveredAgo).toMatch(/ago|just now/);
    expect(prov.traceable).toBe(true);
  });

  it('reports null confidence and no trust/trace when the backend sent none', () => {
    const prov = nodeProvenance({});
    expect(prov.confidencePct).toBeNull();
    expect(prov.sourceTrust).toBeUndefined();
    expect(prov.traceable).toBe(false);
    expect(prov.discoveredAgo).toBeUndefined();
  });

  it('ignores a source_trust value outside the observed|asserted|inferred enum', () => {
    expect(nodeProvenance({ source_trust: 'guessed' }).sourceTrust).toBeUndefined();
  });
});
