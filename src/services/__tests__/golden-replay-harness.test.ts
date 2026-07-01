import { describe, it, expect } from 'vitest';
import { hashGraph, hashActivity } from '../golden-replay.js';

describe('hashActivity — broadened digest catches descriptor regressions', () => {
  it('differs when result_classification changes (was self-masked by the 3-field projection)', () => {
    const base = [{ event_id: 'e1', event_type: 'action_completed', description: 'd', result_classification: 'success' }];
    const changed = [{ event_id: 'e1', event_type: 'action_completed', description: 'd', result_classification: 'failure' }];
    expect(hashActivity(base)).not.toBe(hashActivity(changed));
  });

  it('differs when category/technique/outcome/tool_name/provenance changes', () => {
    const base = { event_id: 'e1', event_type: 'x', description: 'd', category: 'recon', technique: 'port_scan', outcome: 'success', tool_name: 'nmap', provenance: 'agent' };
    for (const k of ['category', 'technique', 'outcome', 'tool_name', 'provenance'] as const) {
      const changed = { ...base, [k]: 'DIFFERENT' };
      expect(hashActivity([base])).not.toBe(hashActivity([changed]));
    }
  });

  it('is stable for the same input (deterministic)', () => {
    const h = [{ event_id: 'e1', event_type: 'x', description: 'd', category: 'recon' }];
    expect(hashActivity(h)).toBe(hashActivity([{ ...h[0] }]));
  });

  it('ignores the wall-clock timestamp (structural "what", not "when")', () => {
    const a = [{ event_id: 'e1', event_type: 'x', description: 'd', timestamp: '2026-01-01T00:00:00.000Z' }];
    const b = [{ event_id: 'e1', event_type: 'x', description: 'd', timestamp: '2027-09-09T09:09:09.000Z' }];
    expect(hashActivity(a)).toBe(hashActivity(b));
  });
});

describe('hashGraph — non-finite numbers do not hash-collide with null', () => {
  const g = (v: unknown) => ({ nodes: [{ id: 'n1', properties: { type: 'host', score: v } }], edges: [] }) as any;
  it('NaN, Infinity, -Infinity, and null all hash differently', () => {
    const hs = [hashGraph(g(NaN)), hashGraph(g(Infinity)), hashGraph(g(-Infinity)), hashGraph(g(null))];
    expect(new Set(hs).size).toBe(4);
  });
});
