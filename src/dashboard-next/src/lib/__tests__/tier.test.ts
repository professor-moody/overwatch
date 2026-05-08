import { describe, it, expect } from 'vitest';
import { isCrossTierPath, tierForNode, tiersForPath } from '../tier';
import type { ExportedNode } from '../types';

const N = (id: string, type: string): ExportedNode => ({
  id, type: type as any, label: id, confidence: 1, discovered_at: '2026-01-01T00:00:00Z',
});

describe('tierForNode', () => {
  it('classifies network nodes', () => {
    for (const t of ['host', 'service', 'subnet', 'domain', 'user', 'group', 'credential']) {
      expect(tierForNode(N('x', t))).toBe('network');
    }
  });
  it('classifies app nodes', () => {
    expect(tierForNode(N('w', 'webapp'))).toBe('app');
    expect(tierForNode(N('a', 'api_endpoint'))).toBe('app');
    expect(tierForNode(N('v', 'vulnerability'))).toBe('app');
  });
  it('classifies cloud nodes', () => {
    expect(tierForNode(N('r', 'cloud_resource'))).toBe('cloud');
    expect(tierForNode(N('i', 'cloud_identity'))).toBe('cloud');
    expect(tierForNode(N('p', 'cloud_policy'))).toBe('cloud');
  });
  it('classifies identity nodes', () => {
    expect(tierForNode(N('idp', 'idp'))).toBe('identity');
    expect(tierForNode(N('app', 'idp_application'))).toBe('identity');
    expect(tierForNode(N('p', 'idp_principal'))).toBe('identity');
  });
  it('returns unknown for undefined / unfamiliar types', () => {
    expect(tierForNode(undefined)).toBe('unknown');
    expect(tierForNode(N('x', 'unfamiliar'))).toBe('unknown');
  });
});

describe('tiersForPath / isCrossTierPath', () => {
  const byId = new Map<string, ExportedNode>([
    ['h1', N('h1', 'host')],
    ['w1', N('w1', 'webapp')],
    ['c1', N('c1', 'cloud_resource')],
    ['i1', N('i1', 'idp')],
  ]);

  it('single-tier path → not cross-tier', () => {
    expect(isCrossTierPath(['h1'], byId)).toBe(false);
  });
  it('two-tier path → cross-tier', () => {
    expect(tiersForPath(['h1', 'w1'], byId)).toEqual(new Set(['network', 'app']));
    expect(isCrossTierPath(['h1', 'w1'], byId)).toBe(true);
  });
  it('four-tier path → cross-tier with all four', () => {
    expect(tiersForPath(['h1', 'w1', 'c1', 'i1'], byId).size).toBe(4);
  });
});
