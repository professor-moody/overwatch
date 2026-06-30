import { describe, it, expect } from 'vitest';
import { previewScopeChange, mergeScopeAdds } from '../scope-preview.js';

const nodes = [
  { id: 'h1', properties: { ip: '10.0.0.5', label: '10.0.0.5' } },
  { id: 'h2', properties: { ip: '192.168.1.5', label: '192.168.1.5' } },
  { id: 'w1', properties: { hostname: 'app.corp.com', label: 'app.corp.com' } },
  { id: 'x', properties: { label: 'no-network-identity' } }, // ignored: no ip/hostname
];

describe('previewScopeChange', () => {
  const empty = { cidrs: [], domains: [], exclusions: [] };

  it('reports nodes an added cidr brings into scope', () => {
    const p = previewScopeChange(nodes, empty, { add_cidrs: ['10.0.0.0/24'] });
    expect(p.newly_in_scope_count).toBe(1);
    expect(p.newly_in_scope.map(n => n.id)).toEqual(['h1']);
    expect(p.newly_excluded_count).toBe(0);
  });

  it('an added domain brings a matching hostname (subdomain) into scope', () => {
    const p = previewScopeChange(nodes, empty, { add_domains: ['corp.com'] });
    expect(p.newly_in_scope.map(n => n.id)).toContain('w1');
  });

  it('an added exclusion pushes an in-scope node out', () => {
    const current = { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] };
    const p = previewScopeChange(nodes, current, { add_exclusions: ['10.0.0.5'] });
    expect(p.newly_excluded.map(n => n.id)).toEqual(['h1']);
    expect(p.newly_in_scope_count).toBe(0);
  });

  it('ignores nodes with no ip or hostname', () => {
    const p = previewScopeChange(nodes, empty, { add_cidrs: ['0.0.0.0/0'] });
    expect(p.newly_in_scope.find(n => n.id === 'x')).toBeUndefined();
  });

  it('no transition when the node was already in scope', () => {
    const current = { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] };
    const p = previewScopeChange(nodes, current, { add_cidrs: ['10.0.0.0/16'] });
    expect(p.newly_in_scope_count).toBe(0); // h1 already in scope before
  });
});

describe('mergeScopeAdds', () => {
  it('returns null when there are no scope ops', () => {
    expect(mergeScopeAdds([{ op: 'directive' }, { op: 'approve' }])).toBeNull();
  });
  it('merges multiple scope ops into one net change', () => {
    expect(mergeScopeAdds([
      { op: 'scope', add_cidrs: ['10.0.0.0/24'] },
      { op: 'scope', add_domains: ['corp.com'], add_exclusions: ['10.0.0.9'] },
    ])).toEqual({ add_cidrs: ['10.0.0.0/24'], add_domains: ['corp.com'], add_exclusions: ['10.0.0.9'] });
  });
});
