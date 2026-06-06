import { describe, expect, it } from 'vitest';
import {
  attackPathLaneCounts,
  filterDisplayAttackPaths,
  groupDisplayAttackPaths,
  normalizeApiAttackPath,
  normalizeComputedAttackPath,
} from '../attack-path-workspace';
import type { AttackPath, ExportedNode } from '../types';

const now = '2026-05-15T18:23:34.963Z';

function node(id: string, type: ExportedNode['type'], label = id): ExportedNode {
  return { id, type, label, confidence: 1, discovered_at: now };
}

describe('attack path workspace helpers', () => {
  it('normalizes a short low-noise route into a readable fast-win display model', () => {
    const byId = new Map([
      ['ws01', node('ws01', 'host', 'WS01.corp.local')],
      ['portal', node('portal', 'webapp', 'Benefits Portal')],
    ]);
    const display = normalizeComputedAttackPath({
      nodes: ['ws01', 'portal'],
      edge_types: ['CAN_REACH'],
      edge_ids: ['edge-reach'],
      total_confidence: 0.82,
      total_opsec_noise: 0.3,
    }, byId);

    expect(display?.headline).toBe('WS01.corp.local can reach Benefits Portal');
    expect(display?.group).toBe('fast_wins');
    expect(display?.edges[0]).toMatchObject({ id: 'edge-reach', rawType: 'CAN_REACH', label: 'reaches' });
    expect(display?.riskLabel).toBe('low friction');
  });

  it('groups cloud, identity, and higher-risk paths into operator decision lanes', () => {
    const nodes = [
      node('ws01', 'host', 'WS01'),
      node('portal', 'webapp', 'Benefits Portal'),
      node('role', 'cloud_identity', 'AWS BackupRole'),
      node('idp', 'idp_principal', 'jdoe@corp.local'),
      node('dc01', 'host', 'DC01'),
    ];
    const byId = new Map(nodes.map(item => [item.id, item]));
    const paths = [
      normalizeComputedAttackPath({ nodes: ['ws01', 'portal'], edge_types: ['CAN_REACH'], edge_ids: ['e1'], total_confidence: 0.9, total_opsec_noise: 0.2 }, byId),
      normalizeComputedAttackPath({ nodes: ['ws01', 'portal', 'role'], edge_types: ['CAN_REACH', 'ISSUES_TOKENS_FOR'], edge_ids: ['e1', 'e2'], total_confidence: 0.8, total_opsec_noise: 0.7 }, byId),
      normalizeComputedAttackPath({ nodes: ['ws01', 'idp'], edge_types: ['VALID_FOR_IDP_PRINCIPAL'], edge_ids: ['e3'], total_confidence: 0.8, total_opsec_noise: 0.4 }, byId),
      normalizeComputedAttackPath({ nodes: ['ws01', 'dc01'], edge_types: ['ADMIN_TO'], edge_ids: ['e4'], total_confidence: 0.8, total_opsec_noise: 1.2 }, byId),
    ].filter(Boolean);

    const grouped = groupDisplayAttackPaths(paths as NonNullable<typeof paths[number]>[]);

    expect(grouped.map(group => group.key)).toEqual(['fast_wins', 'cloud_reach', 'identity_pivots', 'higher_risk']);
    expect(filterDisplayAttackPaths(paths as NonNullable<typeof paths[number]>[], 'all')).toHaveLength(4);
    expect(filterDisplayAttackPaths(paths as NonNullable<typeof paths[number]>[], 'cloud_reach').map(path => path.target.id)).toEqual(['role']);
    expect(attackPathLaneCounts(paths as NonNullable<typeof paths[number]>[])).toEqual({
      all: 4,
      fast_wins: 1,
      cloud_reach: 1,
      identity_pivots: 1,
      higher_risk: 1,
    });
  });

  it('normalizes Evidence API path shapes with object nodes, string nodes, and missing edge ids', () => {
    const byId = new Map([
      ['ws01', node('ws01', 'host', 'WS01')],
      ['cred-okta', node('cred-okta', 'credential', 'jdoe:Okta session')],
    ]);
    const apiPath: AttackPath = {
      nodes: [
        'ws01',
        { id: 'cred-okta', label: 'jdoe:Okta session', type: 'credential', edge_type: 'OWNS_CRED' },
        { id: 'principal', label: 'jdoe@corp.local', type: 'idp_principal', edge_type: 'VALID_FOR_IDP_PRINCIPAL' },
      ],
      total_confidence: 0.75,
      total_opsec_noise: 0.6,
    };

    const display = normalizeApiAttackPath(apiPath, byId);

    expect(display?.nodeIds).toEqual(['ws01', 'cred-okta', 'principal']);
    expect(display?.edgeIds).toEqual([]);
    expect(display?.rawEdgeTypes).toEqual(['OWNS_CRED', 'VALID_FOR_IDP_PRINCIPAL']);
    expect(display?.group).toBe('identity_pivots');
  });
});
