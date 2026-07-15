import { describe, expect, it } from 'vitest';
import {
  findingAffectedNodeIds,
  narrativeItemsFromChains,
  resolveEvidenceQuery,
} from '../evidence-narrative';
import type { ExportedGraph } from '../types';
import type { FindingDto } from '../api';

const graph: ExportedGraph = {
  nodes: [
    { id: 'host-1', type: 'host', label: 'DC01.corp.local', hostname: 'DC01', ip: '10.10.10.10', confidence: 1, discovered_at: 'now' },
    { id: 'cred-1', type: 'credential', label: 'jdoe:NTLM', cred_user: 'jdoe', confidence: 1, discovered_at: 'now' },
  ],
  edges: [],
  coldInventory: [],
};

const finding: FindingDto = {
  id: 'finding-1',
  title: 'Domain admin path',
  severity: 'high',
  category: 'access_path',
  description: 'Path to DC01',
  affected_assets: ['DC01.corp.local'],
  remediation: 'Restrict admin paths',
  risk_score: 8,
};

describe('evidence narrative helpers', () => {
  it('resolves evidence queries from node properties and finding assets', () => {
    expect(resolveEvidenceQuery('DC01', graph)).toBe('host-1');
    expect(resolveEvidenceQuery('10.10.10.10', graph)).toBe('host-1');
    expect(resolveEvidenceQuery('jdoe:NTLM', graph)).toBe('cred-1');
    expect(resolveEvidenceQuery('Domain admin path', graph, [finding])).toBe('host-1');
    expect(findingAffectedNodeIds(finding, graph)).toEqual(['host-1']);
  });

  it('turns evidence chain responses into compact narrative items', () => {
    const items = narrativeItemsFromChains([{
      node_id: 'host-1',
      count: 1,
      node_props: { label: 'DC01.corp.local' },
      chains: [{ activity_id: 'evt-1', timestamp: '2026-05-15T00:00:00Z', event_type: 'action_completed', description: 'done', snippet: 'SMB evidence' }],
    }]);

    expect(items).toEqual([{
      id: 'host-1',
      node_id: 'host-1',
      label: 'DC01.corp.local',
      count: 1,
      latest: '2026-05-15T00:00:00Z',
      description: 'done',
      proof: 'SMB evidence',
      source_kind: 'activity',
      event_type: 'action_completed',
      action_id: undefined,
      tool: undefined,
    }]);
  });
});
