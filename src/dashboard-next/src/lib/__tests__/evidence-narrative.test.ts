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
      command: undefined,
      agent_id: undefined,
      source_trust: undefined,
      exit_code: undefined,
      content_hash: undefined,
      evidence_id: undefined,
      excerpts: undefined,
      source_kind: 'activity',
      event_type: 'action_completed',
      action_id: undefined,
      tool: undefined,
    }]);
  });

  it('carries the proof (matched excerpts + source_trust + exit code + hash) for a finding', () => {
    const [item] = narrativeItemsFromChains([{
      node_id: 'host-1',
      count: 1,
      node_props: { label: 'DC01.corp.local' },
      chains: [{
        activity_id: 'act-1', timestamp: '2026-05-15T00:00:00Z', event_type: 'action_completed',
        description: 'nxc found creds', agent_id: 'recon', command: 'nxc smb 10.10.10.10',
        source_trust: 'observed', exit_code: 0, content_hash: 'deadbeefcafe',
        excerpts: [{ snippet: 'admin:Pwn3d!', byte_start: 40, byte_end: 52, matched_by: 'nxc', verified: true }],
      }],
    }]);
    expect(item.source_trust).toBe('observed');
    expect(item.exit_code).toBe(0);
    expect(item.content_hash).toBe('deadbeefcafe');
    expect(item.excerpts).toHaveLength(1);
    expect(item.excerpts![0]).toMatchObject({ snippet: 'admin:Pwn3d!', byte_start: 40, byte_end: 52, verified: true });
  });

  it('lifts the command + agent from whichever lifecycle entry carries them ("how it was found")', () => {
    // The command is on the run entry and the result snippet on the completion entry -
    // both must survive, and the presence of a command makes it command_output.
    const [item] = narrativeItemsFromChains([{
      node_id: 'host-1',
      count: 2,
      node_props: { label: 'DC01.corp.local' },
      chains: [
        { activity_id: 'evt-run', timestamp: '2026-05-15T00:00:00Z', event_type: 'action_started', description: 'running', agent_id: 'recon-agent', command: 'nxc smb 10.10.10.10' },
        { activity_id: 'evt-done', timestamp: '2026-05-15T00:00:05Z', event_type: 'action_completed', description: 'done', snippet: 'Pwn3d!' },
      ],
    }]);
    expect(item.command).toBe('nxc smb 10.10.10.10');
    expect(item.agent_id).toBe('recon-agent');
    expect(item.source_kind).toBe('command_output');
    expect(item.proof).toBe('running'); // chains[0] snippet/description is the current proof selection
  });
});
