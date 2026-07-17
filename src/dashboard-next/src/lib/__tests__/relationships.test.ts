import { describe, expect, it } from 'vitest';
import {
  buildAssetNodeMatcher,
  deriveNodeRelationships,
  getActionNodeIds,
  getFrontierNodeIds,
  getSessionNodeIds,
  resolveAssetToNodeId,
} from '../relationships';
import type { ExportedGraph, FrontierItem, PendingAction, SessionInfo } from '../types';
import type { FindingDto } from '../api';

describe('relationship helpers', () => {
  it('extracts node ids from sessions, actions, and frontier items', () => {
    const session = {
      id: 's1',
      kind: 'pty',
      state: 'connected',
      target_node: 'host-1',
      credential_node: 'cred-1',
      principal_node: 'user-1',
    } as SessionInfo;
    const action = {
      action_id: 'a1',
      technique: 'test',
      target: 'host-1',
      target_node: 'host-2',
      noise_level: 0,
      description: 'x',
      submitted_at: '2026-05-15T00:00:00Z',
    } as PendingAction;
    const frontier = {
      id: 'f1',
      type: 'inferred_edge',
      description: 'x',
      edge_source: 'host-1',
      edge_target: 'svc-1',
      edge_type: 'RUNS',
      graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 1 },
      opsec_noise: 0.2,
      staleness_seconds: 0,
    } as FrontierItem;

    expect(getSessionNodeIds(session)).toEqual(['host-1', 'user-1', 'cred-1']);
    expect(getActionNodeIds(action)).toEqual(['host-2', 'host-1']);
    expect(getFrontierNodeIds(frontier)).toEqual(['host-1', 'svc-1']);
  });

  it('matches finding affected assets to graph node ids and labels', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'host-1', type: 'host', label: 'DC01.corp.local', confidence: 1, discovered_at: 'now', hostname: 'DC01' },
      ],
      edges: [],
      coldInventory: [],
    };
    const matches = buildAssetNodeMatcher(graph);

    expect(matches('host-1', 'host-1')).toBe(true);
    expect(matches('DC01.corp.local', 'host-1')).toBe(true);
    expect(matches('DC01', 'host-1')).toBe(true);
    expect(matches('other', 'host-1')).toBe(false);
    expect(resolveAssetToNodeId('DC01', graph)).toBe('host-1');
  });

  it('derives all node relationships from plain dashboard state', () => {
    const finding: FindingDto = {
      id: 'finding-1',
      title: 'Domain admin session',
      severity: 'high',
      category: 'access',
      description: 'x',
      affected_assets: ['DC01.corp.local'],
      remediation: 'x',
      risk_score: 8,
    };
    const graph: ExportedGraph = {
      nodes: [
        { id: 'host-1', type: 'host', label: 'DC01.corp.local', confidence: 1, discovered_at: 'now' },
      ],
      edges: [],
      coldInventory: [],
    };

    const relationships = deriveNodeRelationships('host-1', {
      graph,
      sessions: [{
        id: 's1',
        kind: 'pty',
        transport: 'pty',
        state: 'connected',
        title: 'shell',
        target_node: 'host-1',
        started_at: 'now',
        last_activity_at: 'now',
        capabilities: {},
        buffer_end_pos: 0,
      }],
      pendingActions: [{ action_id: 'a1', technique: 'nmap', target: 'host-1', noise_level: 0.2, description: 'scan', submitted_at: 'now' }],
      frontier: [{ id: 'f1', type: 'incomplete_node', description: 'enrich', node_id: 'host-1', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 1 }, opsec_noise: 0.2, staleness_seconds: 0 }],
      findings: [finding],
    });

    expect(relationships.sessions).toHaveLength(1);
    expect(relationships.pendingActions).toHaveLength(1);
    expect(relationships.frontier).toHaveLength(1);
    expect(relationships.findings).toHaveLength(1);
  });
});
