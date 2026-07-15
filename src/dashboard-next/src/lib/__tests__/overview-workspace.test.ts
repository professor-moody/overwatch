import { describe, expect, it } from 'vitest';
import {
  deriveAccessFacts,
  deriveAttentionItems,
  deriveChangedItems,
  deriveNextActionItems,
  deriveNowItems,
  deriveRecentChanges,
  deriveVerificationItems,
} from '../overview-workspace';
import type { AccessSummary, ActivityEntry, Campaign, ExportedNode, FrontierItem, PendingAction, SessionInfo } from '../types';

describe('overview workspace helpers', () => {
  it('places attention before frontier while preserving server candidate order', () => {
    const pending = [{ action_id: 'a1', technique: 'scan', target: 'host-1', noise_level: 0, description: 'scan', submitted_at: 'now' }] as PendingAction[];
    const frontier = [
      { id: 'f-low', type: 'incomplete_node', node_id: 'host-0', description: 'low', graph_metrics: { hops_to_objective: 3, fan_out_estimate: 1, node_degree: 1, confidence: 1 }, opsec_noise: 0.2, staleness_seconds: 0 },
      { id: 'f-high', type: 'incomplete_node', description: 'high', node_id: 'host-1', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 9 }, opsec_noise: 0.2, staleness_seconds: 0 },
    ] as FrontierItem[];

    const items = deriveAttentionItems({
      pendingActions: pending,
      readinessIssues: ['missing tool'],
      frontier,
    });

    expect(items.map(item => item.id)).toEqual(['pending-actions', 'readiness', 'f-low', 'f-high']);
    expect(items[0].route).toBe('actions');
    expect(items[2].nodeId).toBe('host-0');
  });

  it('orders blocking Now items before routine work and treats expired tokens as attention', () => {
    const creds = [
      {
        id: 'cred-expired',
        type: 'credential',
        label: 'Expired PAT',
        confidence: 1,
        discovered_at: '2026-05-01T00:00:00Z',
        credential_status: 'active',
        cred_token_expires_at: '2026-05-01T00:00:00Z',
      },
    ] as ExportedNode[];
    const sessions = [
      { id: 's-error', kind: 'pty', state: 'error', target_node: 'host-1' },
    ] as SessionInfo[];

    const items = deriveNowItems({
      pendingActions: [],
      readinessIssues: ['missing tool'],
      credentialNodes: creds,
      sessions,
      nowMs: new Date('2026-05-02T00:00:00Z').getTime(),
    });

    expect(items.map(item => item.id)).toEqual(['readiness', 'expired-credentials', 'session-errors']);
    expect(items[1].route).toBe('credentials');
    expect(items[2].route).toBe('sessions');
  });

  it('summarizes Next actions with rank reason, context, and node ids', () => {
    const items = deriveNextActionItems([
      { id: 'low', type: 'incomplete_node', node_id: 'host-low', description: 'low', graph_metrics: { hops_to_objective: 2, fan_out_estimate: 1, node_degree: 1, confidence: 1 }, opsec_noise: 0.2, staleness_seconds: 0 },
      {
        id: 'high',
        type: 'inferred_edge',
        description: 'Test high path',
        edge_source: 'cred-1',
        edge_target: 'svc-1',
        edge_type: 'VALID_ON',
        graph_metrics: { hops_to_objective: 1, fan_out_estimate: 2, node_degree: 1, confidence: 1.2 },
        opsec_noise: 0.2,
        staleness_seconds: 0,
      },
    ] as FrontierItem[], 2);

    expect(items).toHaveLength(2);
    expect(items[1]).toMatchObject({
      id: 'high',
      context: 'cred-1 -> svc-1',
      primaryNode: 'cred-1',
      scoreMultiplier: 1.2,
    });
    expect(items[1].reason).toContain('near objective');
    expect(items[1].nodeIds).toEqual(['cred-1', 'svc-1']);
  });

  it('summarizes current access using live connected sessions only', () => {
    const access: AccessSummary = {
      current_access_level: 'local_admin',
      compromised_hosts: ['host-1', 'host-2'],
      valid_credentials: ['cred-1'],
    };
    const sessions = [
      { id: 's1', kind: 'pty', state: 'connected' },
      { id: 's2', kind: 'pty', state: 'closed' },
    ] as SessionInfo[];

    const campaigns = [
      { id: 'c1', name: 'Active', strategy: 'custom', status: 'active', items: [], created_at: 'now', abort_conditions: [], progress: { total: 0, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 }, findings: [] },
      { id: 'c2', name: 'Paused', strategy: 'custom', status: 'paused', items: [], created_at: 'now', abort_conditions: [], progress: { total: 0, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 }, findings: [] },
    ] as Campaign[];

    expect(deriveAccessFacts(access, sessions, campaigns)).toEqual({
      level: 'local_admin',
      liveSessions: 1,
      hosts: 2,
      validCredentials: 1,
      activeCampaigns: 1,
      pausedCampaigns: 1,
    });
  });

  it('returns newest described activity first', () => {
    const entries = [
      { id: 'old', timestamp: '2026-05-15T10:00:00Z', event_type: 'action', description: 'old' },
      { id: 'blank', timestamp: '2026-05-15T10:01:00Z' },
      { id: 'new', timestamp: '2026-05-15T10:02:00Z', event_type: 'finding', description: 'new' },
    ] as ActivityEntry[];

    expect(deriveRecentChanges(entries).map(entry => entry.id)).toEqual(['new', 'old']);
  });

  it('prioritizes verification-needed trust signals without replacing attention items', () => {
    const items = deriveVerificationItems([
      { id: 'info', source: 'finding', severity: 'info', label: 'Estimated CVSS', finding_id: 'finding-1', timestamp: '2026-05-15T10:02:00Z' },
      { id: 'error', source: 'activity', severity: 'error', label: 'No parser data', node_ids: ['host-1'], timestamp: '2026-05-15T10:01:00Z' },
      { id: 'warn', source: 'activity', severity: 'warning', label: 'Dropped records', timestamp: '2026-05-15T10:03:00Z' },
    ]);

    expect(items.map(item => item.id)).toEqual(['error', 'warn', 'info']);
    expect(items[0].route).toBe('graph');
    expect(items[0].nodeId).toBe('host-1');
  });

  it('combines activity and trust signals into newest-first Changed items', () => {
    const changed = deriveChangedItems(
      [
        { id: 'old', timestamp: '2026-05-15T10:00:00Z', event_type: 'action', description: 'old' },
        { id: 'new', timestamp: '2026-05-15T10:03:00Z', event_type: 'finding', description: 'new finding', target_node_ids: ['host-1'] },
      ] as ActivityEntry[],
      [
        { id: 'warn', source: 'activity', severity: 'warning', label: 'Dropped records', timestamp: '2026-05-15T10:02:00Z' },
      ],
    );

    expect(changed.map(item => item.id)).toEqual(['new', 'warn', 'old']);
    expect(changed[0]).toMatchObject({ route: 'graph', nodeId: 'host-1' });
    expect(changed[1]).toMatchObject({ source: 'trust', tone: 'warning' });
  });

  it('summarizes CVSS trust signals instead of exposing full vectors in Changed items', () => {
    const changed = deriveChangedItems(
      [],
      [
        {
          id: 'cvss',
          source: 'finding',
          severity: 'warning',
          label: 'Estimated CVSS',
          detail: 'Derived from current graph evidence: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N',
          timestamp: '2026-05-15T10:02:00Z',
        },
      ],
    );

    expect(changed[0].label).toBe('Estimated CVSS requires verification');
    expect(changed[0].label).not.toContain('CVSS:3.1');
    expect(changed[0].detail).toContain('CVSS:3.1');
  });
});
