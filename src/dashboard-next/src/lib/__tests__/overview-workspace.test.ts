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
  it('prioritizes pending approvals, readiness, and top frontier items', () => {
    const pending = [{ action_id: 'a1', technique: 'scan', target: 'host-1', noise_level: 0, description: 'scan', submitted_at: 'now' }] as PendingAction[];
    const frontier = [
      { id: 'f-low', type: 'incomplete_node', priority: 1, description: 'low' },
      { id: 'f-high', type: 'incomplete_node', priority: 9, description: 'high', node_id: 'host-1' },
    ] as FrontierItem[];

    const items = deriveAttentionItems({
      pendingActions: pending,
      readinessIssues: ['missing tool'],
      frontier,
    });

    expect(items.map(item => item.id)).toEqual(['pending-actions', 'readiness', 'f-high', 'f-low']);
    expect(items[0].route).toBe('actions');
    expect(items[2].nodeId).toBe('host-1');
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
      { id: 'low', type: 'incomplete_node', priority: 1, description: 'low' },
      {
        id: 'high',
        frontier_item_id: 'frontier-high',
        type: 'inferred_edge',
        priority: 9,
        description: 'Test high path',
        edge_source: 'cred-1',
        edge_target: 'svc-1',
        graph_metrics: { hops_to_objective: 1, fan_out_estimate: 2, confidence: 1.2 },
      },
    ] as FrontierItem[], 1);

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: 'frontier-high',
      context: 'cred-1 -> svc-1',
      primaryNode: 'cred-1',
      priority: 9,
    });
    expect(items[0].reason).toContain('near objective');
    expect(items[0].nodeIds).toEqual(['cred-1', 'svc-1']);
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
      { id: 'c1', name: 'Active', strategy: 'custom', status: 'active', items: [], created_at: 'now' },
      { id: 'c2', name: 'Paused', strategy: 'custom', status: 'paused', items: [], created_at: 'now' },
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
});
