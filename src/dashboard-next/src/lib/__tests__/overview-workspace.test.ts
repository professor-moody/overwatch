import { describe, expect, it } from 'vitest';
import { deriveAccessFacts, deriveAttentionItems, deriveRecentChanges, deriveVerificationItems } from '../overview-workspace';
import type { AccessSummary, ActivityEntry, FrontierItem, PendingAction, SessionInfo } from '../types';

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

    expect(deriveAccessFacts(access, sessions)).toEqual({
      level: 'local_admin',
      liveSessions: 1,
      hosts: 2,
      validCredentials: 1,
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
});
