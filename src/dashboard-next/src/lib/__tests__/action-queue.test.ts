import { describe, expect, it } from 'vitest';
import {
  actionNodeId,
  computeActionRisk,
  groupActionsByTechnique,
  sortActionsForQueue,
  sortTechniqueGroups,
} from '../action-queue';
import type { PendingAction } from '../types';

function action(partial: Partial<PendingAction>): PendingAction {
  return {
    action_id: partial.action_id || 'act-1',
    technique: partial.technique || 'enumeration',
    target: partial.target || 'host-1',
    noise_level: partial.noise_level ?? 0,
    description: partial.description || 'test action',
    submitted_at: partial.submitted_at || '2026-05-15T10:00:00Z',
    ...partial,
  };
}

describe('action queue helpers', () => {
  it('computes risk from noise, warnings, and defensive signals', () => {
    expect(computeActionRisk(action({ noise_level: 0.2 })).label).toBe('LOW');
    expect(computeActionRisk(action({ noise_level: 1.5, validation_result: 'warning_only' })).label).toBe('MED');
    expect(computeActionRisk(action({
      noise_level: 2,
      opsec_context: { defensive_signals: ['edr', 'rate-limit'] },
    })).label).toBe('HIGH');
  });

  it('sorts stably by risk and then submitted time', () => {
    const first = action({ action_id: 'act-a', noise_level: 0.1, submitted_at: '2026-05-15T10:00:00Z' });
    const newest = action({ action_id: 'act-b', noise_level: 0.1, submitted_at: '2026-05-15T11:00:00Z' });
    const risky = action({ action_id: 'act-c', noise_level: 2, submitted_at: '2026-05-15T09:00:00Z' });

    expect(sortActionsForQueue([first, newest, risky], 'risk').map(a => a.action_id)).toEqual(['act-c', 'act-b', 'act-a']);
  });

  it('groups and orders techniques by max risk and count', () => {
    const grouped = groupActionsByTechnique([
      action({ action_id: 'a1', technique: 'scan', noise_level: 0.1 }),
      action({ action_id: 'a2', technique: 'scan', noise_level: 0.1 }),
      action({ action_id: 'b1', technique: 'exploit', noise_level: 2 }),
    ]);

    expect(grouped.scan).toHaveLength(2);
    expect(sortTechniqueGroups(grouped)[0][0]).toBe('exploit');
  });

  it('prefers explicit target node for graph links', () => {
    expect(actionNodeId(action({ target: 'raw-target', target_node: 'node-1' }))).toBe('node-1');
  });
});
