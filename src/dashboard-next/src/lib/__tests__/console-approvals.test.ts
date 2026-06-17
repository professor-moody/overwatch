import { describe, it, expect } from 'vitest';
import {
  buildConsoleApprovals,
  isDenyReasonValid,
  toConsoleApprovalItem,
} from '../console-approvals';
import type { PendingAction } from '../types';

const NOW = Date.UTC(2026, 5, 16, 0, 0, 0);

function action(overrides: Partial<PendingAction> = {}): PendingAction {
  return {
    action_id: 'act-1',
    technique: 'enumeration',
    description: 'enumerate the host',
    submitted_at: new Date(NOW - 10_000).toISOString(),
    ...overrides,
  };
}

// Risk score = noise*2 + defensive_signals + (warning_only ? 1 : 0).
// HIGH >= 6, MED >= 3, LOW otherwise.
function highRisk(id: string): PendingAction {
  return action({ action_id: id, opsec_context: { noise_level: 3.5 } });
}
function lowRisk(id: string): PendingAction {
  return action({ action_id: id, opsec_context: { noise_level: 0 } });
}

describe('buildConsoleApprovals', () => {
  it('returns an empty view when nothing is pending (so the strip can hide)', () => {
    const view = buildConsoleApprovals([], { now: NOW });
    expect(view.total).toBe(0);
    expect(view.items).toEqual([]);
    expect(view.overflow).toBe(0);
    expect(view.highCount).toBe(0);
  });

  it('sorts items by risk (highest first) — console and triage view agree', () => {
    const view = buildConsoleApprovals([lowRisk('low'), highRisk('high')], { now: NOW });
    expect(view.items.map((i) => i.action_id)).toEqual(['high', 'low']);
    expect(view.items[0].risk.label).toBe('HIGH');
    expect(view.items[1].risk.label).toBe('LOW');
  });

  it('caps to the limit and reports overflow + full total', () => {
    const pending = Array.from({ length: 6 }, (_, i) => lowRisk(`a${i}`));
    const view = buildConsoleApprovals(pending, { limit: 4, now: NOW });
    expect(view.items).toHaveLength(4);
    expect(view.total).toBe(6);
    expect(view.overflow).toBe(2);
  });

  it('counts HIGH / warning / timeout-soon across the full queue, not just the visible slice', () => {
    const soon = action({
      action_id: 'soon',
      timeout_at: new Date(NOW + 30_000).toISOString(),
    });
    const warning = action({ action_id: 'warn', validation_result: 'warning_only' });
    const view = buildConsoleApprovals(
      [highRisk('h1'), highRisk('h2'), warning, soon, lowRisk('l1')],
      { limit: 2, now: NOW },
    );
    expect(view.total).toBe(5);
    expect(view.items).toHaveLength(2);
    expect(view.highCount).toBe(2);
    expect(view.warningCount).toBe(1);
    expect(view.timeoutSoonCount).toBe(1);
  });
});

describe('toConsoleApprovalItem', () => {
  it('resolves target via node → ip → cidr → raw fallback chain', () => {
    expect(toConsoleApprovalItem(action({ target_node: 'host-1' }), NOW).target).toBe('host-1');
    expect(toConsoleApprovalItem(action({ target_ip: '10.0.0.5' }), NOW).target).toBe('10.0.0.5');
    expect(toConsoleApprovalItem(action({ target_cidr: '10.0.0.0/24' }), NOW).target).toBe('10.0.0.0/24');
    expect(toConsoleApprovalItem(action({ target: 'raw-target' }), NOW).target).toBe('raw-target');
    expect(toConsoleApprovalItem(action(), NOW).target).toBe('unknown target');
  });

  it('falls back to technique/action_id when description is empty', () => {
    const item = toConsoleApprovalItem(
      { action_id: 'x', description: '', submitted_at: new Date(NOW).toISOString() } as PendingAction,
      NOW,
    );
    expect(item.description).toBe('x');
    expect(item.technique).toBe('unknown');
  });

  it('flags timeout_soon within the 60s window', () => {
    const soon = toConsoleApprovalItem(action({ timeout_at: new Date(NOW + 30_000).toISOString() }), NOW);
    const later = toConsoleApprovalItem(action({ timeout_at: new Date(NOW + 600_000).toISOString() }), NOW);
    expect(soon.lifecycle).toBe('timeout_soon');
    expect(later.lifecycle).not.toBe('timeout_soon');
  });
});

describe('isDenyReasonValid', () => {
  it('requires a non-empty reason (audit semantics)', () => {
    expect(isDenyReasonValid('too noisy')).toBe(true);
    expect(isDenyReasonValid('')).toBe(false);
    expect(isDenyReasonValid('   ')).toBe(false);
    expect(isDenyReasonValid(null)).toBe(false);
    expect(isDenyReasonValid(undefined)).toBe(false);
  });
});
