import { describe, it, expect } from 'vitest';
import { objectiveState } from '../OverviewPanel';

// The four legible objective states derived from the temporal model (achieved / currently_satisfied
// / lost_at), so the Overview no longer shows a plain green ✓ for a lapsed objective nor conflates a
// revoked (disproven) objective with one that was never reached.
describe('objectiveState', () => {
  it('satisfied: achieved and currently satisfied (or freshly achieved with no live value)', () => {
    expect(objectiveState({ achieved: true, currently_satisfied: true })).toBe('satisfied');
    expect(objectiveState({ achieved: true })).toBe('satisfied'); // freshly achieved, live value not yet distinct
  });

  it('lapsed: achieved milestone whose live support has decayed', () => {
    expect(objectiveState({ achieved: true, currently_satisfied: false, lost_at: '2026-08-17T00:00:00Z' })).toBe('lapsed');
  });

  it('revoked: not achieved, but was once satisfied then disproven (lost_at set)', () => {
    expect(objectiveState({ achieved: false, currently_satisfied: false, lost_at: '2026-08-17T00:00:00Z' })).toBe('revoked');
  });

  it('unreached: never achieved and never satisfied', () => {
    expect(objectiveState({ achieved: false })).toBe('unreached');
    expect(objectiveState({})).toBe('unreached');
  });
});
