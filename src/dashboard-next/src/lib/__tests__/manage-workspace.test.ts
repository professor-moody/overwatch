import { describe, expect, it } from 'vitest';
import { reconcileRuntimeEngagement } from '../manage-workspace';
import type { EngagementListItem } from '../types';

function record(id: string, active = false): EngagementListItem {
  return { id, name: id, profile: 'network', is_active: active, objectives_count: 0 } as EngagementListItem;
}

describe('reconcileRuntimeEngagement', () => {
  it('marks the active runtime as runtime-only when the library is unavailable', () => {
    const result = reconcileRuntimeEngagement({ id: 'eng-1' }, [], false);
    expect(result.runtimeOnly).toBe(true);
    expect(result.matchingRecord).toBeNull();
  });

  it('reconciles and removes the matching library record from the secondary list', () => {
    const result = reconcileRuntimeEngagement({ id: 'eng-1' }, [record('eng-1'), record('eng-2')], true);
    expect(result.runtimeOnly).toBe(false);
    expect(result.matchingRecord?.id).toBe('eng-1');
    expect(result.libraryRecords.map(item => item.id)).toEqual(['eng-2']);
  });

  it('falls back to the library active marker when runtime ids differ during compatibility reads', () => {
    const result = reconcileRuntimeEngagement({ id: 'runtime-id' }, [record('library-id', true)], true);
    expect(result.matchingRecord?.id).toBe('library-id');
    expect(result.libraryRecords).toEqual([]);
  });
});
