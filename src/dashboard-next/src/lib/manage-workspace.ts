import type { EngagementListItem } from './types';

export interface RuntimeEngagementIdentity {
  id: string;
}

export interface EngagementReconciliation {
  matchingRecord: EngagementListItem | null;
  libraryRecords: EngagementListItem[];
  runtimeOnly: boolean;
}

/** Keep the live runtime first without rendering its library record twice. */
export function reconcileRuntimeEngagement(
  runtime: RuntimeEngagementIdentity | null | undefined,
  library: EngagementListItem[],
  libraryAvailable: boolean,
): EngagementReconciliation {
  const matchingRecord = runtime
    ? library.find(record => record.id === runtime.id || record.is_active) ?? null
    : library.find(record => record.is_active) ?? null;
  return {
    matchingRecord,
    libraryRecords: matchingRecord ? library.filter(record => record.id !== matchingRecord.id) : library,
    runtimeOnly: Boolean(runtime) && (!libraryAvailable || !matchingRecord),
  };
}
