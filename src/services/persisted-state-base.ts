import {
  engagementConfigSchema,
  type EngagementConfig,
} from '../types.js';
import {
  CURRENT_STATE_VERSION,
  detectJournalVersion,
  detectStateVersion,
  validatePersistedStateV1,
  type SupportedJournalVersion,
  type SupportedStateVersion,
} from './persisted-state.js';
import type { OverwatchGraph } from './engine-context.js';
import { createOverwatchGraph } from './graphology-types.js';

export type ValidatedPersistedStateBase = {
  record: Record<string, unknown>;
  config: EngagementConfig;
  checkpoint: number;
  stateVersion: SupportedStateVersion;
  journalVersion: SupportedJournalVersion;
  rollbackIntentPresent: boolean;
};

/**
 * Validate the side-effect-free structural portion of a persisted recovery
 * base. StatePersistence adds compaction-authority and rollback checks around
 * this shared core, while setup/doctor use it only to avoid treating an
 * arbitrary JSON object with a readable `config` property as durable state.
 */
export function validatePersistedStateBaseContainer(
  data: unknown,
  createGraph: () => OverwatchGraph = createOverwatchGraph,
): ValidatedPersistedStateBase {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('persisted state is not an object');
  }
  const record = data as Record<string, unknown>;
  const stateVersion = detectStateVersion(record);
  const journalVersion = detectJournalVersion(record, stateVersion);
  if (stateVersion === CURRENT_STATE_VERSION) validatePersistedStateV1(record);

  const configValidation = engagementConfigSchema.safeParse(record.config);
  if (!configValidation.success) {
    const issues = configValidation.error.issues
      .map(issue => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
      .join('; ');
    throw new Error(`persisted state config is invalid: ${issues}`);
  }
  if (!record.graph || typeof record.graph !== 'object' || Array.isArray(record.graph)) {
    throw new Error('persisted state is missing graph');
  }

  validatePersistedAuxiliaryShapes(record);
  if (
    record.journalSnapshotSeq !== undefined
    && (!Number.isSafeInteger(record.journalSnapshotSeq) || (record.journalSnapshotSeq as number) < 0)
  ) {
    throw new Error('persisted journalSnapshotSeq must be a non-negative safe integer');
  }
  const checkpoint = typeof record.journalSnapshotSeq === 'number'
    ? record.journalSnapshotSeq
    : 0;
  const scratch = createGraph();
  scratch.import(record.graph as Parameters<OverwatchGraph['import']>[0]);
  return {
    record,
    config: configValidation.data,
    checkpoint,
    stateVersion,
    journalVersion,
    rollbackIntentPresent: Object.prototype.hasOwnProperty.call(record, 'rollbackIntent'),
  };
}

/** Legacy snapshots may omit auxiliary fields, but a present field with the
 * wrong container shape is not a valid full-state recovery base. */
export function validatePersistedAuxiliaryShapes(record: Record<string, unknown>): void {
  const arrayFields = [
    'activityLog',
    'agents',
    'campaigns',
    'agentDirectives',
    'approvalRequests',
    'inferenceRules',
    'trackedProcesses',
    'runtimeRuns',
    'playbookRuns',
    'sessionDescriptors',
    'commandPlans',
    'commandOutcomes',
    'applicationCommands',
    'coldStore',
    'chainCheckpoints',
    'recentFindingHashes',
  ] as const;
  for (const field of arrayFields) {
    if (Object.prototype.hasOwnProperty.call(record, field) && !Array.isArray(record[field])) {
      throw new Error(`persisted ${field} must be an array when present`);
    }
  }

  const objectFields = [
    'opsecTracker',
    'frontierLinkage',
    'frontierLeases',
    'frontierWeights',
    'artifactReferences',
    'proposedPlans',
    'agentQueries',
  ] as const;
  for (const field of objectFields) {
    const value = record[field];
    if (
      Object.prototype.hasOwnProperty.call(record, field)
      && (value === null || typeof value !== 'object' || Array.isArray(value))
    ) {
      throw new Error(`persisted ${field} must be an object when present`);
    }
  }

  if (Array.isArray(record.coldStore)) {
    for (const [index, value] of record.coldStore.entries()) {
      if (
        !value
        || typeof value !== 'object'
        || Array.isArray(value)
        || typeof (value as Record<string, unknown>).id !== 'string'
        || (value as Record<string, unknown>).id === ''
      ) {
        throw new Error(`persisted coldStore[${index}] must be an object with a nonempty id`);
      }
    }
  }
  if (
    record.deterministicSeq !== undefined
    && (!Number.isSafeInteger(record.deterministicSeq) || (record.deterministicSeq as number) < 0)
  ) {
    throw new Error('persisted deterministicSeq must be a non-negative safe integer');
  }
  for (const field of ['chainEventsSinceCheckpoint', 'dedupCount'] as const) {
    if (
      record[field] !== undefined
      && (!Number.isSafeInteger(record[field]) || (record[field] as number) < 0)
    ) {
      throw new Error(`persisted ${field} must be a non-negative safe integer`);
    }
  }
  if (record.lastKnownPhaseId !== undefined && typeof record.lastKnownPhaseId !== 'string') {
    throw new Error('persisted lastKnownPhaseId must be a string when present');
  }
}
