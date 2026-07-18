import type {
  PersistedCommandOutcomeV1,
  PersistedCommandPlanV1,
} from './persisted-state.js';

export const COMMAND_COORDINATION_CHANGE_PAYLOAD_VERSION = 1 as const;
export const MAX_COMMAND_COORDINATION_VALUE_BYTES = 1024 * 1024;
export const MAX_COMMAND_COORDINATION_RECORDS = 4_096;

export type CommandPlanValue = Omit<PersistedCommandPlanV1, 'plan_id'>;
export type CommandOutcomeValue = Omit<PersistedCommandOutcomeV1, 'plan_id'>;

interface CommandCoordinationChangeBaseV1 {
  payload_version: typeof COMMAND_COORDINATION_CHANGE_PAYLOAD_VERSION;
  operation_id: string;
  occurred_at: string;
  key: string;
}

export type CommandCoordinationChangePayloadV1 =
  | (CommandCoordinationChangeBaseV1 & {
      record_kind: 'plan';
      before: CommandPlanValue | null;
      after: CommandPlanValue | null;
    })
  | (CommandCoordinationChangeBaseV1 & {
      record_kind: 'outcome';
      before: CommandOutcomeValue | null;
      after: CommandOutcomeValue | null;
    });
