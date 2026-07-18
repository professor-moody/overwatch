// ============================================================
// Overwatch — bounded application-command WAL delta
// ============================================================

import type { PersistedApplicationCommandV1 } from './persisted-state.js';

export const APPLICATION_COMMAND_CHANGE_PAYLOAD_VERSION = 1 as const;

/**
 * Compare-and-apply command mutation. `before` makes a divergent replay stop
 * instead of overwriting later truth; `after` makes repeated recovery
 * idempotent. Snapshots retain the complete command map for compatibility.
 */
export interface ApplicationCommandChangePayloadV1 {
  payload_version: typeof APPLICATION_COMMAND_CHANGE_PAYLOAD_VERSION;
  operation_id: string;
  occurred_at: string;
  idempotency_key: string;
  before: PersistedApplicationCommandV1 | null;
  after: PersistedApplicationCommandV1 | null;
}
