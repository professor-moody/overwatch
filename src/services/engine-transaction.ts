// ============================================================
// Overwatch — Versioned engine transactions
//
// A transaction is the logical durability unit used by journal v2. The
// physical WAL may contain several bounded frames for one transaction, but
// recovery exposes and applies it only after a checksum-valid tx_commit.
// ============================================================

import type { GraphUpdateDetail } from './engine-context.js';
import type { MutationType } from './mutation-journal.js';

export interface EngineOperation {
  type: MutationType;
  payload: Record<string, unknown>;
}

export interface EngineTransactionDraft {
  operations: EngineOperation[];
  source_action_id?: string;
  update_detail?: GraphUpdateDetail;
}

export interface EngineTransaction extends EngineTransactionDraft {
  version: 2;
  tx_id: string;
  /** Logical transaction sequence used by snapshots and replay checkpoints. */
  seq: number;
  /** Inclusive physical WAL frame range occupied by this transaction. */
  begin_frame_seq: number;
  commit_frame_seq: number;
  ts: string;
}

export type EngineTransactionApplyResult =
  | { status: 'applied' }
  | { status: 'skipped'; reason: string };

export interface EngineTransactionApplier {
  applyTransaction(transaction: EngineTransaction): EngineTransactionApplyResult;
}
