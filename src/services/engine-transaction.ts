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
  | { status: 'applied'; update_detail?: GraphUpdateDetail; bounded?: boolean }
  | { status: 'skipped'; reason: string };

export interface EngineTransactionApplier {
  applyTransaction(transaction: EngineTransaction): EngineTransactionApplyResult;
}

/** Observes speculative operation drafts before and after their live effect.
 * The observer is process-local and never serialized into the transaction. */
export interface EngineOperationDraftObserver {
  beforeOperation(draft: EngineTransactionDraft): unknown;
  afterOperation(draft: EngineTransactionDraft, token: unknown): void;
  authorizeMutation(
    target: 'graph' | 'cold_store',
    method: string,
    args: readonly unknown[],
    token: unknown,
  ): boolean;
}
