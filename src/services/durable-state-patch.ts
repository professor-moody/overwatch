// ============================================================
// Overwatch — Durable coordination-state patch
//
// Graph/cold/config composites retain their purpose-built deterministic
// operations. Snapshot-only coordination domains use this typed replacement
// patch so their immutable after-state can be committed before it becomes live.
// ============================================================

export const DURABLE_STATE_SLICE_KEYS = [
  'activity',
  'agents',
  'campaigns',
  'directives',
  'approvals',
  'inference_rules',
  'tracked_processes',
  'runtime_runs',
  'playbook_runs',
  'session_descriptors',
  'plans_questions',
  'command_state',
  'opsec',
  'frontier',
  // Bounded command transactions persist score weights without cloning the
  // unbounded frontier-linkage registry. The legacy combined `frontier` slice
  // remains readable for older transactions and bulk restore paths.
  'frontier_weights',
  'finding_counters',
  'phase',
  'config',
  'artifacts',
] as const;

export type DurableStateSliceKey = typeof DURABLE_STATE_SLICE_KEYS[number];

export type DurableStateSlices = Partial<Record<DurableStateSliceKey, unknown>>;

export interface DurableStatePatchV1 {
  payload_version: 1;
  operation_id: string;
  occurred_at: string;
  reason: string;
  slices: DurableStateSlices;
}
