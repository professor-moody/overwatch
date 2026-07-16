// ============================================================
// Overwatch — Versioned persisted-state envelope
// ============================================================

import type {
  AgentDirective,
  AgentTask,
  Campaign,
  EngagementConfig,
  InferenceRule,
  SessionCapabilities,
  SessionDefaultValidation,
  SessionKind,
  SessionState,
} from '../types.js';
import { engagementConfigSchema } from '../types.js';
import type { ActivityLogEntry } from './engine-context.js';
import type { ChainCheckpoint } from './activity-chain.js';
import type { ColdNodeRecord } from './cold-store.js';
import type { DurableApprovalRecord } from './pending-action-queue.js';
import type { TrackedProcess } from './process-tracker.js';
import type { SerializedProposedPlanStore } from './proposed-plan-store.js';
import type { SerializedAgentQueryStore } from './agent-query-store.js';
import type { CoordinationRecoveryWarning } from './agent-identity.js';
import type { OperatorOp } from './command-interpreter.js';

export const CURRENT_STATE_VERSION = 1 as const;
export const LEGACY_STATE_VERSION = 0 as const;
export const LEGACY_JOURNAL_VERSION = 1 as const;
export const CURRENT_JOURNAL_VERSION = 2 as const;

export type SupportedStateVersion =
  | typeof LEGACY_STATE_VERSION
  | typeof CURRENT_STATE_VERSION;

export type SupportedJournalVersion =
  | typeof LEGACY_JOURNAL_VERSION
  | typeof CURRENT_JOURNAL_VERSION;

export class PersistedStateVersionError extends Error {
  constructor(
    message: string,
    readonly observedVersion?: unknown,
    readonly kind: 'invalid' | 'unsupported' = 'unsupported',
  ) {
    super(message);
    this.name = 'PersistedStateVersionError';
  }
}

export class PersistedJournalVersionError extends Error {
  constructor(
    message: string,
    readonly observedVersion?: unknown,
    readonly kind: 'invalid' | 'unsupported' = 'unsupported',
  ) {
    super(message);
    this.name = 'PersistedJournalVersionError';
  }
}

function recordOf(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PersistedStateVersionError('persisted state is not an object', undefined, 'invalid');
  }
  return value as Record<string, unknown>;
}

/** A missing discriminator is the only legacy-v0 representation. */
export function detectStateVersion(value: unknown): SupportedStateVersion {
  const record = recordOf(value);
  if (!Object.prototype.hasOwnProperty.call(record, 'state_version')) {
    return LEGACY_STATE_VERSION;
  }
  const observed = record.state_version;
  if (!Number.isSafeInteger(observed) || (observed as number) <= 0) {
    throw new PersistedStateVersionError(
      'persisted state_version must be a positive safe integer when present',
      observed,
      'invalid',
    );
  }
  if (observed !== CURRENT_STATE_VERSION) {
    throw new PersistedStateVersionError(
      `persisted state version ${String(observed)} is unsupported by this binary (supports ${CURRENT_STATE_VERSION})`,
      observed,
      'unsupported',
    );
  }
  return CURRENT_STATE_VERSION;
}

/**
 * Primitive JSONL is journal format v1. Legacy state did not stamp it; V1
 * state must do so explicitly so PR6 can introduce transaction journal v2
 * without an older binary guessing.
 */
export function detectJournalVersion(
  value: unknown,
  stateVersion: SupportedStateVersion = detectStateVersion(value),
): SupportedJournalVersion {
  const record = recordOf(value);
  if (stateVersion === LEGACY_STATE_VERSION) {
    if (!Object.prototype.hasOwnProperty.call(record, 'journal_version')) {
      return LEGACY_JOURNAL_VERSION;
    }
  }
  const observed = record.journal_version;
  if (!Number.isSafeInteger(observed) || (observed as number) <= 0) {
    throw new PersistedJournalVersionError(
      'persisted journal_version must be a positive safe integer',
      observed,
      'invalid',
    );
  }
  if (observed !== LEGACY_JOURNAL_VERSION && observed !== CURRENT_JOURNAL_VERSION) {
    throw new PersistedJournalVersionError(
      `persisted journal version ${String(observed)} is unsupported by this binary (supports ${LEGACY_JOURNAL_VERSION} and ${CURRENT_JOURNAL_VERSION})`,
      observed,
      'unsupported',
    );
  }
  return observed as SupportedJournalVersion;
}

export interface PersistedSessionResumeIntentV1 {
  policy: 'none' | 'manual';
  requested: boolean;
  prior_state?: Extract<SessionState, 'pending' | 'connected'>;
  recorded_at: string;
}

/** Runtime handles, buffers, secrets, and PIDs are deliberately absent. */
export interface PersistedSessionDescriptorV1 {
  session_id: string;
  kind: SessionKind;
  transport: string;
  lifecycle: SessionState;
  mode?: 'connect' | 'listen';
  bind_host?: string;
  advertise_host?: string;
  accept_mode?: 'single' | 'rearm';
  reachability_warnings?: string[];
  title: string;
  host?: string;
  user?: string;
  port?: number;
  owner_task_id?: string;
  recovery_warning?: string;
  target_node?: string;
  principal_node?: string;
  credential_node?: string;
  action_id?: string;
  frontier_item_id?: string;
  started_at: string;
  last_activity_at: string;
  closed_at?: string;
  capabilities: SessionCapabilities;
  notes?: string;
  default_validation?: SessionDefaultValidation;
  resume_intent: PersistedSessionResumeIntentV1;
}

export interface PersistedRuntimeRunV1 {
  run_id: string;
  kind: 'headless_agent' | 'tracked_process';
  task_id?: string;
  action_id?: string;
  agent_id?: string;
  pid?: number;
  process_group_id?: number;
  process_start_identity?: string;
  daemon_owner?: string;
  command_fingerprint?: string;
  started_at: string;
  last_output_at?: string;
  completed_at?: string;
  lifecycle: 'reserved' | 'running' | 'completed' | 'failed' | 'unknown' | 'interrupted';
  evidence_state?: 'none' | 'pending' | 'captured' | 'failed';
  recovery_warning?: string;
}

/** Seeded in V1; PR12 supplies the first producer/consumer. */
export interface PersistedPlaybookRunV1 {
  run_id: string;
  [key: string]: unknown;
}

export interface PersistedArtifactReferenceV1 {
  kind: 'evidence_manifest' | 'report_manifest' | 'tape' | 'bundle' | 'cookie_jar';
  path: string;
  sha256?: string;
}

export interface PersistedArtifactReferencesV1 {
  evidence_manifest?: PersistedArtifactReferenceV1;
  report_manifest?: PersistedArtifactReferenceV1;
  tapes: PersistedArtifactReferenceV1[];
  bundles: PersistedArtifactReferenceV1[];
  cookie_jars: PersistedArtifactReferenceV1[];
}

export interface PersistedCommandPlanV1 {
  plan_id: string;
  ops: OperatorOp[];
  command: string;
  created_at: number;
  expires_at: number;
}

export interface PersistedCommandOutcomeV1 {
  plan_id: string;
  at: number;
  expires_at: number;
  results: unknown[];
}

/**
 * The public V1 shape intentionally retains the legacy flat field names. That
 * keeps rollback/replay compatibility simple while making every category and
 * version decision explicit.
 */
export interface PersistedStateV1 {
  state_version: typeof CURRENT_STATE_VERSION;
  journal_version: SupportedJournalVersion;
  config: EngagementConfig;
  graph: unknown;
  activityLog: ActivityLogEntry[];
  agents: Array<[string, AgentTask]>;
  coordinationRecoveryWarnings?: CoordinationRecoveryWarning[];
  campaigns: Array<[string, Campaign]>;
  agentDirectives: Array<[string, AgentDirective[]]>;
  approvalRequests: Array<[string, DurableApprovalRecord]>;
  inferenceRules: InferenceRule[];
  trackedProcesses: TrackedProcess[];
  runtimeRuns: PersistedRuntimeRunV1[];
  playbookRuns: Array<[string, PersistedPlaybookRunV1]>;
  sessionDescriptors: PersistedSessionDescriptorV1[];
  proposedPlans: SerializedProposedPlanStore;
  agentQueries: SerializedAgentQueryStore;
  commandPlans: Array<[string, Omit<PersistedCommandPlanV1, 'plan_id'>]>;
  commandOutcomes: Array<[string, Omit<PersistedCommandOutcomeV1, 'plan_id'>]>;
  coldStore: ColdNodeRecord[];
  opsecTracker: unknown;
  frontierLinkage: unknown;
  frontierLeases: unknown;
  frontierWeights: {
    fan_out: Record<string, number>;
    noise: Record<string, number>;
  };
  artifactReferences: PersistedArtifactReferencesV1;
  chainCheckpoints: ChainCheckpoint[];
  chainEventsSinceCheckpoint: number;
  deterministicSeq: number;
  recentFindingHashes: Array<[string, number]>;
  dedupCount: number;
  lastKnownPhaseId?: string;
  journalSnapshotSeq: number;
  journalCheckpointSemantics: string;
  rollbackIntent?: unknown;
  walCompactionAuthority?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireRecord(
  value: unknown,
  path: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new PersistedStateVersionError(`${path} must be an object`, CURRENT_STATE_VERSION, 'invalid');
  }
  return value;
}

function requireArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new PersistedStateVersionError(`${path} must be an array`, CURRENT_STATE_VERSION, 'invalid');
  }
  return value;
}

function requireString(value: unknown, path: string, allowEmpty = false): string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) {
    throw new PersistedStateVersionError(`${path} must be ${allowEmpty ? 'a string' : 'a non-empty string'}`, CURRENT_STATE_VERSION, 'invalid');
  }
  return value;
}

function requireSafeInteger(value: unknown, path: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new PersistedStateVersionError(
      `${path} must be a safe integer greater than or equal to ${minimum}`,
      CURRENT_STATE_VERSION,
      'invalid',
    );
  }
  return value as number;
}

function requireFiniteNumber(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new PersistedStateVersionError(`${path} must be a finite number`, CURRENT_STATE_VERSION, 'invalid');
  }
  return value;
}

function requireIsoDate(value: unknown, path: string): string {
  const stringValue = requireString(value, path);
  if (!Number.isFinite(Date.parse(stringValue))) {
    throw new PersistedStateVersionError(`${path} must be an ISO-compatible timestamp`, CURRENT_STATE_VERSION, 'invalid');
  }
  return stringValue;
}

function validateStringNumberRecord(value: unknown, path: string): void {
  const record = requireRecord(value, path);
  for (const [key, candidate] of Object.entries(record)) {
    requireString(key, `${path} key`);
    requireFiniteNumber(candidate, `${path}.${key}`);
  }
}

function validateActivityLog(value: unknown, path: string): void {
  const ids = new Set<string>();
  for (const [index, candidate] of requireArray(value, path).entries()) {
    const entryPath = `${path}[${index}]`;
    const entry = requireRecord(candidate, entryPath);
    const eventId = requireString(entry.event_id, `${entryPath}.event_id`);
    if (ids.has(eventId)) {
      throw new PersistedStateVersionError(`${path} contains duplicate event_id ${eventId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    ids.add(eventId);
    requireIsoDate(entry.timestamp, `${entryPath}.timestamp`);
    requireString(entry.description, `${entryPath}.description`, true);
    for (const field of [
      'agent_id',
      'operator_model',
      'operator_name',
      'operator_session_id',
      'action_id',
      'event_type',
      'tool_name',
      'technique',
      'command_repr',
      'frontier_item_id',
      'linked_agent_task_id',
    ] as const) {
      if (entry[field] !== undefined) requireString(entry[field], `${entryPath}.${field}`, true);
    }
    for (const field of ['target_node_ids', 'target_ips', 'target_cidrs', 'linked_finding_ids'] as const) {
      if (entry[field] !== undefined) {
        requireArray(entry[field], `${entryPath}.${field}`)
          .forEach((item, itemIndex) => requireString(item, `${entryPath}.${field}[${itemIndex}]`));
      }
    }
    for (const field of ['noise_estimate', 'noise_actual'] as const) {
      if (entry[field] !== undefined) requireFiniteNumber(entry[field], `${entryPath}.${field}`);
    }
    if (entry.target_edge !== undefined) {
      const edge = requireRecord(entry.target_edge, `${entryPath}.target_edge`);
      requireString(edge.source, `${entryPath}.target_edge.source`);
      requireString(edge.target, `${entryPath}.target_edge.target`);
      if (edge.type !== undefined) requireString(edge.type, `${entryPath}.target_edge.type`);
    }
    if (entry.details !== undefined) requireRecord(entry.details, `${entryPath}.details`);
    for (const field of ['prev_hash', 'event_hash'] as const) {
      if (entry[field] !== undefined
        && !/^[a-f0-9]{64}$/.test(requireString(entry[field], `${entryPath}.${field}`))) {
        throw new PersistedStateVersionError(`${entryPath}.${field} must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
      }
    }
    if (entry.chain_excluded !== undefined && typeof entry.chain_excluded !== 'boolean') {
      throw new PersistedStateVersionError(`${entryPath}.chain_excluded must be boolean`, CURRENT_STATE_VERSION, 'invalid');
    }
  }
}

function validateColdStore(value: unknown, path: string): void {
  const ids = new Set<string>();
  for (const [index, candidate] of requireArray(value, path).entries()) {
    const recordPath = `${path}[${index}]`;
    const record = requireRecord(candidate, recordPath);
    const id = requireString(record.id, `${recordPath}.id`);
    if (ids.has(id)) {
      throw new PersistedStateVersionError(`${path} contains duplicate cold node id ${id}`, CURRENT_STATE_VERSION, 'invalid');
    }
    ids.add(id);
    requireString(record.type, `${recordPath}.type`);
    requireString(record.label, `${recordPath}.label`, true);
    requireIsoDate(record.discovered_at, `${recordPath}.discovered_at`);
    requireIsoDate(record.last_seen_at, `${recordPath}.last_seen_at`);
    for (const field of [
      'ip',
      'hostname',
      'subnet_cidr',
      'provenance',
      'finding_id',
      'action_id',
    ] as const) {
      if (record[field] !== undefined) requireString(record[field], `${recordPath}.${field}`, true);
    }
    if (record.alive !== undefined && typeof record.alive !== 'boolean') {
      throw new PersistedStateVersionError(`${recordPath}.alive must be boolean`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (record.confidence !== undefined) requireFiniteNumber(record.confidence, `${recordPath}.confidence`);
  }
}

function validateOpsecTracker(value: unknown, path: string): void {
  const tracker = requireRecord(value, path);
  validateStringNumberRecord(tracker.noise_by_host, `${path}.noise_by_host`);
  validateStringNumberRecord(tracker.noise_by_domain, `${path}.noise_by_domain`);
  if (tracker.noise_by_campaign !== undefined) {
    validateStringNumberRecord(tracker.noise_by_campaign, `${path}.noise_by_campaign`);
  }
  requireFiniteNumber(tracker.global_noise, `${path}.global_noise`);
  requireArray(tracker.defensive_signals, `${path}.defensive_signals`).forEach((candidate, index) => {
    const signalPath = `${path}.defensive_signals[${index}]`;
    const signal = requireRecord(candidate, signalPath);
    if (!['lockout', 'connection_reset', 'honeypot', 'rate_limit', 'block'].includes(
      requireString(signal.type, `${signalPath}.type`),
    )) {
      throw new PersistedStateVersionError(`${signalPath}.type is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireIsoDate(signal.detected_at, `${signalPath}.detected_at`);
    requireString(signal.description, `${signalPath}.description`, true);
    if (signal.host_id !== undefined) requireString(signal.host_id, `${signalPath}.host_id`);
    if (signal.domain !== undefined) requireString(signal.domain, `${signalPath}.domain`);
  });
}

function validateFrontierLinkage(value: unknown, path: string): void {
  const tracker = requireRecord(value, path);
  requireSafeInteger(tracker.next_task_call_index, `${path}.next_task_call_index`);
  const ids = new Set<string>();
  requireArray(tracker.records, `${path}.records`).forEach((candidate, index) => {
    const recordPath = `${path}.records[${index}]`;
    const record = requireRecord(candidate, recordPath);
    const id = requireString(record.frontier_item_id, `${recordPath}.frontier_item_id`);
    if (ids.has(id)) {
      throw new PersistedStateVersionError(`${path}.records contains duplicate frontier_item_id ${id}`, CURRENT_STATE_VERSION, 'invalid');
    }
    ids.add(id);
    requireIsoDate(record.emitted_at, `${recordPath}.emitted_at`);
    requireSafeInteger(record.emitted_call_index, `${recordPath}.emitted_call_index`);
    requireSafeInteger(record.last_seen_call_index, `${recordPath}.last_seen_call_index`);
    if (!['open', 'validated', 'pursued', 'rejected_explicit', 'dropped'].includes(
      requireString(record.linkage_status, `${recordPath}.linkage_status`),
    )) {
      throw new PersistedStateVersionError(`${recordPath}.linkage_status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (record.last_event_id !== undefined) requireString(record.last_event_id, `${recordPath}.last_event_id`);
    if (record.status_set_at !== undefined) requireIsoDate(record.status_set_at, `${recordPath}.status_set_at`);
  });
}

function validateFrontierLeases(value: unknown, path: string): void {
  const leases = requireRecord(value, path);
  const byItem = requireRecord(leases.byItem, `${path}.byItem`);
  for (const [itemId, candidate] of Object.entries(byItem)) {
    const leasePath = `${path}.byItem.${itemId}`;
    const lease = requireRecord(candidate, leasePath);
    if (requireString(lease.frontier_item_id, `${leasePath}.frontier_item_id`) !== itemId) {
      throw new PersistedStateVersionError(`${leasePath}.frontier_item_id must match map key`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireString(lease.agent_id, `${leasePath}.agent_id`);
    requireString(lease.task_id, `${leasePath}.task_id`);
    requireIsoDate(lease.leased_at, `${leasePath}.leased_at`);
    requireIsoDate(lease.expires_at, `${leasePath}.expires_at`);
    requireSafeInteger(lease.ttl_seconds, `${leasePath}.ttl_seconds`, 1);
  }
}

function validateMapTuples(
  value: unknown,
  path: string,
  validateValue: (candidate: unknown, entryPath: string, key: string) => void,
): void {
  const seen = new Set<string>();
  for (const [index, candidate] of requireArray(value, path).entries()) {
    if (!Array.isArray(candidate) || candidate.length !== 2) {
      throw new PersistedStateVersionError(`${path}[${index}] must be a [key, value] tuple`, CURRENT_STATE_VERSION, 'invalid');
    }
    const key = requireString(candidate[0], `${path}[${index}][0]`);
    if (seen.has(key)) {
      throw new PersistedStateVersionError(`${path} contains duplicate key ${key}`, CURRENT_STATE_VERSION, 'invalid');
    }
    seen.add(key);
    validateValue(candidate[1], `${path}[${index}][1]`, key);
  }
}

function validateOperatorOps(value: unknown, path: string): void {
  for (const [index, candidate] of requireArray(value, path).entries()) {
    const opPath = `${path}[${index}]`;
    const op = requireRecord(candidate, opPath);
    const kind = requireString(op.op, `${opPath}.op`);
    if (!['directive', 'scope', 'approve', 'deny', 'dispatch'].includes(kind)) {
      throw new PersistedStateVersionError(`${opPath}.op is unsupported`, CURRENT_STATE_VERSION, 'invalid');
    }
    const optionalString = (field: string, allowEmpty = false): void => {
      if (op[field] !== undefined) requireString(op[field], `${opPath}.${field}`, allowEmpty);
    };
    const optionalStringArray = (field: string): string[] | undefined => {
      if (op[field] === undefined) return undefined;
      return requireArray(op[field], `${opPath}.${field}`).map((item, itemIndex) =>
        requireString(item, `${opPath}.${field}[${itemIndex}]`));
    };
    if (kind === 'directive') {
      requireString(op.task_id, `${opPath}.task_id`);
      requireString(op.agent_label, `${opPath}.agent_label`);
      if (!['pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct'].includes(
        requireString(op.kind, `${opPath}.kind`),
      )) {
        throw new PersistedStateVersionError(`${opPath}.kind is invalid`, CURRENT_STATE_VERSION, 'invalid');
      }
      optionalStringArray('node_ids');
      optionalStringArray('frontier_types');
      optionalString('note', true);
    } else if (kind === 'scope') {
      const cidrs = optionalStringArray('add_cidrs') ?? [];
      const domains = optionalStringArray('add_domains') ?? [];
      const exclusions = optionalStringArray('add_exclusions') ?? [];
      if (cidrs.length + domains.length + exclusions.length === 0) {
        throw new PersistedStateVersionError(`${opPath} must contain at least one scope update`, CURRENT_STATE_VERSION, 'invalid');
      }
    } else if (kind === 'approve') {
      requireString(op.action_id, `${opPath}.action_id`);
      optionalString('notes', true);
    } else if (kind === 'deny') {
      requireString(op.action_id, `${opPath}.action_id`);
      optionalString('reason', true);
    } else {
      const targetNodeIds = requireArray(op.target_node_ids, `${opPath}.target_node_ids`);
      if (targetNodeIds.length === 0) {
        throw new PersistedStateVersionError(`${opPath}.target_node_ids must not be empty`, CURRENT_STATE_VERSION, 'invalid');
      }
      targetNodeIds.forEach((item, itemIndex) =>
        requireString(item, `${opPath}.target_node_ids[${itemIndex}]`));
      optionalString('archetype');
      optionalString('skill', true);
      optionalString('objective', true);
    }
  }
}

function validateProposedPlans(value: unknown, path: string): void {
  const store = requireRecord(value, path);
  const planIds = new Set<string>();
  for (const [index, candidate] of requireArray(store.plans, `${path}.plans`).entries()) {
    const plan = requireRecord(candidate, `${path}.plans[${index}]`);
    const planId = requireString(plan.plan_id, `${path}.plans[${index}].plan_id`);
    if (planIds.has(planId)) {
      throw new PersistedStateVersionError(`${path}.plans contains duplicate plan_id ${planId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    planIds.add(planId);
    requireString(plan.command, `${path}.plans[${index}].command`, true);
    requireString(plan.summary, `${path}.plans[${index}].summary`, true);
    requireSafeInteger(plan.created_at, `${path}.plans[${index}].created_at`);
    requireSafeInteger(plan.expires_at, `${path}.plans[${index}].expires_at`);
    const status = requireString(plan.status, `${path}.plans[${index}].status`);
    if (!['open', 'confirmed', 'denied', 'expired'].includes(status)) {
      throw new PersistedStateVersionError(`${path}.plans[${index}].status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    for (const field of [
      'owner_task_id',
      'owner_agent_label',
      'source_task_id',
      'source_agent_id',
      'recovery_warning',
    ] as const) {
      if (plan[field] !== undefined) {
        requireString(plan[field], `${path}.plans[${index}].${field}`, field === 'recovery_warning');
      }
    }
    for (const field of [
      'resolved_at',
      'confirmed_at',
      'denied_at',
      'expired_at',
      'acknowledged_at',
    ] as const) {
      if (plan[field] !== undefined) requireSafeInteger(plan[field], `${path}.plans[${index}].${field}`);
    }
    if (plan.execution_outcome !== undefined) {
      const outcome = requireRecord(plan.execution_outcome, `${path}.plans[${index}].execution_outcome`);
      if (!['succeeded', 'partial', 'failed'].includes(
        requireString(outcome.status, `${path}.plans[${index}].execution_outcome.status`),
      )) {
        throw new PersistedStateVersionError(
          `${path}.plans[${index}].execution_outcome.status is invalid`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      requireSafeInteger(outcome.completed_at, `${path}.plans[${index}].execution_outcome.completed_at`);
      requireArray(outcome.results, `${path}.plans[${index}].execution_outcome.results`);
    }
    validateOperatorOps(plan.ops, `${path}.plans[${index}].ops`);
  }
  for (const [index, candidate] of requireArray(store.tombstones, `${path}.tombstones`).entries()) {
    if (!Array.isArray(candidate) || candidate.length !== 2) {
      throw new PersistedStateVersionError(`${path}.tombstones[${index}] must be a tuple`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireString(candidate[0], `${path}.tombstones[${index}][0]`);
    if (!['confirmed', 'denied', 'expired'].includes(String(candidate[1]))) {
      throw new PersistedStateVersionError(`${path}.tombstones[${index}][1] is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
  }
}

function validateAgentQueries(value: unknown, path: string): void {
  const store = requireRecord(value, path);
  const queryIds = new Set<string>();
  for (const [index, candidate] of requireArray(store.queries, `${path}.queries`).entries()) {
    const query = requireRecord(candidate, `${path}.queries[${index}]`);
    const queryId = requireString(query.query_id, `${path}.queries[${index}].query_id`);
    if (queryIds.has(queryId)) {
      throw new PersistedStateVersionError(`${path}.queries contains duplicate query_id ${queryId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    queryIds.add(queryId);
    for (const field of [
      'owner_task_id',
      'owner_agent_label',
      'task_id',
      'agent_id',
      'recovery_warning',
    ] as const) {
      if (query[field] !== undefined) {
        requireString(query[field], `${path}.queries[${index}].${field}`, field === 'recovery_warning');
      }
    }
    requireString(query.question, `${path}.queries[${index}].question`);
    requireSafeInteger(query.created_at, `${path}.queries[${index}].created_at`);
    requireSafeInteger(query.expires_at, `${path}.queries[${index}].expires_at`);
    const status = requireString(query.status, `${path}.queries[${index}].status`);
    if (!['open', 'answered', 'expired'].includes(status)) {
      throw new PersistedStateVersionError(`${path}.queries[${index}].status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (status === 'answered') {
      requireString(query.answer, `${path}.queries[${index}].answer`, true);
      requireSafeInteger(query.answered_at, `${path}.queries[${index}].answered_at`);
    }
    for (const field of ['delivered_at', 'acknowledged_at', 'expired_at'] as const) {
      if (query[field] !== undefined) requireSafeInteger(query[field], `${path}.queries[${index}].${field}`);
    }
    if (query.options !== undefined) {
      requireArray(query.options, `${path}.queries[${index}].options`)
        .forEach((option, optionIndex) => requireString(option, `${path}.queries[${index}].options[${optionIndex}]`));
    }
  }
}

function validateSessionDescriptors(value: unknown, path: string): void {
  const sessionIds = new Set<string>();
  for (const [index, candidate] of requireArray(value, path).entries()) {
    const descriptor = requireRecord(candidate, `${path}[${index}]`);
    const sessionId = requireString(descriptor.session_id, `${path}[${index}].session_id`);
    if (sessionIds.has(sessionId)) {
      throw new PersistedStateVersionError(`${path} contains duplicate session_id ${sessionId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    sessionIds.add(sessionId);
    if (!['ssh', 'local_pty', 'socket'].includes(requireString(descriptor.kind, `${path}[${index}].kind`))) {
      throw new PersistedStateVersionError(`${path}[${index}].kind is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireString(descriptor.transport, `${path}[${index}].transport`);
    if (!['pending', 'connected', 'closed', 'error'].includes(requireString(descriptor.lifecycle, `${path}[${index}].lifecycle`))) {
      throw new PersistedStateVersionError(`${path}[${index}].lifecycle is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireString(descriptor.title, `${path}[${index}].title`, true);
    requireIsoDate(descriptor.started_at, `${path}[${index}].started_at`);
    requireIsoDate(descriptor.last_activity_at, `${path}[${index}].last_activity_at`);
    if (descriptor.closed_at !== undefined) requireIsoDate(descriptor.closed_at, `${path}[${index}].closed_at`);
    if (descriptor.mode !== undefined && !['connect', 'listen'].includes(
      requireString(descriptor.mode, `${path}[${index}].mode`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].mode is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (descriptor.accept_mode !== undefined && !['single', 'rearm'].includes(
      requireString(descriptor.accept_mode, `${path}[${index}].accept_mode`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].accept_mode is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    for (const field of [
      'transport',
      'bind_host',
      'advertise_host',
      'host',
      'user',
      'owner_task_id',
      'recovery_warning',
      'target_node',
      'principal_node',
      'credential_node',
      'action_id',
      'frontier_item_id',
      'notes',
    ] as const) {
      if (descriptor[field] !== undefined) {
        requireString(descriptor[field], `${path}[${index}].${field}`, field === 'notes');
      }
    }
    if (descriptor.port !== undefined) {
      const port = requireSafeInteger(descriptor.port, `${path}[${index}].port`);
      if (port > 65_535) {
        throw new PersistedStateVersionError(`${path}[${index}].port must be at most 65535`, CURRENT_STATE_VERSION, 'invalid');
      }
    }
    if (descriptor.reachability_warnings !== undefined) {
      requireArray(descriptor.reachability_warnings, `${path}[${index}].reachability_warnings`)
        .forEach((warning, warningIndex) =>
          requireString(warning, `${path}[${index}].reachability_warnings[${warningIndex}]`, true));
    }
    const capabilities = requireRecord(descriptor.capabilities, `${path}[${index}].capabilities`);
    for (const field of ['has_stdin', 'has_stdout', 'supports_resize', 'supports_signals'] as const) {
      if (typeof capabilities[field] !== 'boolean') {
        throw new PersistedStateVersionError(`${path}[${index}].capabilities.${field} must be boolean`, CURRENT_STATE_VERSION, 'invalid');
      }
    }
    if (!['none', 'dumb', 'partial', 'full'].includes(
      requireString(capabilities.tty_quality, `${path}[${index}].capabilities.tty_quality`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].capabilities.tty_quality is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (capabilities.serves_mock_service_id !== undefined) {
      requireString(capabilities.serves_mock_service_id, `${path}[${index}].capabilities.serves_mock_service_id`);
    }
    if (descriptor.default_validation !== undefined) {
      const validation = requireRecord(descriptor.default_validation, `${path}[${index}].default_validation`);
      requireString(validation.technique, `${path}[${index}].default_validation.technique`);
      for (const field of ['target_ip', 'target_url', 'target_node', 'agent_id'] as const) {
        if (validation[field] !== undefined) {
          requireString(validation[field], `${path}[${index}].default_validation.${field}`);
        }
      }
      if (validation.allow_unverified_scope !== undefined
        && typeof validation.allow_unverified_scope !== 'boolean') {
        throw new PersistedStateVersionError(
          `${path}[${index}].default_validation.allow_unverified_scope must be boolean`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
    }
    const resume = requireRecord(descriptor.resume_intent, `${path}[${index}].resume_intent`);
    if (!['none', 'manual'].includes(requireString(resume.policy, `${path}[${index}].resume_intent.policy`))) {
      throw new PersistedStateVersionError(`${path}[${index}].resume_intent.policy is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (typeof resume.requested !== 'boolean') {
      throw new PersistedStateVersionError(`${path}[${index}].resume_intent.requested must be boolean`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (resume.prior_state !== undefined && !['pending', 'connected'].includes(
      requireString(resume.prior_state, `${path}[${index}].resume_intent.prior_state`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].resume_intent.prior_state is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireIsoDate(resume.recorded_at, `${path}[${index}].resume_intent.recorded_at`);
  }
}

function validateRuntimeRuns(value: unknown, path: string): void {
  const runIds = new Set<string>();
  for (const [index, candidate] of requireArray(value, path).entries()) {
    const run = requireRecord(candidate, `${path}[${index}]`);
    const runId = requireString(run.run_id, `${path}[${index}].run_id`);
    if (runIds.has(runId)) {
      throw new PersistedStateVersionError(`${path} contains duplicate run_id ${runId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    runIds.add(runId);
    if (!['headless_agent', 'tracked_process'].includes(requireString(run.kind, `${path}[${index}].kind`))) {
      throw new PersistedStateVersionError(`${path}[${index}].kind is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireIsoDate(run.started_at, `${path}[${index}].started_at`);
    if (run.last_output_at !== undefined) requireIsoDate(run.last_output_at, `${path}[${index}].last_output_at`);
    if (run.completed_at !== undefined) requireIsoDate(run.completed_at, `${path}[${index}].completed_at`);
    for (const field of [
      'task_id',
      'action_id',
      'agent_id',
      'process_start_identity',
      'daemon_owner',
      'recovery_warning',
    ] as const) {
      if (run[field] !== undefined) requireString(run[field], `${path}[${index}].${field}`, field === 'recovery_warning');
    }
    for (const field of ['pid', 'process_group_id'] as const) {
      if (run[field] !== undefined) requireSafeInteger(run[field], `${path}[${index}].${field}`, 1);
    }
    if (run.command_fingerprint !== undefined
      && !/^[a-f0-9]{64}$/.test(requireString(run.command_fingerprint, `${path}[${index}].command_fingerprint`))) {
      throw new PersistedStateVersionError(`${path}[${index}].command_fingerprint must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (!['reserved', 'running', 'completed', 'failed', 'unknown', 'interrupted'].includes(
      requireString(run.lifecycle, `${path}[${index}].lifecycle`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].lifecycle is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (run.evidence_state !== undefined && !['none', 'pending', 'captured', 'failed'].includes(
      requireString(run.evidence_state, `${path}[${index}].evidence_state`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].evidence_state is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
  }
}

function validateAgentTask(value: unknown, path: string, key: string): void {
  const task = requireRecord(value, path);
  const id = requireString(task.id, `${path}.id`);
  if (id !== key) {
    throw new PersistedStateVersionError(`${path}.id must match map key`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireString(task.agent_id, `${path}.agent_id`);
  if (task.task_id !== undefined && requireString(task.task_id, `${path}.task_id`) !== key) {
    throw new PersistedStateVersionError(`${path}.task_id must match map key`, CURRENT_STATE_VERSION, 'invalid');
  }
  if (task.agent_label !== undefined
    && requireString(task.agent_label, `${path}.agent_label`) !== task.agent_id) {
    throw new PersistedStateVersionError(
      `${path}.agent_label must match compatibility alias agent_id`,
      CURRENT_STATE_VERSION,
      'invalid',
    );
  }
  requireIsoDate(task.assigned_at, `${path}.assigned_at`);
  if (!['pending', 'running', 'completed', 'failed', 'interrupted'].includes(
    requireString(task.status, `${path}.status`),
  )) {
    throw new PersistedStateVersionError(`${path}.status is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireArray(task.subgraph_node_ids, `${path}.subgraph_node_ids`)
    .forEach((nodeId, index) => requireString(nodeId, `${path}.subgraph_node_ids[${index}]`));
  if (task.completed_at !== undefined) requireIsoDate(task.completed_at, `${path}.completed_at`);
  if (task.heartbeat_at !== undefined) requireIsoDate(task.heartbeat_at, `${path}.heartbeat_at`);
  if (task.heartbeat_ttl_seconds !== undefined) {
    requireSafeInteger(task.heartbeat_ttl_seconds, `${path}.heartbeat_ttl_seconds`, 1);
  }
}

function validateCoordinationRecoveryWarnings(value: unknown, path: string): void {
  const ids = new Set<string>();
  for (const [index, candidate] of requireArray(value, path).entries()) {
    const warning = requireRecord(candidate, `${path}[${index}]`);
    const id = requireString(warning.warning_id, `${path}[${index}].warning_id`);
    if (ids.has(id)) {
      throw new PersistedStateVersionError(
        `${path} contains duplicate warning_id ${id}`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    ids.add(id);
    requireString(warning.relationship, `${path}[${index}].relationship`);
    requireString(warning.reference, `${path}[${index}].reference`);
    requireString(warning.message, `${path}[${index}].message`);
    if (warning.candidate_task_ids !== undefined) {
      requireArray(warning.candidate_task_ids, `${path}[${index}].candidate_task_ids`)
        .forEach((taskId, taskIndex) =>
          requireString(taskId, `${path}[${index}].candidate_task_ids[${taskIndex}]`));
    }
  }
}

function validateCampaign(value: unknown, path: string, key: string): void {
  const campaign = requireRecord(value, path);
  const id = requireString(campaign.id, `${path}.id`);
  if (id !== key) {
    throw new PersistedStateVersionError(`${path}.id must match map key`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireString(campaign.name, `${path}.name`, true);
  if (!['credential_spray', 'enumeration', 'post_exploitation', 'network_discovery', 'custom'].includes(
    requireString(campaign.strategy, `${path}.strategy`),
  )) {
    throw new PersistedStateVersionError(`${path}.strategy is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  if (!['draft', 'active', 'paused', 'completed', 'aborted'].includes(
    requireString(campaign.status, `${path}.status`),
  )) {
    throw new PersistedStateVersionError(`${path}.status is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireArray(campaign.items, `${path}.items`)
    .forEach((item, index) => requireString(item, `${path}.items[${index}]`));
  requireArray(campaign.findings, `${path}.findings`)
    .forEach((finding, index) => requireString(finding, `${path}.findings[${index}]`));
  requireArray(campaign.abort_conditions, `${path}.abort_conditions`).forEach((candidate, index) => {
    const condition = requireRecord(candidate, `${path}.abort_conditions[${index}]`);
    if (!['consecutive_failures', 'total_failures_pct', 'opsec_noise_ceiling', 'time_limit_seconds'].includes(
      requireString(condition.type, `${path}.abort_conditions[${index}].type`),
    )) {
      throw new PersistedStateVersionError(`${path}.abort_conditions[${index}].type is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireFiniteNumber(condition.threshold, `${path}.abort_conditions[${index}].threshold`);
  });
  const progress = requireRecord(campaign.progress, `${path}.progress`);
  for (const field of ['total', 'completed', 'succeeded', 'failed', 'consecutive_failures'] as const) {
    requireSafeInteger(progress[field], `${path}.progress.${field}`);
  }
  requireIsoDate(campaign.created_at, `${path}.created_at`);
  if (campaign.started_at !== undefined) requireIsoDate(campaign.started_at, `${path}.started_at`);
  if (campaign.completed_at !== undefined) requireIsoDate(campaign.completed_at, `${path}.completed_at`);
}

function validateDirectiveList(value: unknown, path: string, taskId: string): void {
  const ids = new Set<string>();
  requireArray(value, path).forEach((candidate, index) => {
    const directive = requireRecord(candidate, `${path}[${index}]`);
    const id = requireString(directive.id, `${path}[${index}].id`);
    if (ids.has(id)) {
      throw new PersistedStateVersionError(`${path} contains duplicate directive id ${id}`, CURRENT_STATE_VERSION, 'invalid');
    }
    ids.add(id);
    if (requireString(directive.task_id, `${path}[${index}].task_id`) !== taskId) {
      throw new PersistedStateVersionError(`${path}[${index}].task_id must match map key`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (!['pause', 'resume', 'stop', 'narrow_scope', 'skip_types', 'prioritize', 'instruct'].includes(
      requireString(directive.kind, `${path}[${index}].kind`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].kind is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireString(directive.issued_by, `${path}[${index}].issued_by`);
    requireIsoDate(directive.issued_at, `${path}[${index}].issued_at`);
    if (!['pending', 'acknowledged', 'superseded'].includes(
      requireString(directive.status, `${path}[${index}].status`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
  });
}

function validateApproval(value: unknown, path: string, key: string): void {
  const approval = requireRecord(value, path);
  if (requireString(approval.action_id, `${path}.action_id`) !== key) {
    throw new PersistedStateVersionError(`${path}.action_id must match map key`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireIsoDate(approval.submitted_at, `${path}.submitted_at`);
  requireIsoDate(approval.timeout_at, `${path}.timeout_at`);
  requireString(approval.description, `${path}.description`, true);
  requireRecord(approval.opsec_context, `${path}.opsec_context`);
  if (!['valid', 'warning_only'].includes(requireString(approval.validation_result, `${path}.validation_result`))) {
    throw new PersistedStateVersionError(`${path}.validation_result is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  if (!['pending', 'approved', 'denied', 'timeout', 'aborted'].includes(
    requireString(approval.status, `${path}.status`),
  )) {
    throw new PersistedStateVersionError(`${path}.status is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  if (approval.resolved_at !== undefined) requireIsoDate(approval.resolved_at, `${path}.resolved_at`);
  for (const field of ['task_id', 'agent_label', 'agent_id', 'recovery_warning'] as const) {
    if (approval[field] !== undefined) {
      requireString(approval[field], `${path}.${field}`, field === 'recovery_warning');
    }
  }
}

function validateTrackedProcesses(value: unknown, path: string): void {
  const ids = new Set<string>();
  requireArray(value, path).forEach((candidate, index) => {
    const process = requireRecord(candidate, `${path}[${index}]`);
    const id = requireString(process.id, `${path}[${index}].id`);
    if (ids.has(id)) {
      throw new PersistedStateVersionError(`${path} contains duplicate process id ${id}`, CURRENT_STATE_VERSION, 'invalid');
    }
    ids.add(id);
    requireSafeInteger(process.pid, `${path}[${index}].pid`, 1);
    requireString(process.command, `${path}[${index}].command`, true);
    requireString(process.description, `${path}[${index}].description`, true);
    requireIsoDate(process.started_at, `${path}[${index}].started_at`);
    if (process.completed_at !== undefined) requireIsoDate(process.completed_at, `${path}[${index}].completed_at`);
    if (!['running', 'completed', 'failed', 'unknown'].includes(
      requireString(process.status, `${path}[${index}].status`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
  });
}

function validateInferenceRules(value: unknown, path: string): void {
  const ids = new Set<string>();
  requireArray(value, path).forEach((candidate, index) => {
    const rule = requireRecord(candidate, `${path}[${index}]`);
    const id = requireString(rule.id, `${path}[${index}].id`);
    if (ids.has(id)) {
      throw new PersistedStateVersionError(`${path} contains duplicate rule id ${id}`, CURRENT_STATE_VERSION, 'invalid');
    }
    ids.add(id);
    requireString(rule.name, `${path}[${index}].name`);
    requireString(rule.description, `${path}[${index}].description`, true);
    requireRecord(rule.trigger, `${path}[${index}].trigger`);
    requireArray(rule.produces, `${path}[${index}].produces`);
  });
}

function validateChainCheckpoints(value: unknown, path: string): void {
  requireArray(value, path).forEach((candidate, index) => {
    const checkpoint = requireRecord(candidate, `${path}[${index}]`);
    requireSafeInteger(checkpoint.schema_version, `${path}[${index}].schema_version`, 1);
    requireSafeInteger(checkpoint.event_index, `${path}[${index}].event_index`);
    requireString(checkpoint.event_id, `${path}[${index}].event_id`);
    if (!/^[a-f0-9]{64}$/.test(requireString(checkpoint.event_hash, `${path}[${index}].event_hash`))) {
      throw new PersistedStateVersionError(`${path}[${index}].event_hash must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireSafeInteger(checkpoint.events_since_previous, `${path}[${index}].events_since_previous`);
    requireIsoDate(checkpoint.emitted_at, `${path}[${index}].emitted_at`);
  });
}

function validateArtifactReferences(value: unknown, path: string): void {
  const references = requireRecord(value, path);
  const seen = new Set<string>();
  const validateReference = (
    candidate: unknown,
    referencePath: string,
    expectedKind: PersistedArtifactReferenceV1['kind'],
  ): void => {
    const reference = requireRecord(candidate, referencePath);
    const kind = requireString(reference.kind, `${referencePath}.kind`);
    if (kind !== expectedKind) {
      throw new PersistedStateVersionError(`${referencePath}.kind must be ${expectedKind}`, CURRENT_STATE_VERSION, 'invalid');
    }
    const referencePathValue = requireString(reference.path, `${referencePath}.path`);
    const identity = `${kind}:${referencePathValue}`;
    if (seen.has(identity)) {
      throw new PersistedStateVersionError(`${path} contains duplicate artifact reference ${identity}`, CURRENT_STATE_VERSION, 'invalid');
    }
    seen.add(identity);
    if (reference.sha256 !== undefined && !/^[a-f0-9]{64}$/.test(requireString(reference.sha256, `${referencePath}.sha256`))) {
      throw new PersistedStateVersionError(`${referencePath}.sha256 must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
    }
  };
  if (references.evidence_manifest !== undefined) {
    validateReference(references.evidence_manifest, `${path}.evidence_manifest`, 'evidence_manifest');
  }
  if (references.report_manifest !== undefined) {
    validateReference(references.report_manifest, `${path}.report_manifest`, 'report_manifest');
  }
  for (const [list, kind] of [
    ['tapes', 'tape'],
    ['bundles', 'bundle'],
    ['cookie_jars', 'cookie_jar'],
  ] as const) {
    requireArray(references[list], `${path}.${list}`)
      .forEach((candidate, index) =>
        validateReference(candidate, `${path}.${list}[${index}]`, kind));
  }
}

/**
 * V1 is intentionally strict about fields owned by this binary. Additive
 * unknown fields remain allowed, but a declared V1 envelope may never silently
 * coerce a missing or malformed durable collection to an empty value.
 */
export function validatePersistedStateV1(value: unknown): PersistedStateV1 {
  const record = recordOf(value);
  if (detectStateVersion(record) !== CURRENT_STATE_VERSION) {
    throw new PersistedStateVersionError('persisted state is not V1', record.state_version, 'invalid');
  }
  detectJournalVersion(record, CURRENT_STATE_VERSION);
  if (!engagementConfigSchema.safeParse(record.config).success) {
    throw new PersistedStateVersionError('persisted V1 config is invalid', CURRENT_STATE_VERSION, 'invalid');
  }
  requireRecord(record.graph, 'persisted graph');

  validateActivityLog(record.activityLog, 'persisted activityLog');
  validateColdStore(record.coldStore, 'persisted coldStore');
  validateMapTuples(record.agents, 'persisted agents', validateAgentTask);
  if (record.coordinationRecoveryWarnings !== undefined) {
    validateCoordinationRecoveryWarnings(
      record.coordinationRecoveryWarnings,
      'persisted coordinationRecoveryWarnings',
    );
  }
  validateMapTuples(record.campaigns, 'persisted campaigns', validateCampaign);
  validateMapTuples(record.agentDirectives, 'persisted agentDirectives', validateDirectiveList);
  validateMapTuples(record.approvalRequests, 'persisted approvalRequests', validateApproval);
  validateInferenceRules(record.inferenceRules, 'persisted inferenceRules');
  validateTrackedProcesses(record.trackedProcesses, 'persisted trackedProcesses');
  validateRuntimeRuns(record.runtimeRuns, 'persisted runtimeRuns');
  validateMapTuples(record.playbookRuns, 'persisted playbookRuns', (candidate, path, key) => {
    const run = requireRecord(candidate, path);
    const id = requireString(run.run_id, `${path}.run_id`);
    if (id !== key) throw new PersistedStateVersionError(`${path}.run_id must match map key`, CURRENT_STATE_VERSION, 'invalid');
  });
  validateSessionDescriptors(record.sessionDescriptors, 'persisted sessionDescriptors');
  validateProposedPlans(record.proposedPlans, 'persisted proposedPlans');
  validateAgentQueries(record.agentQueries, 'persisted agentQueries');
  validateMapTuples(record.commandPlans, 'persisted commandPlans', (candidate, path) => {
    const plan = requireRecord(candidate, path);
    requireString(plan.command, `${path}.command`, true);
    requireSafeInteger(plan.created_at, `${path}.created_at`);
    requireSafeInteger(plan.expires_at, `${path}.expires_at`);
    validateOperatorOps(plan.ops, `${path}.ops`);
  });
  validateMapTuples(record.commandOutcomes, 'persisted commandOutcomes', (candidate, path) => {
    const outcome = requireRecord(candidate, path);
    requireSafeInteger(outcome.at, `${path}.at`);
    requireSafeInteger(outcome.expires_at, `${path}.expires_at`);
    requireArray(outcome.results, `${path}.results`);
  });
  validateOpsecTracker(record.opsecTracker, 'persisted opsecTracker');
  validateFrontierLinkage(record.frontierLinkage, 'persisted frontierLinkage');
  validateFrontierLeases(record.frontierLeases, 'persisted frontierLeases');
  const weights = requireRecord(record.frontierWeights, 'persisted frontierWeights');
  validateStringNumberRecord(weights.fan_out, 'persisted frontierWeights.fan_out');
  validateStringNumberRecord(weights.noise, 'persisted frontierWeights.noise');
  validateArtifactReferences(record.artifactReferences, 'persisted artifactReferences');
  validateChainCheckpoints(record.chainCheckpoints, 'persisted chainCheckpoints');

  requireSafeInteger(record.chainEventsSinceCheckpoint, 'persisted chainEventsSinceCheckpoint');
  requireSafeInteger(record.deterministicSeq, 'persisted deterministicSeq');
  validateMapTuples(record.recentFindingHashes, 'persisted recentFindingHashes', (candidate, path) => {
    requireFiniteNumber(candidate, path);
  });
  requireSafeInteger(record.dedupCount, 'persisted dedupCount');
  requireSafeInteger(record.journalSnapshotSeq, 'persisted journalSnapshotSeq');
  requireString(record.journalCheckpointSemantics, 'persisted journalCheckpointSemantics');
  return record as unknown as PersistedStateV1;
}
