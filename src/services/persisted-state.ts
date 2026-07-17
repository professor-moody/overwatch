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
  SessionConnectionState,
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
  /** Additive richer prior state; the preceding V1 reader ignores it while
   * continuing to validate the legacy-compatible `prior_state`. */
  recovery_prior_state?: Extract<SessionState, 'resume_available'>;
  recorded_at: string;
}

/** Runtime handles, buffers, secrets, and PIDs are deliberately absent. */
export interface PersistedSessionDescriptorV1 {
  session_id: string;
  kind: SessionKind;
  adapter?: SessionKind;
  transport: string;
  /**
   * Kept within the original V1 enum so the preceding binary can still open a
   * PR9-written state file. New recovery-only states are carried additively in
   * `recovery_lifecycle`.
   */
  lifecycle: Extract<SessionState, 'pending' | 'connected' | 'closed' | 'error'>;
  recovery_lifecycle?: Extract<SessionState, 'resume_available' | 'interrupted'>;
  listener_id?: string;
  connection_generation?: number;
  connection_id?: string;
  connection_started_at?: string;
  last_connection_id?: string;
  last_connection_state?: SessionConnectionState;
  last_connection_closed_at?: string;
  mode?: 'connect' | 'listen';
  bind_host?: string;
  advertise_host?: string;
  accept_mode?: 'single' | 'rearm';
  reachability_warnings?: string[];
  auth_status?: 'shell_confirmed' | 'connected_unconfirmed' | 'auth_prompt' | 'auth_failed';
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
  /** PID of the managed supervisor (the process-group owner). */
  pid?: number;
  /** PID of the actual target child, informational only. */
  target_pid?: number;
  process_group_id?: number;
  process_start_identity?: string;
  ownership_token?: string;
  daemon_owner?: string;
  command_fingerprint?: string;
  ownership_mode?: 'managed_supervisor' | 'external_adopted';
  signal_scope?: 'process_group' | 'pid' | 'none';
  started_at: string;
  identity_recorded_at?: string;
  ownership_acknowledged_at?: string;
  launched_at?: string;
  last_output_at?: string;
  completed_at?: string;
  lifecycle: 'reserved' | 'running' | 'completed' | 'failed' | 'unknown' | 'interrupted';
  evidence_state?: 'none' | 'pending' | 'captured' | 'failed';
  exit_code?: number | null;
  exit_signal?: string | null;
  finalization_status?: 'completed' | 'failed' | 'interrupted' | 'unknown';
  action_started_event_id?: string;
  action_terminal_event_id?: string;
  recovery_warning?: string;
}

export type PlaybookRunStatus =
  | 'pending'
  | 'blocked'
  | 'awaiting_approval'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'interrupted'
  | 'skipped'
  | 'cancelled';

export type PlaybookAttemptStatus =
  | 'claimed'
  | 'awaiting_approval'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'interrupted'
  | 'cancelled';

export interface PersistedPlaybookDefinitionV1 {
  definition_id: string;
  definition_version: number;
  provider: 'aws' | 'github' | 'entra' | 'oidc';
  title: string;
}

/** An immutable definition snapshot. Re-expansion appends a revision rather
 * than overwriting the plan that an operator previously inspected. */
export interface PersistedPlaybookPlanRevisionV1 {
  revision: number;
  created_at: string;
  plan_hash: string;
  steps: PersistedPlaybookStepDefinitionV1[];
}

export interface PersistedPlaybookStepDefinitionV1 {
  step_id: string;
  ordinal: number;
  description: string;
  depends_on: string[];
  required_bindings: string[];
  produces_bindings: string[];
  execution_template: Record<string, unknown>;
}

export interface PersistedPlaybookAttemptV1 {
  attempt_id: string;
  attempt_number: number;
  status: PlaybookAttemptStatus;
  started_at: string;
  claimed_via: ApplicationCommandTransport;
  claimed_by_task_id?: string;
  executed_via?: ApplicationCommandTransport;
  executed_by_task_id?: string;
  execution_command_id: string;
  execution_idempotency_key: string;
  execution_action_id: string;
  /** Immutable plan snapshot and descriptor fingerprint selected for this attempt. */
  plan_revision: number;
  execution_template_hash: string;
  execution_started_at?: string;
  completed_at?: string;
  action_id?: string;
  evidence_ids: string[];
  finding_ids: string[];
  execution_outcome?: 'succeeded' | 'failed' | 'interrupted';
  parse_outcome?: 'ok' | 'no_data' | 'validation_failed' | 'parser_exception' | 'partial';
  error?: string;
}

export interface PersistedPlaybookStepRunV1 {
  step_id: string;
  ordinal: number;
  description: string;
  status: PlaybookRunStatus;
  depends_on: string[];
  required_bindings: string[];
  produces_bindings: string[];
  /** Non-secret values resolved by the server for the current plan revision. */
  resolved_bindings: Record<string, unknown>;
  resolved_execution?: Record<string, unknown>;
  blocked_reason?: string;
  attempts: PersistedPlaybookAttemptV1[];
  started_at?: string;
  completed_at?: string;
  updated_at: string;
}

/** Durable playbook coordination state. Runtime process handles and credential
 * material remain outside this record; execution descriptors reference the
 * selected credential id and are resolved only at execution time. */
export interface PersistedDurablePlaybookRunV1 {
  schema_version: 1;
  run_id: string;
  definition: PersistedPlaybookDefinitionV1;
  credential_id: string;
  input_hash: string;
  normalized_inputs: Record<string, unknown>;
  /** Current non-secret binding set derived from graph truth during expansion. */
  bindings: Record<string, unknown>;
  plan_revisions: PersistedPlaybookPlanRevisionV1[];
  current_plan_revision: number;
  steps: PersistedPlaybookStepRunV1[];
  status: PlaybookRunStatus;
  report_status: 'generated' | 'partial' | 'completed';
  created_at: string;
  updated_at: string;
  started_at?: string;
  completed_at?: string;
  resume_count: number;
  recovery_warning?: string;
}

/** Compatibility for state V1 files written while playbook persistence was a
 * reserved, producer-less slot. These records are preserved and surfaced as
 * inert recovery warnings; they are never guessed into an executable run. */
export interface PersistedLegacyPlaybookRunV1 {
  run_id: string;
  schema_version?: undefined;
  [key: string]: unknown;
}

export type PersistedPlaybookRunV1 =
  | PersistedDurablePlaybookRunV1
  | PersistedLegacyPlaybookRunV1;

export interface PersistedArtifactReferenceV1 {
  kind: 'evidence_manifest' | 'report_manifest' | 'tape' | 'bundle' | 'cookie_jar';
  path: string;
  sha256?: string;
  size_bytes?: number;
  availability?: 'available' | 'missing' | 'invalid';
  integrity?: 'verified' | 'unverified';
  bundle_id?: string;
}

export interface PersistedArtifactGenerationRegistrationV1 {
  registry_version: 1;
  root: string;
  namespace: string;
  legacy_names: string[];
}

export interface PersistedArtifactReferencesV1 {
  evidence_manifest?: PersistedArtifactReferenceV1;
  report_manifest?: PersistedArtifactReferenceV1;
  tapes: PersistedArtifactReferenceV1[];
  bundles: PersistedArtifactReferenceV1[];
  cookie_jars: PersistedArtifactReferenceV1[];
  /** Additive V1 field. Older V1 states legitimately omit it. */
  generation_registrations?: PersistedArtifactGenerationRegistrationV1[];
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

export type ApplicationCommandTransport =
  | 'mcp'
  | 'dashboard'
  | 'cli'
  | 'planner'
  | 'scripted_runner'
  | 'headless_runner'
  | 'system';

export type ApplicationCommandStatus =
  | 'accepted'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'interrupted';

/**
 * Durable transport-neutral command record.
 *
 * The map is keyed by the actor-scoped idempotency identity. Keeping this
 * separate from the legacy ten-minute plan result cache lets preceding V1
 * readers continue to ignore the additive field while current binaries retain
 * response-ready command truth across retries and restarts.
 */
export interface PersistedApplicationCommandV1 {
  command_id: string;
  idempotency_key: string;
  input_sha256: string;
  validated_input: unknown;
  command_kind: string;
  transport: ApplicationCommandTransport;
  actor_task_id: string | null;
  action_id?: string;
  frontier_item_id?: string;
  plan_id?: string;
  status: ApplicationCommandStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  result?: unknown;
  error?: {
    code?: string;
    message: string;
    details?: unknown;
  };
  entity_refs?: Record<string, string | string[]>;
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
  /** Additive in PR10; absent means no transport-neutral commands exist yet. */
  applicationCommands?: Array<[string, PersistedApplicationCommandV1]>;
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

const PLAYBOOK_RUN_STATUSES = new Set<PlaybookRunStatus>([
  'pending',
  'blocked',
  'awaiting_approval',
  'running',
  'succeeded',
  'failed',
  'interrupted',
  'skipped',
  'cancelled',
]);

function validatePlaybookRun(candidate: unknown, path: string, key: string): void {
  const run = requireRecord(candidate, path);
  const id = requireString(run.run_id, `${path}.run_id`);
  if (id !== key) {
    throw new PersistedStateVersionError(`${path}.run_id must match map key`, CURRENT_STATE_VERSION, 'invalid');
  }
  // State V1 originally reserved this slot with no producer. Preserve those
  // inert placeholders instead of turning an additive upgrade into data loss.
  if (run.schema_version === undefined) return;
  if (run.schema_version !== 1) {
    throw new PersistedStateVersionError(`${path}.schema_version is unsupported`, CURRENT_STATE_VERSION, 'unsupported');
  }
  const definition = requireRecord(run.definition, `${path}.definition`);
  requireString(definition.definition_id, `${path}.definition.definition_id`);
  requireSafeInteger(definition.definition_version, `${path}.definition.definition_version`, 1);
  if (!['aws', 'github', 'entra', 'oidc'].includes(requireString(definition.provider, `${path}.definition.provider`))) {
    throw new PersistedStateVersionError(`${path}.definition.provider is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireString(definition.title, `${path}.definition.title`);
  requireString(run.credential_id, `${path}.credential_id`);
  for (const field of ['input_hash'] as const) {
    if (!/^[a-f0-9]{64}$/.test(requireString(run[field], `${path}.${field}`))) {
      throw new PersistedStateVersionError(`${path}.${field} must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
    }
  }
  requireRecord(run.normalized_inputs, `${path}.normalized_inputs`);
  const planRevisions = requireArray(run.plan_revisions, `${path}.plan_revisions`);
  if (planRevisions.length === 0) {
    throw new PersistedStateVersionError(`${path}.plan_revisions must not be empty`, CURRENT_STATE_VERSION, 'invalid');
  }
  const revisionIds = new Set<number>();
  const revisionStepIds = new Map<number, Set<string>>();
  for (const [revisionIndex, candidateRevision] of planRevisions.entries()) {
    const revisionPath = `${path}.plan_revisions[${revisionIndex}]`;
    const revision = requireRecord(candidateRevision, revisionPath);
    const revisionId = requireSafeInteger(revision.revision, `${revisionPath}.revision`, 1);
    if (revisionIds.has(revisionId)) {
      throw new PersistedStateVersionError(`${path}.plan_revisions contains duplicate revision ${revisionId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    revisionIds.add(revisionId);
    requireIsoDate(revision.created_at, `${revisionPath}.created_at`);
    if (!/^[a-f0-9]{64}$/.test(requireString(revision.plan_hash, `${revisionPath}.plan_hash`))) {
      throw new PersistedStateVersionError(`${revisionPath}.plan_hash must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
    }
    const definedStepIds = new Set<string>();
    for (const [stepIndex, candidateStep] of requireArray(revision.steps, `${revisionPath}.steps`).entries()) {
      const stepPath = `${revisionPath}.steps[${stepIndex}]`;
      const step = requireRecord(candidateStep, stepPath);
      const definedStepId = requireString(step.step_id, `${stepPath}.step_id`);
      if (definedStepIds.has(definedStepId)) {
        throw new PersistedStateVersionError(
          `${revisionPath}.steps contains duplicate step_id ${definedStepId}`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      definedStepIds.add(definedStepId);
      requireSafeInteger(step.ordinal, `${stepPath}.ordinal`, 1);
      requireString(step.description, `${stepPath}.description`);
      for (const field of ['depends_on', 'required_bindings', 'produces_bindings'] as const) {
        requireArray(step[field], `${stepPath}.${field}`).forEach((value, index) =>
          requireString(value, `${stepPath}.${field}[${index}]`));
      }
      requireRecord(step.execution_template, `${stepPath}.execution_template`);
    }
    revisionStepIds.set(revisionId, definedStepIds);
  }
  const currentRevision = requireSafeInteger(run.current_plan_revision, `${path}.current_plan_revision`, 1);
  if (!revisionIds.has(currentRevision)) {
    throw new PersistedStateVersionError(`${path}.current_plan_revision does not exist`, CURRENT_STATE_VERSION, 'invalid');
  }
  const stepIds = new Set<string>();
  let activeAttempts = 0;
  for (const [stepIndex, candidateStep] of requireArray(run.steps, `${path}.steps`).entries()) {
    const stepPath = `${path}.steps[${stepIndex}]`;
    const step = requireRecord(candidateStep, stepPath);
    const stepId = requireString(step.step_id, `${stepPath}.step_id`);
    if (stepIds.has(stepId)) {
      throw new PersistedStateVersionError(`${path}.steps contains duplicate step_id ${stepId}`, CURRENT_STATE_VERSION, 'invalid');
    }
    stepIds.add(stepId);
    requireSafeInteger(step.ordinal, `${stepPath}.ordinal`, 1);
    requireString(step.description, `${stepPath}.description`);
    const status = requireString(step.status, `${stepPath}.status`) as PlaybookRunStatus;
    if (!PLAYBOOK_RUN_STATUSES.has(status)) {
      throw new PersistedStateVersionError(`${stepPath}.status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    for (const field of ['depends_on', 'required_bindings', 'produces_bindings'] as const) {
      requireArray(step[field], `${stepPath}.${field}`).forEach((value, index) =>
        requireString(value, `${stepPath}.${field}[${index}]`));
    }
    if (step.resolved_execution !== undefined) requireRecord(step.resolved_execution, `${stepPath}.resolved_execution`);
    if (step.blocked_reason !== undefined) requireString(step.blocked_reason, `${stepPath}.blocked_reason`);
    requireIsoDate(step.updated_at, `${stepPath}.updated_at`);
    if (step.started_at !== undefined) requireIsoDate(step.started_at, `${stepPath}.started_at`);
    if (step.completed_at !== undefined) requireIsoDate(step.completed_at, `${stepPath}.completed_at`);
    const attemptIds = new Set<string>();
    for (const [attemptIndex, candidateAttempt] of requireArray(step.attempts, `${stepPath}.attempts`).entries()) {
      const attemptPath = `${stepPath}.attempts[${attemptIndex}]`;
      const attempt = requireRecord(candidateAttempt, attemptPath);
      const attemptId = requireString(attempt.attempt_id, `${attemptPath}.attempt_id`);
      if (attemptIds.has(attemptId)) {
        throw new PersistedStateVersionError(`${stepPath}.attempts contains duplicate attempt_id ${attemptId}`, CURRENT_STATE_VERSION, 'invalid');
      }
      attemptIds.add(attemptId);
      requireSafeInteger(attempt.attempt_number, `${attemptPath}.attempt_number`, 1);
      const attemptStatus = requireString(attempt.status, `${attemptPath}.status`);
      if (!['claimed', 'awaiting_approval', 'running', 'succeeded', 'failed', 'interrupted', 'cancelled'].includes(attemptStatus)) {
        throw new PersistedStateVersionError(`${attemptPath}.status is invalid`, CURRENT_STATE_VERSION, 'invalid');
      }
      if (attemptStatus === 'claimed' || attemptStatus === 'awaiting_approval' || attemptStatus === 'running') activeAttempts += 1;
      requireIsoDate(attempt.started_at, `${attemptPath}.started_at`);
      if (attempt.completed_at !== undefined) requireIsoDate(attempt.completed_at, `${attemptPath}.completed_at`);
      if (!['mcp', 'dashboard', 'cli', 'planner', 'scripted_runner', 'headless_runner', 'system'].includes(
        requireString(attempt.claimed_via, `${attemptPath}.claimed_via`),
      )) {
        throw new PersistedStateVersionError(`${attemptPath}.claimed_via is invalid`, CURRENT_STATE_VERSION, 'invalid');
      }
      requireString(attempt.execution_command_id, `${attemptPath}.execution_command_id`);
      requireString(attempt.execution_idempotency_key, `${attemptPath}.execution_idempotency_key`);
      requireString(attempt.execution_action_id, `${attemptPath}.execution_action_id`);
      const attemptPlanRevision = requireSafeInteger(attempt.plan_revision, `${attemptPath}.plan_revision`, 1);
      if (!revisionStepIds.get(attemptPlanRevision)?.has(stepId)) {
        throw new PersistedStateVersionError(
          `${attemptPath}.plan_revision does not define playbook step ${stepId}`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      requireString(attempt.execution_template_hash, `${attemptPath}.execution_template_hash`);
      if (attempt.execution_started_at !== undefined) requireIsoDate(attempt.execution_started_at, `${attemptPath}.execution_started_at`);
      if (attempt.executed_via !== undefined && !['mcp', 'dashboard', 'cli', 'planner', 'scripted_runner', 'headless_runner', 'system'].includes(String(attempt.executed_via))) {
        throw new PersistedStateVersionError(`${attemptPath}.executed_via is invalid`, CURRENT_STATE_VERSION, 'invalid');
      }
      for (const field of ['claimed_by_task_id', 'executed_by_task_id', 'action_id', 'error'] as const) {
        if (attempt[field] !== undefined) requireString(attempt[field], `${attemptPath}.${field}`);
      }
      for (const field of ['evidence_ids', 'finding_ids'] as const) {
        requireArray(attempt[field], `${attemptPath}.${field}`).forEach((value, index) =>
          requireString(value, `${attemptPath}.${field}[${index}]`));
      }
      if (attempt.execution_outcome !== undefined && !['succeeded', 'failed', 'interrupted'].includes(String(attempt.execution_outcome))) {
        throw new PersistedStateVersionError(`${attemptPath}.execution_outcome is invalid`, CURRENT_STATE_VERSION, 'invalid');
      }
      if (attempt.parse_outcome !== undefined && !['ok', 'no_data', 'validation_failed', 'parser_exception', 'partial'].includes(String(attempt.parse_outcome))) {
        throw new PersistedStateVersionError(`${attemptPath}.parse_outcome is invalid`, CURRENT_STATE_VERSION, 'invalid');
      }
    }
    requireRecord(step.resolved_bindings, `${stepPath}.resolved_bindings`);
  }
  if (activeAttempts > 1) {
    throw new PersistedStateVersionError(`${path} contains more than one running attempt`, CURRENT_STATE_VERSION, 'invalid');
  }
  for (const [stepIndex, candidateStep] of (run.steps as unknown[]).entries()) {
    const step = candidateStep as Record<string, unknown>;
    for (const dependency of step.depends_on as string[]) {
      if (!stepIds.has(dependency)) {
        throw new PersistedStateVersionError(`${path}.steps[${stepIndex}] references unknown dependency ${dependency}`, CURRENT_STATE_VERSION, 'invalid');
      }
    }
  }
  const status = requireString(run.status, `${path}.status`) as PlaybookRunStatus;
  if (!PLAYBOOK_RUN_STATUSES.has(status)) {
    throw new PersistedStateVersionError(`${path}.status is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  if (!['generated', 'partial', 'completed'].includes(requireString(run.report_status, `${path}.report_status`))) {
    throw new PersistedStateVersionError(`${path}.report_status is invalid`, CURRENT_STATE_VERSION, 'invalid');
  }
  requireRecord(run.bindings, `${path}.bindings`);
  requireIsoDate(run.created_at, `${path}.created_at`);
  requireIsoDate(run.updated_at, `${path}.updated_at`);
  if (run.started_at !== undefined) requireIsoDate(run.started_at, `${path}.started_at`);
  if (run.completed_at !== undefined) requireIsoDate(run.completed_at, `${path}.completed_at`);
  requireSafeInteger(run.resume_count, `${path}.resume_count`);
  if (run.recovery_warning !== undefined) requireString(run.recovery_warning, `${path}.recovery_warning`);
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
    if (descriptor.adapter !== undefined && !['ssh', 'local_pty', 'socket'].includes(
      requireString(descriptor.adapter, `${path}[${index}].adapter`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].adapter is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    requireString(descriptor.transport, `${path}[${index}].transport`);
    const persistedLifecycle = requireString(
      descriptor.lifecycle,
      `${path}[${index}].lifecycle`,
    );
    if (!['pending', 'connected', 'closed', 'error'].includes(persistedLifecycle)) {
      throw new PersistedStateVersionError(`${path}[${index}].lifecycle is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    const recoveryLifecycle = descriptor.recovery_lifecycle === undefined
      ? undefined
      : requireString(
        descriptor.recovery_lifecycle,
        `${path}[${index}].recovery_lifecycle`,
      );
    if (
      recoveryLifecycle !== undefined
      && recoveryLifecycle !== 'resume_available'
      && recoveryLifecycle !== 'interrupted'
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}].recovery_lifecycle is invalid`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (
      (recoveryLifecycle === 'resume_available' && persistedLifecycle !== 'closed')
      || (recoveryLifecycle === 'interrupted' && persistedLifecycle !== 'error')
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}].recovery_lifecycle has an incompatible V1 lifecycle fallback`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    const lifecycle = recoveryLifecycle ?? persistedLifecycle;
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
      'listener_id',
      'connection_id',
      'last_connection_id',
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
    const connectionGeneration = descriptor.connection_generation === undefined
      ? undefined
      : requireSafeInteger(
        descriptor.connection_generation,
        `${path}[${index}].connection_generation`,
      );
    if (connectionGeneration !== undefined) {
      const generation = connectionGeneration;
      if (generation < 0) {
        throw new PersistedStateVersionError(
          `${path}[${index}].connection_generation must be non-negative`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
    }
    for (const field of [
      'connection_started_at',
      'last_connection_closed_at',
    ] as const) {
      if (descriptor[field] !== undefined) {
        requireIsoDate(descriptor[field], `${path}[${index}].${field}`);
      }
    }
    if (descriptor.last_connection_state !== undefined && ![
      'disconnected',
      'interrupted',
      'closed',
    ].includes(requireString(
      descriptor.last_connection_state,
      `${path}[${index}].last_connection_state`,
    ))) {
      throw new PersistedStateVersionError(
        `${path}[${index}].last_connection_state is invalid`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (descriptor.auth_status !== undefined && ![
      'shell_confirmed',
      'connected_unconfirmed',
      'auth_prompt',
      'auth_failed',
    ].includes(requireString(descriptor.auth_status, `${path}[${index}].auth_status`))) {
      throw new PersistedStateVersionError(
        `${path}[${index}].auth_status is invalid`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
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
    if (
      resume.recovery_prior_state !== undefined
      && requireString(
        resume.recovery_prior_state,
        `${path}[${index}].resume_intent.recovery_prior_state`,
      ) !== 'resume_available'
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}].resume_intent.recovery_prior_state is invalid`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (
      resume.recovery_prior_state !== undefined
      && lifecycle !== 'resume_available'
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}].resume_intent.recovery_prior_state requires resume_available lifecycle`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    requireIsoDate(resume.recorded_at, `${path}[${index}].resume_intent.recorded_at`);
    if (
      lifecycle === 'resume_available'
      && (
        resume.policy !== 'manual'
        || resume.requested !== true
        || descriptor.kind !== 'socket'
        || descriptor.mode !== 'listen'
        || descriptor.accept_mode !== 'rearm'
      )
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}] resume_available requires a requested manual rearm listener`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (lifecycle !== 'connected' && descriptor.connection_id !== undefined) {
      throw new PersistedStateVersionError(
        `${path}[${index}].connection_id is only valid for connected lifecycle`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (
      lifecycle === 'connected'
      && connectionGeneration !== undefined
      && connectionGeneration < 1
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}] connected lifecycle requires connection_generation >= 1`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (
      descriptor.connection_id !== undefined
      && (
        connectionGeneration === undefined
        || connectionGeneration < 1
      )
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}].connection_id requires a positive connection_generation`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
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
    for (const field of [
      'identity_recorded_at',
      'ownership_acknowledged_at',
      'launched_at',
      'last_output_at',
      'completed_at',
    ] as const) {
      if (run[field] !== undefined) requireIsoDate(run[field], `${path}[${index}].${field}`);
    }
    for (const field of [
      'task_id',
      'action_id',
      'agent_id',
      'process_start_identity',
      'ownership_token',
      'daemon_owner',
      'ownership_mode',
      'signal_scope',
      'exit_signal',
      'action_started_event_id',
      'action_terminal_event_id',
      'recovery_warning',
    ] as const) {
      if (run[field] !== undefined && run[field] !== null) {
        requireString(run[field], `${path}[${index}].${field}`, field === 'recovery_warning');
      }
    }
    for (const field of ['pid', 'target_pid', 'process_group_id'] as const) {
      if (run[field] !== undefined) requireSafeInteger(run[field], `${path}[${index}].${field}`, 1);
    }
    if (run.exit_code !== undefined && run.exit_code !== null) {
      requireSafeInteger(run.exit_code, `${path}[${index}].exit_code`);
    }
    if (run.command_fingerprint !== undefined
      && !/^[a-f0-9]{64}$/.test(requireString(run.command_fingerprint, `${path}[${index}].command_fingerprint`))) {
      throw new PersistedStateVersionError(`${path}[${index}].command_fingerprint must be a lowercase SHA-256 digest`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (run.ownership_mode !== undefined && !['managed_supervisor', 'external_adopted'].includes(
      requireString(run.ownership_mode, `${path}[${index}].ownership_mode`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].ownership_mode is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (run.signal_scope !== undefined && !['process_group', 'pid', 'none'].includes(
      requireString(run.signal_scope, `${path}[${index}].signal_scope`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].signal_scope is invalid`, CURRENT_STATE_VERSION, 'invalid');
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
    if (run.finalization_status !== undefined && !['completed', 'failed', 'interrupted', 'unknown'].includes(
      requireString(run.finalization_status, `${path}[${index}].finalization_status`),
    )) {
      throw new PersistedStateVersionError(`${path}[${index}].finalization_status is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (run.ownership_mode === 'external_adopted' && run.signal_scope !== 'none') {
      throw new PersistedStateVersionError(
        `${path}[${index}] external_adopted ownership requires signal_scope none`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (run.lifecycle === 'running' && run.ownership_mode === 'managed_supervisor') {
      if (run.pid === undefined || run.ownership_acknowledged_at === undefined) {
        throw new PersistedStateVersionError(
          `${path}[${index}] running managed ownership requires an acknowledged pid`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (run.process_start_identity === undefined) {
        throw new PersistedStateVersionError(
          `${path}[${index}] running managed ownership requires a process start identity`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (run.ownership_token === undefined) {
        throw new PersistedStateVersionError(
          `${path}[${index}] running managed ownership requires an ownership token`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (
        run.signal_scope === 'process_group'
        && (run.process_group_id === undefined || run.process_group_id !== run.pid)
      ) {
        throw new PersistedStateVersionError(
          `${path}[${index}] running group ownership requires a supervisor-owned process group`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
    }
    if (
      run.finalization_status !== undefined
      && run.finalization_status !== run.lifecycle
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}].finalization_status must match lifecycle`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
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
    for (const field of [
      'task_id',
      'action_id',
      'agent_id',
      'target_node',
      'process_start_identity',
      'ownership_token',
      'daemon_owner',
      'ownership_mode',
      'signal_scope',
      'recovery_warning',
    ] as const) {
      if (process[field] !== undefined) {
        requireString(
          process[field],
          `${path}[${index}].${field}`,
          field === 'recovery_warning',
        );
      }
    }
    if (process.process_group_id !== undefined) {
      requireSafeInteger(process.process_group_id, `${path}[${index}].process_group_id`, 1);
    }
    if (process.command_fingerprint !== undefined
      && !/^[a-f0-9]{64}$/.test(requireString(
        process.command_fingerprint,
        `${path}[${index}].command_fingerprint`,
      ))) {
      throw new PersistedStateVersionError(
        `${path}[${index}].command_fingerprint must be a lowercase SHA-256 digest`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (process.ownership_mode !== undefined && !['managed_supervisor', 'external_adopted'].includes(
      requireString(process.ownership_mode, `${path}[${index}].ownership_mode`),
    )) {
      throw new PersistedStateVersionError(
        `${path}[${index}].ownership_mode is invalid`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (process.signal_scope !== undefined && !['process_group', 'pid', 'none'].includes(
      requireString(process.signal_scope, `${path}[${index}].signal_scope`),
    )) {
      throw new PersistedStateVersionError(
        `${path}[${index}].signal_scope is invalid`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (process.ownership_mode === 'external_adopted' && process.signal_scope !== 'none') {
      throw new PersistedStateVersionError(
        `${path}[${index}] external_adopted ownership requires signal_scope none`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
    if (
      process.status === 'running'
      && process.signal_scope === 'process_group'
      && (process.process_group_id === undefined || process.process_group_id !== process.pid)
    ) {
      throw new PersistedStateVersionError(
        `${path}[${index}] running group ownership requires a supervisor-owned process group`,
        CURRENT_STATE_VERSION,
        'invalid',
      );
    }
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
    if (
      reference.size_bytes !== undefined
      && (!Number.isSafeInteger(reference.size_bytes) || (reference.size_bytes as number) < 0)
    ) {
      throw new PersistedStateVersionError(`${referencePath}.size_bytes must be a non-negative safe integer`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (
      reference.availability !== undefined
      && !['available', 'missing', 'invalid'].includes(String(reference.availability))
    ) {
      throw new PersistedStateVersionError(`${referencePath}.availability is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (
      reference.integrity !== undefined
      && !['verified', 'unverified'].includes(String(reference.integrity))
    ) {
      throw new PersistedStateVersionError(`${referencePath}.integrity is invalid`, CURRENT_STATE_VERSION, 'invalid');
    }
    if (reference.bundle_id !== undefined) requireString(reference.bundle_id, `${referencePath}.bundle_id`);
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
  if (references.generation_registrations !== undefined) {
    const generationKeys = new Set<string>();
    requireArray(references.generation_registrations, `${path}.generation_registrations`)
      .forEach((candidate, index) => {
        const registrationPath = `${path}.generation_registrations[${index}]`;
        const registration = requireRecord(candidate, registrationPath);
        requireSafeInteger(registration.registry_version, `${registrationPath}.registry_version`, 1);
        const root = requireString(registration.root, `${registrationPath}.root`);
        const namespace = requireString(registration.namespace, `${registrationPath}.namespace`);
        if (!root || !/^[A-Za-z0-9_-]{1,64}$/.test(namespace)) {
          throw new PersistedStateVersionError(`${registrationPath} is invalid`, CURRENT_STATE_VERSION, 'invalid');
        }
        const key = `${namespace}\0${root}`;
        if (generationKeys.has(key)) {
          throw new PersistedStateVersionError(`${path} contains duplicate artifact generation ${namespace}:${root}`, CURRENT_STATE_VERSION, 'invalid');
        }
        generationKeys.add(key);
        requireArray(registration.legacy_names, `${registrationPath}.legacy_names`)
          .forEach((name, nameIndex) => {
            const value = requireString(name, `${registrationPath}.legacy_names[${nameIndex}]`);
            if (
              !value
              || value.includes('\0')
              || value.startsWith('/')
              || value.split(/[\\/]+/).some(segment => segment === '.' || segment === '..')
            ) {
              throw new PersistedStateVersionError(
                `${registrationPath}.legacy_names[${nameIndex}] is invalid`,
                CURRENT_STATE_VERSION,
                'invalid',
              );
            }
          });
      });
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
  validateMapTuples(record.playbookRuns, 'persisted playbookRuns', validatePlaybookRun);
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
  if (record.applicationCommands !== undefined) {
    const commandIds = new Set<string>();
    validateMapTuples(record.applicationCommands, 'persisted applicationCommands', (candidate, path, key) => {
      const command = requireRecord(candidate, path);
      const commandId = requireString(command.command_id, `${path}.command_id`);
      if (commandIds.has(commandId)) {
        throw new PersistedStateVersionError(
          `persisted applicationCommands contains duplicate command_id ${commandId}`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      commandIds.add(commandId);
      const idempotencyKey = requireString(command.idempotency_key, `${path}.idempotency_key`);
      if (idempotencyKey !== key) {
        throw new PersistedStateVersionError(
          `${path}.idempotency_key must match map key`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (commandId.length > 256 || idempotencyKey.length > 512) {
        throw new PersistedStateVersionError(
          `${path} command identifiers exceed their supported length`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (!/^[a-f0-9]{64}$/.test(requireString(command.input_sha256, `${path}.input_sha256`))) {
        throw new PersistedStateVersionError(
          `${path}.input_sha256 must be a lowercase SHA-256 digest`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (command.validated_input === undefined) {
        throw new PersistedStateVersionError(
          `${path}.validated_input is required`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      try {
        JSON.stringify(command.validated_input);
      } catch {
        throw new PersistedStateVersionError(
          `${path}.validated_input must be JSON-serializable`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      requireString(command.command_kind, `${path}.command_kind`);
      if (![
        'mcp',
        'dashboard',
        'cli',
        'planner',
        'scripted_runner',
        'headless_runner',
        'system',
      ].includes(requireString(command.transport, `${path}.transport`))) {
        throw new PersistedStateVersionError(
          `${path}.transport is invalid`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      if (command.actor_task_id !== null) {
        requireString(command.actor_task_id, `${path}.actor_task_id`);
      }
      if (!['accepted', 'running', 'succeeded', 'failed', 'interrupted'].includes(
        requireString(command.status, `${path}.status`),
      )) {
        throw new PersistedStateVersionError(
          `${path}.status is invalid`,
          CURRENT_STATE_VERSION,
          'invalid',
        );
      }
      requireIsoDate(command.created_at, `${path}.created_at`);
      if (command.started_at !== undefined) requireIsoDate(command.started_at, `${path}.started_at`);
      if (command.completed_at !== undefined) requireIsoDate(command.completed_at, `${path}.completed_at`);
      for (const field of ['action_id', 'frontier_item_id', 'plan_id'] as const) {
        if (command[field] !== undefined) requireString(command[field], `${path}.${field}`);
      }
      if (command.error !== undefined) {
        const error = requireRecord(command.error, `${path}.error`);
        requireString(error.message, `${path}.error.message`, true);
        if (error.code !== undefined) requireString(error.code, `${path}.error.code`);
      }
      if (command.entity_refs !== undefined) {
        const refs = requireRecord(command.entity_refs, `${path}.entity_refs`);
        for (const [name, value] of Object.entries(refs)) {
          if (typeof value === 'string') {
            requireString(value, `${path}.entity_refs.${name}`);
          } else {
            for (const [index, item] of requireArray(value, `${path}.entity_refs.${name}`).entries()) {
              requireString(item, `${path}.entity_refs.${name}[${index}]`);
            }
          }
        }
      }
    });
  }
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
