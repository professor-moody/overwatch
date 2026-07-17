import { createHash, randomUUID } from 'node:crypto';
import type { GraphEngine } from './graph-engine.js';
import { canonicalJson } from './engagement-config-service.js';
import { getApplicationCommandInvocation } from './application-command-service.js';
import type {
  PersistedDurablePlaybookRunV1,
  PersistedPlaybookAttemptV1,
  PersistedPlaybookDefinitionV1,
  PersistedPlaybookRunV1,
  PersistedPlaybookStepDefinitionV1,
  PersistedPlaybookStepRunV1,
  PlaybookRunStatus,
} from './persisted-state.js';

export type PlaybookParseOutcome =
  | 'ok'
  | 'no_data'
  | 'validation_failed'
  | 'parser_exception'
  | 'partial';

export interface OpenPlaybookInput {
  definition: PersistedPlaybookDefinitionV1;
  credential_id: string;
  normalized_inputs: Record<string, unknown>;
  bindings?: Record<string, unknown>;
  steps: Array<Record<string, unknown>>;
  new_run?: boolean;
}

export interface PlaybookStepClaim {
  run: PersistedDurablePlaybookRunV1;
  step: PersistedPlaybookStepRunV1;
  attempt: PersistedPlaybookAttemptV1;
  execution: Record<string, unknown>;
}

export interface PlaybookAttemptResult {
  execution_outcome: 'succeeded' | 'failed' | 'interrupted';
  parse_outcome?: PlaybookParseOutcome;
  action_id?: string;
  evidence_ids?: string[];
  finding_ids?: string[];
  error?: string;
}

export interface PlaybookAttemptLinkage {
  playbook_run_id?: string;
  playbook_step_id?: string;
  playbook_attempt_id?: string;
  command_id?: string;
  idempotency_key?: string;
  action_id?: string;
}

export class PlaybookRunError extends Error {
  constructor(
    message: string,
    readonly code:
      | 'PLAYBOOK_NOT_FOUND'
      | 'PLAYBOOK_LEGACY_RECORD'
      | 'PLAYBOOK_STEP_NOT_FOUND'
      | 'PLAYBOOK_CONFLICT'
      | 'PLAYBOOK_BLOCKED'
      | 'PLAYBOOK_ATTEMPT_NOT_FOUND',
    readonly http_status: 404 | 409 = code.includes('NOT_FOUND') ? 404 : 409,
  ) {
    super(message);
    this.name = 'PlaybookRunError';
  }
}

const listeners = new WeakMap<GraphEngine, Set<(run: PersistedDurablePlaybookRunV1) => void>>();

function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function now(engine: GraphEngine): string {
  return engine.now();
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? structuredClone(value as Record<string, unknown>)
    : {};
}

function withoutSecrets(value: unknown, key = '', parentKey = ''): unknown {
  // Environment-variable names and env_from_credential values are references,
  // not credential material. Redacting them would corrupt the executable plan.
  if (parentKey === 'env_from_credential' || /_env_var$/i.test(key)) {
    return structuredClone(value);
  }
  if (
    key
    && !/^(credential_id|source_credential_id|credential_execution_binding)$/i.test(key)
    && /(cred_value|password|private[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?cookie|authorization|bearer|secret_value)/i.test(key)
  ) return '<redacted>';
  if (Array.isArray(value)) return value.map(item => withoutSecrets(item, '', key));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([childKey, child]) => [childKey, withoutSecrets(child, childKey, key)]));
  }
  return value;
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((candidate): candidate is string => typeof candidate === 'string' && candidate.length > 0))]
    : [];
}

function durableRun(value: PersistedPlaybookRunV1): value is PersistedDurablePlaybookRunV1 {
  return value.schema_version === 1;
}

function stepId(definitionId: string, descriptor: Record<string, unknown>): string {
  if (typeof descriptor.step_id === 'string' && descriptor.step_id.trim()) return descriptor.step_id.trim();
  const stable = sha256({
    definition_id: definitionId,
    description: descriptor.description,
    parse_with: descriptor.parse_with,
    tool: descriptor.tool,
  }).slice(0, 16);
  return `${definitionId}:${stable}`;
}

function normalizeDescriptor(
  definitionId: string,
  descriptorInput: Record<string, unknown>,
  index: number,
): { definition: PersistedPlaybookStepDefinitionV1; step: PersistedPlaybookStepRunV1 } {
  const descriptor = withoutSecrets(asRecord(descriptorInput)) as Record<string, unknown>;
  const ordinal = Number.isSafeInteger(descriptor.step) && Number(descriptor.step) > 0
    ? Number(descriptor.step)
    : index + 1;
  const id = stepId(definitionId, descriptor);
  const description = typeof descriptor.description === 'string' && descriptor.description.trim()
    ? descriptor.description
    : `Playbook step ${ordinal}`;
  const dependsOn = strings(descriptor.depends_on);
  const requiredBindings = strings(descriptor.required_bindings);
  const producesBindings = strings(descriptor.produces_bindings);
  const explicitlyBlocked = descriptor.status === 'blocked'
    || descriptor.ready === false
    || descriptor.command === null;
  const blockedReason = typeof descriptor.blocked_reason === 'string'
    ? descriptor.blocked_reason
    : explicitlyBlocked
      ? 'The execution descriptor is not ready; required dependencies or bindings are unresolved.'
      : undefined;
  const execution = {
    ...descriptor,
    step: ordinal,
    step_id: id,
    depends_on: dependsOn,
    required_bindings: requiredBindings,
    produces_bindings: producesBindings,
    ready: !explicitlyBlocked,
    status: explicitlyBlocked ? 'blocked' : 'ready',
  };
  const definition: PersistedPlaybookStepDefinitionV1 = {
    step_id: id,
    ordinal,
    description,
    depends_on: dependsOn,
    required_bindings: requiredBindings,
    produces_bindings: producesBindings,
    execution_template: structuredClone(execution),
  };
  return {
    definition,
    step: {
      step_id: id,
      ordinal,
      description,
      status: explicitlyBlocked ? 'blocked' : 'pending',
      depends_on: dependsOn,
      required_bindings: requiredBindings,
      produces_bindings: producesBindings,
      resolved_bindings: {},
      resolved_execution: structuredClone(execution),
      blocked_reason: blockedReason,
      attempts: [],
      updated_at: '',
    },
  };
}

function descriptorBindings(descriptor: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!descriptor) return {};
  const sources = [descriptor.bindings, descriptor.parser_context, descriptor.args]
    .filter((value): value is Record<string, unknown> =>
      !!value && typeof value === 'object' && !Array.isArray(value));
  const bindings: Record<string, unknown> = {};
  for (const source of sources) {
    for (const [key, value] of Object.entries(source)) {
      if (value !== undefined && value !== null && ['string', 'number', 'boolean'].includes(typeof value)) {
        bindings[key] = structuredClone(value);
      }
    }
  }
  return bindings;
}

function missingBindings(bindings: Record<string, unknown>, requirements: string[]): string[] {
  return requirements.filter(requirement => {
    const separator = requirement.indexOf('=');
    const key = separator === -1 ? requirement : requirement.slice(0, separator);
    const expected = separator === -1 ? undefined : requirement.slice(separator + 1);
    const actual = bindings[key];
    if (actual === undefined || actual === null || actual === '') return true;
    return expected !== undefined && String(actual) !== expected;
  });
}

function semanticExecutionHash(execution: Record<string, unknown> | undefined): string {
  if (!execution) return sha256(null);
  const {
    step: _step,
    description: _description,
    expected: _expected,
    ready: _ready,
    status: _status,
    blocked_reason: _blockedReason,
    ...semantic
  } = execution;
  return sha256(semantic);
}

function attemptPlanReference(
  run: PersistedDurablePlaybookRunV1,
  step: PersistedPlaybookStepRunV1,
): { revision: number; template_hash: string } {
  const templateHash = sha256(step.resolved_execution);
  const revision = run.plan_revisions.find(candidate => candidate.revision === run.current_plan_revision);
  const definition = revision?.steps.find(candidate => candidate.step_id === step.step_id);
  if (!revision || !definition || sha256(definition.execution_template) !== templateHash) {
    throw new PlaybookRunError(
      `Playbook step ${step.step_id} is not actionable in current plan revision ${run.current_plan_revision}. Re-expand the playbook before execution.`,
      'PLAYBOOK_CONFLICT',
    );
  }
  return { revision: revision.revision, template_hash: templateHash };
}

const EXECUTION_METADATA_KEYS = new Set([
  'step', 'step_id', 'expected', 'blocking', 'runner', 'tool',
  'env_from_credential', 'ready', 'status', 'depends_on', 'required_bindings',
  'produces_bindings', 'blocked_reason', 'est_noise', 'destructive',
]);
const EXECUTION_LINKAGE_KEYS = new Set([
  'playbook_run_id', 'playbook_step_id', 'playbook_attempt_id',
  'command_id', 'idempotency_key', 'action_id',
]);
const EXECUTION_ACTOR_KEYS = new Set(['agent_id', 'frontier_item_id']);

function withoutExecutionLinkage(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutExecutionLinkage);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .filter(([key]) => !EXECUTION_LINKAGE_KEYS.has(key))
    .map(([key, nested]) => [key, withoutExecutionLinkage(nested)]));
}

function immutableAttemptTemplate(
  run: PersistedDurablePlaybookRunV1,
  step: PersistedPlaybookStepRunV1,
  attempt: PersistedPlaybookAttemptV1,
): Record<string, unknown> {
  const revision = run.plan_revisions.find(candidate => candidate.revision === attempt.plan_revision);
  const definition = revision?.steps.find(candidate => candidate.step_id === step.step_id);
  if (!definition || sha256(definition.execution_template) !== attempt.execution_template_hash) {
    throw new PlaybookRunError(
      `Playbook attempt ${attempt.attempt_id} is not backed by its recorded immutable execution template.`,
      'PLAYBOOK_CONFLICT',
    );
  }
  return definition.execution_template;
}

function assertInvocationMatchesTemplate(
  template: Record<string, unknown>,
  invocation: Record<string, unknown>,
  attemptId: string,
  credentialValue: (credentialId: string) => string | undefined,
): void {
  const expected = typeof template.tool === 'string'
    && template.args && typeof template.args === 'object' && !Array.isArray(template.args)
    ? template.args as Record<string, unknown>
    : template;
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (EXECUTION_METADATA_KEYS.has(key) || EXECUTION_LINKAGE_KEYS.has(key)) continue;
    const actualValue = invocation[key];
    if (expectedValue === undefined) continue;
    if (actualValue === undefined
      || canonicalJson(withoutExecutionLinkage(actualValue))
      !== canonicalJson(withoutExecutionLinkage(expectedValue))) {
      throw new PlaybookRunError(
        `Runner input for playbook attempt ${attemptId} does not match the immutable ${key} value. Prepare a new attempt instead of editing the descriptor.`,
        'PLAYBOOK_CONFLICT',
      );
    }
  }

  const declaredKeys = new Set(Object.keys(expected));
  const credentialEnv = template.env_from_credential;
  const credentialEnvEntries = credentialEnv
    && typeof credentialEnv === 'object'
    && !Array.isArray(credentialEnv)
    ? Object.entries(credentialEnv as Record<string, unknown>)
    : [];
  for (const [key, actualValue] of Object.entries(invocation)) {
    if (actualValue === undefined
      || declaredKeys.has(key)
      || EXECUTION_LINKAGE_KEYS.has(key)
      || EXECUTION_ACTOR_KEYS.has(key)) continue;

    // MCP's public process schemas materialize these safe defaults. They do
    // not broaden the immutable descriptor and therefore compare as absence.
    if (key === 'validate' && actualValue === true) continue;
    if (key === 'args' && Array.isArray(actualValue) && actualValue.length === 0) continue;

    // Credential material is deliberately excluded from the immutable plan.
    // Permit only the exact environment-variable names declared by
    // env_from_credential, and never accept the credential node ID as the
    // value that reaches the child process.
    if (key === 'env'
      && actualValue
      && typeof actualValue === 'object'
      && !Array.isArray(actualValue)
      && credentialEnvEntries.length > 0) {
      const actualEntries = Object.entries(actualValue as Record<string, unknown>);
      const expectedNames = credentialEnvEntries.map(([name]) => name).sort();
      const actualNames = actualEntries.map(([name]) => name).sort();
      const valuesAreResolved = actualEntries.every(([name, value]) => {
        const credentialId = credentialEnvEntries.find(([expectedName]) => expectedName === name)?.[1];
        const expectedValue = typeof credentialId === 'string'
          ? credentialValue(credentialId)
          : undefined;
        return typeof value === 'string' && expectedValue !== undefined && value === expectedValue;
      });
      if (canonicalJson(actualNames) === canonicalJson(expectedNames) && valuesAreResolved) continue;
    }

    throw new PlaybookRunError(
      `Runner input for playbook attempt ${attemptId} contains unclaimed execution field ${key}. Prepare a new attempt instead of extending the descriptor.`,
      'PLAYBOOK_CONFLICT',
    );
  }
}

function replayReceiptOutcome(result: unknown): PlaybookAttemptResult['execution_outcome'] | undefined {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return undefined;
  const receipt = result as Record<string, unknown>;
  if (receipt.interrupted === true
    || receipt.timed_out === true
    || receipt.approval_status === 'aborted'
    || receipt.code === 'PERSISTENCE_INTERRUPTED'
    || receipt.code === 'COMMAND_INTERRUPTED') return 'interrupted';
  if (receipt.is_error === true || receipt.executed === false || receipt.spawn_error) return 'failed';
  return 'succeeded';
}

function isTerminal(status: PlaybookRunStatus): boolean {
  return ['succeeded', 'failed', 'skipped', 'cancelled'].includes(status);
}

function activeAttempt(step: PersistedPlaybookStepRunV1): PersistedPlaybookAttemptV1 | undefined {
  return step.attempts.find(attempt => ['claimed', 'awaiting_approval', 'running'].includes(attempt.status));
}

function currentPlanStepIds(run: PersistedDurablePlaybookRunV1): Set<string> {
  const revision = run.plan_revisions.find(candidate => candidate.revision === run.current_plan_revision);
  return new Set(revision?.steps.map(step => step.step_id) ?? []);
}

function updateDerivedStatus(run: PersistedDurablePlaybookRunV1): void {
  const currentIds = currentPlanStepIds(run);
  const steps = run.steps.filter(step => currentIds.has(step.step_id));
  const attempts = run.steps.flatMap(step => step.attempts);
  const hasPartial = attempts.some(attempt => attempt.parse_outcome === 'partial');
  const active = run.steps.map(step => step.status)
    .find(status => status === 'running' || status === 'awaiting_approval');
  if (active) {
    delete run.completed_at;
    run.status = active;
    run.report_status = attempts.length === 0 ? 'generated' : 'partial';
    return;
  }
  if (steps.length > 0 && steps.every(step => step.status === 'succeeded' || step.status === 'skipped')) {
    const allSkipped = steps.every(step => step.status === 'skipped');
    run.status = allSkipped ? 'skipped' : 'succeeded';
    run.report_status = allSkipped || hasPartial ? 'partial' : 'completed';
    run.completed_at ??= run.updated_at;
    return;
  }
  delete run.completed_at;
  if (steps.some(step => step.status === 'running')) run.status = 'running';
  else if (steps.some(step => step.status === 'awaiting_approval')) run.status = 'awaiting_approval';
  else if (steps.some(step => step.status === 'interrupted')) run.status = 'interrupted';
  else if (steps.some(step => step.status === 'failed')) run.status = 'failed';
  else {
    const unfinished = steps.filter(step => !isTerminal(step.status));
    run.status = unfinished.length > 0 && unfinished.every(step => step.status === 'blocked')
      ? 'blocked'
      : 'pending';
  }
  run.report_status = attempts.length === 0
    ? 'generated'
    : 'partial';
  if (hasPartial) run.report_status = 'partial';
}

function refreshDependencyState(run: PersistedDurablePlaybookRunV1): void {
  const byId = new Map(run.steps.map(step => [step.step_id, step]));
  for (const step of run.steps) {
    step.resolved_bindings = {
      ...structuredClone(run.bindings),
      ...descriptorBindings(step.resolved_execution),
    };
    if (isTerminal(step.status) || step.status === 'running' || step.status === 'interrupted') continue;
    const unsatisfied = step.depends_on.filter(dependency => byId.get(dependency)?.status !== 'succeeded');
    const unresolvedBindings = missingBindings(step.resolved_bindings, step.required_bindings);
    const descriptorReady = step.resolved_execution?.ready !== false
      && step.resolved_execution?.status !== 'blocked'
      && step.resolved_execution?.command !== null;
    if (unsatisfied.length > 0) {
      step.status = 'blocked';
      step.blocked_reason = `Waiting for dependencies: ${unsatisfied.join(', ')}`;
    } else if (unresolvedBindings.length > 0) {
      step.status = 'blocked';
      step.blocked_reason = `Waiting for bindings: ${unresolvedBindings.join(', ')}`;
    } else if (!descriptorReady) {
      step.status = 'blocked';
      step.blocked_reason = typeof step.resolved_execution?.blocked_reason === 'string'
        ? step.resolved_execution.blocked_reason
        : 'Required bindings are unresolved.';
    } else {
      step.status = 'pending';
      delete step.blocked_reason;
    }
  }
  updateDerivedStatus(run);
}

export class PlaybookRunService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly publishChanges = true,
  ) {}

  static onChange(
    engine: GraphEngine,
    listener: (run: PersistedDurablePlaybookRunV1) => void,
  ): () => void {
    let bucket = listeners.get(engine);
    if (!bucket) {
      bucket = new Set();
      listeners.set(engine, bucket);
    }
    bucket.add(listener);
    return () => bucket?.delete(listener);
  }

  publish(run: PersistedDurablePlaybookRunV1): void {
    for (const listener of listeners.get(this.engine) ?? []) {
      try { listener(structuredClone(run)); } catch { /* observers cannot fail a durable command */ }
    }
  }

  list(filter: {
    credential_id?: string;
    status?: PlaybookRunStatus;
    open_only?: boolean;
  } = {}): PersistedPlaybookRunV1[] {
    return this.engine.getPlaybookRuns()
      .filter(run => !filter.credential_id || (durableRun(run) && run.credential_id === filter.credential_id))
      .filter(run => !filter.status || (durableRun(run) && run.status === filter.status))
      .filter(run => !filter.open_only || (durableRun(run) && !['succeeded', 'skipped', 'cancelled'].includes(run.status)))
      .sort((left, right) => {
        const leftAt = durableRun(left) ? left.updated_at : '';
        const rightAt = durableRun(right) ? right.updated_at : '';
        return rightAt.localeCompare(leftAt) || left.run_id.localeCompare(right.run_id);
      });
  }

  get(runId: string): PersistedPlaybookRunV1 {
    const run = this.engine.getPlaybookRun(runId);
    if (!run) throw new PlaybookRunError(`Playbook run not found: ${runId}`, 'PLAYBOOK_NOT_FOUND');
    return run;
  }

  getDurable(runId: string): PersistedDurablePlaybookRunV1 {
    const run = this.get(runId);
    if (!durableRun(run)) {
      throw new PlaybookRunError(
        `Playbook run ${runId} is a legacy placeholder and cannot be executed. Start a new run.`,
        'PLAYBOOK_LEGACY_RECORD',
      );
    }
    return run;
  }

  open(input: OpenPlaybookInput): { run: PersistedDurablePlaybookRunV1; created: boolean } {
    const normalizedInputs = withoutSecrets(input.normalized_inputs) as Record<string, unknown>;
    const resolvedBindings = withoutSecrets(input.bindings ?? {}) as Record<string, unknown>;
    const inputHash = sha256(normalizedInputs);
    const matches = this.engine.getPlaybookRuns()
      .filter((candidate): candidate is PersistedDurablePlaybookRunV1 =>
        durableRun(candidate)
        && candidate.definition.definition_id === input.definition.definition_id
        && candidate.definition.definition_version === input.definition.definition_version
        && candidate.credential_id === input.credential_id
        && candidate.input_hash === inputHash
        && candidate.status !== 'cancelled')
      .sort((left, right) => {
        const leftOpen = ['succeeded', 'skipped'].includes(left.status) ? 0 : 1;
        const rightOpen = ['succeeded', 'skipped'].includes(right.status) ? 0 : 1;
        return rightOpen - leftOpen || right.updated_at.localeCompare(left.updated_at);
      });
    const existing = input.new_run ? undefined : matches[0];
    const at = now(this.engine);
    const normalizedSteps = input.steps.map((step, index) =>
      normalizeDescriptor(input.definition.definition_id, step, index));
    const planSteps = normalizedSteps.map(step => step.definition);
    const planHash = sha256(planSteps);

    if (existing) {
      const run = structuredClone(existing);
      run.bindings = resolvedBindings;
      const latest = run.plan_revisions.find(revision => revision.plan_hash === planHash);
      if (!latest) {
        run.plan_revisions.push({
          revision: Math.max(0, ...run.plan_revisions.map(revision => revision.revision)) + 1,
          created_at: at,
          plan_hash: planHash,
          steps: planSteps,
        });
      }
      run.current_plan_revision = run.plan_revisions.find(revision => revision.plan_hash === planHash)!.revision;
      const byId = new Map(run.steps.map(step => [step.step_id, step]));
      const currentStepIds = new Set(normalizedSteps.map(normalized => normalized.step.step_id));
      for (const prior of run.steps) {
        if (currentStepIds.has(prior.step_id) || activeAttempt(prior)) continue;
        prior.status = 'cancelled';
        prior.completed_at ??= at;
        prior.updated_at = at;
        prior.blocked_reason = `Superseded by playbook plan revision ${run.current_plan_revision}.`;
      }
      for (const normalized of normalizedSteps) {
        const prior = byId.get(normalized.step.step_id);
        if (!prior) {
          normalized.step.updated_at = at;
          run.steps.push(normalized.step);
          continue;
        }
        // An active attempt owns the exact descriptor it claimed. Record the
        // newer immutable plan revision, but do not swap the live step beneath
        // the runner; a later expansion materializes it after terminalization.
        if (activeAttempt(prior)) {
          prior.updated_at = at;
          continue;
        }
        const executionChanged = semanticExecutionHash(prior.resolved_execution)
          !== semanticExecutionHash(normalized.step.resolved_execution);
        prior.ordinal = normalized.step.ordinal;
        prior.description = normalized.step.description;
        prior.depends_on = normalized.step.depends_on;
        prior.required_bindings = normalized.step.required_bindings;
        prior.produces_bindings = normalized.step.produces_bindings;
        prior.resolved_execution = normalized.step.resolved_execution;
        if (prior.status === 'cancelled') {
          const lastAttempt = prior.attempts.at(-1);
          const sameCompletedTemplate = !!lastAttempt
            && lastAttempt.execution_template_hash === sha256(normalized.step.resolved_execution)
            && ['succeeded', 'failed', 'interrupted'].includes(lastAttempt.status);
          prior.status = sameCompletedTemplate
            ? lastAttempt.status as PlaybookRunStatus
            : normalized.step.status;
          prior.blocked_reason = normalized.step.blocked_reason;
          if (!sameCompletedTemplate) delete prior.completed_at;
        } else if (prior.status === 'succeeded' && executionChanged) {
          prior.status = normalized.step.status;
          prior.blocked_reason = normalized.step.blocked_reason;
          delete prior.completed_at;
        } else if (!isTerminal(prior.status) && prior.status !== 'running' && prior.status !== 'interrupted') {
          prior.status = normalized.step.status;
          prior.blocked_reason = normalized.step.blocked_reason;
        }
        prior.updated_at = at;
      }
      run.steps.sort((left, right) => left.ordinal - right.ordinal || left.step_id.localeCompare(right.step_id));
      run.updated_at = at;
      refreshDependencyState(run);
      return { run: this.save(run), created: false };
    }

    const run: PersistedDurablePlaybookRunV1 = {
      schema_version: 1,
      run_id: `playbook_${randomUUID()}`,
      definition: structuredClone(input.definition),
      credential_id: input.credential_id,
      input_hash: inputHash,
      normalized_inputs: normalizedInputs,
      bindings: resolvedBindings,
      plan_revisions: [{ revision: 1, created_at: at, plan_hash: planHash, steps: planSteps }],
      current_plan_revision: 1,
      steps: normalizedSteps.map(({ step }) => ({ ...step, updated_at: at })),
      status: 'pending',
      report_status: 'generated',
      created_at: at,
      updated_at: at,
      resume_count: 0,
    };
    refreshDependencyState(run);
    return { run: this.save(run), created: true };
  }

  startStep(runId: string, stepId: string): PlaybookStepClaim {
    return this.claimStep(runId, stepId, false);
  }

  retryStep(runId: string, stepId: string): PlaybookStepClaim {
    return this.claimStep(runId, stepId, true);
  }

  resume(runId: string): PersistedDurablePlaybookRunV1 {
    const run = structuredClone(this.getDurable(runId));
    if (!run.steps.some(step => step.status === 'interrupted')) {
      throw new PlaybookRunError(`Playbook run ${runId} is ${run.status} and cannot be resumed.`, 'PLAYBOOK_CONFLICT');
    }
    const at = now(this.engine);
    for (const step of run.steps) {
      if (step.status === 'interrupted') {
        step.status = 'pending';
        delete step.completed_at;
        step.updated_at = at;
      }
    }
    run.resume_count += 1;
    run.updated_at = at;
    delete run.completed_at;
    refreshDependencyState(run);
    return this.save(run);
  }

  skipStep(runId: string, stepId: string, reason?: string): PersistedDurablePlaybookRunV1 {
    const run = structuredClone(this.getDurable(runId));
    if (run.steps.some(step => activeAttempt(step))) {
      throw new PlaybookRunError('A playbook attempt is already running. Finish or interrupt it before skipping another step.', 'PLAYBOOK_CONFLICT');
    }
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    if (!step) throw new PlaybookRunError(`Playbook step not found: ${stepId}`, 'PLAYBOOK_STEP_NOT_FOUND');
    if (step.status === 'succeeded' || step.status === 'skipped' || step.status === 'cancelled') {
      throw new PlaybookRunError(`Playbook step ${stepId} is already ${step.status}.`, 'PLAYBOOK_CONFLICT');
    }
    const at = now(this.engine);
    step.status = 'skipped';
    step.completed_at = at;
    step.updated_at = at;
    step.blocked_reason = reason?.trim() || 'Skipped by the operator.';
    run.updated_at = at;
    refreshDependencyState(run);
    return this.save(run);
  }

  interruptAttempt(runId: string, stepId: string, reason?: string): PersistedDurablePlaybookRunV1 {
    const run = structuredClone(this.getDurable(runId));
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    if (!step) throw new PlaybookRunError(`Playbook step not found: ${stepId}`, 'PLAYBOOK_STEP_NOT_FOUND');
    const attempt = activeAttempt(step);
    if (!attempt) {
      throw new PlaybookRunError(`Playbook step ${stepId} has no active attempt to interrupt.`, 'PLAYBOOK_CONFLICT');
    }
    if (attempt.status !== 'claimed') {
      throw new PlaybookRunError(
        `Playbook step ${stepId} has already begun execution as ${attempt.execution_command_id}; release is no longer safe. Stop or await that command instead.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    const at = now(this.engine);
    attempt.status = 'interrupted';
    attempt.execution_outcome = 'interrupted';
    attempt.completed_at = at;
    attempt.error = reason?.trim() || 'The claimed step was released before execution completed.';
    step.status = 'interrupted';
    step.completed_at = at;
    step.updated_at = at;
    run.updated_at = at;
    refreshDependencyState(run);
    return this.save(run);
  }

  finishAttempt(
    runId: string,
    stepId: string,
    attemptId: string,
    result: PlaybookAttemptResult,
  ): PersistedDurablePlaybookRunV1 {
    const run = structuredClone(this.getDurable(runId));
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    if (!step) throw new PlaybookRunError(`Playbook step not found: ${stepId}`, 'PLAYBOOK_STEP_NOT_FOUND');
    const attempt = step.attempts.find(candidate => candidate.attempt_id === attemptId);
    if (!attempt) throw new PlaybookRunError(`Playbook attempt not found: ${attemptId}`, 'PLAYBOOK_ATTEMPT_NOT_FOUND');
    if (attempt.status === 'claimed' && result.execution_outcome === 'succeeded') {
      throw new PlaybookRunError(
        `Playbook attempt ${attemptId} has not crossed the execution boundary. Run the claimed descriptor before recording success.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    if (!['claimed', 'running', 'awaiting_approval'].includes(attempt.status)) {
      const sameTerminalResult = attempt.status !== 'claimed'
        && attempt.execution_outcome === result.execution_outcome
        && attempt.parse_outcome === result.parse_outcome
        && attempt.action_id === (result.action_id ?? attempt.action_id)
        && canonicalJson(attempt.evidence_ids) === canonicalJson([...new Set(result.evidence_ids ?? [])])
        && canonicalJson(attempt.finding_ids) === canonicalJson([...new Set(result.finding_ids ?? [])]);
      if (sameTerminalResult) return run;
      throw new PlaybookRunError(
        `Playbook attempt ${attemptId} is ${attempt.status} and cannot accept a different terminal result.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    if (result.action_id && result.action_id !== attempt.execution_action_id) {
      throw new PlaybookRunError(
        `Playbook attempt ${attemptId} is bound to action ${attempt.execution_action_id}, not ${result.action_id}.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    const at = now(this.engine);
    const invocation = getApplicationCommandInvocation();
    attempt.executed_via = invocation?.transport ?? 'system';
    if (invocation?.actor_task_id) attempt.executed_by_task_id = invocation.actor_task_id;
    attempt.execution_outcome = result.execution_outcome;
    attempt.parse_outcome = result.parse_outcome;
    attempt.action_id = result.action_id ?? attempt.execution_action_id;
    attempt.evidence_ids = [...new Set(result.evidence_ids ?? [])];
    attempt.finding_ids = [...new Set(result.finding_ids ?? [])];
    attempt.error = result.error;
    attempt.completed_at = at;
    const parserFailed = result.parse_outcome !== undefined
      && ['no_data', 'validation_failed', 'parser_exception'].includes(result.parse_outcome);
    attempt.status = result.execution_outcome === 'interrupted'
      ? 'interrupted'
      : result.execution_outcome === 'failed' || parserFailed
        ? 'failed'
        : 'succeeded';
    step.status = attempt.status;
    step.completed_at = at;
    step.updated_at = at;
    run.updated_at = at;
    refreshDependencyState(run);
    return this.save(run);
  }

  /** Public/manual completion may reference only artifacts that already exist
   * and are attributed to this attempt's immutable action. Ordinary runner
   * completion derives the same IDs from its internal response path. */
  finishAttemptVerified(
    runId: string,
    stepId: string,
    attemptId: string,
    result: PlaybookAttemptResult,
  ): PersistedDurablePlaybookRunV1 {
    const run = this.getDurable(runId);
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    if (!step) throw new PlaybookRunError(`Playbook step not found: ${stepId}`, 'PLAYBOOK_STEP_NOT_FOUND');
    const attempt = step.attempts.find(candidate => candidate.attempt_id === attemptId);
    if (!attempt) throw new PlaybookRunError(`Playbook attempt not found: ${attemptId}`, 'PLAYBOOK_ATTEMPT_NOT_FOUND');
    const actionId = attempt.execution_action_id;

    // A byte-identical terminal completion is an idempotent replay. The
    // original active transition already validated its artifacts and boundary;
    // finishAttempt still rejects any changed terminal payload.
    if (!['claimed', 'running', 'awaiting_approval'].includes(attempt.status)) {
      return this.finishAttempt(runId, stepId, attemptId, result);
    }

    if (result.execution_outcome === 'succeeded' && attempt.status !== 'running') {
      throw new PlaybookRunError(
        `Playbook attempt ${attemptId} is ${attempt.status}; success requires a running attempt with a durable terminal action.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    const history = this.engine.getFullHistory();
    if (attempt.status === 'running' && !history.some(entry =>
      entry.action_id === actionId
      && (entry.event_type === 'action_completed' || entry.event_type === 'action_failed'))) {
      throw new PlaybookRunError(
        `Playbook action ${actionId} has not reached a durable terminal event.`,
        'PLAYBOOK_CONFLICT',
      );
    }

    for (const evidenceId of new Set(result.evidence_ids ?? [])) {
      const record = this.engine.getEvidenceStore().getRecord(evidenceId);
      if (!record || record.evidence_id !== evidenceId || record.action_id !== actionId) {
        throw new PlaybookRunError(
          `Evidence ${evidenceId} is not a durable artifact of playbook action ${actionId}.`,
          'PLAYBOOK_CONFLICT',
        );
      }
    }
    for (const findingId of new Set(result.finding_ids ?? [])) {
      const linked = history.some(entry =>
        entry.action_id === actionId
        && (entry.event_type === 'finding_ingested' || entry.event_type === 'finding_reported')
        && entry.linked_finding_ids?.includes(findingId));
      if (!linked) {
        throw new PlaybookRunError(
          `Finding ${findingId} is not durably attributed to playbook action ${actionId}.`,
          'PLAYBOOK_CONFLICT',
        );
      }
    }
    return this.finishAttempt(runId, stepId, attemptId, result);
  }

  recoverInterruptedRuns(): number {
    if (!this.engine.isPersistenceWritable()) return 0;
    const at = now(this.engine);
    let changed = 0;
    const runs = this.engine.getPlaybookRuns();
    const recovered = runs.map(candidate => {
      if (!durableRun(candidate)) return candidate;
      const run = structuredClone(candidate);
      let runChanged = false;
      for (const step of run.steps) {
        for (const attempt of step.attempts) {
          if (!['claimed', 'awaiting_approval', 'running'].includes(attempt.status)) continue;
          if (attempt.status === 'running' || attempt.status === 'awaiting_approval') {
            const recoveredEvidence = this.engine.getEvidenceStore().list({ action_id: attempt.execution_action_id });
            attempt.evidence_ids = [...new Set([
              ...attempt.evidence_ids,
              ...recoveredEvidence.map(record => record.evidence_id),
            ])];
            const recoveredFindings = this.engine.getFullHistory()
              .filter(entry => entry.action_id === attempt.execution_action_id
                && (entry.event_type === 'finding_ingested' || entry.event_type === 'finding_reported'))
              .flatMap(entry => entry.linked_finding_ids ?? []);
            attempt.finding_ids = [...new Set([...attempt.finding_ids, ...recoveredFindings])];
            attempt.action_id = attempt.execution_action_id;
          }
          attempt.status = 'interrupted';
          attempt.execution_outcome = 'interrupted';
          attempt.completed_at = at;
          attempt.error = 'The daemon restarted before this attempt reached a durable terminal outcome.';
          step.status = 'interrupted';
          step.completed_at = at;
          step.updated_at = at;
          runChanged = true;
        }
      }
      if (!runChanged) return candidate;
      run.updated_at = at;
      refreshDependencyState(run);
      changed += 1;
      return run;
    }).filter((run): run is PersistedPlaybookRunV1 => run !== undefined);
    if (changed > 0) {
      this.engine.setPlaybookRuns(recovered);
      for (const run of recovered) {
        if (!durableRun(run) || run.updated_at !== at) continue;
        this.publish(run);
      }
    }
    return changed;
  }

  private claimStep(runId: string, stepId: string, retry: boolean): PlaybookStepClaim {
    const run = structuredClone(this.getDurable(runId));
    const claimedStep = run.steps.find(step => activeAttempt(step));
    if (claimedStep) {
      const claimed = activeAttempt(claimedStep)!;
      const owner = claimed.claimed_by_task_id
        ? `${claimed.claimed_by_task_id} via ${claimed.claimed_via}`
        : claimed.claimed_via;
      throw new PlaybookRunError(
        `Only one playbook step may run at a time. ${claimedStep.step_id} is claimed by ${owner}; interrupt or complete that attempt first.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    if (!step) throw new PlaybookRunError(`Playbook step not found: ${stepId}`, 'PLAYBOOK_STEP_NOT_FOUND');
    refreshDependencyState(run);
    if (step.status === 'blocked') {
      throw new PlaybookRunError(step.blocked_reason ?? `Playbook step ${stepId} is blocked.`, 'PLAYBOOK_BLOCKED');
    }
    if (!step.resolved_execution) {
      throw new PlaybookRunError(`Playbook step ${stepId} has no resolved execution descriptor.`, 'PLAYBOOK_BLOCKED');
    }
    const planReference = attemptPlanReference(run, step);
    if (retry) {
      const lastAttempt = step.attempts.at(-1);
      const resumedInterrupted = step.status === 'pending' && lastAttempt?.status === 'interrupted';
      const replannedTerminal = step.status === 'pending'
        && !!lastAttempt
        && lastAttempt.execution_template_hash !== planReference.template_hash;
      if (!['failed', 'interrupted'].includes(step.status) && !resumedInterrupted && !replannedTerminal) {
        throw new PlaybookRunError(`Playbook step ${stepId} is ${step.status}; only failed or interrupted steps can be retried.`, 'PLAYBOOK_CONFLICT');
      }
    } else if (step.attempts.length > 0 || step.status !== 'pending') {
      throw new PlaybookRunError(`Playbook step ${stepId} is ${step.status}; use retry for a prior failed attempt.`, 'PLAYBOOK_CONFLICT');
    }
    const at = now(this.engine);
    const invocation = getApplicationCommandInvocation();
    const attemptId = `attempt_${randomUUID()}`;
    const attempt: PersistedPlaybookAttemptV1 = {
      attempt_id: attemptId,
      attempt_number: step.attempts.length + 1,
      status: 'claimed',
      started_at: at,
      claimed_via: invocation?.transport ?? 'system',
      ...(invocation?.actor_task_id ? { claimed_by_task_id: invocation.actor_task_id } : {}),
      execution_command_id: `playbook_exec_${randomUUID()}`,
      execution_idempotency_key: `playbook_attempt:${attemptId}`,
      execution_action_id: `playbook_action_${randomUUID()}`,
      plan_revision: planReference.revision,
      execution_template_hash: planReference.template_hash,
      evidence_ids: [],
      finding_ids: [],
    };
    step.attempts.push(attempt);
    step.status = 'pending';
    step.started_at ??= at;
    delete step.completed_at;
    step.updated_at = at;
    run.started_at ??= at;
    run.updated_at = at;
    updateDerivedStatus(run);
    const execution = this.threadAttempt(step.resolved_execution, run.run_id, step.step_id, attempt);
    const stored = this.save(run);
    return {
      run: stored,
      step: structuredClone(stored.steps.find(candidate => candidate.step_id === stepId)!),
      attempt: structuredClone(attempt),
      execution,
    };
  }

  private threadAttempt(
    descriptor: Record<string, unknown>,
    runId: string,
    stepId: string,
    attempt: PersistedPlaybookAttemptV1,
  ): Record<string, unknown> {
    const threaded = structuredClone(descriptor);
    const linkage = {
      playbook_run_id: runId,
      playbook_step_id: stepId,
      playbook_attempt_id: attempt.attempt_id,
      command_id: attempt.execution_command_id,
      idempotency_key: attempt.execution_idempotency_key,
      action_id: attempt.execution_action_id,
    };
    Object.assign(threaded, linkage);
    if (threaded.parser_context && typeof threaded.parser_context === 'object' && !Array.isArray(threaded.parser_context)) {
      threaded.parser_context = { ...(threaded.parser_context as Record<string, unknown>), ...linkage };
    }
    if (threaded.args && typeof threaded.args === 'object' && !Array.isArray(threaded.args)) {
      threaded.args = { ...(threaded.args as Record<string, unknown>), ...linkage };
    }
    return threaded;
  }

  private save(run: PersistedDurablePlaybookRunV1): PersistedDurablePlaybookRunV1 {
    const saved = this.engine.recordPlaybookRun(run) as PersistedDurablePlaybookRunV1;
    if (this.publishChanges) this.publish(saved);
    return saved;
  }

  beginAttemptExecution(linkage: PlaybookAttemptLinkage & { command_id?: string; idempotency_key?: string }): PersistedDurablePlaybookRunV1 | undefined {
    const { playbook_run_id: runId, playbook_step_id: stepId, playbook_attempt_id: attemptId } = linkage;
    if (!runId && !stepId && !attemptId) return undefined;
    if (!runId || !stepId || !attemptId) {
      throw new PlaybookRunError('Playbook run, step, and attempt linkage must be supplied together.', 'PLAYBOOK_CONFLICT');
    }
    const run = structuredClone(this.getDurable(runId));
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    const attempt = step?.attempts.find(candidate => candidate.attempt_id === attemptId);
    if (!step || !attempt) throw new PlaybookRunError('The claimed playbook attempt does not exist.', 'PLAYBOOK_ATTEMPT_NOT_FOUND');
    if (
      linkage.command_id !== attempt.execution_command_id
      || linkage.idempotency_key !== attempt.execution_idempotency_key
    ) {
      throw new PlaybookRunError(
        'The runner command_id/idempotency_key do not match the durable playbook claim.',
        'PLAYBOOK_CONFLICT',
      );
    }
    if (attempt.status === 'running' || ['succeeded', 'failed', 'interrupted', 'cancelled'].includes(attempt.status)) {
      return run;
    }
    if (attempt.status !== 'claimed') {
      throw new PlaybookRunError(`Playbook attempt ${attemptId} is already ${attempt.status}.`, 'PLAYBOOK_CONFLICT');
    }
    const at = now(this.engine);
    const invocation = getApplicationCommandInvocation();
    attempt.status = 'running';
    attempt.execution_started_at = at;
    attempt.action_id = attempt.execution_action_id;
    attempt.executed_via = invocation?.transport ?? 'system';
    if (invocation?.actor_task_id) attempt.executed_by_task_id = invocation.actor_task_id;
    step.status = 'running';
    step.updated_at = at;
    run.updated_at = at;
    updateDerivedStatus(run);
    return this.save(run);
  }

  /** Authenticate a runner invocation against the exact durable claim before
   * any validation, approval, or provider precondition can return early. */
  validateAttemptLinkage(
    linkage: PlaybookAttemptLinkage & object,
  ): PersistedDurablePlaybookRunV1 | undefined {
    const { playbook_run_id: runId, playbook_step_id: stepId, playbook_attempt_id: attemptId } = linkage;
    if (!runId && !stepId && !attemptId) return undefined;
    if (!runId || !stepId || !attemptId) {
      throw new PlaybookRunError('Incomplete playbook attempt linkage.', 'PLAYBOOK_CONFLICT');
    }
    const run = this.getDurable(runId);
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    const attempt = step?.attempts.find(candidate => candidate.attempt_id === attemptId);
    if (!step || !attempt) {
      throw new PlaybookRunError('The claimed playbook attempt does not exist.', 'PLAYBOOK_ATTEMPT_NOT_FOUND');
    }
    if (
      linkage.command_id !== attempt.execution_command_id
      || linkage.idempotency_key !== attempt.execution_idempotency_key
    ) {
      throw new PlaybookRunError(
        'The runner command_id/idempotency_key do not match the durable playbook claim.',
        'PLAYBOOK_CONFLICT',
      );
    }
    if (linkage.action_id !== attempt.execution_action_id) {
      throw new PlaybookRunError(
        `The runner action_id does not match the durable playbook claim ${attempt.execution_action_id}.`,
        'PLAYBOOK_CONFLICT',
      );
    }
    assertInvocationMatchesTemplate(
      immutableAttemptTemplate(run, step, attempt),
      linkage as unknown as Record<string, unknown>,
      attempt.attempt_id,
      credentialId => {
        const credential = this.engine.getNode(credentialId);
        return credential?.type === 'credential' && typeof credential.cred_value === 'string'
          ? credential.cred_value
          : undefined;
      },
    );
    if (!['claimed', 'awaiting_approval', 'running'].includes(attempt.status)) {
      const command = this.engine.getApplicationCommandById(attempt.execution_command_id);
      const result = command?.result;
      const retainedResponse = result
        && typeof command.result === 'object'
        && !Array.isArray(command.result)
        && typeof (command.result as { response_evidence_id?: unknown }).response_evidence_id === 'string';
      const responseActionId = result && typeof result === 'object' && !Array.isArray(result)
        ? (result as { action_id?: unknown }).action_id
        : undefined;
      if (!command
        || command.command_kind !== 'process.execute'
        || command.status !== 'succeeded'
        || command.action_id !== attempt.execution_action_id
        || responseActionId !== attempt.execution_action_id
        || replayReceiptOutcome(result) !== attempt.execution_outcome
        || !retainedResponse) {
        throw new PlaybookRunError(
          `Playbook attempt ${attempt.attempt_id} is ${attempt.status}; only a matching succeeded command with a retained response can replay. Prepare a retry instead.`,
          'PLAYBOOK_CONFLICT',
        );
      }
    }
    return run;
  }

  markAttemptExecutionState(
    linkage: PlaybookAttemptLinkage & { command_id?: string; idempotency_key?: string },
    state: 'awaiting_approval' | 'running',
  ): PersistedDurablePlaybookRunV1 | undefined {
    const { playbook_run_id: runId, playbook_step_id: stepId, playbook_attempt_id: attemptId } = linkage;
    if (!runId && !stepId && !attemptId) return undefined;
    if (!runId || !stepId || !attemptId) throw new PlaybookRunError('Incomplete playbook attempt linkage.', 'PLAYBOOK_CONFLICT');
    const run = structuredClone(this.getDurable(runId));
    const step = run.steps.find(candidate => candidate.step_id === stepId);
    const attempt = step?.attempts.find(candidate => candidate.attempt_id === attemptId);
    if (!step || !attempt) throw new PlaybookRunError('The claimed playbook attempt does not exist.', 'PLAYBOOK_ATTEMPT_NOT_FOUND');
    if (
      linkage.command_id !== attempt.execution_command_id
      || linkage.idempotency_key !== attempt.execution_idempotency_key
    ) {
      throw new PlaybookRunError(
        'The runner command_id/idempotency_key do not match the durable playbook claim.',
        'PLAYBOOK_CONFLICT',
      );
    }
    if (attempt.status === 'running' && state === 'awaiting_approval') {
      throw new PlaybookRunError(`Playbook attempt ${attemptId} is already running.`, 'PLAYBOOK_CONFLICT');
    }
    if (!['claimed', 'running', 'awaiting_approval'].includes(attempt.status)) {
      throw new PlaybookRunError(`Playbook attempt ${attemptId} is ${attempt.status}.`, 'PLAYBOOK_CONFLICT');
    }
    if (attempt.status === state && step.status === state) return run;
    const at = now(this.engine);
    const invocation = getApplicationCommandInvocation();
    attempt.status = state;
    if (state === 'running') {
      attempt.execution_started_at ??= at;
      attempt.action_id = attempt.execution_action_id;
      attempt.executed_via = invocation?.transport ?? 'system';
      if (invocation?.actor_task_id) attempt.executed_by_task_id = invocation.actor_task_id;
    }
    step.status = state;
    step.updated_at = at;
    run.updated_at = at;
    updateDerivedStatus(run);
    return this.save(run);
  }
}

export function playbookProcessLifecycle(
  engine: GraphEngine,
  linkage: PlaybookAttemptLinkage & object,
): ((state: 'awaiting_approval' | 'running') => void) | undefined {
  const hasAny = !!(linkage.playbook_run_id || linkage.playbook_step_id || linkage.playbook_attempt_id);
  if (!hasAny) return undefined;
  if (!linkage.playbook_run_id || !linkage.playbook_step_id || !linkage.playbook_attempt_id) {
    throw new PlaybookRunError('Incomplete playbook attempt linkage.', 'PLAYBOOK_CONFLICT');
  }
  const service = new PlaybookRunService(engine);
  service.validateAttemptLinkage(linkage);
  return state => { service.markAttemptExecutionState(linkage, state); };
}

export function isDurablePlaybookRun(
  run: PersistedPlaybookRunV1,
): run is PersistedDurablePlaybookRunV1 {
  return durableRun(run);
}

/** Close a claimed attempt from the ordinary instrumented tool response. This
 * keeps run_bash/run_tool/token replay as the execution boundary and records
 * only action/evidence/finding references in playbook state. */
export function finishPlaybookAttemptFromToolResponse(
  engine: GraphEngine,
  linkage: PlaybookAttemptLinkage,
  response: { content?: unknown; isError?: boolean },
): PersistedDurablePlaybookRunV1 | undefined {
  const runId = linkage.playbook_run_id;
  const stepId = linkage.playbook_step_id;
  const attemptId = linkage.playbook_attempt_id;
  if (!runId && !stepId && !attemptId) return undefined;
  if (!runId || !stepId || !attemptId) {
    throw new PlaybookRunError(
      'playbook_run_id, playbook_step_id, and playbook_attempt_id must be supplied together.',
      'PLAYBOOK_CONFLICT',
    );
  }
  let payload: Record<string, unknown> = {};
  const blocks = Array.isArray(response.content) ? response.content : [];
  for (const block of blocks) {
    if (!block || typeof block !== 'object' || (block as { type?: unknown }).type !== 'text') continue;
    const text = (block as { text?: unknown }).text;
    if (typeof text !== 'string') continue;
    try {
      const candidate = JSON.parse(text) as unknown;
      if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
        payload = candidate as Record<string, unknown>;
        break;
      }
    } catch { /* retain an empty structured payload */ }
  }
  const parseSummary = payload.parse_summary && typeof payload.parse_summary === 'object'
    ? payload.parse_summary as Record<string, unknown>
    : undefined;
  const parseOutcome = parseSummary?.parse_outcome ?? payload.parse_outcome;
  const interrupted = payload.interrupted === true
    || payload.timed_out === true
    || payload.approval_status === 'aborted'
    || payload.code === 'PERSISTENCE_INTERRUPTED'
    || payload.code === 'COMMAND_INTERRUPTED';
  const executionOutcome = interrupted
    ? 'interrupted' as const
    : response.isError === true || payload.executed === false || payload.spawn_error
      ? 'failed' as const
      : 'succeeded' as const;
  const evidenceIds = [
    payload.stdout_evidence_id,
    payload.stderr_evidence_id,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);
  const findingIds = [
    parseSummary?.finding_id,
    payload.finding_id,
    ...(Array.isArray(payload.finding_ids) ? payload.finding_ids : []),
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);
  return new PlaybookRunService(engine).finishAttempt(runId, stepId, attemptId, {
    execution_outcome: executionOutcome,
    parse_outcome: typeof parseOutcome === 'string'
      && ['ok', 'no_data', 'validation_failed', 'parser_exception', 'partial'].includes(parseOutcome)
      ? parseOutcome as PlaybookParseOutcome
      : undefined,
    action_id: typeof payload.action_id === 'string' ? payload.action_id : undefined,
    evidence_ids: evidenceIds,
    finding_ids: findingIds,
    error: typeof payload.error === 'string'
      ? payload.error
      : typeof payload.reason === 'string'
        ? payload.reason
        : undefined,
  });
}

/** Ensure a runner exception also reaches a durable terminal playbook state.
 * The normal response path remains the source of action/evidence/finding refs. */
export async function withPlaybookAttemptCompletion<T extends { content?: unknown; isError?: boolean }>(
  engine: GraphEngine,
  linkage: PlaybookAttemptLinkage,
  operation: () => Promise<T>,
  options: { begin_execution?: boolean } = {},
): Promise<T> {
  const service = new PlaybookRunService(engine);
  if (options.begin_execution !== false) service.beginAttemptExecution(linkage);
  try {
    const result = await operation();
    finishPlaybookAttemptFromToolResponse(engine, linkage, result);
    return result;
  } catch (error) {
    finishPlaybookAttemptFromToolResponse(engine, linkage, {
      isError: true,
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          playbook_runner_exception: true,
        }),
      }],
    });
    throw error;
  }
}
