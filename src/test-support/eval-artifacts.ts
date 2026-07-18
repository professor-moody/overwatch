import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

export const EVAL_ARTIFACT_SCHEMA_VERSION = 1;
export const DEFAULT_EVAL_ARTIFACT_ROOT = 'eval-artifacts';

export type EvalOutcome =
  | 'completed'
  | 'failed'
  | 'interrupted'
  | 'timed_out'
  | 'budget_exhausted'
  | 'harness_error';

export interface EvalArtifactUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number;
  cache_creation_input_tokens: number;
  accounting_tokens: number;
}

export interface EvalArtifactStart {
  kind: 'prompt' | 'orchestration';
  scenario: string;
  model: string;
  promptVariant: string;
  command: {
    binary: string;
    args: string[];
    env?: Record<string, string | undefined>;
  };
  limits: {
    max_budget_usd?: number;
    max_total_usd?: number;
    max_turns: number;
    timeout_ms: number;
  };
  rootDir?: string;
  runId?: string;
  startedAt?: string;
}

export interface EvalArtifactFinalize {
  outcome: EvalOutcome;
  agentNdjson?: string;
  record?: unknown;
  grade?: unknown;
  usage?: EvalArtifactUsage;
  reportedCostUsd?: number;
  reservedCostUsd?: number;
  graphDelta?: unknown;
  toolCalls?: unknown[];
  error?: unknown;
  finishedAt?: string;
}

export interface EvalArtifactMember {
  sha256: string;
  bytes: number;
}

export interface EvalArtifactManifest {
  schema_version: typeof EVAL_ARTIFACT_SCHEMA_VERSION;
  run_id: string;
  evaluation_kind: EvalArtifactStart['kind'];
  scenario: string;
  model: string;
  prompt_variant: string;
  outcome: EvalOutcome;
  eligible_for_baseline: boolean;
  limits: EvalArtifactStart['limits'];
  usage: EvalArtifactUsage;
  cost: {
    reported_usd: number | null;
    reserved_usd: number;
  };
  graph_delta: unknown;
  tool_calls: unknown[];
  timestamps: {
    started_at: string;
    finished_at: string;
  };
  artifacts: Record<string, EvalArtifactMember>;
}

const REDACTED = '[REDACTED]';
const SENSITIVE_KEY = /^(?:authorization|proxy_authorization|cookie|cookies|set_cookie|password|passwd|passphrase|secret|secret_value|client_secret|private_key|api_key|apikey|access_token|refresh_token|id_token|session_token|bearer_token|token|credential|credentials|credential_value|cred_value|credential_material|session_credentials|aws_session_credentials|engagement_nonce)$/iu;
const SENSITIVE_ENV_KEY = /(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|PRIVATE_KEY|API_KEY|AUTHORIZATION|COOKIE|CREDENTIAL|ENGAGEMENT_NONCE)/iu;

function redactCommandArgs(args: string[]): string[] {
  const output = [...args];
  for (let index = 0; index < output.length; index += 1) {
    if (/^--(?:token|password|secret|api-key|authorization|cookie|credential)(?:=|$)/iu.test(output[index] ?? '')) {
      const [flag, inlineValue] = (output[index] ?? '').split('=', 2);
      if (inlineValue !== undefined) output[index] = `${flag}=${REDACTED}`;
      else if (index + 1 < output.length) output[index + 1] = REDACTED;
    }
  }
  return output.map(redactString);
}

function redactString(value: string): string {
  return value
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/giu, '$1 [REDACTED]')
    .replace(/\b((?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|OVERWATCH_[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|NONCE)|AZURE_CLIENT_SECRET|ENTRA_REFRESH_TOKEN)=)[^\s"']+/giu, '$1[REDACTED]')
    .replace(/\b((?:password|passwd|passphrase|client_secret|secret|access_token|refresh_token|api_key|token|engagement_nonce)\s*[:=]\s*)[^\s,"']+/giu, '$1[REDACTED]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu, '[REDACTED PRIVATE KEY]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu, '[REDACTED JWT]');
}

/** Redact credential-bearing fields while preserving accounting fields such as
 * input_tokens and cache_creation_input_tokens. */
export function redactEvalValue(value: unknown, parentKey?: string): unknown {
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(item => redactEvalValue(item));
  if (!value || typeof value !== 'object') return value;

  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY.test(key)) {
      output[key] = REDACTED;
      continue;
    }
    if (parentKey === 'env' && SENSITIVE_ENV_KEY.test(key)) {
      output[key] = REDACTED;
      continue;
    }
    output[key] = redactEvalValue(child, key);
  }
  return output;
}

export function redactEvalNdjson(ndjson: string): string {
  const lines = ndjson.split('\n');
  const redacted = lines.map(line => {
    if (!line.trim()) return '';
    try {
      return JSON.stringify(redactEvalValue(JSON.parse(line)));
    } catch {
      return redactString(line);
    }
  });
  return redacted.join('\n');
}

function safeSegment(value: string, fallback: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9._-]+/gu, '-').replace(/^-+|-+$/gu, '');
  return normalized.slice(0, 80) || fallback;
}

function timestampSegment(iso: string): string {
  return iso.replace(/\.\d{3}Z$/u, 'Z').replace(/[:]/gu, '-');
}

function jsonBytes(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(redactEvalValue(value), null, 2)}\n`, 'utf8');
}

function checksum(bytes: Buffer): EvalArtifactMember {
  return {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.byteLength,
  };
}

function writePrivateFile(directory: string, name: string, bytes: Buffer): EvalArtifactMember {
  const path = join(directory, name);
  writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
  return checksum(bytes);
}

export class EvalArtifactSession {
  readonly directory: string;
  readonly runId: string;
  readonly startedAt: string;
  private finalizationStarted = false;
  private finalized = false;

  constructor(private readonly start: EvalArtifactStart) {
    this.runId = safeSegment(start.runId ?? randomUUID(), 'run');
    this.startedAt = start.startedAt ?? new Date().toISOString();
    const root = resolve(start.rootDir ?? DEFAULT_EVAL_ARTIFACT_ROOT);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    chmodSync(root, 0o700);
    this.directory = join(
      root,
      `${timestampSegment(this.startedAt)}-${safeSegment(start.scenario, 'scenario')}-${this.runId}`,
    );
    mkdirSync(this.directory, { mode: 0o700 });
    chmodSync(this.directory, 0o700);
  }

  get isFinalized(): boolean {
    return this.finalized;
  }

  get hasFinalizationStarted(): boolean {
    return this.finalizationStarted;
  }

  finalize(input: EvalArtifactFinalize): EvalArtifactManifest {
    if (this.finalizationStarted) throw new Error(`Evaluation artifacts already finalized or finalizing: ${this.directory}`);
    this.finalizationStarted = true;

    const finishedAt = input.finishedAt ?? new Date().toISOString();
    const usage: EvalArtifactUsage = input.usage ?? {
      input_tokens: 0,
      output_tokens: 0,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 0,
      accounting_tokens: 0,
    };
    const toolCalls = Array.isArray(input.toolCalls) ? input.toolCalls : [];
    const eligibleForBaseline = input.outcome === 'completed'
      && input.record !== undefined
      && input.grade !== undefined;
    const members: Record<string, EvalArtifactMember> = {};

    const agentBytes = Buffer.from(redactEvalNdjson(input.agentNdjson ?? ''), 'utf8');
    members['agent.ndjson'] = writePrivateFile(this.directory, 'agent.ndjson', agentBytes);
    members['record.json'] = writePrivateFile(this.directory, 'record.json', jsonBytes({
      schema_version: EVAL_ARTIFACT_SCHEMA_VERSION,
      outcome: input.outcome,
      record: input.record ?? null,
      error: input.error instanceof Error
        ? { name: input.error.name, message: input.error.message }
        : input.error ?? null,
    }));
    members['grade.json'] = writePrivateFile(this.directory, 'grade.json', jsonBytes({
      schema_version: EVAL_ARTIFACT_SCHEMA_VERSION,
      outcome: input.outcome,
      eligible_for_baseline: eligibleForBaseline,
      grade: input.grade ?? null,
    }));
    members['command.json'] = writePrivateFile(this.directory, 'command.json', jsonBytes({
      schema_version: EVAL_ARTIFACT_SCHEMA_VERSION,
      binary: basename(this.start.command.binary),
      args: redactCommandArgs(this.start.command.args),
      env: this.start.command.env ?? {},
      tool_calls: toolCalls,
    }));

    const manifest: EvalArtifactManifest = {
      schema_version: EVAL_ARTIFACT_SCHEMA_VERSION,
      run_id: this.runId,
      evaluation_kind: this.start.kind,
      scenario: this.start.scenario,
      model: this.start.model,
      prompt_variant: this.start.promptVariant,
      outcome: input.outcome,
      eligible_for_baseline: eligibleForBaseline,
      limits: this.start.limits,
      usage,
      cost: {
        reported_usd: input.reportedCostUsd ?? null,
        reserved_usd: input.reservedCostUsd ?? 0,
      },
      graph_delta: redactEvalValue(input.graphDelta ?? null),
      tool_calls: redactEvalValue(toolCalls) as unknown[],
      timestamps: {
        started_at: this.startedAt,
        finished_at: finishedAt,
      },
      artifacts: members,
    };
    writePrivateFile(this.directory, 'manifest.json', jsonBytes(manifest));
    this.finalized = true;
    return manifest;
  }
}

/** Real runs always preserve evidence. Fake/CI runs remain temporary unless the
 * caller explicitly opts in (normally in an artifact-specific test). */
export function shouldPreserveEvalArtifacts(usingFake: boolean, explicitlyRequested = false): boolean {
  return !usingFake || explicitlyRequested;
}
