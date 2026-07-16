// ============================================================
// Overwatch — durable boundary for one-shot external processes
// ============================================================

import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandService,
  type ApplicationCommandExecution,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import { canonicalJson } from './engagement-config-service.js';

export interface ProcessToolResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
  [PROCESS_COMMAND_TERMINAL]?: Parameters<GraphEngine['finishRuntimeAction']>[0];
  [key: string]: unknown;
}

export const PROCESS_COMMAND_TERMINAL = Symbol('overwatch.process-command-terminal');

export interface ProcessCommandDescriptor {
  invoking_tool: 'run_bash' | 'run_tool';
  action_id?: string;
  frontier_item_id?: string;
  agent_id?: string;
  tool_name?: string;
  technique?: string;
  target_node_ids?: string[];
  target_ips?: string[];
  target_cidrs?: string[];
  has_target_url: boolean;
  has_cloud_resource: boolean;
  timeout_ms: number;
  validate: boolean;
  allow_unverified_scope: boolean;
  operator_infra: boolean;
  parse_with?: string;
  parse_stream: 'stdout' | 'stderr' | 'combined' | 'auto';
  env_keys: string[];
  redacts_arguments: boolean;
  redacted_secret_count: number;
  /** SHA-256 of the exact execution request; raw request values are not stored. */
  request_fingerprint: string;
}

export interface PersistedProcessCommandResult {
  response_evidence_id: string;
  action_id?: string;
  is_error: boolean;
  executed?: boolean;
  interrupted?: boolean;
  code?: string;
  reason?: string;
  error?: string;
  validation_result?: string;
  errors?: string[];
  warnings?: string[];
  approval_status?: string;
  binary?: string;
  exit_code?: number | null;
  signal?: string | null;
  duration_ms?: number;
  timed_out?: boolean;
  spawn_error?: string;
  stdout_truncated?: boolean;
  stderr_truncated?: boolean;
  stdout_total_bytes?: number;
  stderr_total_bytes?: number;
  stdout_evidence_id?: string;
  stderr_evidence_id?: string;
  parse_summary?: Record<string, unknown>;
}

const processCommandDescriptorSchema = z.object({
  invoking_tool: z.enum(['run_bash', 'run_tool']),
  action_id: z.string().min(1).optional(),
  frontier_item_id: z.string().min(1).optional(),
  agent_id: z.string().min(1).optional(),
  tool_name: z.string().min(1).optional(),
  technique: z.string().min(1).optional(),
  target_node_ids: z.array(z.string().min(1)).optional(),
  target_ips: z.array(z.string().min(1)).optional(),
  target_cidrs: z.array(z.string().min(1)).optional(),
  has_target_url: z.boolean(),
  has_cloud_resource: z.boolean(),
  timeout_ms: z.number().int().positive(),
  validate: z.boolean(),
  allow_unverified_scope: z.boolean(),
  operator_infra: z.boolean(),
  parse_with: z.string().min(1).optional(),
  parse_stream: z.enum(['stdout', 'stderr', 'combined', 'auto']),
  env_keys: z.array(z.string()).default([]),
  redacts_arguments: z.boolean(),
  redacted_secret_count: z.number().int().nonnegative(),
  request_fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

const persistedProcessCommandResultSchema = z.object({
  response_evidence_id: z.string().min(1),
  action_id: z.string().min(1).optional(),
  is_error: z.boolean(),
  executed: z.boolean().optional(),
  interrupted: z.boolean().optional(),
  code: z.string().optional(),
  reason: z.string().optional(),
  error: z.string().optional(),
  validation_result: z.string().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  approval_status: z.string().optional(),
  binary: z.string().optional(),
  exit_code: z.number().int().nullable().optional(),
  signal: z.string().nullable().optional(),
  duration_ms: z.number().nonnegative().optional(),
  timed_out: z.boolean().optional(),
  spawn_error: z.string().optional(),
  stdout_truncated: z.boolean().optional(),
  stderr_truncated: z.boolean().optional(),
  stdout_total_bytes: z.number().int().nonnegative().optional(),
  stderr_total_bytes: z.number().int().nonnegative().optional(),
  stdout_evidence_id: z.string().min(1).optional(),
  stderr_evidence_id: z.string().min(1).optional(),
  parse_summary: z.record(z.unknown()).optional(),
}).strict();

function responsePayload(response: ProcessToolResponse): Record<string, unknown> | undefined {
  const text = response.content.find(entry => entry.type === 'text')?.text;
  if (!text) return undefined;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function terminalCommandError(
  execution: ApplicationCommandExecution<PersistedProcessCommandResult>,
): ProcessToolResponse {
  const inProgress = execution.status === 'accepted' || execution.status === 'running';
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        action_id: execution.record.action_id,
        executed: false,
        command_id: execution.command_id,
        code: inProgress
          ? 'COMMAND_IN_PROGRESS'
          : execution.error?.code ?? (
              execution.status === 'interrupted'
                ? 'COMMAND_INTERRUPTED'
                : 'COMMAND_FAILED'
            ),
        error: inProgress
          ? 'The original operation is still running; Overwatch did not execute it again.'
          : execution.error?.message
            ?? 'The original operation did not reach a replayable terminal response.',
      }, null, 2),
    }],
    isError: true,
  };
}

/**
 * Persist only a one-way digest while still rejecting an idempotency key reused
 * for different argv, environment, parser context, or target metadata.
 */
export function buildProcessRequestFingerprint(request: unknown): string {
  return createHash('sha256')
    .update(canonicalJson(request))
    .digest('hex');
}

function boundedString(value: unknown, max = 4_096): string | undefined {
  if (typeof value !== 'string') return undefined;
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

function boundedStrings(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const strings = value
    .filter((candidate): candidate is string => typeof candidate === 'string')
    .slice(0, 100)
    .map(candidate => boundedString(candidate) ?? '');
  return strings.length > 0 ? strings : undefined;
}

function safeParseSummary(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const source = value as Record<string, unknown>;
  const allowed = [
    'parsed',
    'parse_status',
    'parse_outcome',
    'isError',
    'tool',
    'action_id',
    'finding_id',
    'campaign_id',
    'nodes_parsed',
    'edges_parsed',
    'ingested',
    'validation_errors',
    'warnings',
    'supported_parsers',
    'failure_stage',
    'partial',
    'partial_reason',
    'parse_stream',
    'parsed_from_evidence',
    'evidence_read_error',
    'exit_code',
  ] as const;
  const result: Record<string, unknown> = {};
  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      result[key] = structuredClone(source[key]);
    }
  }
  if (source.parse_status === 'parser_exception') {
    result.error = 'Parser exception detail is available through the original output evidence.';
    result.parser_exception = result.error;
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

function compactResponse(response: ProcessToolResponse): PersistedProcessCommandResult {
  const payload = responsePayload(response) ?? {};
  return {
    // Filled after the bounded, display-safe response artifact is published.
    response_evidence_id: '',
    action_id: boundedString(payload.action_id, 256),
    is_error: response.isError === true,
    executed: typeof payload.executed === 'boolean' ? payload.executed : undefined,
    interrupted: typeof payload.interrupted === 'boolean' ? payload.interrupted : undefined,
    code: boundedString(payload.code, 256),
    reason: boundedString(payload.reason),
    error: boundedString(payload.error),
    validation_result: boundedString(payload.validation_result, 256),
    errors: boundedStrings(payload.errors),
    warnings: boundedStrings(payload.warnings),
    approval_status: boundedString(payload.approval_status, 256),
    binary: boundedString(payload.binary, 1_024),
    exit_code: typeof payload.exit_code === 'number' || payload.exit_code === null
      ? payload.exit_code
      : undefined,
    signal: typeof payload.signal === 'string' || payload.signal === null
      ? payload.signal
      : undefined,
    duration_ms: typeof payload.duration_ms === 'number'
      ? payload.duration_ms
      : undefined,
    timed_out: typeof payload.timed_out === 'boolean'
      ? payload.timed_out
      : undefined,
    spawn_error: boundedString(payload.spawn_error),
    stdout_truncated: typeof payload.stdout_truncated === 'boolean'
      ? payload.stdout_truncated
      : undefined,
    stderr_truncated: typeof payload.stderr_truncated === 'boolean'
      ? payload.stderr_truncated
      : undefined,
    stdout_total_bytes: typeof payload.stdout_total_bytes === 'number'
      ? payload.stdout_total_bytes
      : undefined,
    stderr_total_bytes: typeof payload.stderr_total_bytes === 'number'
      ? payload.stderr_total_bytes
      : undefined,
    stdout_evidence_id: boundedString(payload.stdout_evidence_id, 256),
    stderr_evidence_id: boundedString(payload.stderr_evidence_id, 256),
    parse_summary: safeParseSummary(payload.parse_summary),
  };
}

function replayArtifact(response: ProcessToolResponse): ProcessToolResponse {
  const safe = structuredClone(response);
  for (const entry of safe.content) {
    if (entry.type !== 'text') continue;
    try {
      const payload = JSON.parse(entry.text);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) continue;
      // Arguments are rehydrated from the fingerprint-compatible retry input.
      // Never duplicate credential-bearing argv in the derived response artifact.
      delete payload.args;
      if (payload.parse_summary && typeof payload.parse_summary === 'object') {
        delete payload.parse_summary.error;
        delete payload.parse_summary.parser_exception;
        if (payload.parse_summary.parse_status === 'parser_exception') {
          payload.parse_summary.error =
            'Parser exception detail is available through the original output evidence.';
          payload.parse_summary.parser_exception = payload.parse_summary.error;
        }
      }
      entry.text = JSON.stringify(payload, null, 2);
    } catch {
      // Process responses are JSON today. If an adapter ever returns text,
      // retain it only when it is already within the normal MCP response cap.
      if (entry.text.length > 8_192) {
        entry.text = `${entry.text.slice(0, 8_192)}…`;
      }
    }
  }
  return safe;
}

function wireSafeResponse(response: ProcessToolResponse): ProcessToolResponse {
  const safe = structuredClone(response);
  for (const entry of safe.content) {
    if (entry.type !== 'text') continue;
    try {
      const payload = JSON.parse(entry.text);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) continue;
      if (payload.parse_summary && typeof payload.parse_summary === 'object') {
        if (payload.parse_summary.parse_status === 'parser_exception') {
          payload.parse_summary.error =
            'Parser exception detail is available through the original output evidence.';
          payload.parse_summary.parser_exception = payload.parse_summary.error;
        } else {
          delete payload.parse_summary.parser_exception;
        }
      }
      entry.text = JSON.stringify(payload, null, 2);
    } catch {
      // Preserve the ordinary bounded text response.
    }
  }
  return safe;
}

/**
 * One service instance is retained per engine so concurrent retries join the
 * same in-flight promise. Different MCP/dashboard clients still share durable
 * idempotency through ApplicationCommandService after the process exits.
 */
export class ProcessCommandService {
  private readonly commands: ApplicationCommandService;

  constructor(private readonly engine: GraphEngine) {
    this.commands = new ApplicationCommandService(engine);
  }

  async execute(
    descriptor: ProcessCommandDescriptor,
    operation: () => Promise<ProcessToolResponse>,
    replay: (
      receipt: PersistedProcessCommandResult,
      storedResponse: ProcessToolResponse,
    ) => ProcessToolResponse,
    metadata: ApplicationCommandMetadata = {},
  ): Promise<ProcessToolResponse> {
    let liveResponse: ProcessToolResponse | undefined;
    let terminalRuntimeInput:
      | Parameters<GraphEngine['finishRuntimeAction']>[0]
      | undefined;
    const execution = await this.commands.executeAsync({
      command_kind: 'process.execute',
      input: descriptor,
      schema: processCommandDescriptorSchema,
      metadata: {
        ...metadata,
        action_id: metadata.action_id ?? descriptor.action_id,
        frontier_item_id:
          metadata.frontier_item_id ?? descriptor.frontier_item_id,
      },
      reserve: () => ({
        result: {
          reserved: true,
          invoking_tool: descriptor.invoking_tool,
        },
        action_id: descriptor.action_id,
        frontier_item_id: descriptor.frontier_item_id,
      }),
      execute: async () => {
        liveResponse = await operation();
        terminalRuntimeInput = liveResponse[PROCESS_COMMAND_TERMINAL];
        if (terminalRuntimeInput) {
          delete liveResponse[PROCESS_COMMAND_TERMINAL];
        }
        liveResponse = wireSafeResponse(liveResponse);
        const compact = compactResponse(liveResponse);
        const actionId = compact.action_id ?? descriptor.action_id;
        let responseEvidenceId: string;
        try {
          responseEvidenceId = this.engine.getEvidenceStore().store({
            action_id: actionId,
            agent_id: descriptor.agent_id,
            evidence_type: 'log',
            filename: 'application-command-response.json',
            content: JSON.stringify(replayArtifact(liveResponse)),
          });
        } catch {
          // The target process has already reached a real terminal state. Return
          // a failed transition (rather than throw) so runtime/action finality
          // and the command failure still commit atomically.
          return {
            status: 'failed',
            error: {
              code: 'COMMAND_RESPONSE_PERSIST_FAILED',
              message:
                'The process completed, but its replay response could not be persisted.',
            },
            action_id: actionId,
            frontier_item_id: descriptor.frontier_item_id,
            entity_refs: {
              evidence_ids: [
                compact.stdout_evidence_id,
                compact.stderr_evidence_id,
              ].filter((value): value is string => typeof value === 'string'),
            },
          };
        }
        compact.response_evidence_id = responseEvidenceId;
        return {
          // A target/tool failure is still a successfully completed application
          // command whose exact failure response must be replayed.
          status: 'succeeded',
          result: compact,
          action_id: actionId,
          frontier_item_id: descriptor.frontier_item_id,
          entity_refs: {
            evidence_ids: [
              responseEvidenceId,
              ...[
                compact.stdout_evidence_id,
                compact.stderr_evidence_id,
              ].filter((value): value is string => typeof value === 'string'),
            ],
          },
        };
      },
      completion_state_keys: ['runtime_runs', 'activity'],
      completion_effects: () => {
        if (terminalRuntimeInput) {
          this.engine.finishRuntimeAction(terminalRuntimeInput);
        }
      },
    });

    if (execution.status !== 'succeeded') {
      return terminalCommandError(execution);
    }
    if (liveResponse) return liveResponse;
    const compact = persistedProcessCommandResultSchema.safeParse(execution.result);
    if (!compact.success) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id: execution.record.action_id,
            executed: false,
            command_id: execution.command_id,
            code: 'COMMAND_RESPONSE_INVALID',
            error: 'The durable command completed, but its response reference is invalid. Overwatch did not execute it again.',
          }, null, 2),
        }],
        isError: true,
      };
    }
    try {
      const artifact = this.engine.getEvidenceStore().getContent(
        compact.data.response_evidence_id,
      );
      if (artifact === null) {
        throw new Error(
          `response artifact is missing: ${compact.data.response_evidence_id}`,
        );
      }
      const storedResponse = JSON.parse(artifact) as ProcessToolResponse;
      return replay(compact.data, storedResponse);
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id: compact.data.action_id,
            executed: false,
            command_id: execution.command_id,
            code: 'COMMAND_RESPONSE_UNAVAILABLE',
            error: 'The original operation completed, but its evidence-backed response could not be reconstructed. Overwatch did not execute it again.',
            details: error instanceof Error ? error.message : String(error),
          }, null, 2),
        }],
        isError: true,
      };
    }
  }
}
