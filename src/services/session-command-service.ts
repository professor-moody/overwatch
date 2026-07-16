// ============================================================
// Overwatch — durable boundary for instrumented session sends
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

export interface SessionToolResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
  [SESSION_COMMAND_TERMINAL]?: Parameters<GraphEngine['logActionEvent']>[0];
  [key: string]: unknown;
}

export const SESSION_COMMAND_TERMINAL = Symbol('overwatch.session-command-terminal');

export interface SessionCommandDescriptor {
  session_id: string;
  action_id?: string;
  agent_id?: string;
  command_length: number;
  request_fingerprint: string;
  timeout_ms: number;
  idle_ms: number;
  has_wait_for: boolean;
  force: boolean;
  technique?: string;
  target_ip?: string;
  has_target_url: boolean;
  target_node?: string;
  allow_unverified_scope: boolean;
  noise_estimate?: number;
}

interface PersistedSessionCommandResult {
  action_id?: string;
  is_error: boolean;
  response_fields: Record<string, unknown>;
  evidence_id?: string;
  captured_bytes: number;
  had_text: boolean;
}

const sessionCommandDescriptorSchema = z.object({
  session_id: z.string().min(1),
  action_id: z.string().min(1).optional(),
  agent_id: z.string().min(1).optional(),
  command_length: z.number().int().nonnegative(),
  request_fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  timeout_ms: z.number().int().nonnegative(),
  idle_ms: z.number().int().nonnegative(),
  has_wait_for: z.boolean(),
  force: z.boolean(),
  technique: z.string().min(1).optional(),
  target_ip: z.string().min(1).optional(),
  has_target_url: z.boolean(),
  target_node: z.string().min(1).optional(),
  allow_unverified_scope: z.boolean(),
  noise_estimate: z.number().optional(),
}).strict();

const persistedSessionCommandResultSchema = z.object({
  action_id: z.string().min(1).optional(),
  is_error: z.boolean(),
  response_fields: z.record(z.unknown()),
  evidence_id: z.string().min(1).optional(),
  captured_bytes: z.number().int().nonnegative(),
  had_text: z.boolean(),
}).strict();

function payload(response: SessionToolResponse): Record<string, unknown> {
  const text = response.content.find(entry => entry.type === 'text')?.text;
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function compactResponse(response: SessionToolResponse): PersistedSessionCommandResult {
  const source = structuredClone(payload(response));
  const rawText = typeof source.text === 'string' ? source.text : '';
  delete source.text;
  delete source.command;
  delete source.output;
  delete source.raw_output;
  return {
    action_id: typeof source.action_id === 'string' ? source.action_id : undefined,
    is_error: response.isError === true,
    response_fields: source,
    evidence_id: typeof source.evidence_id === 'string'
      ? source.evidence_id
      : undefined,
    captured_bytes: Buffer.byteLength(rawText),
    had_text: Object.prototype.hasOwnProperty.call(payload(response), 'text'),
  };
}

function normalizedLiveResponse(
  response: SessionToolResponse,
  compact: PersistedSessionCommandResult,
): SessionToolResponse {
  const normalized = structuredClone(compact.response_fields);
  if (compact.had_text) {
    const original = payload(response);
    normalized.text = typeof original.text === 'string' ? original.text : '';
  }
  return {
    content: [{
      type: 'text',
      text: JSON.stringify(normalized, null, 2),
    }],
    ...(response.isError === true ? { isError: true } : {}),
  };
}

function commandFailure(
  execution: ApplicationCommandExecution<PersistedSessionCommandResult>,
): SessionToolResponse {
  const running = execution.status === 'accepted' || execution.status === 'running';
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        action_id: execution.record.action_id,
        executed: false,
        command_id: execution.command_id,
        code: running
          ? 'COMMAND_IN_PROGRESS'
          : execution.error?.code ?? (
              execution.status === 'interrupted'
                ? 'COMMAND_INTERRUPTED'
                : 'COMMAND_FAILED'
            ),
        error: running
          ? 'The original session command is still running; Overwatch did not send it again.'
          : execution.error?.message
            ?? 'The original session command has no replayable terminal result.',
      }, null, 2),
    }],
    isError: true,
  };
}

export function buildSessionRequestFingerprint(shape: unknown): string {
  return createHash('sha256').update(canonicalJson(shape)).digest('hex');
}

export class SessionCommandService {
  private readonly commands: ApplicationCommandService;

  constructor(private readonly engine: GraphEngine) {
    this.commands = new ApplicationCommandService(engine);
  }

  async execute(
    descriptor: SessionCommandDescriptor,
    operation: (bindActionId: (actionId: string) => void) => Promise<SessionToolResponse>,
    metadata: ApplicationCommandMetadata = {},
  ): Promise<SessionToolResponse> {
    let liveResponse: SessionToolResponse | undefined;
    let terminalActionInput:
      | Parameters<GraphEngine['logActionEvent']>[0]
      | undefined;
    const execution = await this.commands.executeAsync({
      command_kind: 'session.send',
      input: descriptor,
      schema: sessionCommandDescriptorSchema,
      metadata: {
        ...metadata,
        action_id: metadata.action_id ?? descriptor.action_id,
      },
      reserve: () => ({
        result: {
          reserved: true,
          session_id: descriptor.session_id,
        },
        action_id: descriptor.action_id,
        entity_refs: { session_ids: [descriptor.session_id] },
      }),
      execute: async (_input, runningRecord) => {
        liveResponse = await operation(actionId => {
          if (runningRecord.action_id === actionId) return;
          this.commands.transition(runningRecord.command_id, {
            status: 'running',
            result: runningRecord.result,
            action_id: actionId,
            entity_refs: {
              session_ids: [descriptor.session_id],
            },
          });
          runningRecord.action_id = actionId;
        });
        terminalActionInput = liveResponse[SESSION_COMMAND_TERMINAL];
        if (terminalActionInput) {
          delete liveResponse[SESSION_COMMAND_TERMINAL];
        }
        const compact = compactResponse(liveResponse);
        liveResponse = normalizedLiveResponse(liveResponse, compact);
        return {
          status: 'succeeded',
          result: compact,
          action_id: compact.action_id ?? descriptor.action_id,
          entity_refs: {
            session_ids: [descriptor.session_id],
            ...(compact.evidence_id
              ? { evidence_ids: [compact.evidence_id] }
              : {}),
          },
        };
      },
      completion_state_keys: ['activity'],
      completion_effects: () => {
        if (terminalActionInput) {
          this.engine.logActionEvent(terminalActionInput);
        }
      },
    });
    if (liveResponse) return liveResponse;
    if (execution.status !== 'succeeded') return commandFailure(execution);
    const compact = persistedSessionCommandResultSchema.safeParse(execution.result);
    if (!compact.success) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id: execution.record.action_id,
            executed: false,
            code: 'COMMAND_RESPONSE_INVALID',
            error: 'The original session command result is invalid; Overwatch did not send it again.',
          }, null, 2),
        }],
        isError: true,
      };
    }
    const reconstructed = structuredClone(compact.data.response_fields);
    if (compact.data.had_text) {
      if (!compact.data.evidence_id) {
        if (compact.data.captured_bytes === 0) {
          reconstructed.text = '';
        } else {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                action_id: compact.data.action_id,
                executed: false,
                code: 'COMMAND_RESPONSE_UNAVAILABLE',
                error: 'The original session output was not durably captured; Overwatch did not send the command again.',
              }, null, 2),
            }],
            isError: true,
          };
        }
      } else {
        const text = this.engine.getEvidenceStore().getRawOutput(
          compact.data.evidence_id,
          { max_bytes: 16 * 1024 * 1024 },
        );
        if (text === null) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                action_id: compact.data.action_id,
                executed: false,
                code: 'COMMAND_RESPONSE_UNAVAILABLE',
                error: 'The original session output evidence is unavailable; Overwatch did not send the command again.',
                evidence_id: compact.data.evidence_id,
              }, null, 2),
            }],
            isError: true,
          };
        }
        // SessionManager places text first in its result today. Property order is
        // not a wire contract, but retaining it keeps JSON snapshots stable.
        reconstructed.text = text;
      }
    }
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(reconstructed, null, 2),
      }],
      ...(compact.data.is_error ? { isError: true } : {}),
    };
  }
}
