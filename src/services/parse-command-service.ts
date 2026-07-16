// ============================================================
// Overwatch — transport-neutral direct parse command boundary
// ============================================================

import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { GraphEngine } from './graph-engine.js';
import {
  ApplicationCommandFailedError,
  ApplicationCommandInProgressError,
  ApplicationCommandService,
  type ApplicationCommandMetadata,
} from './application-command-service.js';
import { canonicalJson } from './engagement-config-service.js';
import type {
  ParseIngestCommandCompletion,
  ParseIngestResult,
} from './parse-ingest.js';

export interface ParseCommandDescriptor {
  tool_name: string;
  source_kind: 'output' | 'file_path' | 'evidence';
  source_reference?: string;
  source_length: number;
  source_fingerprint: string;
  context_keys: string[];
  agent_id?: string;
  action_id?: string;
  frontier_item_id?: string;
  ingest: boolean;
}

const parseCommandDescriptorSchema = z.object({
  tool_name: z.string().min(1),
  source_kind: z.enum(['output', 'file_path', 'evidence']),
  source_reference: z.string().min(1).optional(),
  source_length: z.number().int().nonnegative(),
  source_fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  context_keys: z.array(z.string()),
  agent_id: z.string().min(1).optional(),
  action_id: z.string().min(1).optional(),
  frontier_item_id: z.string().min(1).optional(),
  ingest: z.boolean(),
}).strict();

function safeParseResult(result: ParseIngestResult): ParseIngestResult {
  const safe = structuredClone(result);
  if (safe.parse_status === 'parser_exception') {
    safe.error =
      'Parser exception detail is available through the original input/evidence.';
    safe.parser_exception = safe.error;
  } else {
    delete safe.parser_exception;
  }
  return safe;
}

/** Digest the exact parse request without storing its raw output or context. */
export function buildParseSourceFingerprint(input: unknown): string {
  return createHash('sha256').update(canonicalJson(input)).digest('hex');
}

export class ParseCommandService {
  constructor(
    private readonly engine: GraphEngine,
    private readonly commands = new ApplicationCommandService(engine),
  ) {}

  async execute(
    descriptor: ParseCommandDescriptor,
    operation: (completion: ParseIngestCommandCompletion) => ParseIngestResult,
    metadata: ApplicationCommandMetadata = {},
  ): Promise<ParseIngestResult> {
    const reserved = this.commands.reserveSync({
      command_kind: 'parse_output.execute',
      input: descriptor,
      schema: parseCommandDescriptorSchema,
      metadata: {
        ...metadata,
        action_id: metadata.action_id ?? descriptor.action_id,
        frontier_item_id:
          metadata.frontier_item_id ?? descriptor.frontier_item_id,
      },
      reserve: () => ({
        result: {
          reserved: true,
          tool_name: descriptor.tool_name,
          source_kind: descriptor.source_kind,
        },
        action_id: descriptor.action_id,
        frontier_item_id: descriptor.frontier_item_id,
      }),
    });
    if (reserved.replayed) {
      if (reserved.status === 'accepted' || reserved.status === 'running') {
        throw new ApplicationCommandInProgressError(reserved.record);
      }
      if (reserved.status === 'failed' || reserved.status === 'interrupted') {
        throw new ApplicationCommandFailedError(reserved.record);
      }
      return structuredClone(reserved.result) as unknown as ParseIngestResult;
    }

    this.commands.transition(reserved.command_id, {
      status: 'running',
      result: reserved.result,
      action_id: descriptor.action_id,
      frontier_item_id: descriptor.frontier_item_id,
    });

    let liveResult: ParseIngestResult | undefined;
    let completionAttempted = false;
    const completion: ParseIngestCommandCompletion = (result, appendAudit) => {
      const safe = safeParseResult(result);
      completionAttempted = true;
      this.commands.transition(
        reserved.command_id,
        {
          // Parser/validation/no-data failures are completed command outcomes,
          // not reasons to parse or ingest a second time.
          status: 'succeeded',
          result: safe,
          action_id: safe.action_id,
          frontier_item_id: descriptor.frontier_item_id,
          entity_refs: {
            ...(safe.finding_id ? { finding_ids: [safe.finding_id] } : {}),
            ...(safe.campaign_id ? { campaign_ids: [safe.campaign_id] } : {}),
          },
        },
        ['activity'],
        appendAudit,
      );
      liveResult = safe;
    };

    try {
      operation(completion);
    } catch (error) {
      const current = this.engine.getApplicationCommandById(reserved.command_id);
      if (current?.status === 'succeeded') {
        return structuredClone(current.result) as ParseIngestResult;
      }
      // A failed completion append must remain running for recovery. Recording
      // a second failure transition could hide a committed finding transaction.
      if (completionAttempted) throw error;
      const failed = this.commands.transition(
        reserved.command_id,
        {
          status: 'failed',
          error: {
            code: 'PARSE_COMMAND_FAILED',
            message: error instanceof Error ? error.message : String(error),
          },
          action_id: descriptor.action_id,
          frontier_item_id: descriptor.frontier_item_id,
        },
      );
      throw new ApplicationCommandFailedError(failed.record);
    }
    if (!liveResult) {
      throw new Error('Parse operation returned without a durable terminal result.');
    }
    return liveResult;
  }

  resolveActorTaskId(agentReference?: string): string | null {
    if (!agentReference) return null;
    const resolution = this.engine.resolveAgentTaskReference(agentReference);
    return resolution.status === 'exact'
      || resolution.status === 'unique_legacy_label'
      ? resolution.task.task_id ?? resolution.task.id
      : null;
  }
}
