import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import { ApplicationCommandConflictError } from '../application-command-service.js';
import {
  ExternalMutationCommandService,
  buildExternalMutationFingerprint,
} from '../external-mutation-command-service.js';
import { GraphEngine } from '../graph-engine.js';

function config(id: string): EngagementConfig {
  return {
    id,
    name: id,
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: ['10.30.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('ExternalMutationCommandService', () => {
  let directory: string;
  let statePath: string;
  let engines: GraphEngine[];

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-external-command-'));
    statePath = join(directory, 'state.json');
    engines = [];
  });

  afterEach(() => {
    for (const engine of engines) engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function open(): GraphEngine {
    const engine = new GraphEngine(config('external-command-test'), statePath);
    engines.push(engine);
    return engine;
  }

  function close(engine: GraphEngine): void {
    engine.dispose();
    engines.splice(engines.indexOf(engine), 1);
  }

  const descriptor = {
    operation_id: 'mcp.test_mutation',
    request_fingerprint: buildExternalMutationFingerprint({ value: 'stable' }),
  };

  it('replays the exact inline response after restart without another mutation', async () => {
    const first = open();
    let executions = 0;
    const original = await new ExternalMutationCommandService(first).execute({
      descriptor,
      metadata: { idempotency_key: 'external-inline-retry' },
      operation: () => {
        executions += 1;
        return { ok: true, executions, nested: { value: 'stable' } };
      },
    });
    expect(original).toMatchObject({
      status: 'succeeded',
      replayed: false,
      response: { ok: true, executions: 1 },
    });
    close(first);

    const second = open();
    const replay = await new ExternalMutationCommandService(second).execute({
      descriptor,
      metadata: { retry_token: original.retry_token },
      operation: () => {
        executions += 1;
        return { ok: false, executions };
      },
    });
    expect(replay).toMatchObject({
      status: 'succeeded',
      replayed: true,
      response: { ok: true, executions: 1, nested: { value: 'stable' } },
    });
    expect(executions).toBe(1);
  });

  it('joins concurrent callers across service instances', async () => {
    const engine = open();
    let executions = 0;
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const operation = async () => {
      executions += 1;
      await gate;
      return { ok: true, executions };
    };
    const first = new ExternalMutationCommandService(engine).execute({
      descriptor,
      metadata: { idempotency_key: 'external-concurrent' },
      operation,
    });
    const second = new ExternalMutationCommandService(engine).execute({
      descriptor,
      metadata: { idempotency_key: 'external-concurrent' },
      operation,
    });
    release();
    const [left, right] = await Promise.all([first, second]);
    expect(executions).toBe(1);
    expect(left.response).toEqual({ ok: true, executions: 1 });
    expect(right.response).toEqual(left.response);
    expect([left.replayed, right.replayed]).toContain(true);
  });

  it('rejects changed request fingerprints under one idempotency identity', async () => {
    const engine = open();
    const service = new ExternalMutationCommandService(engine);
    await service.execute({
      descriptor,
      metadata: { idempotency_key: 'external-conflict' },
      operation: () => ({ ok: true }),
    });
    await expect(service.execute({
      descriptor: {
        ...descriptor,
        request_fingerprint: buildExternalMutationFingerprint({ value: 'changed' }),
      },
      metadata: { idempotency_key: 'external-conflict' },
      operation: () => ({ ok: false }),
    })).rejects.toThrow(ApplicationCommandConflictError);
  });

  it('retains ordinary error-shaped adapter responses as replayable outcomes', async () => {
    const engine = open();
    const service = new ExternalMutationCommandService(engine);
    const original = await service.execute({
      descriptor,
      metadata: { idempotency_key: 'external-tool-error' },
      operation: () => ({
        isError: true,
        content: [{ type: 'text', text: 'target rejected the operation' }],
      }),
    });
    const replay = await service.execute({
      descriptor,
      metadata: { retry_token: original.retry_token },
      operation: () => ({ isError: false }),
    });
    expect(replay.status).toBe('succeeded');
    expect(replay.response).toEqual(original.response);
  });

  it('detects response-artifact corruption without falsifying command status or re-executing', async () => {
    const engine = open();
    const service = new ExternalMutationCommandService(engine);
    let executions = 0;
    const original = await service.execute({
      descriptor,
      metadata: { idempotency_key: 'external-artifact-integrity' },
      operation: () => {
        executions += 1;
        return { output: 'a'.repeat(70 * 1024) };
      },
    });
    const command = engine.getApplicationCommand(original.idempotency_key)!;
    const result = command.result as { response_evidence_id: string };
    const record = engine.getEvidenceStore().getRecord(result.response_evidence_id)!;
    writeFileSync(
      join(directory, 'evidence', `${record.blob_key ?? record.evidence_id}.content`),
      JSON.stringify({ corrupted: true }),
    );

    const replay = await service.execute({
      descriptor,
      metadata: { retry_token: original.retry_token },
      operation: () => {
        executions += 1;
        return { output: 'must-not-run' };
      },
    });
    expect(replay).toMatchObject({
      status: 'succeeded',
      replayed: true,
      delivery_error: { code: 'COMMAND_RESPONSE_UNAVAILABLE' },
    });
    expect(replay.response).toBeUndefined();
    expect(executions).toBe(1);
  });
});
