import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import type { PendingAction } from '../pending-action-queue.js';
import { GraphEngine } from '../graph-engine.js';
import {
  ApprovalCommandService,
} from '../approval-command-service.js';

function config(): EngagementConfig {
  return {
    id: 'approval-command-test',
    name: 'Approval command test',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  };
}

function pending(actionId: string): Omit<
  PendingAction,
  'status' | 'submitted_at' | 'timeout_at'
> {
  return {
    action_id: actionId,
    description: `approval ${actionId}`,
    validation_result: 'valid',
    opsec_context: {
      global_noise_spent: 0,
      noise_budget_remaining: 1,
      recommended_approach: 'normal',
      defensive_signals: [],
    },
  };
}

describe('ApprovalCommandService', () => {
  let directory: string;
  let statePath: string;
  let engine: GraphEngine;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-approval-command-'));
    statePath = join(directory, 'state.json');
    engine = new GraphEngine(config(), statePath);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function seed(actionId: string) {
    const action = pending(actionId);
    engine.recordApprovalRequest(action);
    return engine.getPendingActionQueue().submit(action);
  }

  it('commits durable approval before settling the live waiter and replays exactly once', async () => {
    const waiter = seed('approval-success');
    const commands = new ApprovalCommandService(engine);

    const metadata = { idempotency_key: 'approval-success-attempt' };
    const first = commands.approve('approval-success', 'looks good', metadata);
    expect(first).toMatchObject({
      status: 'succeeded',
      replayed: false,
      result: { approved: true, denied: false },
    });
    expect(engine.getApprovalRequest('approval-success')).toMatchObject({
      status: 'approved',
      operator_notes: 'looks good',
    });
    await expect(waiter).resolves.toMatchObject({
      status: 'approved',
      operator_notes: 'looks good',
    });

    const replay = commands.approve('approval-success', 'looks good', metadata);
    expect(replay).toMatchObject({
      command_id: first.command_id,
      status: 'succeeded',
      replayed: true,
    });
  });

  it('does not release the live waiter when durable resolution fails', async () => {
    const waiter = seed('approval-failure');
    const commands = new ApprovalCommandService(engine);
    vi.spyOn(engine, 'resolveApprovalRequest').mockImplementation(() => {
      throw Object.assign(new Error('durable approval write failed'), {
        code: 'APPROVAL_WRITE_FAILED',
      });
    });

    expect(() => commands.approve(
      'approval-failure',
      undefined,
      { idempotency_key: 'approval-failure-first' },
    )).toThrow(
      'durable approval write failed',
    );
    expect(engine.getPendingActionQueue().getAction('approval-failure')).toMatchObject({
      status: 'pending',
    });
    expect(engine.getApprovalRequest('approval-failure')).toMatchObject({
      status: 'pending',
    });

    vi.restoreAllMocks();
    const retry = commands.deny(
      'approval-failure',
      'retry safely',
      { idempotency_key: 'approval-failure-retry' },
    );
    expect(retry.result).toMatchObject({ denied: true });
    await expect(waiter).resolves.toMatchObject({
      status: 'denied',
      reason: 'retry safely',
    });
  });

  it('replays a completed approval after restart without requiring a live waiter', async () => {
    const waiter = seed('approval-restart');
    const metadata = { idempotency_key: 'approval-restart-attempt' };
    const first = new ApprovalCommandService(engine).approve(
      'approval-restart',
      undefined,
      metadata,
    );
    await waiter;
    engine.flushNow();
    engine.dispose();

    engine = new GraphEngine(config(), statePath);
    const replay = new ApprovalCommandService(engine).approve(
      'approval-restart',
      undefined,
      metadata,
    );
    expect(replay).toMatchObject({
      command_id: first.command_id,
      status: 'succeeded',
      replayed: true,
      result: { approved: true },
    });
  });

  it('rejects the opposite resolution after the live action is already settled', async () => {
    const waiter = seed('approval-conflict');
    const commands = new ApprovalCommandService(engine);
    commands.approve('approval-conflict');
    await waiter;

    expect(() => commands.deny('approval-conflict', 'changed mind')).toThrow(
      'no live tool call is waiting',
    );
    expect(engine.getApprovalRequest('approval-conflict')?.status).toBe('approved');
  });
});
