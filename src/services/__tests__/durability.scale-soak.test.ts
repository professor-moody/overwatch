import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { EngagementConfig } from '../../types.js';
import { ApplicationCommandService } from '../application-command-service.js';
import { canonicalJson } from '../engagement-config-service.js';
import { GraphEngine } from '../graph-engine.js';
import { PlaybookCommandService } from '../playbook-command-service.js';
import type { PersistedDurablePlaybookRunV1 } from '../persisted-state.js';
import { DURABLE_STATE_SLICE_KEYS } from '../durable-state-patch.js';
import { MAX_SNAPSHOTS } from '../state-persistence.js';

const commandSchema = z.object({ epoch: z.number().int(), operation: z.number().int() }).strict();
const EPOCH_TIME = Date.parse('2030-01-01T00:00:00.000Z');

function config(): EngagementConfig {
  return {
    id: 'durability-scale-soak',
    name: 'Durability scale soak',
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  };
}

function semanticTruth(engine: GraphEngine) {
  const graph = engine.exportGraph({ includeDerivedCommunities: false });
  const ctx = (engine as unknown as {
    ctx: { captureDurableStateSlices(keys: typeof DURABLE_STATE_SLICE_KEYS): unknown };
  }).ctx;
  const durableSlices = ctx.captureDurableStateSlices(DURABLE_STATE_SLICE_KEYS) as Record<string, unknown>;
  const activitySlice = durableSlices.activity as {
    activityLog?: Array<{ description?: string }>;
  } | undefined;
  const durableWithoutActivity = { ...durableSlices };
  delete durableWithoutActivity.activity;
  const stable = {
    nodes: [...graph.nodes].sort((left, right) => left.id.localeCompare(right.id)),
    edges: [...graph.edges].sort((left, right) => {
      const leftKey = `${left.id ?? ''}:${left.source}:${left.target}:${left.properties.type}`;
      const rightKey = `${right.id ?? ''}:${right.source}:${right.target}:${right.properties.type}`;
      return leftKey.localeCompare(rightKey);
    }),
    cold_nodes: [...(graph.cold_nodes ?? [])].sort((left, right) => left.id.localeCompare(right.id)),
    durable_slices: durableWithoutActivity,
    // Starting/recovering a writable engine deliberately appends lifecycle
    // markers. Exclude only those startup observations and their derived
    // chain-tail counters; every domain/audit event remains restart truth.
    durable_activity: (activitySlice?.activityLog ?? [])
      .filter(event =>
        event.description !== 'Resumed engagement from persisted state'
        && !/^WAL replay applied \d+ of \d+ mutation\(s\)$/.test(event.description ?? '')),
    agents: engine.getAgentTasks()
      .map(task => ({ id: task.task_id ?? task.id, status: task.status, summary: task.result_summary }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    commands: engine.listApplicationCommands()
      .map(command => ({
        id: command.command_id,
        key: command.idempotency_key,
        status: command.status,
        result: command.result,
      }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    runtime_runs: engine.getRuntimeRuns()
      .map(run => ({ id: run.run_id, lifecycle: run.lifecycle, final: run.finalization_status }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    playbook_runs: engine.getPlaybookRuns()
      .map(run => {
        const durable = run.schema_version === 1
          ? run as PersistedDurablePlaybookRunV1
          : undefined;
        return {
          id: run.run_id,
          status: durable?.status,
          attempts: durable?.steps.flatMap(step => step.attempts.map(attempt => ({
            id: attempt.attempt_id,
            status: attempt.status,
          }))) ?? [],
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id)),
    questions: engine.getAgentQueryStore().getAll()
      .map(query => ({ id: query.query_id, status: query.status, answer: query.answer }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    plans: engine.getProposedPlanStore().getAll()
      .map(plan => ({ id: plan.plan_id, status: plan.status, command: plan.command }))
      .sort((left, right) => left.id.localeCompare(right.id)),
  };
  return JSON.parse(canonicalJson(stable)) as typeof stable;
}

describe.sequential('mixed durability soak', () => {
  let root: string | undefined;
  let engine: GraphEngine | undefined;

  afterEach(() => {
    engine?.dispose();
    engine = undefined;
    if (root) rmSync(root, { recursive: true, force: true });
    root = undefined;
  });

  it('preserves semantic truth through 300+ mixed operations and repeated restarts', () => {
    root = mkdtempSync(join(tmpdir(), 'overwatch-durability-soak-'));
    const stateFile = join(root, 'state.json');
    const epochs = process.env.OVERWATCH_SOAK_PROFILE === 'extended' ? 40 : 12;
    const graphCommandsPerEpoch = 16;
    let expectedTruth: ReturnType<typeof semanticTruth> | undefined;
    let previousCommand: { epoch: number; operation: number } | undefined;
    let operationCount = 0;
    let expectWalOnlyReplay = false;
    let walOnlyReopens = 0;

    for (let epoch = 0; epoch < epochs; epoch++) {
      engine = new GraphEngine(config(), stateFile);
      const recovery = engine.getStatePersistenceRecoveryStatus();
      expect(recovery).toMatchObject({ complete: true, writable: true });
      expect(recovery.highest_allocated_logical_seq)
        .toBe(recovery.highest_contiguous_applied_logical_seq);
      if (expectWalOnlyReplay) {
        expect(recovery.journal.applied).toBeGreaterThan(0);
        walOnlyReopens++;
      }
      if (expectedTruth) expect(semanticTruth(engine)).toEqual(expectedTruth);

      if (previousCommand) {
        let duplicateHandlerRan = false;
        const replay = new ApplicationCommandService(engine).executeSync({
          command_kind: 'soak.graph.add',
          input: previousCommand,
          schema: commandSchema,
          metadata: {
            command_id: `ignored-retry-${epoch}`,
            idempotency_key: `soak-graph-${previousCommand.epoch}-${previousCommand.operation}`,
          },
          state_keys: [],
          execute: () => {
            duplicateHandlerRan = true;
            throw new Error('replayed graph command executed twice');
          },
        });
        expect(replay).toMatchObject({ replayed: true, status: 'succeeded' });
        expect(duplicateHandlerRan).toBe(false);
      }

      const commands = new ApplicationCommandService(engine);
      for (let operation = 0; operation < graphCommandsPerEpoch; operation++) {
        const input = { epoch, operation };
        const execution = commands.executeSync({
          command_kind: 'soak.graph.add',
          input,
          schema: commandSchema,
          metadata: {
            command_id: `soak-graph-command-${epoch}-${operation}`,
            idempotency_key: `soak-graph-${epoch}-${operation}`,
          },
          state_keys: [],
          execute: parsed => {
            const nodeId = `soak-node-${parsed.epoch}-${parsed.operation}`;
            engine!.addNode({
              id: nodeId,
              type: 'group',
              label: `Soak node ${parsed.epoch}/${parsed.operation}`,
              confidence: 1,
              discovered_at: new Date(EPOCH_TIME + parsed.epoch * 1_000 + parsed.operation).toISOString(),
            });
            return { node_id: nodeId };
          },
        });
        expect(execution).toMatchObject({ replayed: false, status: 'succeeded' });
        operationCount += 2; // one domain mutation plus its durable command outcome
        previousCommand = input;
      }

      const taskId = `soak-task-${epoch}`;
      expect(engine.registerAgent({
        id: taskId,
        task_id: taskId,
        agent_id: `soak-agent-${epoch}`,
        agent_label: `soak-agent-${epoch}`,
        assigned_at: new Date(EPOCH_TIME + epoch * 1_000).toISOString(),
        status: 'running',
        subgraph_node_ids: [],
      }).ok).toBe(true);
      expect(engine.updateAgentStatus(taskId, 'completed', `epoch ${epoch} complete`)).toBe(true);
      operationCount += 2;

      const runId = `soak-runtime-${epoch}`;
      engine.reserveRuntimeRun({
        run_id: runId,
        kind: 'tracked_process',
        task_id: taskId,
        agent_id: `soak-agent-${epoch}`,
        daemon_owner: 'soak-daemon',
        command_fingerprint: createHash('sha256').update(runId).digest('hex'),
      });
      engine.finalizeRuntimeRun({ run_id: runId, lifecycle: 'completed' });
      operationCount += 2;

      const playbooks = new PlaybookCommandService(engine);
      const opened = playbooks.open({
        definition: {
          definition_id: 'soak-playbook',
          definition_version: 1,
          provider: 'aws',
          title: 'Soak playbook',
        },
        credential_id: `soak-credential-${epoch}`,
        normalized_inputs: { epoch },
        new_run: true,
        steps: [{
          step: 1,
          step_id: 'identity',
          description: 'Resolve soak identity',
          runner: 'run_bash',
          command: `identity-${epoch}`,
          parse_with: 'aws_sts_caller_identity',
          parser_context: { source_credential_id: `soak-credential-${epoch}` },
          depends_on: [],
          required_bindings: [],
          produces_bindings: [],
          ready: true,
          status: 'ready',
        }],
      }, {
        command_id: `soak-playbook-open-${epoch}`,
        idempotency_key: `soak-playbook-open-${epoch}`,
      });
      const claim = playbooks.start(opened.run.run_id, 'identity', {
        command_id: `soak-playbook-start-${epoch}`,
        idempotency_key: `soak-playbook-start-${epoch}`,
      });
      playbooks.complete(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
        execution_outcome: 'failed',
        error: 'deterministic pre-execution soak failure',
      }, {
        command_id: `soak-playbook-complete-${epoch}`,
        idempotency_key: `soak-playbook-complete-${epoch}`,
      });
      operationCount += 3;

      const question = engine.getAgentQueryStore().add({
        owner_task_id: taskId,
        owner_agent_label: `soak-agent-${epoch}`,
        question: `Continue epoch ${epoch}?`,
        now: EPOCH_TIME + epoch * 10,
      });
      expect(engine.getAgentQueryStore().answer(
        question.query_id,
        'yes',
        EPOCH_TIME + epoch * 10 + 1,
      )).not.toBeNull();
      expect(engine.getAgentQueryStore().acknowledge(
        question.query_id,
        taskId,
        EPOCH_TIME + epoch * 10 + 2,
      )).not.toBeNull();
      engine.createCommandPlan({
        command: `soak plan ${epoch}`,
        ops: [],
        now: EPOCH_TIME + epoch * 10,
        ttlMs: 60 * 60_000,
      });
      operationCount += 4;

      expectedTruth = semanticTruth(engine);
      // Alternate real crash-before-snapshot WAL recovery with forced base
      // publication/compaction so the same test proves both recovery paths.
      expectWalOnlyReplay = epoch % 2 === 0;
      if (!expectWalOnlyReplay) engine.flushNow();
      engine.dispose();
      engine = undefined;
    }

    expect(operationCount).toBeGreaterThanOrEqual(300);
    expect(walOnlyReopens).toBe(Math.floor(epochs / 2));
    for (let reopen = 0; reopen < 3; reopen++) {
      engine = new GraphEngine(config(), stateFile);
      expect(semanticTruth(engine)).toEqual(expectedTruth);
      const recovery = engine.getStatePersistenceRecoveryStatus();
      expect(recovery).toMatchObject({ complete: true, writable: true });
      expect(recovery.highest_allocated_logical_seq)
        .toBe(recovery.highest_contiguous_applied_logical_seq);
      engine.dispose();
      engine = undefined;
    }

    const residue = readdirSync(root).filter(name =>
      name.endsWith('.tmp')
      || name.endsWith('.compact')
      || name.includes('.quarantine-'));
    expect(residue).toEqual([]);
    const snapshotDirectory = join(root, '.snapshots');
    expect(existsSync(snapshotDirectory)).toBe(true);
    const snapshots = readdirSync(snapshotDirectory).filter(name => name.endsWith('.json'));
    expect(snapshots).toHaveLength(MAX_SNAPSHOTS);
    const checkpoints = snapshots.map(name => {
      const snapshot = JSON.parse(readFileSync(join(snapshotDirectory, name), 'utf8')) as {
        journalSnapshotSeq?: number;
      };
      return snapshot.journalSnapshotSeq;
    });
    expect(checkpoints.every(checkpoint => Number.isSafeInteger(checkpoint))).toBe(true);
    expect(new Set(checkpoints).size).toBe(snapshots.length);
  }, 90_000);
});
