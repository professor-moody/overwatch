import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentTask, EngagementConfig } from '../../types.js';
import type { AgentCoordinationChangePayloadV1 } from '../agent-coordination-change.js';
import {
  AgentWorkCommandError,
  AgentWorkCommandService,
} from '../agent-work-command-service.js';
import { deriveLegacyAgentWorkMetadata } from '../agent-work.js';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import { withApplicationCommandInvocation } from '../application-command-service.js';

const NOW = '2026-07-18T12:00:00.000Z';

function config(id = 'agent-work-command-test'): EngagementConfig {
  return {
    id,
    name: id,
    created_at: NOW,
    scope: { cidrs: ['10.40.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
}

function task(id: string, overrides: Partial<AgentTask> = {}): AgentTask {
  const label = `agent-${id}`;
  return {
    id,
    task_id: id,
    agent_id: label,
    agent_label: label,
    assigned_at: NOW,
    status: 'completed',
    subgraph_node_ids: ['node-a', 'node-b'],
    archetype: 'recon_scanner',
    role: 'default',
    skill: 'subnet-enumeration',
    objective: 'Map the target surface',
    ...overrides,
  };
}

const handoffInput = {
  archetype: 'web_tester',
  objective: 'Investigate the web surface',
  summary: 'Recon is complete; continue with application testing.',
  key_finding_ids: ['finding-2', 'finding-1'],
};

function splitInput() {
  return {
    summary: 'Partition the remaining node work.',
    children: [
      {
        archetype: 'recon_scanner',
        objective: 'Map node A',
        target_node_ids: ['node-a'],
      },
      {
        archetype: 'web_tester',
        objective: 'Inspect node B',
        target_node_ids: ['node-b'],
      },
    ],
  };
}

function expectCommandError(
  operation: () => unknown,
  code: string,
): AgentWorkCommandError {
  let error: unknown;
  try {
    operation();
  } catch (candidate) {
    error = candidate;
  }
  expect(error).toBeInstanceOf(AgentWorkCommandError);
  expect(error).toMatchObject({ code });
  return error as AgentWorkCommandError;
}

describe('AgentWorkCommandService', () => {
  let directory: string;
  let statePath: string;
  let engines: GraphEngine[];

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-work-command-'));
    statePath = join(directory, 'state.json');
    engines = [];
  });

  afterEach(() => {
    for (const engine of engines) engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  function open(id?: string): GraphEngine {
    const engine = new GraphEngine(config(id), statePath);
    engines.push(engine);
    return engine;
  }

  function registered(engine: GraphEngine, value: AgentTask): AgentTask {
    expect(engine.registerAgent(value)).toMatchObject({ ok: true });
    return engine.getTask(value.id)!;
  }

  function releaseFixtureLease(engine: GraphEngine, taskId: string): void {
    (engine as unknown as { ctx: { frontierLeases: { releaseByTask(id: string): number } } })
      .ctx.frontierLeases.releaseByTask(taskId);
  }

  it('hands off terminal work while preserving lineage, scope, and references', () => {
    const engine = open();
    const source = registered(engine, task('handoff-source'));
    const execution = new AgentWorkCommandService(engine).handoff(
      source.id,
      handoffInput,
      { idempotency_key: 'handoff-terminal-success', transport: 'dashboard' },
    );

    expect(execution).toMatchObject({ status: 'succeeded', replayed: false });
    expect(execution.result).toMatchObject({
      operation: 'handoff',
      source_task_id: source.id,
      warnings: [],
      created_tasks: [{
        status: 'pending',
        subgraph_node_ids: ['node-a', 'node-b'],
        archetype: 'web_tester',
        objective: handoffInput.objective,
        work: {
          root_task_id: source.id,
          relation: {
            kind: 'handoff',
            source_task_id: source.id,
            summary: handoffInput.summary,
            key_finding_ids: ['finding-1', 'finding-2'],
          },
        },
      }],
    });
    expect(engine.getTask(source.id)).toMatchObject({ no_retry: true });
  });

  it('rejects a live source and leaves the roster unchanged', () => {
    const engine = open();
    const source = registered(engine, task('live-source', { status: 'running' }));
    const before = engine.getAgentTasks();

    expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(source.id, handoffInput),
      'AGENT_HANDOFF_REQUIRES_TERMINAL',
    );
    expect(engine.getAgentTasks()).toEqual(before);
  });

  it('allows operator surfaces but rejects work shaping by a scoped worker token', () => {
    const engine = open();
    const source = registered(engine, task('operator-owned-source'));
    const actor = registered(engine, task('scoped-worker-actor', { status: 'running' }));
    const error = expectCommandError(
      () => withApplicationCommandInvocation({
        transport: 'mcp',
        actor_task_id: actor.id,
      }, () => new AgentWorkCommandService(engine).handoff(source.id, handoffInput)),
      'AGENT_WORK_OPERATOR_REQUIRED',
    );
    expect(error.http_status).toBe(403);
    expect(engine.getAgentWorkSuccessors(source.id, 'handoff')).toHaveLength(0);
    expectCommandError(
      () => withApplicationCommandInvocation({
        transport: 'mcp',
        actor_task_id: actor.id,
      }, () => new AgentWorkCommandService(engine).findDuplicates()),
      'AGENT_WORK_OPERATOR_REQUIRED',
    );
  });

  it('falls back from a stale frontier to node scope and refuses a scope-less fallback', () => {
    const engine = open();
    const scoped = registered(engine, task('stale-scoped', {
      frontier_item_id: 'frontier-no-longer-actionable',
      subgraph_node_ids: ['node-a'],
    }));
    releaseFixtureLease(engine, scoped.id);
    const fallback = new AgentWorkCommandService(engine).handoff(scoped.id, handoffInput);
    expect(fallback.result).toMatchObject({
      warnings: ['frontier_not_reacquired'],
      created_tasks: [{ subgraph_node_ids: ['node-a'] }],
    });
    expect(fallback.result!.created_tasks[0]!.frontier_item_id).toBeUndefined();

    const scopeless = registered(engine, task('stale-scopeless', {
      frontier_item_id: 'another-stale-frontier',
      subgraph_node_ids: [],
    }));
    releaseFixtureLease(engine, scopeless.id);
    expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(scopeless.id, handoffInput),
      'AGENT_HANDOFF_NO_ACTIONABLE_SCOPE',
    );
    expect(engine.getTask(scopeless.id)).not.toMatchObject({ no_retry: true });
  });

  it('replays the same command key and treats an identical different-key request semantically', () => {
    const engine = open();
    const source = registered(engine, task('idempotent-source'));
    const service = new AgentWorkCommandService(engine);
    const first = service.handoff(source.id, handoffInput, {
      idempotency_key: 'handoff-repeat-key',
    });
    const sameKey = service.handoff(source.id, handoffInput, {
      idempotency_key: 'handoff-repeat-key',
      command_id: 'ignored-on-replay',
    });
    const successorId = first.result!.created_tasks[0]!.id;
    expect(engine.updateAgentStatus(successorId, 'completed', 'successor settled')).toBe(true);
    expect(engine.dismissAgent(source.id)).toBe(false);
    expect(engine.dismissAgent(successorId)).toBe(false);
    const differentKey = service.handoff(source.id, handoffInput, {
      idempotency_key: 'handoff-semantic-repeat',
    });

    expect(sameKey.replayed).toBe(true);
    expect(sameKey.command_id).toBe(first.command_id);
    expect(differentKey.replayed).toBe(false);
    expect(first.result?.reused_existing).toBe(false);
    expect(differentKey.result?.reused_existing).toBe(true);
    expect(differentKey.result?.created_tasks.map(value => value.id))
      .toEqual(first.result?.created_tasks.map(value => value.id));
    expect(engine.getAgentTasks()).toHaveLength(2);
  });

  it('rejects leased or filtered live frontier work instead of treating it as stale node work', () => {
    const engine = open();
    const leasedSource = registered(engine, task('leased-frontier-source', {
      frontier_item_id: 'frontier-leased',
      subgraph_node_ids: ['node-a'],
    }));
    releaseFixtureLease(engine, leasedSource.id);
    const ctx = (engine as unknown as { ctx: any }).ctx;
    ctx.frontierLeases.acquire({
      frontier_item_id: 'frontier-leased',
      task_id: 'other-live-task',
      agent_id: 'other-live-agent',
      now: engine.now(),
    });
    expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(leasedSource.id, handoffInput),
      'AGENT_HANDOFF_FRONTIER_LEASED',
    );

    const filteredSource = registered(engine, task('filtered-frontier-source', {
      frontier_item_id: 'frontier-filtered',
      subgraph_node_ids: ['node-b'],
    }));
    releaseFixtureLease(engine, filteredSource.id);
    vi.spyOn(engine, 'getFrontierItem').mockImplementation(itemId =>
      itemId === 'frontier-filtered' ? ({ id: itemId } as never) : null);
    vi.spyOn(engine, 'getActionableFrontierItem').mockReturnValue(null);
    expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(filteredSource.id, handoffInput),
      'AGENT_HANDOFF_FRONTIER_FILTERED',
    );
  });

  it('prevents cross-kind successor duplication and shaping from merged-away sources', () => {
    const handoffEngine = open();
    const handoffSource = registered(handoffEngine, task('cross-kind-handoff'));
    new AgentWorkCommandService(handoffEngine).handoff(handoffSource.id, handoffInput);
    expectCommandError(
      () => new AgentWorkCommandService(handoffEngine).split(handoffSource.id, splitInput()),
      'AGENT_WORK_ALREADY_SHAPED',
    );

    handoffEngine.dispose();
    engines = engines.filter(candidate => candidate !== handoffEngine);
    statePath = join(directory, 'cross-kind-split-state.json');
    const splitEngine = open('cross-kind-split');
    const splitSource = registered(splitEngine, task('cross-kind-split-source'));
    new AgentWorkCommandService(splitEngine).split(splitSource.id, splitInput());
    expectCommandError(
      () => new AgentWorkCommandService(splitEngine).handoff(splitSource.id, handoffInput),
      'AGENT_WORK_ALREADY_SHAPED',
    );

    const canonical = registered(splitEngine, task('merge-target', { subgraph_node_ids: [] }));
    const mergedSource = registered(splitEngine, task('merge-source', { subgraph_node_ids: [] }));
    new AgentWorkCommandService(splitEngine).merge(canonical.id, {
      summary: 'Consolidate duplicate work.',
      duplicate_task_ids: [mergedSource.id],
    });
    expectCommandError(
      () => new AgentWorkCommandService(splitEngine).handoff(mergedSource.id, handoffInput),
      'AGENT_WORK_SOURCE_MERGED',
    );
  });

  it('blocks unsettled questions and open planner proposals until their original owner resolves them', () => {
    const engine = open();
    const source = registered(engine, task('decision-owner'));
    const now = Date.parse(engine.now());
    const query = engine.getAgentQueryStore().add({
      owner_task_id: source.id,
      owner_agent_label: source.agent_id,
      question: 'Should this work continue?',
      now,
    });
    const openQuestion = expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(source.id, handoffInput),
      'AGENT_WORK_OWNERSHIP_ACTIVE',
    );
    expect(openQuestion.details).toMatchObject({ blockers: expect.arrayContaining(['question']) });
    engine.getAgentQueryStore().answer(query.query_id, 'yes', now + 1);
    expect(engine.getAgentWorkTransferBlockers(source.id)).toContain('question');
    engine.getAgentQueryStore().acknowledge(query.query_id, source.id, now + 2);

    const plan = engine.getProposedPlanStore().add({
      command: 'continue the assessment',
      ops: [],
      summary: 'Continue with the next bounded step.',
      owner_task_id: source.id,
      owner_agent_label: source.agent_id,
      now,
    });
    expect(engine.getAgentWorkTransferBlockers(source.id)).toContain('plan');
    engine.getProposedPlanStore().resolve(plan.plan_id, 'denied', now + 3);
    expect(engine.getAgentWorkTransferBlockers(source.id)).not.toContain('plan');
  });

  it('reports every non-transferable ownership domain without relabelling it', () => {
    const engine = open();
    const source = registered(engine, task('resource-owner'));
    const ctx = (engine as unknown as { ctx: any }).ctx;
    ctx.sessionDescriptors.push({
      session_id: 'session-owned',
      owner_task_id: source.id,
      lifecycle: 'connected',
    });
    ctx.playbookRuns.set('playbook-owned', {
      schema_version: 1,
      run_id: 'playbook-owned',
      steps: [{ attempts: [{ claimed_by_task_id: source.id, status: 'running' }] }],
    });
    ctx.approvalRequests.set('approval-owned', {
      action_id: 'approval-owned',
      task_id: source.id,
      status: 'pending',
    });
    ctx.agentDirectives.set(source.id, [{ directive_id: 'directive-owned', status: 'pending' }]);

    expect(engine.getAgentWorkTransferBlockers(source.id)).toEqual(expect.arrayContaining([
      'session',
      'playbook_attempt',
      'approval',
      'directive',
    ]));
    expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(source.id, handoffInput),
      'AGENT_WORK_OWNERSHIP_ACTIVE',
    );
    expect(ctx.sessionDescriptors[0].owner_task_id).toBe(source.id);
  });

  it('revalidates campaign lifecycle and drops attribution for a stale active item', () => {
    const engine = open();
    const draft = engine.createCampaign({
      name: 'handoff campaign',
      strategy: 'enumeration',
      item_ids: ['frontier-campaign-item'],
      abort_conditions: [],
    });
    const inactive = registered(engine, task('inactive-campaign-source', {
      campaign_id: draft.id,
      frontier_item_id: 'frontier-campaign-item',
      subgraph_node_ids: ['node-a'],
    }));
    releaseFixtureLease(engine, inactive.id);
    expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(inactive.id, handoffInput),
      'AGENT_HANDOFF_CAMPAIGN_INACTIVE',
    );

    engine.activateCampaign(draft.id);
    const result = new AgentWorkCommandService(engine).handoff(inactive.id, handoffInput, {
      idempotency_key: 'active-stale-campaign-handoff',
    });
    expect(result.result).toMatchObject({
      warnings: ['frontier_not_reacquired', 'campaign_not_reacquired'],
    });
    expect(result.result!.created_tasks[0]!.campaign_id).toBeUndefined();
    expect(result.result!.created_tasks[0]!.frontier_item_id).toBeUndefined();
  });

  it('drops both campaign and frontier attribution when an active campaign item is terminal', () => {
    const engine = open();
    const campaign = engine.createCampaign({
      name: 'partially complete handoff campaign',
      strategy: 'enumeration',
      item_ids: ['frontier-done', 'frontier-pending'],
      abort_conditions: [],
    });
    engine.activateCampaign(campaign.id);
    engine.updateCampaignProgress(campaign.id, 'frontier-done', 'success');
    const source = registered(engine, task('terminal-campaign-item-source', {
      campaign_id: campaign.id,
      frontier_item_id: 'frontier-done',
      subgraph_node_ids: ['node-a'],
    }));
    releaseFixtureLease(engine, source.id);
    vi.spyOn(engine, 'getFrontierItem').mockReturnValue({ id: 'frontier-done' } as never);
    vi.spyOn(engine, 'getActionableFrontierItem').mockReturnValue({ id: 'frontier-done' } as never);

    const execution = new AgentWorkCommandService(engine).handoff(source.id, handoffInput);
    expect(execution.result).toMatchObject({
      warnings: ['frontier_not_reacquired', 'campaign_not_reacquired'],
      created_tasks: [{ status: 'pending' }],
    });
    expect(execution.result!.created_tasks[0]!.frontier_item_id).toBeUndefined();
    expect(execution.result!.created_tasks[0]!.campaign_id).toBeUndefined();
  });

  it('preserves an active leaf campaign item and atomically leases it to the pending successor', () => {
    const engine = open();
    const campaign = engine.createCampaign({
      name: 'active leaf handoff campaign',
      strategy: 'enumeration',
      item_ids: ['frontier-pending'],
      abort_conditions: [],
    });
    engine.activateCampaign(campaign.id);
    const source = registered(engine, task('active-campaign-item-source', {
      campaign_id: campaign.id,
      frontier_item_id: 'frontier-pending',
      subgraph_node_ids: ['node-a'],
    }));
    releaseFixtureLease(engine, source.id);
    vi.spyOn(engine, 'getFrontierItem').mockImplementation(itemId =>
      itemId === 'frontier-pending' ? ({ id: itemId } as never) : null);
    vi.spyOn(engine, 'getActionableFrontierItem').mockImplementation(itemId =>
      itemId === 'frontier-pending' ? ({ id: itemId } as never) : null);
    engine.flushNow();
    const checkpoint = JSON.parse(readFileSync(statePath, 'utf8')).journalSnapshotSeq as number;

    expect(engine.getActiveFrontierLease('frontier-pending')).toBeNull();
    const execution = new AgentWorkCommandService(engine).handoff(source.id, handoffInput, {
      idempotency_key: 'active-campaign-item-handoff',
    });
    const successor = execution.result!.created_tasks[0]!;

    expect(execution.result).toMatchObject({ warnings: [] });
    expect(successor).toMatchObject({
      status: 'pending',
      campaign_id: campaign.id,
      frontier_item_id: 'frontier-pending',
    });
    expect(engine.getActiveFrontierLease('frontier-pending')).toEqual({
      task_id: successor.id,
      agent_id: successor.agent_label,
    });
    const coordination = new MutationJournal(statePath)
      .readTransactionsSince(checkpoint)
      .flatMap(transaction => transaction.operations)
      .find(operation => operation.type === 'agent_coordination_change');
    expect(coordination).toMatchObject({
      payload: {
        task_changes: expect.arrayContaining([
          { task_id: source.id, before: expect.anything(), after: expect.anything() },
          { task_id: successor.id, before: null, after: expect.objectContaining({ status: 'pending' }) },
        ]),
        lease_changes: [{
          frontier_item_id: 'frontier-pending',
          before: null,
          after: expect.objectContaining({ task_id: successor.id }),
        }],
      },
    });
  });

  it('splits node work as an exact disjoint union and reuses autogenerated labels', () => {
    const engine = open();
    const source = registered(engine, task('split-source'));
    const service = new AgentWorkCommandService(engine);
    const first = service.split(source.id, splitInput(), {
      idempotency_key: 'split-first',
    });
    const semanticReplay = service.split(source.id, splitInput(), {
      idempotency_key: 'split-second',
    });

    expect(first.result?.created_tasks).toHaveLength(2);
    expect(first.result?.created_tasks.map(value => value.agent_label))
      .toEqual(['split-split-so-1', 'split-split-so-2']);
    expect(first.result?.created_tasks.flatMap(value => value.subgraph_node_ids).sort())
      .toEqual(['node-a', 'node-b']);
    expect(semanticReplay.result?.created_tasks.map(value => value.id).sort())
      .toEqual(first.result?.created_tasks.map(value => value.id).sort());
    expect(engine.getAgentTasks()).toHaveLength(3);
    expect(engine.getTask(source.id)).toMatchObject({ no_retry: true });
  });

  it('rejects overlapping and incomplete split partitions without changing the source', () => {
    const overlapEngine = open('split-overlap');
    const overlapSource = registered(overlapEngine, task('overlap-source'));
    const overlap = splitInput();
    overlap.children[1]!.target_node_ids = ['node-a'];
    expectCommandError(
      () => new AgentWorkCommandService(overlapEngine).split(overlapSource.id, overlap),
      'AGENT_SPLIT_SCOPE_OVERLAP',
    );
    expect(overlapEngine.getTask(overlapSource.id)).not.toMatchObject({ no_retry: true });
    expect(overlapEngine.getAgentTasks()).toHaveLength(1);

    overlapEngine.dispose();
    engines = engines.filter(candidate => candidate !== overlapEngine);
    statePath = join(directory, 'gap-state.json');
    const gapEngine = open('split-gap');
    const gapSource = registered(gapEngine, task('gap-source', {
      subgraph_node_ids: ['node-a', 'node-b', 'node-c'],
    }));
    expectCommandError(
      () => new AgentWorkCommandService(gapEngine).split(gapSource.id, splitInput()),
      'AGENT_SPLIT_SCOPE_GAP',
    );
    expect(gapEngine.getTask(gapSource.id)).not.toMatchObject({ no_retry: true });
    expect(gapEngine.getAgentTasks()).toHaveLength(1);
  });

  it('applies no split changes when any planned child conflicts', () => {
    const engine = open();
    const source = registered(engine, task('atomic-source'));
    registered(engine, task('existing-live', {
      status: 'running',
      subgraph_node_ids: ['node-b'],
      archetype: 'web_tester',
      role: 'default',
      skill: 'web-testing',
      objective: 'Existing node B work',
    }));
    const before = engine.getAgentTasks();

    expectCommandError(
      () => new AgentWorkCommandService(engine).split(source.id, splitInput()),
      'AGENT_WORK_NODE_CONFLICT',
    );
    expect(engine.getAgentTasks()).toEqual(before);
    expect(engine.getTask(source.id)).not.toMatchObject({ no_retry: true });
  });

  it('merges exact terminal duplicates, rejects a live duplicate, and repeats an existing merge', () => {
    const engine = open();
    const canonical = registered(engine, task('canonical', { subgraph_node_ids: [] }));
    const duplicate = registered(engine, task('duplicate', { subgraph_node_ids: [] }));
    const service = new AgentWorkCommandService(engine);
    const merged = service.merge(canonical.id, {
      summary: 'Collapse duplicate recon work.',
      duplicate_task_ids: [duplicate.id],
    }, { idempotency_key: 'merge-first' });
    expect(merged.result?.canonical_task_id).toBe(canonical.id);
    expect(merged.result?.updated_tasks.find(value => value.id === canonical.id)).toBeDefined();
    expect(merged.result?.updated_tasks.find(value => value.id === duplicate.id)).toMatchObject({
      no_retry: true,
      work: { merged_into_task_id: canonical.id },
    });
    const repeated = service.merge(canonical.id, {
      summary: 'Collapse duplicate recon work.',
      duplicate_task_ids: [duplicate.id],
    }, { idempotency_key: 'merge-semantic-repeat' });
    expect(repeated.result?.updated_tasks.map(value => value.id).sort())
      .toEqual([canonical.id, duplicate.id].sort());

    const live = registered(engine, task('live-duplicate', {
      status: 'running',
      subgraph_node_ids: [],
    }));
    expectCommandError(
      () => service.merge(canonical.id, {
        summary: 'Live duplicates are unsafe to merge.',
        duplicate_task_ids: [live.id],
      }),
      'AGENT_MERGE_REQUIRES_TERMINAL',
    );
    expect(engine.getTask(live.id)?.work?.merged_into_task_id).toBeUndefined();
  });

  it('refuses to transfer a terminal task that still owns a durable runtime run', () => {
    const engine = open();
    const source = registered(engine, task('owned-source'));
    engine.reserveRuntimeRun({
      run_id: 'runtime-owned-by-source',
      kind: 'headless_agent',
      task_id: source.id,
      agent_id: source.agent_id,
      daemon_owner: 'daemon-test',
      command_fingerprint: 'fingerprint-test',
    });

    const error = expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(source.id, handoffInput),
      'AGENT_WORK_OWNERSHIP_ACTIVE',
    );
    expect(error.details).toMatchObject({ blockers: ['runtime_run'] });
    expect(engine.getAgentTasks()).toHaveLength(1);
  });

  it('blocks transfer when recovery left ambiguous warning-backed ownership', () => {
    const engine = open();
    const source = registered(engine, task('ambiguous-owner-source'));
    const ctx = (engine as unknown as { ctx: any }).ctx;
    ctx.runtimeRuns.push({
      schema_version: 1,
      run_id: 'legacy',
      kind: 'headless_agent',
      agent_id: source.agent_id,
      daemon_owner: 'legacy-daemon',
      lifecycle: 'unknown',
      evidence_state: 'none',
      reserved_at: NOW,
      updated_at: NOW,
      recovery_warning: 'legacy owner is ambiguous',
    });
    ctx.coordinationRecoveryWarnings.push({
      warning_id: 'coord-ambiguous-owner',
      relationship: 'runtime_run:legacy',
      reference: source.agent_id,
      message: 'legacy owner is ambiguous',
      candidate_task_ids: [source.id, 'another-task'],
      payload: { lifecycle: 'unknown' },
    });
    expect(engine.getAgentWorkTransferBlockers(source.id)).toContain('unresolved_ownership');
    const error = expectCommandError(
      () => new AgentWorkCommandService(engine).handoff(source.id, handoffInput),
      'AGENT_WORK_OWNERSHIP_ACTIVE',
    );
    expect(error.details).toMatchObject({ blockers: ['unresolved_ownership'] });

    ctx.runtimeRuns[0].lifecycle = 'completed';
    expect(engine.getAgentWorkTransferBlockers(source.id)).not.toContain('unresolved_ownership');
    expect(new AgentWorkCommandService(engine).handoff(source.id, handoffInput).result)
      .toMatchObject({ source_task_id: source.id });
  });

  it('blocks every candidate when a live legacy tracked-process label is ambiguous', () => {
    const engine = open();
    const first = registered(engine, task('ambiguous-process-a', {
      agent_id: 'shared-label',
      agent_label: 'shared-label',
    }));
    const second = registered(engine, task('ambiguous-process-b', {
      agent_id: 'shared-label',
      agent_label: 'shared-label',
    }));
    const ctx = (engine as unknown as { ctx: any }).ctx;
    ctx.trackedProcesses.push({
      id: 'legacy-process',
      agent_id: 'shared-label',
      status: 'running',
    });
    expect(engine.getAgentWorkTransferBlockers(first.id)).toContain('unresolved_ownership');
    expect(engine.getAgentWorkTransferBlockers(second.id)).toContain('unresolved_ownership');
  });

  it('journals only bounded task images, replays them after a crash, and omits a full agents patch', () => {
    const engine = open();
    const source = registered(engine, task('wal-source'));
    engine.flushNow();
    const checkpoint = JSON.parse(readFileSync(statePath, 'utf8')).journalSnapshotSeq as number;
    const result = new AgentWorkCommandService(engine).handoff(source.id, handoffInput, {
      idempotency_key: 'wal-handoff',
    });
    const successorId = result.result!.created_tasks[0]!.id;
    const transactions = new MutationJournal(statePath).readTransactionsSince(checkpoint);
    expect(transactions).toHaveLength(1);
    const operations = transactions[0]!.operations;
    const coordination = operations.find(operation => operation.type === 'agent_coordination_change');
    expect(coordination).toMatchObject({
      payload: {
        payload_version: 1,
        task_changes: [
          { task_id: source.id, before: expect.anything(), after: expect.objectContaining({ no_retry: true }) },
          { task_id: successorId, before: null, after: expect.objectContaining({ id: successorId }) },
        ],
      },
    });
    expect(Buffer.byteLength(JSON.stringify(coordination))).toBeLessThan(32 * 1024);
    expect(operations.some(operation =>
      operation.type === 'state_patch'
      && Boolean((operation.payload as { slices?: { agents?: unknown } }).slices?.agents)
    )).toBe(false);

    engine.dispose();
    engines = engines.filter(candidate => candidate !== engine);
    const restarted = open();
    expect(restarted.getTask(source.id)).toMatchObject({ no_retry: true });
    expect(restarted.getTask(successorId)).toMatchObject({
      id: successorId,
      status: 'pending',
      work: { relation: { kind: 'handoff', source_task_id: source.id } },
    });
  });

  it('replays a complete post-fsync coordination transaction exactly once after a pre-apply crash', () => {
    const engine = open();
    const source = registered(engine, task('post-fsync-source'));
    engine.flushNow();
    const journal = (engine as unknown as {
      ctx: { mutationJournal: { appendTransaction: (draft: unknown) => unknown } };
    }).ctx.mutationJournal;
    const append = journal.appendTransaction.bind(journal);
    vi.spyOn(journal, 'appendTransaction').mockImplementationOnce((draft: unknown) => {
      append(draft);
      throw new Error('synthetic crash after WAL fsync before apply');
    });

    expect(() => new AgentWorkCommandService(engine).handoff(source.id, handoffInput, {
      command_id: 'post-fsync-handoff-command',
      idempotency_key: 'post-fsync-handoff-key',
    })).toThrow('synthetic crash after WAL fsync before apply');
    vi.restoreAllMocks();
    engine.dispose();
    engines = engines.filter(candidate => candidate !== engine);

    const restarted = open();
    const successors = restarted.getAgentWorkSuccessors(source.id, 'handoff');
    expect(successors).toHaveLength(1);
    expect(successors[0]).toMatchObject({ status: 'pending' });
    expect(restarted.getTask(source.id)).toMatchObject({ no_retry: true });
    expect(restarted.getApplicationCommandById('post-fsync-handoff-command')).toMatchObject({
      status: 'succeeded',
    });
    expect(restarted.getFullHistory().filter(event =>
      event.details?.reason === 'agent_work_handoff'
      && event.details?.source_task_id === source.id)).toHaveLength(1);

    const replay = new AgentWorkCommandService(restarted).handoff(source.id, handoffInput, {
      command_id: 'post-fsync-handoff-command',
      idempotency_key: 'post-fsync-handoff-key',
    });
    expect(replay.replayed).toBe(true);
    expect(restarted.getAgentWorkSuccessors(source.id, 'handoff')).toHaveLength(1);
    expect(restarted.getFullHistory().filter(event =>
      event.details?.reason === 'agent_work_handoff'
      && event.details?.source_task_id === source.id)).toHaveLength(1);
  });

  it('rejects an incomplete speculative replay before appending a WAL transaction', () => {
    const engine = open();
    const source = registered(engine, task('replay-proof-source'));
    const internals = engine as unknown as {
      persistence: { applyTransactionDraft: (...args: any[]) => any };
      ctx: { mutationJournal: { appendTransaction: (...args: any[]) => any } | null };
    };
    const apply = internals.persistence.applyTransactionDraft.bind(internals.persistence);
    vi.spyOn(internals.persistence, 'applyTransactionDraft').mockImplementationOnce((draft: any, mutators: any) =>
      apply({
        ...draft,
        operations: draft.operations.filter((operation: { type: string }) =>
          operation.type !== 'agent_coordination_change'),
      }, mutators));
    const append = vi.spyOn(internals.ctx.mutationJournal!, 'appendTransaction');

    expect(() => new AgentWorkCommandService(engine).handoff(source.id, handoffInput, {
      idempotency_key: 'incomplete-replay-proof',
    })).toThrow(/did not reproduce its captured after-state/);
    expect(append).not.toHaveBeenCalled();
    expect(engine.getTask(source.id)?.no_retry).toBeUndefined();
    expect(engine.getAgentWorkSuccessors(source.id, 'handoff')).toHaveLength(0);
  });

  it('keeps 50k-task and 50k-lease coordination allocation bounded to touched records', () => {
    const engine = open();
    const ctx = (engine as unknown as { ctx: any }).ctx;
    for (let index = 0; index < 50_000; index++) {
      const id = `history-${index}`;
      ctx.agents.set(id, task(id, { subgraph_node_ids: [] }));
      ctx.frontierLeases.applySnapshot(`frontier-history-${index}`, {
        frontier_item_id: `frontier-history-${index}`,
        task_id: id,
        agent_id: `agent-${id}`,
        leased_at: NOW,
        expires_at: '2026-07-19T12:00:00.000Z',
        ttl_seconds: 86_400,
      });
    }
    const serialize = vi.spyOn(ctx.frontierLeases, 'serialize');
    const cloneRoster = vi.spyOn(engine, 'getAgentTasks');
    const created = task('bounded-new', {
      status: 'running',
      subgraph_node_ids: [],
      frontier_item_id: 'frontier-bounded-new',
    });
    engine.applyAgentCoordinationTaskChanges('bounded 50k coordination', [{
      task_id: created.id,
      after: created,
    }]);
    expect(engine.getAgentWorkSuccessors('missing-source', 'handoff')).toEqual([]);
    expect(serialize).not.toHaveBeenCalled();
    expect(cloneRoster).not.toHaveBeenCalled();
    expect(ctx.frontierLeases.getSnapshot('frontier-bounded-new')).toMatchObject({
      task_id: created.id,
    });
    ctx.agents.clear();
    ctx.frontierLeases = new (ctx.frontierLeases.constructor)();
  });

  it('prevalidates every CAS image before applying any task change and is replay-idempotent', () => {
    const engine = open();
    const first = registered(engine, task('cas-first'));
    const second = registered(engine, task('cas-second'));
    const firstAfter = { ...first, no_retry: true };
    const secondAfter = { ...second, no_retry: true };
    const payload: AgentCoordinationChangePayloadV1 = {
      payload_version: 1,
      operation_id: 'cas-all-or-nothing',
      occurred_at: NOW,
      reason: 'test CAS prevalidation',
      task_changes: [
        { task_id: first.id, before: first, after: firstAfter },
        {
          task_id: second.id,
          before: { ...second, objective: 'wrong preimage' },
          after: secondAfter,
        },
      ],
      lease_changes: [],
    };
    expect(engine.applyAgentCoordinationChangeMutation(payload)).toMatchObject({
      status: 'skipped',
      reason: expect.stringContaining('no longer matches its expected preimage'),
    });
    expect(engine.getTask(first.id)?.no_retry).toBeUndefined();
    expect(engine.getTask(second.id)?.no_retry).toBeUndefined();

    payload.task_changes[1]!.before = second;
    expect(engine.applyAgentCoordinationChangeMutation(payload)).toEqual({ status: 'applied' });
    expect(engine.applyAgentCoordinationChangeMutation(payload)).toEqual({ status: 'applied' });
    expect(engine.getTask(first.id)).toMatchObject({ no_retry: true });
    expect(engine.getTask(second.id)).toMatchObject({ no_retry: true });
  });

  it('finds exact unmerged duplicate work and prefers the live canonical task', () => {
    const engine = open();
    registered(engine, task('new-live', {
      assigned_at: '2026-07-18T11:00:00.000Z',
      status: 'running',
      subgraph_node_ids: [],
    }));
    registered(engine, task('old-terminal', {
      assigned_at: '2026-07-18T10:00:00.000Z',
      subgraph_node_ids: [],
    }));
    registered(engine, task('different', { objective: 'Different work' }));
    const result = new AgentWorkCommandService(engine).findDuplicates();
    expect(result).toMatchObject({
      total: 1,
      groups: [{
        canonical_task_id: 'new-live',
        candidate_task_ids: ['new-live', 'old-terminal'],
      }],
    });
    expect(result.groups[0]!.tasks.every(value => value.work.signature.length === 64)).toBe(true);
  });

  it('rejects a merge when declared exact-work signatures differ', () => {
    const engine = open();
    const canonical = task('signature-canonical');
    canonical.work = deriveLegacyAgentWorkMetadata(canonical);
    const duplicate = task('signature-different', { objective: 'A different objective' });
    duplicate.work = deriveLegacyAgentWorkMetadata(duplicate);
    registered(engine, canonical);
    registered(engine, duplicate);

    expectCommandError(
      () => new AgentWorkCommandService(engine).merge(canonical.id, {
        summary: 'This must not merge.',
        duplicate_task_ids: [duplicate.id],
      }),
      'AGENT_WORK_SIGNATURE_MISMATCH',
    );
  });
});
