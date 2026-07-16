import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { MutationJournal } from '../mutation-journal.js';
import type { EngagementConfig } from '../../types.js';

function config(id: string): EngagementConfig {
  return {
    id,
    name: id,
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function checkpoint(path: string): number {
  return JSON.parse(readFileSync(path, 'utf-8')).journalSnapshotSeq as number;
}

describe('EngineTransaction v2 coordination boundary', () => {
  let dir: string;
  let statePath: string;
  let engagement: EngagementConfig;
  const engines = new Set<GraphEngine>();

  function open(): GraphEngine {
    const engine = new GraphEngine(engagement, statePath);
    engines.add(engine);
    return engine;
  }

  function crash(engine: GraphEngine): void {
    if (!engines.delete(engine)) return;
    engine.dispose();
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-engine-transaction-'));
    statePath = join(dir, 'state.json');
    engagement = config(`tx-${dir.split('/').at(-1)}`);
  });

  afterEach(() => {
    for (const engine of engines) engine.dispose();
    engines.clear();
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it('recovers a command-plan state patch that crashed before the snapshot', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);
    const updates: unknown[] = [];
    first.onUpdate(detail => updates.push(detail));
    const planId = first.createCommandPlan({
      command: 'dispatch recon',
      ops: [],
      now: 1_000,
      ttlMs: 60_000,
    });

    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transactions).toHaveLength(1);
    expect(transactions[0]).toMatchObject({
      seq: base + 1,
      operations: [{
        type: 'state_patch',
        payload: {
          payload_version: 1,
          reason: 'create command plan',
          slices: { command_state: expect.anything() },
        },
      }],
    });
    expect(updates).toHaveLength(1);
    crash(first);

    const second = open();
    expect(second.getCommandPlan(planId, 1_001)).toMatchObject({
      command: 'dispatch recon',
      created_at: 1_000,
      expires_at: 61_000,
    });
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      complete: true,
      writable: true,
      base_checkpoint: base + 1,
      journal: { applied: 1, skipped: 0, failed: 0 },
    });
  });

  it('commits config, OPSEC, objective graph, and audit effects as one transaction', () => {
    const first = open();
    first.flushNow();
    const ctx = (first as any).ctx;
    const persistence = (first as any).persistence;
    const appended: Array<{ operations: Array<{ type: string; payload: Record<string, unknown> }> }> = [];
    const appendTransaction = ctx.mutationJournal.appendTransaction.bind(ctx.mutationJournal);
    vi.spyOn(ctx.mutationJournal, 'appendTransaction').mockImplementation((draft: any) => {
      appended.push(structuredClone(draft));
      return appendTransaction(draft);
    });
    const persistImmediate = persistence.persistImmediate.bind(persistence);
    vi.spyOn(persistence, 'persistImmediate')
      .mockImplementationOnce(() => {
        throw new Error('synthetic config crash before checkpoint');
      })
      .mockImplementation(persistImmediate);

    expect(() => first.updateConfig({
      name: 'Transactionally updated',
      opsec: {
        ...first.getConfig().opsec,
        enabled: true,
        max_noise: 0.25,
      },
      objectives: [{
        id: 'config-objective',
        description: 'Config transaction objective',
        achieved: false,
      }],
    })).toThrow('synthetic config crash before checkpoint');

    expect(appended).toHaveLength(1);
    expect(appended[0].operations.map(operation => operation.type)).toEqual([
      'add_node',
      'state_patch',
    ]);
    expect(appended[0].operations.at(-1)).toMatchObject({
      type: 'state_patch',
      payload: {
        reason: 'commit runtime configuration (engine.update_config)',
        slices: {
          config: expect.objectContaining({
            name: 'Transactionally updated',
            opsec: expect.objectContaining({ enabled: true, max_noise: 0.25 }),
          }),
          activity: expect.anything(),
          frontier: expect.anything(),
        },
      },
    });
    expect(first.getNode('obj-config-objective')).toMatchObject({
      type: 'objective',
      objective_description: 'Config transaction objective',
    });
    crash(first);
    vi.restoreAllMocks();

    const second = open();
    expect(second.getConfig()).toMatchObject({
      name: 'Transactionally updated',
      opsec: expect.objectContaining({ enabled: true, max_noise: 0.25 }),
      objectives: [expect.objectContaining({ id: 'config-objective' })],
    });
    expect(second.getNode('obj-config-objective')).toMatchObject({
      type: 'objective',
      objective_description: 'Config transaction objective',
    });
  });

  it('fails stop after a committed state patch cannot apply, then replays it once', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);
    const ctx = (first as any).ctx;
    const applyDurableStatePatch = ctx.applyDurableStatePatch.bind(ctx);
    vi.spyOn(ctx, 'applyDurableStatePatch').mockImplementationOnce((slices: any) => {
      // Simulate an applier that mutates the selected live slice and only then
      // fails. The transaction is committed, but degraded memory must return
      // to the pre-append baseline until restart replays the transaction.
      applyDurableStatePatch({ command_state: slices.command_state });
      throw new Error('synthetic state-patch apply failure');
    });

    expect(() => first.createCommandPlan({
      command: 'durable despite failed live apply',
      ops: [],
      now: 2_000,
      ttlMs: 60_000,
    })).toThrow('synthetic state-patch apply failure');
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      base_checkpoint: base,
      reason: expect.stringContaining('failed during in-memory application'),
    });
    const committed = new MutationJournal(statePath).readTransactionsSince(base);
    const commandPlans = (committed[0]!.operations[0]!.payload as any)
      .slices.command_state.commandPlans as Array<[string, unknown]>;
    const planId = commandPlans[0]![0];
    expect(first.getCommandPlan(planId, 2_001)).toBeUndefined();
    crash(first);
    vi.restoreAllMocks();

    const second = open();
    expect(second.getCommandPlan(planId, 2_001)).toMatchObject({
      command: 'durable despite failed live apply',
    });
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'recovered',
      complete: true,
      writable: true,
      base_checkpoint: base + 1,
      journal: { applied: 1 },
    });
  });

  it('captures guarded operations without a journal and rejects unsafe collector nesting', () => {
    const first = open();
    const ctx = (first as any).ctx;
    const journal = ctx.mutationJournal;
    const graph = ctx.graph.export();
    try {
      ctx.mutationJournal = null;
      const captured = ctx.captureEngineOperations(() => first.addNode({
        id: 'captured-without-journal',
        type: 'host',
        label: 'Captured scratch node',
        discovered_at: '2026-07-16T00:10:00.000Z',
        confidence: 1,
      }));
      expect(captured.operations).toEqual([
        expect.objectContaining({
          type: 'add_node',
          payload: {
            props: expect.objectContaining({ id: 'captured-without-journal' }),
          },
        }),
      ]);
      expect(() => ctx.captureEngineOperations(() =>
        ctx.journalMutation('add_node', { props: { id: 'append-only' } })
      )).toThrow('journalMutation is append-only');
      expect(() => ctx.captureEngineOperations(() =>
        ctx.captureEngineOperations(() => undefined)
      )).toThrow('Nested engine operation capture is not supported');
      expect(() => ctx.withTransactionDraft(() =>
        ctx.captureEngineOperations(() => undefined)
      )).toThrow('inside a state-only transaction draft');
      ctx.transactionApplyDepth = 1;
      expect(() => ctx.captureEngineOperations(() => undefined))
        .toThrow('while a committed transaction is applying');
      ctx.transactionApplyDepth = 0;
      expect(() => ctx.captureEngineOperations(async () => undefined))
        .toThrow('only supports synchronous mutations');
    } finally {
      ctx.transactionApplyDepth = 0;
      ctx.graph.clear();
      ctx.graph.import(graph);
      ctx.mutationJournal = journal;
    }
  });

  it('commits an agent registration, lease, activity, and frontier linkage as one transaction', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);
    const result = first.registerAgent({
      id: 'task-one',
      agent_id: 'agent-one',
      assigned_at: '2026-07-16T00:00:00.000Z',
      status: 'running',
      subgraph_node_ids: [],
      frontier_item_id: 'frontier-one',
      skill: 'default',
    });
    expect(result.ok).toBe(true);

    const [transaction] = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transaction.operations).toHaveLength(1);
    expect(transaction.operations[0]).toMatchObject({
      type: 'state_patch',
      payload: {
        slices: {
          agents: expect.anything(),
          activity: expect.anything(),
        },
      },
    });
    crash(first);

    const second = open();
    expect(second.getTask('task-one')).toMatchObject({
      id: 'task-one',
      status: 'interrupted',
      frontier_item_id: 'frontier-one',
    });
  });

  it('commits attached proposal and question stores before their live mutation returns', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);
    const plan = first.getProposedPlanStore().add({
      command: 'scan the target',
      ops: [],
      summary: 'scan',
      now: 10_000,
    });
    const query = first.getAgentQueryStore().add({
      task_id: 'task-question',
      agent_id: 'agent-question',
      question: 'Proceed?',
      now: 10_000,
    });
    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transactions).toHaveLength(2);
    expect(transactions.every(transaction =>
      transaction.operations[0]?.type === 'state_patch'
      && (transaction.operations[0].payload as any).slices.plans_questions
    )).toBe(true);
    crash(first);

    const second = open();
    expect(second.getProposedPlanStore().get(plan.plan_id)).toMatchObject({
      command: 'scan the target',
      status: 'open',
    });
    expect(second.getAgentQueryStore().get(query.query_id)).toMatchObject({
      question: 'Proceed?',
      status: 'open',
    });
  });

  it('journals frontier-generated campaigns before exposing them', () => {
    engagement = {
      ...engagement,
      scope: { cidrs: ['10.20.30.0/30'], domains: [], exclusions: [] },
    };
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);

    first.computeFrontier();
    const campaign = first.getCampaigns().find(item => item.strategy === 'network_discovery');
    expect(campaign).toBeDefined();

    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transactions.some(transaction =>
      transaction.operations[0]?.type === 'state_patch'
      && (transaction.operations[0].payload as any).reason === 'generate frontier campaigns'
      && (transaction.operations[0].payload as any).slices.campaigns
    )).toBe(true);
    crash(first);

    const second = open();
    expect(second.getCampaign(campaign!.id)).toMatchObject({
      id: campaign!.id,
      strategy: 'network_discovery',
    });
  });

  it('commits inference-rule state and its audit event together', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);

    first.addInferenceRule({
      id: 'rule-durable',
      name: 'Durable rule',
      description: 'Survives a crash before snapshot',
      trigger: { node_type: 'host' },
      produces: [],
    });

    const [transaction] = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transaction.operations).toEqual([
      expect.objectContaining({
        type: 'state_patch',
        payload: expect.objectContaining({
          reason: 'add or update inference rule',
          slices: expect.objectContaining({
            inference_rules: expect.anything(),
            activity: expect.anything(),
          }),
        }),
      }),
    ]);
    crash(first);

    const second = open();
    expect(second.getInferenceRules()).toContainEqual(expect.objectContaining({
      id: 'rule-durable',
      name: 'Durable rule',
    }));
    expect(second.getFullHistory()).toContainEqual(expect.objectContaining({
      event_type: 'inference_generated',
      description: 'Custom inference rule added: Durable rule',
    }));
  });

  it('commits duplicate attribution, dedup state, audit, and campaign linkage as one transaction', () => {
    const first = open();
    const observedAt = '2026-07-16T00:20:00.000Z';
    const campaign = first.createCampaign({
      name: 'Finding atomicity',
      strategy: 'custom',
      item_ids: ['frontier-finding-atomicity'],
    });
    const baseFinding = {
      id: 'finding-original',
      agent_id: 'agent-a',
      action_id: 'action-a',
      frontier_item_id: 'frontier-finding-atomicity',
      timestamp: observedAt,
      tool_name: 'nmap',
      nodes: [{
        id: 'finding-dedup-host',
        type: 'host' as const,
        label: 'Dedup host',
        ip: '10.0.0.8',
      }],
      edges: [],
    };
    const original = first.ingestFinding(baseFinding);
    const hostId = original.new_nodes[0]!;
    first.flushNow();
    const base = checkpoint(statePath);

    const duplicate = first.ingestFinding({
      ...baseFinding,
      id: 'finding-duplicate',
      agent_id: 'agent-b',
      action_id: 'action-b',
      timestamp: '2026-07-16T00:20:01.000Z',
    });
    expect(duplicate).toMatchObject({
      deduplicated: true,
      updated_nodes: [hostId],
      campaign_id: campaign.id,
    });

    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transactions).toHaveLength(1);
    expect(transactions[0]).toMatchObject({
      source_action_id: 'action-b',
      operations: [
        {
          type: 'merge_node_attrs',
          payload: {
            props: expect.objectContaining({
              id: hostId,
              sources: ['agent-a', 'agent-b'],
            }),
          },
        },
        {
          type: 'state_patch',
          payload: {
            reason: 'record duplicate finding',
            slices: {
              finding_counters: expect.objectContaining({ dedupCount: 1 }),
              activity: expect.anything(),
              campaigns: expect.anything(),
            },
          },
        },
      ],
    });
    crash(first);

    const second = open();
    expect(second.getNode(hostId)?.sources).toEqual(['agent-a', 'agent-b']);
    expect((second as any).ctx.dedupCount).toBe(1);
    expect(second.getCampaign(campaign.id)?.findings).toEqual([
      'finding-original',
      'finding-duplicate',
    ]);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'finding_ingested'
      && entry.linked_finding_ids?.includes('finding-duplicate')
    )).toHaveLength(1);
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      journal: { applied: 1 },
    });
  });

  it('commits a first-time hot+cold finding, audit, fingerprint, and campaign as one transaction', () => {
    const first = open();
    const campaign = first.createCampaign({
      name: 'First ingest',
      strategy: 'custom',
      item_ids: ['frontier-first-ingest'],
    });
    first.flushNow();
    const base = checkpoint(statePath);
    const updates: unknown[] = [];
    first.onUpdate(detail => updates.push(detail));

    const finding = {
      id: 'finding-first',
      agent_id: 'agent-first',
      action_id: 'action-first',
      frontier_item_id: 'frontier-first-ingest',
      timestamp: '2026-07-16T00:22:00.000Z',
      tool_name: 'discovery',
      nodes: [
        {
          id: 'host-first-cold',
          type: 'host' as const,
          label: '10.0.0.22',
          ip: '10.0.0.22',
          alive: true,
        },
        {
          id: 'webapp-first-hot',
          type: 'webapp' as const,
          label: 'First app',
          url: 'https://first.example.test',
        },
        {
          id: 'service-first-hot',
          type: 'service' as const,
          label: 'HTTPS service',
          port: 443,
          service_name: 'https',
        },
      ],
      edges: [{
        source: 'service-first-hot',
        target: 'webapp-first-hot',
        properties: {
          type: 'HOSTS' as const,
          confidence: 1,
          discovered_at: '2026-07-16T00:22:00.000Z',
        },
      }],
    };
    const result = first.ingestFinding(finding);
    expect(result).toMatchObject({
      new_nodes: ['webapp-first-hot', 'service-first-hot'],
      campaign_id: campaign.id,
    });
    expect((first as any).ctx.coldStore.has('host-10-0-0-22')).toBe(true);

    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transactions).toHaveLength(1);
    expect(transactions[0].source_action_id).toBe('action-first');
    expect(transactions[0].operations.map(operation => operation.type)).toEqual(
      expect.arrayContaining(['cold_add', 'add_node', 'add_edge', 'state_patch']),
    );
    expect(transactions[0].operations.at(-1)).toMatchObject({
      type: 'state_patch',
      payload: {
        reason: 'ingest finding',
        slices: {
          activity: expect.anything(),
          frontier: expect.anything(),
          finding_counters: expect.objectContaining({
            recentFindingHashes: expect.any(Array),
            dedupCount: 0,
          }),
          campaigns: expect.anything(),
          phase: expect.anything(),
        },
      },
    });
    expect(updates).toEqual([
      expect.objectContaining({
        new_nodes: ['service-first-hot', 'webapp-first-hot'],
        new_edges: expect.arrayContaining([expect.any(String)]),
      }),
    ]);
    crash(first);

    const second = open();
    expect(second.getNode('webapp-first-hot')).toMatchObject({
      type: 'webapp',
      url: 'https://first.example.test',
    });
    expect(second.findEdgeId('service-first-hot', 'webapp-first-hot', 'HOSTS')).toBeTruthy();
    expect((second as any).ctx.coldStore.has('host-10-0-0-22')).toBe(true);
    expect(second.getCampaign(campaign.id)?.findings).toEqual(['finding-first']);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'finding_ingested'
      && entry.linked_finding_ids?.includes('finding-first')
    )).toHaveLength(1);
    expect((second as any).ctx.recentFindingHashes.size).toBe(1);

    const retry = second.ingestFinding({
      ...finding,
      id: 'finding-first-retry',
      action_id: 'action-first-retry',
      timestamp: '2026-07-16T00:22:01.000Z',
    });
    expect(retry.deduplicated).toBe(true);
    expect((second as any).ctx.coldStore.count()).toBe(1);
    expect(second.getCampaign(campaign.id)?.findings).toEqual([
      'finding-first',
      'finding-first-retry',
    ]);
  });

  it('rolls back a committed first-ingest after-state failure and recovers it whole', () => {
    const first = open();
    const campaign = first.createCampaign({
      name: 'Failed live install',
      strategy: 'custom',
      item_ids: ['frontier-failed-live-install'],
    });
    first.flushNow();
    const base = checkpoint(statePath);
    const ctx = (first as any).ctx;
    const applyPatch = ctx.applyDurableStatePatch.bind(ctx);
    vi.spyOn(ctx, 'applyDurableStatePatch')
      .mockImplementationOnce(applyPatch)
      .mockImplementationOnce(applyPatch)
      .mockImplementationOnce(applyPatch)
      .mockImplementationOnce((slices: any) => {
        applyPatch(slices);
        throw new Error('synthetic finding after-state failure');
      })
      .mockImplementation(applyPatch);

    expect(() => first.ingestFinding({
      id: 'finding-install-failure',
      agent_id: 'agent-install-failure',
      action_id: 'action-install-failure',
      frontier_item_id: 'frontier-failed-live-install',
      timestamp: '2026-07-16T00:23:00.000Z',
      tool_name: 'discovery',
      nodes: [
        {
          id: 'host-install-failure-cold',
          type: 'host',
          label: '10.0.0.23',
          ip: '10.0.0.23',
          alive: true,
        },
        {
          id: 'webapp-install-failure',
          type: 'webapp',
          label: 'Failure app',
          url: 'https://failure.example.test',
        },
      ],
      edges: [],
    })).toThrow('synthetic finding after-state failure');

    expect(first.getNode('webapp-install-failure')).toBeNull();
    expect(ctx.coldStore.has('host-10-0-0-23')).toBe(false);
    expect(ctx.recentFindingHashes.size).toBe(0);
    expect(first.getCampaign(campaign.id)?.findings).toEqual([]);
    expect(first.getFullHistory().some(entry =>
      entry.linked_finding_ids?.includes('finding-install-failure')
    )).toBe(false);
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: false,
      writable: false,
      reason: expect.stringContaining('failed during in-memory application'),
    });
    expect(new MutationJournal(statePath).readTransactionsSince(base)).toHaveLength(1);
    crash(first);
    vi.restoreAllMocks();

    const second = open();
    expect(second.getNode('webapp-install-failure')).toMatchObject({ type: 'webapp' });
    expect((second as any).ctx.coldStore.has('host-10-0-0-23')).toBe(true);
    expect((second as any).ctx.recentFindingHashes.size).toBe(1);
    expect(second.getCampaign(campaign.id)?.findings).toEqual(['finding-install-failure']);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'finding_ingested'
      && entry.linked_finding_ids?.includes('finding-install-failure')
    )).toHaveLength(1);
  });

  it('restores the complete baseline when the first-ingest transaction cannot append', () => {
    const first = open();
    const campaign = first.createCampaign({
      name: 'Append failure',
      strategy: 'custom',
      item_ids: ['frontier-append-failure'],
    });
    first.flushNow();
    const base = checkpoint(statePath);
    const updates: unknown[] = [];
    first.onUpdate(detail => updates.push(detail));
    const ctx = (first as any).ctx;
    vi.spyOn(ctx.mutationJournal, 'appendTransaction')
      .mockImplementationOnce(() => {
        throw new Error('synthetic finding WAL append failure');
      });

    expect(() => first.ingestFinding({
      id: 'finding-append-failure',
      agent_id: 'agent-append-failure',
      action_id: 'action-append-failure',
      frontier_item_id: 'frontier-append-failure',
      timestamp: '2026-07-16T00:23:30.000Z',
      tool_name: 'discovery',
      nodes: [
        {
          id: 'host-append-failure-cold',
          type: 'host',
          label: '10.0.0.24',
          ip: '10.0.0.24',
          alive: true,
        },
        {
          id: 'webapp-append-failure',
          type: 'webapp',
          label: 'Append failure app',
          url: 'https://append-failure.example.test',
        },
      ],
      edges: [],
    })).toThrow('synthetic finding WAL append failure');

    expect(first.getNode('webapp-append-failure')).toBeNull();
    expect(ctx.coldStore.has('host-10-0-0-24')).toBe(false);
    expect(ctx.recentFindingHashes.size).toBe(0);
    expect(first.getCampaign(campaign.id)?.findings).toEqual([]);
    expect(first.getFullHistory().some(entry =>
      entry.linked_finding_ids?.includes('finding-append-failure')
    )).toBe(false);
    expect(updates).toEqual([]);
    expect(new MutationJournal(statePath).readTransactionsSince(base)).toEqual([]);
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
    });
  });

  it('rejects an uncaptured speculative mutation before WAL append and permits a truthful retry', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);
    const ctx = (first as any).ctx;
    vi.spyOn(first, 'linkFindingToCampaign').mockImplementationOnce(() => {
      ctx.graph.addNode('uncaptured-finding-node', {
        id: 'uncaptured-finding-node',
        type: 'host',
        label: 'Uncaptured',
        discovered_at: '2026-07-16T00:23:45.000Z',
        confidence: 1,
      });
      return undefined;
    });
    const finding = {
      id: 'finding-missing-capture',
      agent_id: 'agent-missing-capture',
      action_id: 'action-missing-capture',
      timestamp: '2026-07-16T00:23:45.000Z',
      tool_name: 'discovery',
      nodes: [{
        id: 'webapp-missing-capture',
        type: 'webapp' as const,
        label: 'Capture check app',
        url: 'https://capture-check.example.test',
      }],
      edges: [],
    };

    expect(() => first.ingestFinding(finding))
      .toThrow('did not reproduce its captured after-state');
    expect(first.getNode('webapp-missing-capture')).toBeNull();
    expect(first.getNode('uncaptured-finding-node')).toBeNull();
    expect(ctx.recentFindingHashes.size).toBe(0);
    expect(new MutationJournal(statePath).readTransactionsSince(base)).toEqual([]);
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
    });

    const retry = first.ingestFinding({
      ...finding,
      id: 'finding-missing-capture-retry',
      action_id: 'action-missing-capture-retry',
    });
    expect(retry.deduplicated).toBeUndefined();
    expect(first.getNode('webapp-missing-capture')).toMatchObject({ type: 'webapp' });
  });

  it('catches up deferred objective evaluation on restart and a duplicate retry', () => {
    engagement = {
      ...engagement,
      objectives: [{
        id: 'finding-objective',
        description: 'Obtain the finding target',
        target_node_type: 'webapp',
        target_criteria: { obtained: true },
        achieved: false,
      }],
      phases: [
        {
          id: 'finding-recon',
          name: 'Finding recon',
          order: 1,
          strategies: [],
          entry_criteria: [{ type: 'always' }],
          exit_criteria: [{ type: 'objective_achieved', objective_id: 'finding-objective' }],
        },
        {
          id: 'finding-exploit',
          name: 'Finding exploit',
          order: 2,
          strategies: [],
          entry_criteria: [{ type: 'objective_achieved', objective_id: 'finding-objective' }],
          exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
        },
      ],
    };
    const first = open();
    first.flushNow();
    const evaluateObjectives = (first as any).evaluateObjectives.bind(first);
    vi.spyOn(first as any, 'evaluateObjectives')
      .mockImplementationOnce(() => {
        throw new Error('synthetic post-finding objective crash');
      })
      .mockImplementation(evaluateObjectives);
    const finding = {
      id: 'finding-objective-source',
      agent_id: 'agent-objective',
      action_id: 'action-objective',
      timestamp: '2026-07-16T00:24:00.000Z',
      tool_name: 'discovery',
      nodes: [{
        id: 'webapp-objective-target',
        type: 'webapp' as const,
        label: 'Objective app',
        url: 'https://objective.example.test',
        obtained: true,
      }],
      edges: [],
    };
    expect(() => first.ingestFinding(finding)).toThrow('synthetic post-finding objective crash');
    expect(first.getNode('webapp-objective-target')).not.toBeNull();
    expect(first.getConfig().objectives[0].achieved).toBe(false);
    crash(first);
    vi.restoreAllMocks();

    const second = open();
    expect(second.getConfig().objectives[0].achieved).toBe(true);
    expect((second as any).ctx.lastKnownPhaseId).toBe('finding-exploit');
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'objective_achieved'
      && (entry.details as any)?.objective_id === 'finding-objective'
    )).toHaveLength(1);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'phase_exited'
      && (entry.details as any)?.phase_id === 'finding-recon'
    )).toHaveLength(1);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'phase_entered'
      && (entry.details as any)?.phase_id === 'finding-exploit'
    )).toHaveLength(1);
    const retry = second.ingestFinding({
      ...finding,
      id: 'finding-objective-retry',
      action_id: 'action-objective-retry',
      timestamp: '2026-07-16T00:24:01.000Z',
    });
    expect(retry.deduplicated).toBe(true);
    expect(second.getConfig().objectives[0].achieved).toBe(true);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'objective_achieved'
      && (entry.details as any)?.objective_id === 'finding-objective'
    )).toHaveLength(1);
  });

  it('commits phase exit, phase entry, and the phase checkpoint as one state patch', () => {
    engagement = {
      ...engagement,
      objectives: [{
        id: 'phase-gate',
        description: 'Open the exploit phase',
        achieved: false,
      }],
      phases: [
        {
          id: 'recon',
          name: 'Recon',
          order: 1,
          strategies: [],
          entry_criteria: [{ type: 'always' }],
          exit_criteria: [{ type: 'objective_achieved', objective_id: 'phase-gate' }],
        },
        {
          id: 'exploit',
          name: 'Exploit',
          order: 2,
          strategies: [],
          entry_criteria: [{ type: 'objective_achieved', objective_id: 'phase-gate' }],
          exit_criteria: [{ type: 'objective_achieved', objective_id: 'never' }],
        },
      ],
    };
    const first = open();
    (first as any).recordPhaseTransitionsIfAny();
    first.flushNow();
    expect((first as any).ctx.lastKnownPhaseId).toBe('recon');

    expect(first.updateObjective('phase-gate', { achieved: true })).toBe(true);
    const base = checkpoint(statePath);
    (first as any).recordPhaseTransitionsIfAny();

    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transactions).toHaveLength(1);
    expect(transactions[0].operations).toEqual([
      expect.objectContaining({
        type: 'state_patch',
        payload: expect.objectContaining({
          reason: 'record phase transition',
          slices: expect.objectContaining({
            activity: expect.anything(),
            frontier: expect.anything(),
            phase: { lastKnownPhaseId: 'exploit' },
          }),
        }),
      }),
    ]);
    const patchedHistory = (transactions[0].operations[0].payload as any)
      .slices.activity.activityLog as Array<{ event_type?: string; details?: { phase_id?: string } }>;
    expect(patchedHistory.slice(-2)).toEqual([
      expect.objectContaining({
        event_type: 'phase_exited',
        details: expect.objectContaining({ phase_id: 'recon' }),
      }),
      expect.objectContaining({
        event_type: 'phase_entered',
        details: expect.objectContaining({ phase_id: 'exploit' }),
      }),
    ]);
    crash(first);

    const second = open();
    expect((second as any).ctx.lastKnownPhaseId).toBe('exploit');
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'phase_exited'
      && (entry.details as any)?.phase_id === 'recon'
    )).toHaveLength(1);
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'phase_entered'
      && (entry.details as any)?.phase_id === 'exploit'
    )).toHaveLength(1);
  });

  it('replays the deterministic audit event for an inferred-edge confirmation', () => {
    const first = open();
    const observedAt = '2026-07-16T00:30:00.000Z';
    const nodeBase = {
      confidence: 1,
      discovered_at: observedAt,
      discovered_by: 'test',
    };
    first.addNode({ id: 'confirm-source', type: 'host', label: 'Source', ...nodeBase });
    first.addNode({ id: 'confirm-target', type: 'host', label: 'Target', ...nodeBase });
    first.addEdge('confirm-source', 'confirm-target', {
      type: 'RELATED',
      confidence: 0.5,
      inferred_by_rule: 'rule-confirmation',
      discovered_at: observedAt,
      discovered_by: 'test',
    });
    first.flushNow();
    const base = checkpoint(statePath);

    first.withClock('2026-07-16T00:31:00.000Z', () => {
      first.addEdge('confirm-source', 'confirm-target', {
        type: 'RELATED',
        confidence: 1,
        discovered_at: observedAt,
        discovered_by: 'test',
      });
    });
    expect(first.getFullHistory()).toContainEqual(expect.objectContaining({
      timestamp: '2026-07-16T00:31:00.000Z',
      event_type: 'inference_generated',
      description: expect.stringContaining('Confirmed inferred edge [rule-confirmation]'),
    }));
    expect(new MutationJournal(statePath).readTransactionsSince(base)).toHaveLength(1);
    crash(first);

    const second = open();
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'inference_generated'
      && entry.description.includes('Confirmed inferred edge [rule-confirmation]')
    )).toEqual([
      expect.objectContaining({
        timestamp: '2026-07-16T00:31:00.000Z',
      }),
    ]);
  });

  it('commits surfaced frontier state and dropped-item audit atomically', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);

    first.recordFrontierEmission(['frontier-stale']);
    for (let index = 0; index < 5; index++) {
      first.recordFrontierEmission([]);
    }

    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    const droppedTransaction = transactions.at(-1)!;
    expect(droppedTransaction.operations).toEqual([
      expect.objectContaining({
        type: 'state_patch',
        payload: expect.objectContaining({
          reason: 'record surfaced frontier items',
          slices: expect.objectContaining({
            frontier: expect.anything(),
            activity: expect.anything(),
          }),
        }),
      }),
    ]);
    crash(first);

    const second = open();
    expect(second.getFrontierLinkage().get('frontier-stale')).toMatchObject({
      linkage_status: 'dropped',
    });
    expect(second.getFullHistory().filter(entry =>
      entry.event_type === 'frontier_item_dropped'
      && entry.frontier_item_id === 'frontier-stale'
    )).toHaveLength(1);
  });

  it('journals web-chain annotations as one graph transaction', () => {
    const first = open();
    const observedAt = '2026-07-16T01:00:00.000Z';
    const nodeBase = {
      confidence: 1,
      discovered_at: observedAt,
      discovered_by: 'test',
    };
    first.addNode({
      id: 'bypass-1',
      type: 'vulnerability',
      label: 'Auth bypass',
      vuln_type: 'auth_bypass',
      ...nodeBase,
    });
    first.addNode({ id: 'webapp-1', type: 'webapp', label: 'App', ...nodeBase });
    first.addNode({ id: 'service-1', type: 'service', label: 'HTTP', ...nodeBase });
    first.addNode({ id: 'host-1', type: 'host', label: 'Host', ...nodeBase });
    first.addEdge('bypass-1', 'webapp-1', {
      type: 'AUTH_BYPASS',
      confidence: 1,
      discovered_at: observedAt,
      discovered_by: 'test',
    });
    first.addEdge('service-1', 'webapp-1', {
      type: 'HOSTS',
      confidence: 1,
      discovered_at: observedAt,
      discovered_by: 'test',
    });
    first.addEdge('host-1', 'service-1', {
      type: 'RUNS',
      confidence: 1,
      discovered_at: observedAt,
      discovered_by: 'test',
    });
    first.flushNow();
    const base = checkpoint(statePath);

    expect(first.enrichWebAttackChains()).toContainEqual(expect.objectContaining({
      template_id: 'auth-bypass-to-admin',
      completion: 1,
    }));
    const transactions = new MutationJournal(statePath).readTransactionsSince(base);
    const graphTransaction = transactions.find(transaction =>
      transaction.operations.some(operation => operation.type === 'merge_node_attrs')
    );
    expect(graphTransaction?.operations).toEqual([
      expect.objectContaining({
        type: 'merge_node_attrs',
        payload: expect.objectContaining({
          props: expect.objectContaining({
            id: 'host-1',
            chain_template: 'auth-bypass-to-admin',
          }),
        }),
      }),
    ]);
    crash(first);

    const second = open();
    expect(second.getNode('host-1')?.chain_template).toBe('auth-bypass-to-admin');
  });

  it('rolls back partial live web-chain annotation before restart replay', () => {
    const first = open();
    const observedAt = '2026-07-16T02:00:00.000Z';
    const nodeBase = {
      confidence: 1,
      discovered_at: observedAt,
      discovered_by: 'test',
    };
    for (const suffix of ['one', 'two']) {
      first.addNode({
        id: `sqli-${suffix}`,
        type: 'vulnerability',
        label: `SQLi ${suffix}`,
        vuln_type: 'sqli',
        exploitable: true,
        ...nodeBase,
      });
      first.addNode({
        id: `cred-${suffix}`,
        type: 'credential',
        label: `Credential ${suffix}`,
        ...nodeBase,
      });
      first.addEdge(`sqli-${suffix}`, `cred-${suffix}`, {
        type: 'EXPLOITS',
        confidence: 1,
        discovered_at: observedAt,
        discovered_by: 'test',
      });
    }
    first.flushNow();
    const base = checkpoint(statePath);

    const addNode = first.addNode.bind(first);
    vi.spyOn(first, 'addNode')
      .mockImplementationOnce(props => addNode(props))
      .mockImplementationOnce(() => {
        throw new Error('synthetic second annotation failure');
      });

    expect(() => first.enrichWebAttackChains()).toThrow('synthetic second annotation failure');
    expect(first.getNode('cred-one')?.chain_template).toBeUndefined();
    expect(first.getNode('cred-two')?.chain_template).toBeUndefined();
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      complete: false,
      writable: false,
      reason: expect.stringContaining('failed during in-memory application'),
    });

    const [transaction] = new MutationJournal(statePath).readTransactionsSince(base);
    expect(transaction.operations).toHaveLength(2);
    expect(transaction.operations.every(operation => operation.type === 'merge_node_attrs')).toBe(true);
    crash(first);
    vi.restoreAllMocks();

    const second = open();
    expect(second.getNode('cred-one')?.chain_template).toBe('sqli-to-lateral');
    expect(second.getNode('cred-two')?.chain_template).toBe('sqli-to-lateral');
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      journal: { applied: 1 },
    });
  });

  it('journals standalone activity as a bounded append delta through the public API', () => {
    const first = open();
    first.flushNow();
    const base = checkpoint(statePath);

    for (let index = 0; index < 128; index += 1) {
      first.logActionEvent({
        description: `bounded activity ${String(index).padStart(3, '0')}`,
        event_type: 'system',
        provenance: 'system',
      });
    }

    const journal = new MutationJournal(statePath);
    const transactions = journal.readTransactionsSince(base);
    journal.dispose();
    expect(transactions).toHaveLength(128);
    expect(transactions.every(transaction =>
      transaction.operations.length === 1
      && transaction.operations[0]?.type === 'activity_append'
    )).toBe(true);

    const payloadSizes = transactions.map(transaction => {
      const payload = transaction.operations[0]!.payload as Record<string, unknown>;
      expect(payload).not.toHaveProperty('slices');
      expect(payload).not.toHaveProperty('activityLog');
      expect(payload).toMatchObject({
        payload_version: 1,
        items: [{ entry: { description: expect.any(String) } }],
        expected: { activity_length: expect.any(Number) },
        final: { deterministic_seq: expect.any(Number) },
      });
      return JSON.stringify(payload).length;
    });
    expect(Math.max(...payloadSizes)).toBeLessThan(8 * 1024);
    expect(Math.max(...payloadSizes) - Math.min(...payloadSizes)).toBeLessThan(512);
  });

  it('replays activity chain, checkpoint, action mapping, and frontier linkage exactly', () => {
    engagement = {
      ...engagement,
      engagement_nonce: 'a'.repeat(64),
      hash_chain_enabled: true,
    };
    const first = open();
    first.recordFrontierEmission(['frontier-activity']);
    first.flushNow();
    const base = checkpoint(statePath);
    const ctx = (first as any).ctx;
    ctx.checkpointOptions = { every_events: 1 };

    const event = first.logActionEvent({
      description: 'validated bounded activity',
      event_type: 'action_validated',
      category: 'frontier',
      provenance: 'agent',
      action_id: 'action-activity',
      frontier_item_id: 'frontier-activity',
      agent_id: 'agent-activity',
    });
    const journal = new MutationJournal(statePath);
    const [transaction] = journal.readTransactionsSince(base);
    journal.dispose();
    expect(transaction.operations).toHaveLength(1);
    expect(transaction.operations[0]).toMatchObject({
      type: 'activity_append',
      payload: {
        payload_version: 1,
        result_event_id: event.event_id,
        items: [{
          entry: {
            event_id: event.event_id,
            event_hash: event.event_hash,
            prev_hash: event.prev_hash,
          },
          checkpoint: {
            event_id: event.event_id,
            event_hash: event.event_hash,
          },
        }],
        action_frontier_update: {
          action_id: 'action-activity',
          after: {
            frontier_item_id: 'frontier-activity',
            agent_id: 'agent-activity',
          },
        },
      },
    });
    expect(first.getFrontierLinkage().get('frontier-activity')).toMatchObject({
      linkage_status: 'validated',
      last_event_id: event.event_id,
    });
    crash(first);

    const second = open();
    const recovered = second.getFullHistory().filter(candidate =>
      candidate.event_id === event.event_id
    );
    expect(recovered).toEqual([event]);
    expect(second.getFrontierLinkage().get('frontier-activity')).toMatchObject({
      linkage_status: 'validated',
      last_event_id: event.event_id,
    });
    const recoveredChainTail = [...second.getFullHistory()]
      .reverse()
      .find(candidate => candidate.event_hash)
      ?.event_hash;
    const inherited = second.logActionEvent({
      description: 'continued bounded activity',
      event_type: 'action_started',
      provenance: 'agent',
      action_id: 'action-activity',
      agent_id: 'agent-activity',
    });
    expect(inherited.frontier_item_id).toBe('frontier-activity');
    expect(inherited.prev_hash).toBe(recoveredChainTail);
  });

  it('fails stop and rolls back live activity when a committed append cannot apply', () => {
    const first = open();
    first.recordFrontierEmission(['frontier-activity-failure']);
    first.flushNow();
    const base = checkpoint(statePath);
    const ctx = (first as any).ctx;
    const beforeHistory = first.getFullHistory();
    const beforeLinkage = first.getFrontierLinkage()
      .get('frontier-activity-failure');
    const observe = ctx.frontierLinkage.observe.bind(ctx.frontierLinkage);
    vi.spyOn(ctx.frontierLinkage, 'observe')
      .mockImplementationOnce((entry: any) => {
        observe(entry);
        throw new Error('synthetic activity apply failure');
      });

    expect(() => first.logActionEvent({
      description: 'committed activity needing recovery',
      event_type: 'action_validated',
      provenance: 'agent',
      action_id: 'action-activity-failure',
      frontier_item_id: 'frontier-activity-failure',
      agent_id: 'agent-activity-failure',
    })).toThrow('synthetic activity apply failure');

    expect(first.getFullHistory()).toEqual(beforeHistory);
    expect(first.getFrontierLinkage()
      .get('frontier-activity-failure')).toEqual(beforeLinkage);
    expect(first.getPersistenceRecoveryStatus()).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      base_checkpoint: base,
      reason: expect.stringContaining('failed during in-memory application'),
    });
    const journal = new MutationJournal(statePath);
    const [committed] = journal.readTransactionsSince(base);
    journal.dispose();
    expect(committed.operations).toEqual([
      expect.objectContaining({ type: 'activity_append' }),
    ]);
    const committedEvent = (committed.operations[0]!.payload as any)
      .items[0].entry;
    crash(first);
    vi.restoreAllMocks();

    const second = open();
    expect(second.getFullHistory().filter(candidate =>
      candidate.event_id === committedEvent.event_id
    )).toEqual([committedEvent]);
    expect(second.getFrontierLinkage()
      .get('frontier-activity-failure')).toMatchObject({
        linkage_status: 'validated',
        last_event_id: committedEvent.event_id,
      });
    expect(second.getPersistenceRecoveryStatus()).toMatchObject({
      complete: true,
      writable: true,
      journal: { applied: 1 },
    });
  });
});
