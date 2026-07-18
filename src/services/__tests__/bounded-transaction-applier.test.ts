import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import type { EngineContext } from '../engine-context.js';
import type { StatePersistence } from '../state-persistence.js';
import { BoundedTransactionFootprintCapture } from '../transaction-footprint.js';
import type { IdentityRewriteMutationPayloadV1 } from '../mutation-journal.js';
import type { AgentTask, EngagementConfig, NodeProperties } from '../../types.js';
import type { AgentCoordinationChangePayloadV1 } from '../agent-coordination-change.js';

function config(id: string): EngagementConfig {
  return {
    id,
    name: id,
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function node(id: string): NodeProperties {
  return {
    id,
    type: 'host',
    label: id,
    discovered_at: '2026-07-17T00:00:00.000Z',
    confidence: 1,
  };
}

describe('bounded transaction applier', () => {
  let dir: string;
  let engine: GraphEngine;
  let persistence: Pick<StatePersistence, 'applyTransactionDraft'>;
  let ctx: EngineContext;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-bounded-tx-'));
    engine = new GraphEngine(config(`bounded-${dir.split('/').at(-1)}`), join(dir, 'state.json'));
    const internals = engine as unknown as {
      persistence: Pick<StatePersistence, 'applyTransactionDraft'>;
      ctx: EngineContext;
    };
    persistence = internals.persistence;
    ctx = internals.ctx;
  });

  afterEach(() => {
    engine.dispose();
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it('applies supported primitive operations without exporting or clearing the graph', () => {
    const exportGraph = vi.spyOn(ctx.graph, 'export');
    const clearGraph = vi.spyOn(ctx.graph, 'clear');
    const result = persistence.applyTransactionDraft({
      operations: [
        { type: 'add_node', payload: { props: node('bounded-a') } },
        {
          type: 'merge_node_attrs',
          payload: { props: { id: 'bounded-a', label: 'updated' } },
        },
      ],
    }, engine);

    expect(result).toMatchObject({
      status: 'applied',
      bounded: true,
      update_detail: { new_nodes: ['bounded-a'] },
    });
    expect(ctx.graph.getNodeAttribute('bounded-a', 'label')).toBe('updated');
    expect(exportGraph).not.toHaveBeenCalled();
    expect(clearGraph).not.toHaveBeenCalled();
  });

  it('restores graph, cold-store revision, and selected state slices after a later skip', () => {
    const originalName = engine.getConfig().name;
    const originalColdRevision = ctx.coldStore.getRevision();
    const clearGraph = vi.spyOn(ctx.graph, 'clear');
    const result = persistence.applyTransactionDraft({
      operations: [
        { type: 'add_node', payload: { props: node('rolled-back-node') } },
        { type: 'add_node', payload: { props: node('rolled-back-peer') } },
        {
          type: 'add_edge',
          payload: {
            source: 'rolled-back-node',
            target: 'rolled-back-peer',
            edge_id: 'rolled-back-edge',
            props: {
              type: 'RUNS_ON',
              confidence: 1,
              discovered_at: '2026-07-17T00:00:00.000Z',
            },
          },
        },
        {
          type: 'cold_add',
          payload: {
            record: {
              id: 'rolled-back-cold',
              type: 'host',
              label: 'rolled-back-cold',
              discovered_at: '2026-07-17T00:00:00.000Z',
              last_seen_at: '2026-07-17T00:00:00.000Z',
            },
          },
        },
        {
          type: 'state_patch',
          payload: {
            payload_version: 1,
            operation_id: 'state-before-skip',
            occurred_at: '2026-07-17T00:00:00.000Z',
            reason: 'test rollback',
            slices: { config: { ...engine.getConfig(), name: 'should roll back' } },
          },
        },
        {
          type: 'merge_edge_attrs',
          payload: { edge_id: 'missing-edge', props: { confidence: 0.5 } },
        },
      ],
    }, engine);

    expect(result).toMatchObject({ status: 'skipped', reason: 'missing edge: missing-edge' });
    expect(ctx.graph.hasNode('rolled-back-node')).toBe(false);
    expect(ctx.graph.hasNode('rolled-back-peer')).toBe(false);
    expect(ctx.graph.hasEdge('rolled-back-edge')).toBe(false);
    expect(ctx.coldStore.has('rolled-back-cold')).toBe(false);
    expect(ctx.coldStore.getRevision()).toBe(originalColdRevision);
    expect(engine.getConfig().name).toBe(originalName);
    expect(clearGraph).not.toHaveBeenCalled();
  });

  it('restores every touched record when a mutator throws after changing memory', () => {
    let calls = 0;
    const throwingMutators = new Proxy(engine, {
      get(target, property, receiver) {
        if (property === 'addNode') {
          return (props: NodeProperties) => {
            const result = target.addNode(props);
            calls++;
            if (calls === 2) throw new Error('synthetic post-mutation failure');
            return result;
          };
        }
        const value = Reflect.get(target, property, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const clearGraph = vi.spyOn(ctx.graph, 'clear');

    expect(() => persistence.applyTransactionDraft({
      operations: [
        { type: 'add_node', payload: { props: node('throw-first') } },
        { type: 'add_node', payload: { props: node('throw-second') } },
      ],
    }, throwingMutators)).toThrow('synthetic post-mutation failure');

    expect(ctx.graph.hasNode('throw-first')).toBe(false);
    expect(ctx.graph.hasNode('throw-second')).toBe(false);
    expect(clearGraph).not.toHaveBeenCalled();
  });

  it('does not undo an idempotently pre-applied coordination change when a later sibling skips', () => {
    const agent: AgentTask = {
      id: 'coordination-idempotent',
      task_id: 'coordination-idempotent',
      agent_id: 'coordination-agent',
      agent_label: 'coordination-agent',
      assigned_at: '2026-07-17T00:00:00.000Z',
      status: 'completed',
      subgraph_node_ids: [],
    };
    expect(engine.registerAgent(agent).ok).toBe(true);
    const before = engine.getTask(agent.id)!;
    const after = { ...before, no_retry: true };
    const coordination: AgentCoordinationChangePayloadV1 = {
      payload_version: 1,
      operation_id: 'coordination-idempotent-op',
      occurred_at: '2026-07-17T00:00:00.000Z',
      reason: 'idempotent rollback regression',
      task_changes: [{ task_id: agent.id, before, after }],
      lease_changes: [],
    };
    expect(engine.applyAgentCoordinationChangeMutation(coordination)).toEqual({ status: 'applied' });

    const result = persistence.applyTransactionDraft({
      operations: [
        { type: 'agent_coordination_change', payload: coordination as unknown as Record<string, unknown> },
        { type: 'merge_edge_attrs', payload: { edge_id: 'missing-after-coordination', props: { confidence: 0.5 } } },
      ],
    }, engine);

    expect(result).toMatchObject({ status: 'skipped' });
    expect(engine.getTask(agent.id)).toMatchObject({ no_retry: true });
  });

  it('retains the full-baseline fallback for unsupported composite operations', () => {
    const exportGraph = vi.spyOn(ctx.graph, 'export');
    const result = persistence.applyTransactionDraft({
      operations: [{
        type: 'scope_updated',
        payload: { payload_version: 999 },
      }],
    }, engine);

    expect(result).toMatchObject({
      status: 'skipped',
      reason: 'unsupported scope_updated payload version: 999',
    });
    expect(exportGraph).toHaveBeenCalled();
  });

  it('rolls back a failed identity rewrite from its exact payload footprint', () => {
    engine.addNode(node('identity-canonical'));
    const before = structuredClone(ctx.graph.getNodeAttributes('identity-canonical') as NodeProperties);
    const payload: IdentityRewriteMutationPayloadV1 = {
      payload_version: 1,
      operation_id: 'identity-failure',
      occurred_at: '2026-07-17T00:00:00.000Z',
      canonical_node_id: 'identity-canonical',
      node_changes: [{
        node_id: 'identity-canonical',
        before: { node_id: 'identity-canonical', props: before },
        after: {
          node_id: 'identity-canonical',
          props: { ...before, label: 'must roll back' },
        },
      }],
      edge_changes: [{
        edge_id: 'identity-invalid-edge',
        after: {
          edge_id: 'identity-invalid-edge',
          source: 'identity-canonical',
          target: 'missing-identity-target',
          props: {
            type: 'RELATED',
            confidence: 1,
            discovered_at: '2026-07-17T00:00:00.000Z',
          },
        },
      }],
      audit_events: [],
      result: {
        removed_nodes: [],
        removed_edges: [],
        new_edges: ['identity-invalid-edge'],
        updated_edges: [],
        updated_canonical: true,
      },
    };
    const exportGraph = vi.spyOn(ctx.graph, 'export');
    const clearGraph = vi.spyOn(ctx.graph, 'clear');

    expect(() => engine.applyIdentityRewriteMutation(payload, false))
      .toThrow('has a missing endpoint');
    expect(ctx.graph.getNodeAttribute('identity-canonical', 'label')).toBe('identity-canonical');
    expect(ctx.graph.hasEdge('identity-invalid-edge')).toBe(false);
    expect(exportGraph).not.toHaveBeenCalled();
    expect(clearGraph).not.toHaveBeenCalled();
  });

  it('drafts, proves, commits, and publishes a finding without whole-graph export', () => {
    const exportGraph = vi.spyOn(ctx.graph, 'export');
    const updates: unknown[] = [];
    engine.onUpdate(detail => updates.push(detail));

    const result = engine.ingestFinding({
      id: 'bounded-finding',
      agent_id: 'bounded-agent',
      action_id: 'bounded-action',
      timestamp: '2026-07-17T00:00:00.000Z',
      tool_name: 'bounded-test',
      nodes: [{
        id: 'bounded-webapp',
        type: 'webapp',
        label: 'Bounded web app',
        url: 'https://bounded.example.test',
      }],
      edges: [],
    });

    expect(result.new_nodes).toContain('bounded-webapp');
    expect(engine.getNode('bounded-webapp')).toMatchObject({ type: 'webapp' });
    expect(exportGraph).not.toHaveBeenCalled();
    expect(updates).toHaveLength(1);
    expect(updates[0]).toMatchObject({ new_nodes: ['bounded-webapp'] });
  });

  it('rejects unrelated graph and cold-store writes inside an active operation', () => {
    engine.addNode(node('authorized-node'));
    engine.addNode({ ...node('unrelated-node'), sources: ['original-source'] });
    engine.addNode(node('unrelated-peer'));
    ctx.graph.setAttribute('nested', { values: ['original'] });
    const unrelatedEdge = engine.addEdge('unrelated-node', 'unrelated-peer', {
      type: 'RUNS_ON',
      confidence: 1,
      discovered_at: '2026-07-17T00:00:00.000Z',
    }).id;
    ctx.coldStore.add({
      id: 'unrelated-cold',
      type: 'host',
      label: 'unrelated-cold',
      discovered_at: '2026-07-17T00:00:00.000Z',
      last_seen_at: '2026-07-17T00:00:00.000Z',
    });

    const graphCapture = new BoundedTransactionFootprintCapture(ctx);
    expect(() => ctx.captureEngineOperations(() => ctx.applyEngineTransaction(
      {
        operations: [{
          type: 'merge_node_attrs',
          payload: { props: { id: 'authorized-node', label: 'authorized update' } },
        }],
      },
      () => {
        ctx.graph.mergeNodeAttributes('authorized-node', { label: 'authorized update' });
        ctx.graph.mergeNodeAttributes('unrelated-node', { label: 'LEAK' });
      },
      'authorization regression',
    ), graphCapture)).toThrow('outside the active engine operation footprint');
    graphCapture.restore();

    expect(ctx.graph.getNodeAttribute('authorized-node', 'label')).toBe('authorized-node');
    expect(ctx.graph.getNodeAttribute('unrelated-node', 'label')).toBe('unrelated-node');

    const referenceCapture = new BoundedTransactionFootprintCapture(ctx);
    ctx.captureEngineOperations(() => ctx.applyEngineTransaction(
      {
        operations: [{
          type: 'merge_node_attrs',
          payload: { props: { id: 'authorized-node', label: 'reference-safe update' } },
        }],
      },
      () => {
        ctx.graph.mergeNodeAttributes('authorized-node', { label: 'reference-safe update' });
        ctx.graph.getNodeAttributes('unrelated-node').label = 'REFERENCE_LEAK';
        const exportedGraph = ctx.graph.export();
        const exportedVictim = exportedGraph.nodes.find(candidate => candidate.key === 'unrelated-node');
        (exportedVictim?.attributes?.sources as string[] | undefined)?.push('EXPORT_LEAK');
        const copiedGraph = ctx.graph.copy();
        (copiedGraph.getNodeAttributes('unrelated-node').sources as string[] | undefined)
          ?.push('COPY_LEAK');
        const jsonGraph = ctx.graph.toJSON();
        const jsonVictim = jsonGraph.nodes.find(candidate => candidate.key === 'unrelated-node');
        (jsonVictim?.attributes?.sources as string[] | undefined)?.push('JSON_LEAK');
        const inspectedGraph = ctx.graph.inspect();
        inspectedGraph.nodes['unrelated-node'].label = 'INSPECT_LEAK';
        ((inspectedGraph.attributes.nested as { values: string[] }).values).push('INSPECT_ATTRIBUTE_LEAK');
        (ctx.graph.getAttributes().nested as { values: string[] }).values.push('GET_LEAK');
        ((exportedGraph.attributes?.nested as { values: string[] }).values).push('EXPORT_ATTRIBUTE_LEAK');
        ((jsonGraph.attributes?.nested as { values: string[] }).values).push('JSON_ATTRIBUTE_LEAK');
        for (const copyMethod of ['copy', 'emptyCopy', 'nullCopy'] as const) {
          const detachedCopy = ctx.graph[copyMethod]();
          (detachedCopy.getAttribute('nested') as { values: string[] }).values.push(`${copyMethod}_LEAK`);
        }
        ctx.graph.reduceNodes(
          (accumulator, id, attributes) => {
            if (id === 'unrelated-node') attributes.label = 'REDUCE_LEAK';
            return accumulator;
          },
          () => undefined,
        );
        const cold = ctx.coldStore.get('unrelated-cold');
        if (cold) cold.label = 'COLD_REFERENCE_LEAK';
        const exportedCold = ctx.coldStore.export()
          .find(record => record.id === 'unrelated-cold');
        if (exportedCold) exportedCold.label = 'COLD_EXPORT_LEAK';
        ctx.coldStore.forEach(record => {
          if (record.id === 'unrelated-cold') record.label = 'COLD_ITERATION_LEAK';
        });
      },
      'detached read regression',
    ), referenceCapture);
    referenceCapture.restore();
    expect(ctx.graph.getNodeAttribute('unrelated-node', 'label')).toBe('unrelated-node');
    expect(ctx.graph.getNodeAttribute('unrelated-node', 'sources')).toEqual(['original-source']);
    expect(ctx.graph.getAttribute('nested')).toEqual({ values: ['original'] });
    expect(ctx.coldStore.get('unrelated-cold')?.label).toBe('unrelated-cold');

    const aliasCapture = new BoundedTransactionFootprintCapture(ctx);
    expect(() => ctx.captureEngineOperations(() => ctx.applyEngineTransaction(
      {
        operations: [{
          type: 'merge_node_attrs',
          payload: { props: { id: 'authorized-node', label: 'alias-safe update' } },
        }],
      },
      () => {
        ctx.graph.mergeNodeAttributes('authorized-node', { label: 'alias-safe update' });
        ctx.graph.setSourceAttribute(unrelatedEdge, 'label', 'ALIAS_LEAK');
      },
      'graph alias authorization regression',
    ), aliasCapture)).toThrow('outside the active engine operation footprint');
    aliasCapture.restore();
    expect(ctx.graph.getNodeAttribute('authorized-node', 'label')).toBe('authorized-node');
    expect(ctx.graph.getNodeAttribute('unrelated-node', 'label')).toBe('unrelated-node');

    const graphAttributeCapture = new BoundedTransactionFootprintCapture(ctx);
    expect(() => ctx.captureEngineOperations(() => ctx.applyEngineTransaction(
      {
        operations: [{
          type: 'merge_node_attrs',
          payload: { props: { id: 'authorized-node', label: 'global-safe update' } },
        }],
      },
      () => {
        ctx.graph.mergeNodeAttributes('authorized-node', { label: 'global-safe update' });
        ctx.graph.updateAttributes(attributes => ({ ...attributes, globalLeak: 'YES' }));
      },
      'graph attribute authorization regression',
    ), graphAttributeCapture)).toThrow('outside the active engine operation footprint');
    graphAttributeCapture.restore();
    expect(ctx.graph.getAttribute('globalLeak')).toBeUndefined();

    const coldCapture = new BoundedTransactionFootprintCapture(ctx);
    expect(() => ctx.captureEngineOperations(() => ctx.applyEngineTransaction(
      {
        operations: [{
          type: 'cold_add',
          payload: {
            record: {
              id: 'authorized-cold',
              type: 'host',
              label: 'authorized-cold',
              discovered_at: '2026-07-17T00:00:00.000Z',
              last_seen_at: '2026-07-17T00:00:00.000Z',
            },
          },
        }],
      },
      () => {
        ctx.coldStore.add({
          id: 'authorized-cold',
          type: 'host',
          label: 'authorized-cold',
          discovered_at: '2026-07-17T00:00:00.000Z',
          last_seen_at: '2026-07-17T00:00:00.000Z',
        });
        ctx.coldStore.add({
          id: 'unrelated-cold',
          type: 'host',
          label: 'LEAK',
          discovered_at: '2026-07-17T00:00:00.000Z',
          last_seen_at: '2026-07-17T00:00:01.000Z',
        });
      },
      'cold authorization regression',
    ), coldCapture)).toThrow('outside the active engine operation footprint');
    coldCapture.restore();

    expect(ctx.coldStore.has('authorized-cold')).toBe(false);
    expect(ctx.coldStore.get('unrelated-cold')).toMatchObject({
      label: 'unrelated-cold',
      last_seen_at: '2026-07-17T00:00:00.000Z',
    });
  });
});
