import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Graph from 'graphology';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { NodeProperties, EdgeProperties, InferenceRule } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { StatePersistence, MAX_SNAPSHOTS, FLUSH_DEBOUNCE_MS } from '../state-persistence.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig() {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
  } as any;
}

const BUILTIN_RULES: InferenceRule[] = [{
  id: 'rule-builtin-test',
  name: 'Test builtin rule',
  description: '',
  trigger: { node_type: 'host' },
  produces: [{ edge_type: 'RELATED', source_selector: 'trigger_node', target_selector: 'trigger_node', confidence: 0.5 }],
}];

const now = new Date().toISOString();

describe('StatePersistence', () => {
  let tempDir: string;
  const instances: StatePersistence[] = [];

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'overwatch-persist-test-'));
  });

  afterEach(() => {
    // Dispose all instances to cancel timers and remove process listeners
    for (const p of instances) p.dispose();
    instances.length = 0;
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });

  function buildPersistence(stateFile?: string) {
    const graph = makeGraph();
    const filePath = stateFile || join(tempDir, 'state.json');
    const ctx = new EngineContext(graph, makeConfig(), filePath);
    ctx.inferenceRules.push(...BUILTIN_RULES);
    const persistence = new StatePersistence(ctx, BUILTIN_RULES, makeGraph);
    instances.push(persistence);
    return { ctx, persistence, graph };
  }

  // =============================================
  // persist + loadState round-trip
  // =============================================
  describe('persist + loadState', () => {
    it('round-trips graph nodes and edges through persist/load', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', ip: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);
      graph.addNode('svc-1', { id: 'svc-1', type: 'service', label: 'SMB', port: 445, discovered_at: now, confidence: 1.0 } as NodeProperties);
      graph.addEdge('host-1', 'svc-1', { type: 'RUNS', confidence: 1.0, discovered_at: now } as EdgeProperties);

      persistence.persist();
      persistence.flushNow();

      // Load into a fresh context
      const { ctx: ctx2, persistence: persistence2 } = buildPersistence(ctx.stateFilePath);
      persistence2.loadState();

      expect(ctx2.graph.hasNode('host-1')).toBe(true);
      expect(ctx2.graph.hasNode('svc-1')).toBe(true);
      expect(ctx2.graph.edges('host-1', 'svc-1').length).toBe(1);
    });

    it('round-trips activity log entries', () => {
      const { ctx, persistence } = buildPersistence();
      ctx.logEvent({ description: 'test event', event_type: 'action_completed', result_classification: 'success' });

      persistence.persist();
      persistence.flushNow();

      const { ctx: ctx2, persistence: persistence2 } = buildPersistence(ctx.stateFilePath);
      persistence2.loadState();

      expect(ctx2.activityLog.length).toBe(1);
      expect(ctx2.activityLog[0].description).toBe('test event');
      expect(ctx2.activityLog[0].outcome).toBe('success');
    });

    it('round-trips agents', () => {
      const { ctx, persistence } = buildPersistence();
      ctx.agents.set('agent-1', {
        id: 'task-1',
        agent_id: 'agent-1',
        description: 'test task',
        status: 'running',
        created_at: now,
      } as any);

      persistence.persist();
      persistence.flushNow();

      const { ctx: ctx2, persistence: persistence2 } = buildPersistence(ctx.stateFilePath);
      persistence2.loadState();

      expect(ctx2.agents.has('agent-1')).toBe(true);
      expect(ctx2.agents.get('agent-1')?.status).toBe('running');
    });

    it('excludes builtin rules from persisted state', () => {
      const { ctx, persistence } = buildPersistence();
      // Add a custom rule alongside builtins
      ctx.inferenceRules.push({
        id: 'custom-rule-1',
        name: 'Custom Rule',
        description: '',
        trigger: { node_type: 'host' },
        produces: [{ edge_type: 'RELATED', source_selector: 'trigger_node', target_selector: 'trigger_node', confidence: 0.5 }],
      });

      persistence.persist();
      persistence.flushNow();

      const raw = JSON.parse(readFileSync(ctx.stateFilePath, 'utf-8'));
      // Should only contain the custom rule, not the builtin
      expect(raw.inferenceRules.length).toBe(1);
      expect(raw.inferenceRules[0].id).toBe('custom-rule-1');
    });

    it('round-trips cold store records', () => {
      const { ctx, persistence } = buildPersistence();
      ctx.coldStore.add({
        id: 'host-cold-1',
        type: 'host',
        label: '10.0.0.99',
        ip: '10.0.0.99',
        discovered_at: now,
        last_seen_at: now,
        subnet_cidr: '10.0.0.0/24',
        alive: true,
      });

      persistence.persist();
      persistence.flushNow();

      const { ctx: ctx2, persistence: persistence2 } = buildPersistence(ctx.stateFilePath);
      persistence2.loadState();

      expect(ctx2.coldStore.has('host-cold-1')).toBe(true);
      expect(ctx2.coldStore.get('host-cold-1')?.ip).toBe('10.0.0.99');
    });
  });

  // =============================================
  // Snapshot rotation
  // =============================================
  describe('snapshot rotation', () => {
    it('creates snapshot files on persist', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      // First persist creates the state file
      persistence.persist();
      persistence.flushNow();
      expect(existsSync(ctx.stateFilePath)).toBe(true);

      // Force snapshot rotation by resetting timer
      ctx.lastSnapshotTime = 0;
      persistence.persist();
      persistence.flushNow();

      const snapshots = persistence.listSnapshots();
      expect(snapshots.length).toBeGreaterThan(0);
    });

    it('prunes old snapshots beyond MAX_SNAPSHOTS', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      // Create initial state
      persistence.persist();
      persistence.flushNow();

      // Create more than MAX_SNAPSHOTS by forcing rotation each time
      for (let i = 0; i < MAX_SNAPSHOTS + 3; i++) {
        ctx.lastSnapshotTime = 0;
        persistence.persist();
        persistence.flushNow();
      }

      const snapshots = persistence.listSnapshots();
      expect(snapshots.length).toBeLessThanOrEqual(MAX_SNAPSHOTS);
    });
  });

  // =============================================
  // rollbackToSnapshot
  // =============================================
  describe('rollbackToSnapshot', () => {
    it('restores graph state from a snapshot', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: 'original', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      // Force a snapshot
      ctx.lastSnapshotTime = 0;
      persistence.persist();
      persistence.flushNow();

      const snapshots = persistence.listSnapshots();
      expect(snapshots.length).toBeGreaterThan(0);

      // Modify graph
      graph.addNode('host-2', { id: 'host-2', type: 'host', label: 'new', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      // Rollback to snapshot
      const rolled = persistence.rollbackToSnapshot(snapshots[0], BUILTIN_RULES);
      expect(rolled).toBe(true);
      expect(ctx.graph.hasNode('host-1')).toBe(true);
      // host-2 should be gone after rollback
      expect(ctx.graph.hasNode('host-2')).toBe(false);
    });

    it('returns false for nonexistent snapshot', () => {
      const { persistence } = buildPersistence();
      expect(persistence.rollbackToSnapshot('nonexistent.json', BUILTIN_RULES)).toBe(false);
    });
  });

  // =============================================
  // recoverFromSnapshot
  // =============================================
  describe('recoverFromSnapshot', () => {
    it('recovers from newest valid snapshot when state is corrupted', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: 'original', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      ctx.lastSnapshotTime = 0;
      persistence.persist();
      persistence.flushNow();

      // Corrupt the main state file
      writeFileSync(ctx.stateFilePath, '{invalid json');

      // Recovery should work from snapshot
      const recovered = persistence.recoverFromSnapshot(BUILTIN_RULES);
      expect(recovered).toBe(true);
      expect(ctx.graph.hasNode('host-1')).toBe(true);
    });

    it('returns false when no valid snapshots exist', () => {
      const { persistence } = buildPersistence();
      expect(persistence.recoverFromSnapshot(BUILTIN_RULES)).toBe(false);
    });
  });

  // =============================================
  // Atomic write
  // =============================================
  describe('atomic write', () => {
    it('does not leave .tmp file after successful persist', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      expect(existsSync(ctx.stateFilePath)).toBe(true);
      expect(existsSync(ctx.stateFilePath + '.tmp')).toBe(false);
    });
  });

  // =============================================
  // Write coalescing
  // =============================================
  describe('write coalescing', () => {
    it('marks state dirty after persist() without writing immediately', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persist();

      expect(persistence.isDirty()).toBe(true);
      expect(existsSync(ctx.stateFilePath)).toBe(false);
    });

    it('flushNow() writes immediately and clears dirty flag', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persist();
      persistence.flushNow();

      expect(persistence.isDirty()).toBe(false);
      expect(existsSync(ctx.stateFilePath)).toBe(true);
    });

    it('flushNow() is a no-op when not dirty', () => {
      const { persistence } = buildPersistence();
      const metricsBefore = persistence.getMetrics();

      persistence.flushNow();

      expect(persistence.getMetrics().flushCount).toBe(metricsBefore.flushCount);
    });

    it('persistImmediate() writes even when not dirty', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persistImmediate();

      expect(persistence.isDirty()).toBe(false);
      expect(existsSync(ctx.stateFilePath)).toBe(true);
    });

    it('batch suppresses flush scheduling until endBatch', () => {
      const { ctx, persistence, graph } = buildPersistence();

      persistence.beginBatch();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      graph.addNode('host-2', { id: 'host-2', type: 'host', label: '10.0.0.2', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();

      // Still dirty, not flushed
      expect(persistence.isDirty()).toBe(true);
      expect(existsSync(ctx.stateFilePath)).toBe(false);

      persistence.endBatch();

      // After endBatch, flush is scheduled but not yet executed (debounced)
      // Force it:
      persistence.flushNow();
      expect(persistence.isDirty()).toBe(false);
      expect(existsSync(ctx.stateFilePath)).toBe(true);

      // Both nodes should be persisted
      const raw = JSON.parse(readFileSync(ctx.stateFilePath, 'utf-8'));
      const nodeIds = raw.graph.nodes.map((n: { key: string }) => n.key);
      expect(nodeIds).toContain('host-1');
      expect(nodeIds).toContain('host-2');
    });

    it('nested batches only flush after outermost endBatch', () => {
      const { ctx, persistence, graph } = buildPersistence();

      persistence.beginBatch();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();

      persistence.beginBatch();  // nested
      graph.addNode('host-2', { id: 'host-2', type: 'host', label: '10.0.0.2', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.endBatch();  // end inner — should NOT flush

      expect(persistence.isDirty()).toBe(true);
      // inner endBatch should not trigger write because outer is still open

      persistence.endBatch();  // end outer
      persistence.flushNow();

      expect(persistence.isDirty()).toBe(false);
      const raw = JSON.parse(readFileSync(ctx.stateFilePath, 'utf-8'));
      const nodeIds = raw.graph.nodes.map((n: { key: string }) => n.key);
      expect(nodeIds).toContain('host-1');
      expect(nodeIds).toContain('host-2');
    });

    it('merges detail objects across coalesced persist() calls', () => {
      const { persistence } = buildPersistence();

      persistence.beginBatch();
      persistence.persist({ new_nodes: ['host-1'], new_edges: ['e1'] });
      persistence.persist({ new_nodes: ['host-2'], updated_nodes: ['host-1'] });
      persistence.persist({ new_edges: ['e2'], new_nodes: ['host-1'] }); // duplicate host-1
      persistence.endBatch();

      // Can't directly inspect pendingDetail, but we can check it flushes without error
      persistence.flushNow();
      expect(persistence.isDirty()).toBe(false);
    });

    it('tracks coalesced call metrics', () => {
      const { persistence, graph } = buildPersistence();

      persistence.beginBatch();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.persist();
      persistence.persist();
      persistence.endBatch();
      persistence.flushNow();

      const metrics = persistence.getMetrics();
      expect(metrics.flushCount).toBe(1);  // single write
      expect(metrics.coalescedCalls).toBeGreaterThanOrEqual(3);  // 3 calls coalesced
      expect(metrics.totalSerializeMs).toBeGreaterThanOrEqual(0);
      expect(metrics.totalWriteMs).toBeGreaterThanOrEqual(0);
    });

    it('resetMetrics() clears counters', () => {
      const { persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      persistence.resetMetrics();
      const metrics = persistence.getMetrics();
      expect(metrics.flushCount).toBe(0);
      expect(metrics.coalescedCalls).toBe(0);
    });

    it('debounce timer fires and writes after FLUSH_DEBOUNCE_MS', async () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persist();
      expect(existsSync(ctx.stateFilePath)).toBe(false);

      // Wait for debounce to fire
      await new Promise(resolve => setTimeout(resolve, FLUSH_DEBOUNCE_MS + 50));

      expect(existsSync(ctx.stateFilePath)).toBe(true);
      expect(persistence.isDirty()).toBe(false);
    });

    it('cancelPendingFlush() prevents debounced write', async () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persist();
      persistence.cancelPendingFlush();

      await new Promise(resolve => setTimeout(resolve, FLUSH_DEBOUNCE_MS + 50));

      // Should NOT have written because we cancelled
      expect(existsSync(ctx.stateFilePath)).toBe(false);
      expect(persistence.isDirty()).toBe(true);
    });
  });
});
