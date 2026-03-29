import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Graph from 'graphology';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { NodeProperties, EdgeProperties, InferenceRule } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { StatePersistence, MAX_SNAPSHOTS } from '../state-persistence.js';

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

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'overwatch-persist-test-'));
  });

  afterEach(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });

  function buildPersistence(stateFile?: string) {
    const graph = makeGraph();
    const filePath = stateFile || join(tempDir, 'state.json');
    const ctx = new EngineContext(graph, makeConfig(), filePath);
    ctx.inferenceRules.push(...BUILTIN_RULES);
    const persistence = new StatePersistence(ctx, BUILTIN_RULES, makeGraph);
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
      expect(existsSync(ctx.stateFilePath)).toBe(true);

      // Force snapshot rotation by resetting timer
      ctx.lastSnapshotTime = 0;
      persistence.persist();

      const snapshots = persistence.listSnapshots();
      expect(snapshots.length).toBeGreaterThan(0);
    });

    it('prunes old snapshots beyond MAX_SNAPSHOTS', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      // Create initial state
      persistence.persist();

      // Create more than MAX_SNAPSHOTS by forcing rotation each time
      for (let i = 0; i < MAX_SNAPSHOTS + 3; i++) {
        ctx.lastSnapshotTime = 0;
        persistence.persist();
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

      // Force a snapshot
      ctx.lastSnapshotTime = 0;
      persistence.persist();

      const snapshots = persistence.listSnapshots();
      expect(snapshots.length).toBeGreaterThan(0);

      // Modify graph
      graph.addNode('host-2', { id: 'host-2', type: 'host', label: 'new', discovered_at: now, confidence: 1.0 } as NodeProperties);
      persistence.persist();

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

      ctx.lastSnapshotTime = 0;
      persistence.persist();

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

      expect(existsSync(ctx.stateFilePath)).toBe(true);
      expect(existsSync(ctx.stateFilePath + '.tmp')).toBe(false);
    });
  });
});
