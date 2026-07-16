import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Graph from 'graphology';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { NodeProperties, EdgeProperties, InferenceRule } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { StatePersistence, MAX_SNAPSHOTS, FLUSH_DEBOUNCE_MS } from '../state-persistence.js';
import { mkdirDurable } from '../durable-fs.js';

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

  it('fsyncs every newly created ancestor for a recursively created state path', () => {
    const levelOne = join(tempDir, 'one');
    const levelTwo = join(levelOne, 'two');
    const levelThree = join(levelTwo, 'three');
    const synchronized: string[] = [];

    mkdirDurable(levelThree, directory => synchronized.push(directory));

    expect(existsSync(levelThree)).toBe(true);
    expect(synchronized).toEqual([levelThree, levelTwo, levelOne, tempDir]);
  });

  it('retries ancestor fsyncs after recursive creation succeeded but durability failed', () => {
    const levelOne = join(tempDir, 'retry-one');
    const levelTwo = join(levelOne, 'retry-two');
    const levelThree = join(levelTwo, 'retry-three');
    let calls = 0;

    expect(() => mkdirDurable(levelThree, () => {
      calls++;
      if (calls === 2) throw new Error('synthetic ancestor fsync failure');
    })).toThrow('synthetic ancestor fsync failure');
    expect(existsSync(levelThree)).toBe(true);

    const retried: string[] = [];
    mkdirDurable(levelThree, directory => retried.push(directory));
    expect(retried).toEqual([levelThree, levelTwo, levelOne, tempDir]);
  });

  it('does not fsync arbitrary ancestors of an already-existing writable state directory', () => {
    if (process.platform === 'win32') return;
    const parent = join(tempDir, 'execute-only-parent');
    const stateDirectory = join(parent, 'state');
    mkdirSync(stateDirectory, { recursive: true });
    chmodSync(parent, 0o111);
    try {
      // Traverse-only access to the parent is sufficient for ordinary writes
      // inside the writable state directory.
      writeFileSync(join(stateDirectory, 'ordinary-write'), 'ok');
      expect(() => mkdirDurable(stateDirectory)).not.toThrow();
    } finally {
      chmodSync(parent, 0o700);
    }
  });

  // =============================================
  // persist + loadState round-trip
  // =============================================
  describe('persist + loadState', () => {
    it('rejects a stale state writer after another process advances the durable transaction head', () => {
      const statePath = join(tempDir, 'shared-state.json');
      const first = buildPersistence(statePath);
      first.persistence.persistImmediate();

      const stale = buildPersistence(statePath);
      expect(stale.persistence.restoreBaseAndReplay()).toMatchObject({
        status: 'restored',
        source: 'state',
      });

      const props = {
        id: 'newer-writer-node',
        type: 'host',
        label: 'newer-writer-node',
        discovered_at: now,
        confidence: 1,
      } as NodeProperties;
      first.ctx.applyJournaledMutation(
        'add_node',
        { props },
        () => first.graph.addNode(props.id, props),
      );
      first.persistence.persistImmediate();
      expect(first.ctx.mutationJournal?.compactUpTo(1)).toEqual({
        kept: 0,
        dropped: 1,
      });
      const newerState = readFileSync(statePath);

      expect(() => stale.persistence.persistImmediate()).toThrow(
        /stale|durable transaction head|local applied checkpoint/i,
      );
      expect(readFileSync(statePath)).toEqual(newerState);
      expect(stale.persistence.isWritable()).toBe(false);
    });

    it('retains the checkpoint from an unusable primary when rejecting a stale state writer', () => {
      const statePath = join(tempDir, 'shared-invalid-state.json');
      const first = buildPersistence(statePath);
      first.persistence.persistImmediate();

      const stale = buildPersistence(statePath);
      expect(stale.persistence.restoreBaseAndReplay()).toMatchObject({
        status: 'restored',
        source: 'state',
      });

      const props = {
        id: 'newer-invalid-primary-node',
        type: 'host',
        label: 'newer-invalid-primary-node',
        discovered_at: now,
        confidence: 1,
      } as NodeProperties;
      first.ctx.applyJournaledMutation(
        'add_node',
        { props },
        () => first.graph.addNode(props.id, props),
      );
      first.persistence.persistImmediate();
      expect(first.ctx.mutationJournal?.compactUpTo(1)).toEqual({
        kept: 0,
        dropped: 1,
      });

      const invalidPrimary = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
      delete invalidPrimary.walCompactionAuthority;
      invalidPrimary.activityLog = 'synthetic invalid auxiliary state';
      const invalidBytes = Buffer.from(JSON.stringify(invalidPrimary));
      writeFileSync(statePath, invalidBytes);

      expect(() => stale.persistence.persistImmediate()).toThrow(
        /durable transaction head 1 does not match local applied checkpoint 0/i,
      );
      expect(readFileSync(statePath)).toEqual(invalidBytes);
      expect(stale.persistence.isWritable()).toBe(false);
    });

    it('exposes distinct logical and physical WAL high-water marks across compaction', () => {
      const { ctx, persistence, graph } = buildPersistence();
      persistence.persistImmediate();
      const props = {
        id: 'multi-frame-node',
        type: 'host',
        label: 'x'.repeat(150_000),
        discovered_at: now,
        confidence: 1,
      } as NodeProperties;
      ctx.applyJournaledMutation(
        'add_node',
        { props },
        () => graph.addNode(props.id, props),
      );

      const live = persistence.getRecoveryStatus();
      expect(live).toMatchObject({
        highest_allocated_seq: 1,
        highest_allocated_logical_seq: 1,
        highest_on_disk_seq: 1,
        highest_contiguous_applied_seq: 1,
        highest_contiguous_applied_logical_seq: 1,
      });
      expect(live.highest_allocated_frame_seq).toBeGreaterThan(1);
      expect(live.highest_physical_frame_seq).toBe(
        live.highest_allocated_frame_seq,
      );

      persistence.persistImmediate();
      expect(ctx.mutationJournal?.compactUpTo(1)).toEqual({
        kept: 0,
        dropped: 1,
      });
      expect(persistence.getRecoveryStatus()).toMatchObject({
        highest_allocated_logical_seq: 1,
        highest_allocated_frame_seq: live.highest_allocated_frame_seq,
        highest_physical_frame_seq: live.highest_physical_frame_seq,
        highest_contiguous_applied_logical_seq: 1,
      });
    });

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
      ctx.agents.set('task-1', {
        id: 'task-1',
        agent_id: 'agent-1',
        assigned_at: now,
        status: 'running',
        subgraph_node_ids: [],
      });

      persistence.persist();
      persistence.flushNow();

      const { ctx: ctx2, persistence: persistence2 } = buildPersistence(ctx.stateFilePath);
      persistence2.loadState();

      expect(ctx2.agents.has('task-1')).toBe(true);
      expect(ctx2.agents.get('task-1')?.status).toBe('running');
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

    it('round-trips frontier linkage tracker', () => {
      const { ctx, persistence } = buildPersistence();
      ctx.frontierLinkage.recordEmitted(['fi-1', 'fi-2']);
      ctx.logEvent({
        description: 'pursued',
        event_type: 'action_completed',
        frontier_item_id: 'fi-1',
      });

      persistence.persist();
      persistence.flushNow();

      const { ctx: ctx2, persistence: persistence2 } = buildPersistence(ctx.stateFilePath);
      persistence2.loadState();

      expect(ctx2.frontierLinkage.size()).toBe(2);
      expect(ctx2.frontierLinkage.callIndex()).toBe(1);
      expect(ctx2.frontierLinkage.get('fi-1')?.linkage_status).toBe('pursued');
      expect(ctx2.frontierLinkage.get('fi-2')?.linkage_status).toBe('open');
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
      expect(existsSync(`${ctx.stateFilePath}.rollback-intent.json`)).toBe(false);
    });

    it('rejects an unrestorable snapshot before committing rollback authority or cancelling dirty persistence', async () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', {
        id: 'host-1', type: 'host', label: 'durable-head',
        discovered_at: now, confidence: 1.0,
      } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      ctx.lastSnapshotTime = 0;
      persistence.persist();
      persistence.flushNow();
      const rollbackSnapshot = persistence.listSnapshots()[0];
      const snapshotPath = join(tempDir, rollbackSnapshot);
      const malformed = JSON.parse(readFileSync(snapshotPath, 'utf-8')) as Record<string, unknown>;
      malformed.agents = {}; // graph/config validate, but complete restore cannot construct this Map
      writeFileSync(snapshotPath, JSON.stringify(malformed));

      graph.addNode('host-dirty', {
        id: 'host-dirty', type: 'host', label: 'must-still-flush',
        discovered_at: now, confidence: 1.0,
      } as NodeProperties);
      persistence.persist();

      expect(() => persistence.rollbackToSnapshot(rollbackSnapshot, BUILTIN_RULES)).toThrow(
        /did not start/,
      );
      expect(ctx.graph.hasNode('host-dirty')).toBe(true);
      expect(existsSync(`${ctx.stateFilePath}.rollback-intent.json`)).toBe(false);

      await new Promise(resolve => setTimeout(resolve, FLUSH_DEBOUNCE_MS + 50));
      const primary = JSON.parse(readFileSync(ctx.stateFilePath, 'utf-8')) as Record<string, any>;
      expect((primary.graph.nodes as Array<{ key: string }>).map(node => node.key))
        .toContain('host-dirty');
      expect(persistence.isDirty()).toBe(false);
    });

    it('does not let a superseded snapshot resurrect state after rollback and restart', () => {
      const { ctx, persistence, graph } = buildPersistence();
      graph.addNode('host-1', {
        id: 'host-1', type: 'host', label: 'rollback-target',
        discovered_at: now, confidence: 1.0,
      } as NodeProperties);
      persistence.persist();
      persistence.flushNow();

      ctx.lastSnapshotTime = 0;
      persistence.persist();
      persistence.flushNow();
      const rollbackSnapshot = persistence.listSnapshots()[0];

      graph.addNode('host-2', {
        id: 'host-2', type: 'host', label: 'must-stay-rolled-back',
        discovered_at: now, confidence: 1.0,
      } as NodeProperties);
      persistence.persist();
      persistence.flushNow();
      ctx.lastSnapshotTime = 0;
      persistence.persist();
      persistence.flushNow();
      expect(persistence.listSnapshots().length).toBeGreaterThan(1);
      const supersededSnapshot = persistence.listSnapshots()
        .find(snapshot => snapshot !== rollbackSnapshot)!;
      const supersededPath = join(tempDir, supersededSnapshot);
      const integrityMismatched = JSON.parse(
        readFileSync(supersededPath, 'utf-8'),
      ) as Record<string, any>;
      integrityMismatched.graph.nodes.push({
        key: 'host-integrity-mismatch',
        attributes: {
          id: 'host-integrity-mismatch',
          type: 'host',
          label: 'must-be-superseded',
          discovered_at: now,
          confidence: 1.0,
        },
      });
      writeFileSync(supersededPath, JSON.stringify(integrityMismatched));

      expect(persistence.rollbackToSnapshot(rollbackSnapshot, BUILTIN_RULES)).toBe(true);
      expect(ctx.graph.hasNode('host-2')).toBe(false);
      expect(persistence.listSnapshots()).toEqual([rollbackSnapshot]);

      // Force startup to use the retained rollback anchor. A newer/equal
      // snapshot left behind by rollback would resurrect host-2 here.
      writeFileSync(ctx.stateFilePath, '{corrupt rolled-back primary');
      const { ctx: restarted, persistence: restartedPersistence } = buildPersistence(ctx.stateFilePath);
      restartedPersistence.loadState();
      expect(restarted.graph.hasNode('host-1')).toBe(true);
      expect(restarted.graph.hasNode('host-2')).toBe(false);
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

    it('re-discovers and re-ranks every base after acquiring the migration lease', () => {
      const targetState = join(tempDir, 'state-rerank.json');
      const oldSource = join(tempDir, 'old-source.json');
      const newSource = join(tempDir, 'new-source.json');

      const oldWriter = buildPersistence(oldSource);
      oldWriter.graph.addNode('old-node', {
        id: 'old-node',
        type: 'host',
        label: 'old',
        discovered_at: now,
        confidence: 1,
      } as NodeProperties);
      oldWriter.persistence.persistImmediate();
      const oldLegacy = JSON.parse(readFileSync(oldSource, 'utf8')) as Record<string, unknown>;
      delete oldLegacy.state_version;
      delete oldLegacy.journal_version;
      delete oldLegacy.walCompactionAuthority;

      const newWriter = buildPersistence(newSource);
      newWriter.graph.addNode('new-node', {
        id: 'new-node',
        type: 'host',
        label: 'new',
        discovered_at: now,
        confidence: 1,
      } as NodeProperties);
      newWriter.persistence.persistImmediate();
      const newLegacy = JSON.parse(readFileSync(newSource, 'utf8')) as Record<string, unknown>;
      delete newLegacy.state_version;
      delete newLegacy.journal_version;
      delete newLegacy.walCompactionAuthority;
      writeFileSync(targetState, JSON.stringify(newLegacy));

      const snapshotDirectory = join(tempDir, '.snapshots');
      mkdirSync(snapshotDirectory, { recursive: true });
      const snapshotPath = join(
        snapshotDirectory,
        'state-rerank.snap-2026-07-16T00-00-00-000Z-1.json',
      );
      writeFileSync(snapshotPath, JSON.stringify(oldLegacy));

      const restored = buildPersistence(targetState);
      let inventories = 0;
      (restored.persistence as unknown as {
        collectRestoreCandidates: () => Array<{
          source: 'state' | 'snapshot';
          path: string;
        }>;
      }).collectRestoreCandidates = () => {
        inventories++;
        return inventories === 1
          ? [{ source: 'snapshot', path: snapshotPath }]
          : [
              { source: 'state', path: targetState },
              { source: 'snapshot', path: snapshotPath },
            ];
      };

      expect(restored.persistence.restoreBaseAndReplay()).toMatchObject({
        status: 'restored',
        source: 'state',
      });
      expect(inventories).toBe(2);
      expect(restored.graph.hasNode('new-node')).toBe(true);
      expect(restored.graph.hasNode('old-node')).toBe(false);
    });

    it('finishes a rollback that commits after the initial check but before the migration lease', () => {
      const targetState = join(tempDir, 'state-race.json');
      const rollbackSource = join(tempDir, 'rollback-source.json');

      const targetWriter = buildPersistence(targetState);
      targetWriter.graph.addNode('legacy-head', {
        id: 'legacy-head',
        type: 'host',
        label: 'legacy head',
        discovered_at: now,
        confidence: 1,
      } as NodeProperties);
      targetWriter.persistence.persistImmediate();
      const legacyHead = JSON.parse(readFileSync(targetState, 'utf8')) as Record<string, unknown>;
      delete legacyHead.state_version;
      delete legacyHead.journal_version;
      delete legacyHead.walCompactionAuthority;
      writeFileSync(targetState, JSON.stringify(legacyHead));

      const rollbackWriter = buildPersistence(rollbackSource);
      rollbackWriter.graph.addNode('rollback-authority', {
        id: 'rollback-authority',
        type: 'host',
        label: 'rollback authority',
        discovered_at: now,
        confidence: 1,
      } as NodeProperties);
      rollbackWriter.persistence.persistImmediate();
      const snapshotDirectory = join(tempDir, '.snapshots');
      mkdirSync(snapshotDirectory, { recursive: true });
      const rollbackSnapshot = join(
        snapshotDirectory,
        'state-race.snap-2026-07-16T00-00-00-000Z-1.json',
      );
      writeFileSync(rollbackSnapshot, readFileSync(rollbackSource));

      const racer = buildPersistence(targetState);
      const recovering = buildPersistence(targetState);
      const internal = recovering.persistence as unknown as {
        validateFullStateDetached: (data: unknown, rules: InferenceRule[]) => void;
      };
      const validate = internal.validateFullStateDetached.bind(recovering.persistence);
      let rollbackCommitted = false;
      internal.validateFullStateDetached = (data, rules) => {
        validate(data, rules);
        if (rollbackCommitted) return;
        rollbackCommitted = true;
        expect(racer.persistence.rollbackToSnapshot(
          rollbackSnapshot,
          BUILTIN_RULES,
          { deferAuthorityRelease: true },
        )).toBe(true);
        expect(existsSync(`${targetState}.rollback-intent.json`)).toBe(true);
      };

      expect(recovering.persistence.restoreBaseAndReplay()).toMatchObject({
        status: 'restored',
        source: 'snapshot',
      });
      expect(rollbackCommitted).toBe(true);
      expect(recovering.graph.hasNode('rollback-authority')).toBe(true);
      expect(recovering.graph.hasNode('legacy-head')).toBe(false);
      expect(existsSync(`${targetState}.rollback-intent.json`)).toBe(false);
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

    it('scheduled flush recreates a missing parent directory before writing state', async () => {
      const nestedState = join(tempDir, 'missing-parent', 'state.json');
      const { ctx, persistence, graph } = buildPersistence(nestedState);
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persist();
      await new Promise(resolve => setTimeout(resolve, FLUSH_DEBOUNCE_MS + 50));

      expect(existsSync(ctx.stateFilePath)).toBe(true);
      expect(persistence.isDirty()).toBe(false);
    });

    it('scheduled flush errors are logged rather than escaping the timer', async () => {
      const { ctx, persistence, graph } = buildPersistence();
      // Keep the durable primary/snapshot paths inspectable and fail only the
      // replacement temp write. Read-access failures are recovery gates, not
      // transient flush failures.
      mkdirSync(`${ctx.stateFilePath}.tmp`);
      ctx.lastSnapshotTime = Date.now();
      graph.addNode('host-1', { id: 'host-1', type: 'host', label: '10.0.0.1', discovered_at: now, confidence: 1.0 } as NodeProperties);

      persistence.persist();
      await new Promise(resolve => setTimeout(resolve, FLUSH_DEBOUNCE_MS + 50));

      const failure = ctx.activityLog.find(entry =>
        entry.event_type === 'system' &&
        entry.description.includes('Scheduled state persistence flush failed')
      );
      expect(failure).toBeDefined();
      expect(failure?.result_classification).toBe('failure');
      expect(failure?.details?.timer_kind).toBe('debounce');
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
