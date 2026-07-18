import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AgentTask, EngagementConfig } from '../../types.js';
import {
  buildHandoffAgentWorkMetadata,
  buildMergedAgentWorkMetadata,
  buildSplitAgentWorkMetadata,
  computeAgentWorkSignature,
  deriveLegacyAgentWorkMetadata,
  groupExactDuplicateAgentWork,
  readAgentWorkMetadata,
} from '../agent-work.js';
import { GraphEngine } from '../graph-engine.js';
import { validatePersistedStateV1 } from '../persisted-state.js';
import { validateAgentCoordinationChangePayload } from '../agent-coordination-change.js';

const NOW = '2026-07-18T05:00:00.000Z';

function task(id: string, overrides: Partial<AgentTask> = {}): AgentTask {
  const label = `agent-${id}`;
  return {
    id,
    task_id: id,
    agent_id: label,
    agent_label: label,
    assigned_at: NOW,
    status: 'completed',
    subgraph_node_ids: ['node-b', 'node-a'],
    archetype: 'recon_scanner',
    role: 'default',
    skill: 'subnet-enumeration',
    objective: 'Map the target surface',
    ...overrides,
  };
}

function config(): EngagementConfig {
  return {
    id: 'agent-work-test',
    name: 'Agent work test',
    created_at: NOW,
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', max_noise: 1 },
  };
}

describe('agent work metadata', () => {
  it('computes a canonical exact-work signature independent of presentation and ordering', () => {
    const first = task('task-a', {
      subgraph_node_ids: ['node-b', 'node-a', 'node-b'],
      objective: '  Map\n the   target surface  ',
      status: 'running',
      model: 'model-a',
    });
    const second = task('task-b', {
      subgraph_node_ids: ['node-a', 'node-b'],
      objective: 'Map the target surface',
      status: 'failed',
      model: 'model-b',
    });
    expect(computeAgentWorkSignature(first)).toBe(computeAgentWorkSignature(second));
    expect(computeAgentWorkSignature(first)).toMatch(/^[a-f0-9]{64}$/);

    for (const variant of [
      task('different-frontier', { frontier_item_id: 'frontier-1' }),
      task('different-campaign', { campaign_id: 'campaign-1' }),
      task('different-node', { subgraph_node_ids: ['node-a'] }),
      task('different-archetype', { archetype: 'web_tester' }),
      task('different-role', { role: 'research' }),
      task('different-skill', { skill: 'web-testing' }),
      task('different-objective', { objective: 'Map only web services' }),
    ]) {
      expect(computeAgentWorkSignature(variant)).not.toBe(computeAgentWorkSignature(first));
    }
  });

  it('derives detached metadata for legacy tasks without mutating them', () => {
    const legacy = task('legacy', { frontier_item_id: 'frontier-origin' });
    const before = structuredClone(legacy);
    const derived = deriveLegacyAgentWorkMetadata(legacy);
    expect(derived).toEqual({
      version: 1,
      root_task_id: 'legacy',
      signature: computeAgentWorkSignature(legacy),
      origin_frontier_item_id: 'frontier-origin',
    });
    expect(readAgentWorkMetadata(legacy)).toEqual(derived);
    expect(legacy).toEqual(before);
    expect(legacy.work).toBeUndefined();

    legacy.work = derived;
    const detached = readAgentWorkMetadata(legacy);
    detached.root_task_id = 'changed-only-in-read-copy';
    expect(legacy.work.root_task_id).toBe('legacy');
  });

  it('builds deterministic handoff and split lineage without changing either task', () => {
    const source = task('source', { frontier_item_id: 'frontier-current' });
    source.work = {
      ...deriveLegacyAgentWorkMetadata(source),
      root_task_id: 'root-task',
      origin_frontier_item_id: 'frontier-origin',
    };
    const successor = task('successor', {
      archetype: 'web_tester',
      objective: 'Investigate the web surface',
    });
    const child = task('child', {
      subgraph_node_ids: ['node-a'],
      objective: 'Map node A',
    });
    const sourceBefore = structuredClone(source);
    const successorBefore = structuredClone(successor);
    const childBefore = structuredClone(child);
    const details = {
      created_at: NOW,
      summary: '  Specialist follow-up  ',
      key_finding_ids: ['finding-b', 'finding-a', 'finding-a'],
      key_evidence_ids: ['evidence-1'],
      key_event_ids: ['event-1'],
    };

    expect(buildHandoffAgentWorkMetadata(source, successor, details)).toEqual({
      version: 1,
      root_task_id: 'root-task',
      signature: computeAgentWorkSignature(successor),
      origin_frontier_item_id: 'frontier-origin',
      relation: {
        kind: 'handoff',
        source_task_id: 'source',
        created_at: NOW,
        summary: 'Specialist follow-up',
        key_finding_ids: ['finding-a', 'finding-b'],
        key_evidence_ids: ['evidence-1'],
        key_event_ids: ['event-1'],
      },
    });
    expect(buildSplitAgentWorkMetadata(source, child, details)).toMatchObject({
      root_task_id: 'root-task',
      signature: computeAgentWorkSignature(child),
      relation: { kind: 'split', source_task_id: 'source' },
    });
    expect(source).toEqual(sourceBefore);
    expect(successor).toEqual(successorBefore);
    expect(child).toEqual(childBefore);
    expect(() => buildHandoffAgentWorkMetadata(source, source, details))
      .toThrow(/different tasks/);
  });

  it('builds merge metadata only for exact duplicate work', () => {
    const canonical = task('canonical');
    canonical.work = {
      ...deriveLegacyAgentWorkMetadata(canonical),
      root_task_id: 'canonical-root',
    };
    const duplicate = task('duplicate');
    duplicate.work = {
      ...deriveLegacyAgentWorkMetadata(duplicate),
      root_task_id: 'duplicate-root',
      relation: {
        kind: 'split',
        source_task_id: 'old-parent',
        created_at: NOW,
        summary: 'Previously split from the old parent.',
      },
    };
    const before = structuredClone(duplicate);
    expect(buildMergedAgentWorkMetadata(duplicate, canonical)).toEqual({
      ...duplicate.work,
      root_task_id: 'canonical-root',
      merged_into_task_id: 'canonical',
    });
    expect(duplicate).toEqual(before);
    expect(() => buildMergedAgentWorkMetadata(canonical, canonical)).toThrow(/itself/);
    expect(() => buildMergedAgentWorkMetadata(
      task('different', { objective: 'Different objective' }),
      canonical,
    )).toThrow(/signatures do not match/);
  });

  it('groups exact unmerged duplicates deterministically', () => {
    const first = task('task-z');
    const second = task('task-a', { subgraph_node_ids: ['node-a', 'node-b'] });
    const different = task('task-different', { objective: 'Different objective' });
    const merged = task('task-merged');
    merged.work = {
      ...deriveLegacyAgentWorkMetadata(merged),
      merged_into_task_id: 'task-a',
    };

    const groups = groupExactDuplicateAgentWork([different, first, merged, second]);
    expect(groups).toEqual([{
      signature: computeAgentWorkSignature(first),
      task_ids: ['task-a', 'task-z'],
    }]);
    expect(groupExactDuplicateAgentWork(
      [different, first, merged, second],
      { includeMerged: true },
    )).toEqual([{
      signature: computeAgentWorkSignature(first),
      task_ids: ['task-a', 'task-merged', 'task-z'],
    }]);
  });

  it('orders duplicate task IDs by locale-independent code units', () => {
    const ascii = task('task-z');
    const nonAscii = task('task-ä');
    expect(groupExactDuplicateAgentWork([nonAscii, ascii])).toEqual([{
      signature: computeAgentWorkSignature(ascii),
      task_ids: ['task-z', 'task-ä'],
    }]);
  });

  it('validates declared work metadata while retaining legacy absence', () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-work-'));
    const statePath = join(directory, 'state.json');
    const rootTask = task('task-persisted');
    rootTask.work = deriveLegacyAgentWorkMetadata(rootTask);
    const engine = new GraphEngine(config(), statePath);
    try {
      expect(engine.registerAgent(rootTask).ok).toBe(true);
      engine.persistImmediate();
    } finally {
      engine.dispose();
    }

    try {
      const state = JSON.parse(readFileSync(statePath, 'utf8'));
      expect(() => validatePersistedStateV1(state)).not.toThrow();

      const legacy = structuredClone(state);
      delete legacy.agents[0][1].work;
      expect(() => validatePersistedStateV1(legacy)).not.toThrow();

      const unsupported = structuredClone(state);
      unsupported.agents[0][1].work.version = 2;
      expect(() => validatePersistedStateV1(unsupported)).toThrow(/version is unsupported/);

      const malformedSignature = structuredClone(state);
      malformedSignature.agents[0][1].work.signature = 'not-a-signature';
      expect(() => validatePersistedStateV1(malformedSignature)).toThrow(/SHA-256/);

      const staleSignature = structuredClone(state);
      staleSignature.agents[0][1].objective = 'Semantically different work';
      expect(() => validatePersistedStateV1(staleSignature)).toThrow(/canonical work fields/);

      const selfRelation = structuredClone(state);
      selfRelation.agents[0][1].work.relation = {
        kind: 'handoff',
        source_task_id: 'task-persisted',
        created_at: NOW,
        summary: 'Invalid self relation.',
      };
      expect(() => validatePersistedStateV1(selfRelation)).toThrow(/same task/);

      const duplicateReferences = structuredClone(state);
      duplicateReferences.agents[0][1].work.relation = {
        kind: 'split',
        source_task_id: 'parent-task',
        created_at: NOW,
        summary: 'Retain duplicate-reference validation coverage.',
        key_finding_ids: ['finding-1', 'finding-1'],
      };
      expect(() => validatePersistedStateV1(duplicateReferences)).toThrow(/duplicate ids/);

      const missingSummary = structuredClone(state);
      missingSummary.agents[0][1].work.relation = {
        kind: 'handoff',
        source_task_id: 'parent-task',
        created_at: NOW,
      };
      expect(() => validatePersistedStateV1(missingSummary)).toThrow(/relation.summary/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects non-canonical task aliases and mismatched live-task lease postimages', () => {
    const missingAlias = task('missing-alias') as AgentTask & { task_id?: string };
    delete missingAlias.task_id;
    expect(validateAgentCoordinationChangePayload({
      payload_version: 1,
      operation_id: 'missing-alias-op',
      occurred_at: NOW,
      reason: 'reject legacy aliasless journal images',
      task_changes: [{ task_id: 'missing-alias', before: null, after: missingAlias }],
      lease_changes: [],
    })).toMatchObject({ ok: false, reason: expect.stringContaining('identity must match') });

    const missingRelationSummary = task('missing-relation-summary');
    missingRelationSummary.work = {
      ...deriveLegacyAgentWorkMetadata(missingRelationSummary),
      relation: {
        kind: 'handoff',
        source_task_id: 'source-task',
        created_at: NOW,
      },
    } as AgentTask['work'];
    expect(validateAgentCoordinationChangePayload({
      payload_version: 1,
      operation_id: 'missing-relation-summary-op',
      occurred_at: NOW,
      reason: 'reject incomplete lineage metadata',
      task_changes: [{
        task_id: missingRelationSummary.id,
        before: null,
        after: missingRelationSummary,
      }],
      lease_changes: [],
    })).toMatchObject({ ok: false, reason: expect.stringContaining('relation.summary') });

    const live = task('live-lease-mismatch', {
      status: 'running',
      frontier_item_id: 'frontier-lease-mismatch',
    });
    expect(validateAgentCoordinationChangePayload({
      payload_version: 1,
      operation_id: 'lease-mismatch-op',
      occurred_at: NOW,
      reason: 'reject mismatched lease ownership',
      task_changes: [{ task_id: live.id, before: null, after: live }],
      lease_changes: [{
        frontier_item_id: 'frontier-lease-mismatch',
        before: null,
        after: {
          frontier_item_id: 'frontier-lease-mismatch',
          task_id: 'different-task',
          agent_id: 'different-agent',
          leased_at: NOW,
          expires_at: '2026-07-18T05:10:00.000Z',
          ttl_seconds: 600,
        },
      }],
    })).toMatchObject({ ok: false, reason: expect.stringContaining('matching lease postimage') });
  });
});
