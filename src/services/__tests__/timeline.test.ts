import { describe, it, expect } from 'vitest';
import { buildTimeline, queryTimeline } from '../timeline.js';
import type { ExportedGraph } from '../../types.js';
import type { ActivityLogEntry } from '../engine-context.js';

function ev(o: Partial<ActivityLogEntry> & { event_id: string; timestamp: string; description: string }): ActivityLogEntry {
  return o as ActivityLogEntry;
}

const futureExpiry = new Date(Date.now() + 3600_000).toISOString();
const pastExpiry = new Date(Date.now() - 3600_000).toISOString();

describe('buildTimeline (P3.3)', () => {
  it('emits a node entry with became_true_at from first_seen_at', () => {
    const graph: ExportedGraph = {
      nodes: [{
        id: 'h1',
        properties: {
          id: 'h1', type: 'host', label: 'h1',
          ip: '10.0.0.1',
          discovered_at: '2026-01-01T10:00:00Z',
          first_seen_at: '2026-01-01T10:00:00Z',
          last_seen_at: '2026-01-01T11:00:00Z',
          confidence: 1,
        } as any,
      }],
      edges: [],
    };
    const t = buildTimeline(graph, []);
    expect(t).toHaveLength(1);
    expect(t[0].entity_id).toBe('h1');
    expect(t[0].kind).toBe('node');
    expect(t[0].became_true_at).toBe('2026-01-01T10:00:00Z');
    expect(t[0].last_observed_at).toBe('2026-01-01T11:00:00Z');
    expect(t[0].became_false_at).toBeUndefined();
  });

  it('marks a credential expired when valid_until is in the past', () => {
    const graph: ExportedGraph = {
      nodes: [{
        id: 'cred-1',
        properties: {
          id: 'cred-1', type: 'credential', label: 'cred-1',
          discovered_at: '2026-01-01T10:00:00Z',
          first_seen_at: '2026-01-01T10:00:00Z',
          valid_until: pastExpiry,
          confidence: 1,
        } as any,
      }],
      edges: [],
    };
    const [entry] = buildTimeline(graph, []);
    expect(entry.became_false_at).toBe(pastExpiry);
    expect(entry.invalidation_reason).toBe('valid_until_elapsed');
  });

  it('honors credential_status=rotated/expired regardless of valid_until', () => {
    const graph: ExportedGraph = {
      nodes: [{
        id: 'cred-2',
        properties: {
          id: 'cred-2', type: 'credential', label: 'cred-2',
          discovered_at: '2026-01-01T10:00:00Z',
          first_seen_at: '2026-01-01T10:00:00Z',
          last_seen_at: '2026-01-01T15:00:00Z',
          credential_status: 'rotated',
          valid_until: futureExpiry, // not yet expired by clock; status wins
          confidence: 1,
        } as any,
      }],
      edges: [],
    };
    const [entry] = buildTimeline(graph, []);
    expect(entry.invalidation_reason).toBe('rotated');
    expect(entry.became_false_at).toBe(futureExpiry);
  });

  it('marks HAS_SESSION edges with session_live=false as became_false_at the imported timestamp', () => {
    const graph: ExportedGraph = {
      nodes: [],
      edges: [{
        id: 'sess-1',
        source: 'user-a',
        target: 'host-h1',
        properties: {
          type: 'HAS_SESSION', confidence: 0.9,
          discovered_at: '2026-01-01T09:00:00Z',
          session_live: false,
          session_imported_at: '2026-01-01T08:30:00Z',
        } as any,
      }],
    };
    const [entry] = buildTimeline(graph, []);
    expect(entry.kind).toBe('edge');
    expect(entry.became_false_at).toBe('2026-01-01T08:30:00Z');
    expect(entry.invalidation_reason).toBe('session_not_live');
  });

  it('attributes evidence_refs from activity events that reference the entity', () => {
    const graph: ExportedGraph = {
      nodes: [{
        id: 'h1',
        properties: {
          id: 'h1', type: 'host', label: 'h1',
          discovered_at: '2026-01-01T10:00:00Z',
          first_seen_at: '2026-01-01T10:00:00Z',
          confidence: 1,
        } as any,
      }],
      edges: [],
    };
    const history = [
      ev({ event_id: 'e1', timestamp: '2026-01-01T10:00:00Z', description: 'discovery',
        target_node_ids: ['h1'] }),
      ev({ event_id: 'e2', timestamp: '2026-01-01T10:05:00Z', description: 'enum',
        target_node_ids: ['h1', 'h2'] }),
      ev({ event_id: 'e3', timestamp: '2026-01-01T10:10:00Z', description: 'unrelated' }),
    ];
    const [entry] = buildTimeline(graph, history);
    expect(entry.evidence_refs.sort()).toEqual(['e1', 'e2']);
  });

  it('marks superseded nodes with became_false_at and invalidation_reason', () => {
    const graph: ExportedGraph = {
      nodes: [{
        id: 'old',
        properties: {
          id: 'old', type: 'host', label: 'old',
          discovered_at: '2026-01-01T10:00:00Z',
          first_seen_at: '2026-01-01T10:00:00Z',
          last_seen_at: '2026-01-01T11:00:00Z',
          identity_status: 'superseded',
          superseded_by: 'new',
          confidence: 1,
        } as any,
      }],
      edges: [],
    };
    const [entry] = buildTimeline(graph, []);
    expect(entry.superseding_id).toBe('new');
    expect(entry.invalidation_reason).toBe('superseded');
    expect(entry.became_false_at).toBeDefined();
  });
});

describe('queryTimeline (P3.3)', () => {
  const entries = [
    {
      entity_id: 'old', kind: 'node' as const,
      became_true_at: '2026-01-01T08:00:00Z',
      became_false_at: '2026-01-01T10:00:00Z',
      evidence_refs: [],
    },
    {
      entity_id: 'mid', kind: 'node' as const,
      became_true_at: '2026-01-01T09:00:00Z',
      evidence_refs: [],
    },
    {
      entity_id: 'newer', kind: 'edge' as const,
      became_true_at: '2026-01-01T11:00:00Z',
      evidence_refs: [],
    },
  ];

  it('filters by entity_id', () => {
    expect(queryTimeline(entries, { entity_id: 'mid' })).toHaveLength(1);
  });

  it('filters by kind', () => {
    expect(queryTimeline(entries, { kind: 'edge' }).map(e => e.entity_id)).toEqual(['newer']);
  });

  it('"at" filter returns only entries known-true at that moment', () => {
    // At 09:30: old still true (false_at is 10:00), mid is true, newer not yet.
    const r = queryTimeline(entries, { at: '2026-01-01T09:30:00Z' });
    expect(r.map(e => e.entity_id).sort()).toEqual(['mid', 'old']);
  });

  it('"since" filter returns entries that became true at-or-after', () => {
    const r = queryTimeline(entries, { since: '2026-01-01T09:00:00Z' });
    expect(r.map(e => e.entity_id).sort()).toEqual(['mid', 'newer']);
  });

  it('orders by became_true_at descending', () => {
    const r = queryTimeline(entries, {});
    expect(r.map(e => e.entity_id)).toEqual(['newer', 'mid', 'old']);
  });

  it('respects limit', () => {
    expect(queryTimeline(entries, { limit: 1 })).toHaveLength(1);
  });
});
