// ============================================================
// Overwatch — Engagement Timeline (P3.3 — backend)
//
// "What was true at time T?" Derives a per-node and per-edge timeline
// from the graph + activity log:
//
//   { entity_id, kind: 'node'|'edge', became_true_at, became_false_at?,
//     last_observed_at, evidence_refs[], superseding_id? }
//
// Pulls from existing graph state (no new persistence). Invalidation
// signals come from properties already on the graph:
//   - `valid_until` on credential nodes — became_false_at = valid_until
//     when in the past
//   - `credential_status` set to 'expired'/'rotated' — became_false_at
//     = the timestamp the status was set
//   - `session_live: false` on HAS_SESSION edges — became_false_at =
//     the edge's last `discovered_at` (or session_imported_at when present)
//   - `superseded_by` on a node/edge — both became_false_at and
//     superseding_id point to the replacement
//
// Future: explicit `invalidation` activity events would let the timeline
// scrub through richer state. This pass builds the read API; emission
// of those events lands in a separate pass (deferred per plan note).
// ============================================================

import type { ActivityLogEntry } from './engine-context.js';
import type { ExportedGraph } from '../types.js';

export interface TimelineEntry {
  /** node_id or edge_id. */
  entity_id: string;
  kind: 'node' | 'edge';
  /** When the entity became true (first observed / discovered / confirmed). */
  became_true_at: string;
  /** When the entity stopped being true, if known. */
  became_false_at?: string;
  /** Most recent observation. */
  last_observed_at?: string;
  /** Activity-log event_ids that reference this entity. */
  evidence_refs: string[];
  /** When superseded, the id that replaced this one. */
  superseding_id?: string;
  /** Free-form reason for invalidation (rotated, expired, session_closed, …). */
  invalidation_reason?: string;
}

export interface TimelineQuery {
  entity_id?: string;
  kind?: 'node' | 'edge';
  /** Restrict to entries that were true AT some specific timestamp. */
  at?: string;
  /** Only entries that became true after this timestamp. */
  since?: string;
  limit?: number;
}

export function buildTimeline(
  graph: ExportedGraph,
  history: ActivityLogEntry[],
): TimelineEntry[] {
  const out: TimelineEntry[] = [];
  // Index activity log entries by referenced node_ids so we can attribute
  // evidence cheaply (O(N+M) build, O(1) lookups).
  const evidenceByEntity = indexEvidenceByEntity(history);

  for (const node of graph.nodes) {
    const props = node.properties as Record<string, unknown>;
    const became_true_at = String(
      props.first_seen_at ?? props.confirmed_at ?? props.discovered_at ?? '',
    );
    if (!became_true_at) continue;

    const entry: TimelineEntry = {
      entity_id: node.id,
      kind: 'node',
      became_true_at,
      last_observed_at: typeof props.last_seen_at === 'string' ? props.last_seen_at : undefined,
      evidence_refs: evidenceByEntity.get(node.id) ?? [],
    };

    // Credential rotation/expiry semantics.
    if (props.type === 'credential') {
      const status = props.credential_status;
      const validUntil = typeof props.valid_until === 'string' ? props.valid_until : undefined;
      if (status === 'expired' || status === 'rotated' || status === 'stale') {
        entry.became_false_at = validUntil ?? entry.last_observed_at ?? became_true_at;
        entry.invalidation_reason = String(status);
      } else if (validUntil && Date.parse(validUntil) < Date.now()) {
        entry.became_false_at = validUntil;
        entry.invalidation_reason = 'valid_until_elapsed';
      }
    }

    // Generic supersession signal.
    if (typeof props.superseded_by === 'string') {
      entry.superseding_id = props.superseded_by;
      entry.became_false_at = entry.became_false_at
        ?? (typeof props.superseded_at === 'string' ? props.superseded_at : entry.last_observed_at);
      entry.invalidation_reason = entry.invalidation_reason ?? 'superseded';
    }
    if (props.identity_status === 'superseded' && !entry.became_false_at) {
      entry.became_false_at = entry.last_observed_at ?? became_true_at;
      entry.invalidation_reason = 'superseded';
    }

    out.push(entry);
  }

  for (const edge of graph.edges) {
    const props = edge.properties as Record<string, unknown> & { type?: string };
    const became_true_at = String(props.discovered_at ?? '');
    if (!became_true_at) continue;
    const id = edge.id ?? `${edge.source}|${edge.target}|${props.type ?? ''}`;

    const entry: TimelineEntry = {
      entity_id: id,
      kind: 'edge',
      became_true_at,
      evidence_refs: evidenceByEntity.get(id) ?? [],
    };

    // Session-edge invalidation: imported-but-not-live edges (P2.2 plan
    // language) are stale by construction.
    if (props.type === 'HAS_SESSION') {
      if (props.session_live === false) {
        entry.became_false_at = typeof props.session_imported_at === 'string'
          ? props.session_imported_at
          : became_true_at;
        entry.invalidation_reason = 'session_not_live';
      }
    }

    // Credential / cert / token TTLs that ride on edges (rare today but
    // future-proofed).
    if (typeof props.valid_until === 'string' && Date.parse(props.valid_until) < Date.now()) {
      entry.became_false_at = props.valid_until;
      entry.invalidation_reason = entry.invalidation_reason ?? 'valid_until_elapsed';
    }

    out.push(entry);
  }

  return out;
}

function indexEvidenceByEntity(history: ActivityLogEntry[]): Map<string, string[]> {
  const byId = new Map<string, string[]>();
  const push = (id: string, evid: string) => {
    const list = byId.get(id);
    if (list) list.push(evid);
    else byId.set(id, [evid]);
  };
  for (const e of history) {
    if (Array.isArray(e.target_node_ids)) {
      for (const n of e.target_node_ids) push(n, e.event_id);
    }
    if (e.target_edge && e.target_edge.source && e.target_edge.target) {
      const edgeId = `${e.target_edge.source}|${e.target_edge.target}|${e.target_edge.type ?? ''}`;
      push(edgeId, e.event_id);
    }
  }
  return byId;
}

export function queryTimeline(entries: TimelineEntry[], q: TimelineQuery): TimelineEntry[] {
  let out = entries;
  if (q.entity_id) out = out.filter(e => e.entity_id === q.entity_id);
  if (q.kind) out = out.filter(e => e.kind === q.kind);
  if (q.since) {
    const since = q.since;
    out = out.filter(e => e.became_true_at >= since);
  }
  if (q.at) {
    const at = q.at;
    out = out.filter(e =>
      e.became_true_at <= at && (e.became_false_at === undefined || e.became_false_at > at),
    );
  }
  // Sort by became_true_at descending so newest entries come first.
  out = [...out].sort((a, b) => b.became_true_at.localeCompare(a.became_true_at));
  if (q.limit && out.length > q.limit) out = out.slice(0, q.limit);
  return out;
}
