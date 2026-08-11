// ============================================================
// Attack-graph search core — the shared Dijkstra primitives over the exported
// engagement graph. Extracted from AttackPathsPanel so the panel's route queue
// and the node drawer's single-source reachability read the same edge model,
// bidirectional set, weighting, and objective/target definition — they can't
// drift. Mirrors server-side path-analyzer.ts:
//   - confidence (default): minimize 1 - confidence
//   - stealth:              minimize opsec_noise
// ============================================================

import type { ExportedEdge, ExportedNode } from './types';

export type Optimize = 'confidence' | 'stealth';

/** Edge types that are traversable in both directions for path-finding (a session on
 *  a host is also a way back to the operator, group membership works both ways, …). */
export const BIDIRECTIONAL = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON', 'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS', 'ASSUMES_ROLE', 'MANAGED_BY',
  'FEDERATES_WITH', 'ISSUES_TOKENS_FOR', 'AUTHENTICATES_VIA',
  'ASSIGNED_TO_APP', 'MFA_REQUIRED_FOR', 'VALID_FOR_APP', 'VALID_FOR_IDP_PRINCIPAL',
  'BACKED_BY', 'CAN_REACH', 'HOSTS', 'POLICY_ALLOWS',
]);

export interface Adj {
  to: string;
  weight: number;
  edge_type: string;
  via_edge_id: string;
}

export function edgeWeight(e: ExportedEdge, mode: Optimize): number {
  const conf = typeof e.confidence === 'number' ? e.confidence : 1;
  const noise = typeof e.opsec_noise === 'number' ? (e.opsec_noise as number) : 0.3;
  if (mode === 'stealth') return Math.max(noise, 0.001);
  return Math.max(1 - conf, 0.001);
}

export function edgeKeyForExport(edge: ExportedEdge): string {
  return edge.id || `${edge.source}--${edge.type || ''}--${edge.target}`;
}

export function buildAdjacency(nodes: ExportedNode[], edges: ExportedEdge[], mode: Optimize): Map<string, Adj[]> {
  const adj = new Map<string, Adj[]>();
  for (const n of nodes) adj.set(n.id, []);
  for (const e of edges) {
    // Skip dead session edges (matches server-side path graph).
    if (e.type === 'HAS_SESSION' && e.session_live === false) continue;
    const w = edgeWeight(e, mode);
    const edgeId = edgeKeyForExport(e);
    adj.get(e.source)?.push({ to: e.target, weight: w, edge_type: e.type, via_edge_id: edgeId });
    if (BIDIRECTIONAL.has(e.type)) {
      adj.get(e.target)?.push({ to: e.source, weight: w, edge_type: e.type, via_edge_id: edgeId });
    }
  }
  return adj;
}

export interface DijkstraEntry {
  dist: number;
  prev: string | undefined;
  via: string | undefined;
  viaEdgeId: string | undefined;
}

/** Dijkstra returning shortest-paths from one source to every node. */
export function dijkstra(adj: Map<string, Adj[]>, source: string): Map<string, DijkstraEntry> {
  const dist = new Map<string, DijkstraEntry>();
  for (const id of adj.keys()) dist.set(id, { dist: Infinity, prev: undefined, via: undefined, viaEdgeId: undefined });
  dist.set(source, { dist: 0, prev: undefined, via: undefined, viaEdgeId: undefined });

  // Tiny binary-heap stand-in: array + sort. Graph sizes here are
  // typically <2k nodes; correctness > micro-perf.
  const queue: Array<{ id: string; d: number }> = [{ id: source, d: 0 }];
  const visited = new Set<string>();

  while (queue.length > 0) {
    queue.sort((a, b) => a.d - b.d);
    const cur = queue.shift()!;
    if (visited.has(cur.id)) continue;
    visited.add(cur.id);
    const neighbors = adj.get(cur.id) ?? [];
    for (const n of neighbors) {
      if (visited.has(n.to)) continue;
      const nextDist = cur.d + n.weight;
      const known = dist.get(n.to);
      if (!known || nextDist < known.dist) {
        dist.set(n.to, { dist: nextDist, prev: cur.id, via: n.edge_type, viaEdgeId: n.via_edge_id });
        queue.push({ id: n.to, d: nextDist });
      }
    }
  }
  return dist;
}

export function reconstructPath(
  target: string,
  dijkstraResult: Map<string, DijkstraEntry>,
): { nodes: string[]; edge_types: string[]; edge_ids: string[] } | null {
  const nodes: string[] = [];
  const edge_types: string[] = [];
  const edge_ids: string[] = [];
  let cursor: string | undefined = target;
  while (cursor) {
    nodes.unshift(cursor);
    const entry = dijkstraResult.get(cursor);
    if (!entry || !entry.prev) break;
    if (entry.via) edge_types.unshift(entry.via);
    if (entry.viaEdgeId) edge_ids.unshift(entry.viaEdgeId);
    cursor = entry.prev;
  }
  if (!Number.isFinite(dijkstraResult.get(target)?.dist ?? Infinity)) return null;
  return { nodes, edge_types, edge_ids };
}

/** Objective / high-value endpoints — the path-finding target set, mirroring
 *  path-analyzer and the attack-path panel: explicit objectives (the flag is set at
 *  all), hvt-flagged nodes, and cloud/idp pivot endpoints that are typical goals. */
export function isObjectiveTarget(n: ExportedNode): boolean {
  return n.objective_achieved !== undefined ||
    n.hvt === true ||
    n.type === 'cloud_identity' ||
    n.type === 'cloud_resource' ||
    n.type === 'idp_principal';
}
