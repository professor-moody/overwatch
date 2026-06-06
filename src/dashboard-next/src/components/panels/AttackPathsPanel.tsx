// ============================================================
// Attack Paths Panel.
//
// Surfaces multi-hop attack chains in the engagement graph as an
// operator route queue. Lane filters match the row grouping so the
// operator can move from "what matters" to graph context quickly.
//
// Computes paths client-side with a small Dijkstra over the exported
// graph. The optimization modes mirror server-side path-analyzer.ts:
//   - confidence (default): minimize 1 - confidence
//   - stealth:              minimize opsec_noise
//
// Intentionally NO new API endpoint — reads from the existing
// engagement store. If the graph is empty or no objectives are set,
// the panel renders a directed empty state.
// ============================================================

import { useMemo, useState } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';

import type { ExportedEdge, ExportedNode } from '../../lib/types';
import { tiersForPath, type Tier } from '../../lib/tier';
import {
  ATTACK_PATH_GROUPS,
  attackPathLaneCounts,
  filterDisplayAttackPaths,
  groupDisplayAttackPaths,
  normalizeComputedAttackPath,
  type AttackPathLaneFilter,
  type DisplayAttackPath,
} from '../../lib/attack-path-workspace';
import { AttackPathRouteRow } from '../shared/AttackPathRouteRow';
import { EmptyPanelState, FilterBar, PageHeader, SegmentedControl } from '../shared/primitives';

export type Optimize = 'confidence' | 'stealth';

export interface ComputedPath {
  nodes: string[];
  edge_types: string[];
  edge_ids: string[];
  weight: number;
  total_confidence: number;
  total_opsec_noise: number;
  tiers: Set<Tier>;
}

const BIDIRECTIONAL = new Set([
  'HAS_SESSION', 'ADMIN_TO', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  'OWNS_CRED', 'VALID_ON', 'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  'RELATED', 'SAME_DOMAIN', 'TRUSTS', 'ASSUMES_ROLE', 'MANAGED_BY',
  'FEDERATES_WITH', 'ISSUES_TOKENS_FOR', 'AUTHENTICATES_VIA',
  'ASSIGNED_TO_APP', 'MFA_REQUIRED_FOR', 'VALID_FOR_APP', 'VALID_FOR_IDP_PRINCIPAL',
  'BACKED_BY', 'CAN_REACH', 'HOSTS', 'POLICY_ALLOWS',
]);

function edgeWeight(e: ExportedEdge, mode: Optimize): number {
  const conf = typeof e.confidence === 'number' ? e.confidence : 1;
  const noise = typeof e.opsec_noise === 'number' ? (e.opsec_noise as number) : 0.3;
  if (mode === 'stealth') return Math.max(noise, 0.001);
  return Math.max(1 - conf, 0.001);
}

interface Adj {
  to: string;
  weight: number;
  edge_type: string;
  via_edge_id: string;
}

function edgeKeyForExport(edge: ExportedEdge): string {
  return edge.id || `${edge.source}--${edge.type || ''}--${edge.target}`;
}

function buildAdjacency(nodes: ExportedNode[], edges: ExportedEdge[], mode: Optimize): Map<string, Adj[]> {
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

/** Dijkstra returning shortest-paths from one source to every node. */
function dijkstra(adj: Map<string, Adj[]>, source: string): Map<string, { dist: number; prev: string | undefined; via: string | undefined; viaEdgeId: string | undefined }> {
  const dist = new Map<string, { dist: number; prev: string | undefined; via: string | undefined; viaEdgeId: string | undefined }>();
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

function reconstructPath(target: string, dijkstraResult: ReturnType<typeof dijkstra>): { nodes: string[]; edge_types: string[]; edge_ids: string[] } | null {
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

export function computePaths(
  nodes: ExportedNode[],
  edges: ExportedEdge[],
  optimize: Optimize,
  maxHops: number,
  byId: Map<string, ExportedNode>,
): ComputedPath[] {
  // Source: hosts the operator has access to. Match backend
  // path-analyzer: a host qualifies if (a) compromised flag is set,
  // (b) a live HAS_SESSION edge points at it, OR (c) an ADMIN_TO edge
  // points at it with confidence ≥ 0.9. The ADMIN_TO clause matters
  // for cloud-leaning engagements where the operator owns the
  // jumpbox via cred-derived admin rather than a live shell.
  const sources = nodes.filter(n => {
    if (n.type !== 'host') return false;
    if (n.compromised === true) return true;
    return edges.some(e => {
      if (e.target !== n.id) return false;
      if (e.type === 'HAS_SESSION') return e.session_live !== false && (e.confidence ?? 1) >= 0.7;
      if (e.type === 'ADMIN_TO') return (e.confidence ?? 1) >= 0.9;
      return false;
    });
  }).map(n => n.id);
  // Targets: objective nodes + cloud_identity (federated roles —
  // typical pivot endpoint), cloud_resource, idp_principal, and any
  // node explicitly flagged hvt.
  const targets = nodes.filter(n =>
    n.objective_achieved !== undefined ||
    n.hvt === true ||
    n.type === 'cloud_identity' ||
    n.type === 'cloud_resource' ||
    n.type === 'idp_principal',
  ).map(n => n.id);
  if (sources.length === 0 || targets.length === 0) return [];

  const adj = buildAdjacency(nodes, edges, optimize);
  const out: ComputedPath[] = [];
  const seenSig = new Set<string>();

  for (const src of sources) {
    const result = dijkstra(adj, src);
    for (const tgt of targets) {
      if (src === tgt) continue;
      const recon = reconstructPath(tgt, result);
      if (!recon) continue;
      const hops = recon.nodes.length - 1;
      if (hops > maxHops) continue;
      const sig = recon.nodes.join('>') + '|' + recon.edge_types.join(',');
      if (seenSig.has(sig)) continue;
      seenSig.add(sig);
      // Aggregate confidence and noise from the original edges.
      let total_confidence = 1;
      let total_opsec_noise = 0;
      for (let i = 0; i < recon.nodes.length - 1; i++) {
        const a = recon.nodes[i];
        const b = recon.nodes[i + 1];
        const e = edges.find(ee => (ee.source === a && ee.target === b) || (BIDIRECTIONAL.has(ee.type) && ee.source === b && ee.target === a));
        if (e) {
          total_confidence *= (typeof e.confidence === 'number' ? e.confidence : 1);
          total_opsec_noise += (typeof e.opsec_noise === 'number' ? (e.opsec_noise as number) : 0.3);
        }
      }
      out.push({
        nodes: recon.nodes,
        edge_types: recon.edge_types,
        edge_ids: recon.edge_ids,
        weight: result.get(tgt)!.dist,
        total_confidence,
        total_opsec_noise,
        tiers: tiersForPath(recon.nodes, byId),
      });
    }
  }
  // Sort: cross-tier first, then by weight.
  out.sort((a, b) => {
    const aCross = a.tiers.size >= 2 ? 0 : 1;
    const bCross = b.tiers.size >= 2 ? 0 : 1;
    if (aCross !== bCross) return aCross - bCross;
    return a.weight - b.weight;
  });
  return out;
}

export function AttackPathsPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const initialized = useEngagementStore((s) => s.initialized);
  const { navigateToGraphTarget, navigateToFrontier } = useNavigation();

  const [laneFilter, setLaneFilter] = useState<AttackPathLaneFilter>('all');
  const [maxHops, setMaxHops] = useState<number>(6);
  const [optimize, setOptimize] = useState<Optimize>('confidence');

  const byId = useMemo(() => {
    const m = new Map<string, ExportedNode>();
    for (const n of graph.nodes) m.set(n.id, n);
    return m;
  }, [graph.nodes]);

  const allPaths = useMemo(
    () => computePaths(graph.nodes, graph.edges, optimize, maxHops, byId),
    [graph.nodes, graph.edges, optimize, maxHops, byId],
  );

  const displayPaths = useMemo(
    () => allPaths
      .map(path => normalizeComputedAttackPath(path, byId))
      .filter((path): path is DisplayAttackPath => !!path),
    [allPaths, byId],
  );

  const laneCounts = useMemo(() => attackPathLaneCounts(displayPaths), [displayPaths]);
  const visiblePaths = useMemo(() => filterDisplayAttackPaths(displayPaths, laneFilter), [displayPaths, laneFilter]);

  const limitedPaths = useMemo(() => visiblePaths.slice(0, 100), [visiblePaths]);
  const groupedPaths = useMemo(() => groupDisplayAttackPaths(limitedPaths), [limitedPaths]);

  const inspectPath = (path: DisplayAttackPath) => {
    navigateToGraphTarget({
      kind: 'path',
      nodeIds: path.nodeIds,
      edgeIds: path.edgeIds,
      label: path.headline,
    });
  };

  if (!initialized) {
    return <EmptyPanelState message="Waiting for engagement state..." />;
  }
  if (graph.nodes.length === 0) {
    return <EmptyPanelState message="Run a scan or ingest a finding to populate the engagement graph." />;
  }
  if (allPaths.length === 0) {
    return <EmptyPanelState message="No attack paths reachable from current sources." />;
  }

  return (
    <div className="space-y-4">
      <PageHeader title="Attack Paths" meta={`(${allPaths.length} computed · ${visiblePaths.length} visible)`} />
      <FilterBar>
        <SegmentedControl
          value={laneFilter}
          onChange={setLaneFilter}
          options={[
            { value: 'all' as const, label: 'All', count: laneCounts.all },
            ...ATTACK_PATH_GROUPS.map(group => ({
              value: group.key,
              label: group.label,
              count: laneCounts[group.key],
            })),
          ]}
        />
        <label className="text-xs text-muted-foreground flex items-center gap-2">
          max hops:
          <input
            type="range" min={1} max={12} value={maxHops}
            onChange={e => setMaxHops(parseInt(e.target.value))}
            className="accent-accent"
          />
          <span className="font-mono">{maxHops}</span>
        </label>
        <label className="text-xs text-muted-foreground flex items-center gap-1">
          optimize:
          <select value={optimize} onChange={e => setOptimize(e.target.value as Optimize)} className="bg-card border border-border rounded px-1 py-0.5 text-xs">
            <option value="confidence">Highest confidence</option>
            <option value="stealth">Lowest noise</option>
          </select>
        </label>
      </FilterBar>

      {visiblePaths.length === 0 ? (
        <EmptyPanelState message="No paths match the current filter." />
      ) : (
        <div className="space-y-5">
          {groupedPaths.map(group => (
            <section key={group.key} className="space-y-2">
              <div className="flex flex-wrap items-end justify-between gap-2">
                <div>
                  <h3 className="text-sm font-medium text-foreground">
                    {group.label}
                    <span className="ml-2 text-xs font-normal text-muted-foreground">({group.paths.length})</span>
                  </h3>
                  <p className="text-xs text-muted-foreground">{group.description}</p>
                </div>
              </div>
              <div className="space-y-2">
                {group.paths.map((path, idx) => (
                  <AttackPathRouteRow
                    key={path.id}
                    path={path}
                    index={idx}
                    onInspect={inspectPath}
                    onFrontier={(id) => navigateToFrontier?.(id)}
                  />
                ))}
              </div>
            </section>
          ))}
          {visiblePaths.length > 100 ? (
            <p className="text-xs text-muted-foreground">+ {visiblePaths.length - 100} more not shown — narrow the filter to focus.</p>
          ) : null}
        </div>
      )}
    </div>
  );
}
