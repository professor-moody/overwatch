// ============================================================
// Attack Paths Panel.
//
// Surfaces multi-hop attack chains in the engagement graph with a
// tier filter so cross-tier paths (network → cloud → identity, etc.)
// are easy to find without mining the giant graph view.
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
import { isCrossTierPath, tierForNode, tiersForPath, type Tier } from '../../lib/tier';
import { EmptyState } from '../shared';
import { cn } from '../../lib/utils';

type Optimize = 'confidence' | 'stealth';
type TierFilter = 'any' | 'cross_tier' | Tier;

interface ComputedPath {
  nodes: string[];
  edge_types: string[];
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
  'BACKED_BY', 'CAN_REACH',
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
  via_edge_id: string | undefined;
}

function buildAdjacency(nodes: ExportedNode[], edges: ExportedEdge[], mode: Optimize): Map<string, Adj[]> {
  const adj = new Map<string, Adj[]>();
  for (const n of nodes) adj.set(n.id, []);
  for (const e of edges) {
    // Skip dead session edges (matches server-side path graph).
    if (e.type === 'HAS_SESSION' && e.session_live === false) continue;
    const w = edgeWeight(e, mode);
    adj.get(e.source)?.push({ to: e.target, weight: w, edge_type: e.type, via_edge_id: e.id });
    if (BIDIRECTIONAL.has(e.type)) {
      adj.get(e.target)?.push({ to: e.source, weight: w, edge_type: e.type, via_edge_id: e.id });
    }
  }
  return adj;
}

/** Dijkstra returning shortest-paths from one source to every node. */
function dijkstra(adj: Map<string, Adj[]>, source: string): Map<string, { dist: number; prev: string | undefined; via: string | undefined }> {
  const dist = new Map<string, { dist: number; prev: string | undefined; via: string | undefined }>();
  for (const id of adj.keys()) dist.set(id, { dist: Infinity, prev: undefined, via: undefined });
  dist.set(source, { dist: 0, prev: undefined, via: undefined });

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
        dist.set(n.to, { dist: nextDist, prev: cur.id, via: n.edge_type });
        queue.push({ id: n.to, d: nextDist });
      }
    }
  }
  return dist;
}

function reconstructPath(target: string, dijkstraResult: ReturnType<typeof dijkstra>): { nodes: string[]; edge_types: string[] } | null {
  const nodes: string[] = [];
  const edge_types: string[] = [];
  let cursor: string | undefined = target;
  while (cursor) {
    nodes.unshift(cursor);
    const entry = dijkstraResult.get(cursor);
    if (!entry || !entry.prev) break;
    if (entry.via) edge_types.unshift(entry.via);
    cursor = entry.prev;
  }
  if (!Number.isFinite(dijkstraResult.get(target)?.dist ?? Infinity)) return null;
  return { nodes, edge_types };
}

function computePaths(
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

function tierBadgeClass(t: Tier): string {
  switch (t) {
    case 'network': return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
    case 'app': return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
    case 'cloud': return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
    case 'identity': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    default: return 'bg-muted text-muted-foreground border-border';
  }
}

export function AttackPathsPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const initialized = useEngagementStore((s) => s.initialized);
  const { navigateToGraph, navigateToFrontier } = useNavigation();

  const [tierFilter, setTierFilter] = useState<TierFilter>('cross_tier');
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

  const visiblePaths = useMemo(() => {
    if (tierFilter === 'any') return allPaths;
    if (tierFilter === 'cross_tier') return allPaths.filter(p => p.tiers.size >= 2);
    return allPaths.filter(p => p.tiers.has(tierFilter));
  }, [allPaths, tierFilter]);

  if (!initialized) {
    return <EmptyState title="Loading" description="Waiting for engagement state…" />;
  }
  if (graph.nodes.length === 0) {
    return <EmptyState title="No graph yet" description="Run a scan or ingest a finding to populate the engagement graph." />;
  }
  if (allPaths.length === 0) {
    return (
      <EmptyState
        title="No attack paths reachable from current sources"
        description="A path requires a live session on a host (HAS_SESSION) plus a target node (objective, HVT, cloud_resource, or idp_principal). Open a session or capture a credential to populate sources."
      />
    );
  }

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {(['cross_tier', 'any', 'network', 'app', 'cloud', 'identity'] as TierFilter[]).map(t => (
            <button
              key={t}
              onClick={() => setTierFilter(t)}
              className={cn(
                'px-2 py-1 text-xs rounded border',
                tierFilter === t ? 'bg-accent text-accent-foreground border-accent' : 'border-border bg-card hover:bg-elevated',
              )}
            >
              {t === 'cross_tier' ? 'cross-tier' : t}
            </button>
          ))}
        </div>
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
            <option value="confidence">confidence</option>
            <option value="stealth">stealth</option>
          </select>
        </label>
        <span className="text-xs text-muted-foreground ml-auto">
          {visiblePaths.length} of {allPaths.length} paths
        </span>
      </div>

      {visiblePaths.length === 0 ? (
        <EmptyState title="No paths match the current filter" description="Loosen the tier filter or increase max hops." />
      ) : (
        <div className="space-y-2">
          {visiblePaths.slice(0, 100).map((p, idx) => (
            <PathRow key={idx} path={p} byId={byId} onNavigate={(id) => navigateToGraph?.(id)} onFrontier={(id) => navigateToFrontier?.(id)} />
          ))}
          {visiblePaths.length > 100 ? (
            <p className="text-xs text-muted-foreground">+ {visiblePaths.length - 100} more not shown — narrow the filter to focus.</p>
          ) : null}
        </div>
      )}
    </div>
  );
}

function PathRow({ path, byId, onNavigate, onFrontier }: {
  path: ComputedPath;
  byId: Map<string, ExportedNode>;
  onNavigate?: (id: string) => void;
  onFrontier?: (id: string) => void;
}) {
  const isCross = isCrossTierPath(path.nodes, byId);
  const targetId = path.nodes[path.nodes.length - 1];
  return (
    <div className="rounded border border-border bg-card p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex flex-wrap gap-1">
          {[...path.tiers].map(t => (
            <span key={t} className={cn('px-1.5 py-0.5 text-[10px] rounded border font-mono uppercase', tierBadgeClass(t))}>
              {t}
            </span>
          ))}
          {isCross ? <span className="px-1.5 py-0.5 text-[10px] rounded border bg-yellow-500/20 text-yellow-300 border-yellow-500/40 font-mono uppercase">cross-tier</span> : null}
        </div>
        <div className="flex items-center gap-2">
          <div className="text-xs text-muted-foreground font-mono">
            {path.nodes.length - 1} hop{path.nodes.length === 2 ? '' : 's'} · conf {path.total_confidence.toFixed(2)} · noise {path.total_opsec_noise.toFixed(2)}
          </div>
          {onFrontier && targetId && (
            <button
              onClick={() => onFrontier(targetId)}
              className="text-[10px] px-1.5 py-0.5 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground hover:border-accent/50 transition-colors"
              title="Show frontier items for target node"
            >
              Frontier →
            </button>
          )}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-1 text-xs font-mono">
        {path.nodes.map((id, i) => {
          const node = byId.get(id);
          const tier = tierForNode(node);
          return (
            <span key={`${id}-${i}`} className="flex items-center gap-1">
              <button
                onClick={() => onNavigate?.(id)}
                className={cn('px-1.5 py-0.5 rounded border hover:bg-elevated', tierBadgeClass(tier))}
                title={`${node?.type ?? 'unknown'} · ${id}`}
              >
                {node?.label ?? id}
              </button>
              {i < path.nodes.length - 1 ? (
                <span className="text-muted-foreground">→ {path.edge_types[i] ?? '?'} →</span>
              ) : null}
            </span>
          );
        })}
      </div>
    </div>
  );
}
