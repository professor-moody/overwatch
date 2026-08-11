import { useMemo } from 'react';
import type { NodeRole } from '../../lib/node-significance';
import { nodeProvenance, nodeSignificance } from '../../lib/node-significance';
import { reachableObjectives } from '../../lib/node-reachability';
import type { ExportedGraph } from '../../lib/types';
import { cn } from '../../lib/utils';
import { TrustBadge } from '../shared/primitives';

const ROLE_CLASS: Record<NodeRole, string> = {
  objective: 'border-warning/40 text-warning',
  hvt: 'border-accent/40 text-accent',
  standard: 'border-border text-muted-foreground',
};

const TIER_DOT_CLASS: Record<string, string> = {
  network: 'bg-blue-300',
  app: 'bg-purple-300',
  cloud: 'bg-orange-300',
  identity: 'bg-emerald-300',
  unknown: 'bg-muted-foreground',
};

/**
 * "Why this matters" — leads the node drawer with the node's role (objective /
 * high-value target / routine asset), its trust tier, and how the node came to be
 * known (source trust, confidence, when + who). Every value is read from fields the
 * backend already stamps on the exported node, so the card is honest by construction:
 * an inferred, low-confidence node reads plainly as such.
 */
export function NodeSignificanceCard({ props, nodeType, nodeId, graph }: {
  props: Record<string, unknown>;
  nodeType: string;
  /** Node id + exported graph, when available, drive the single-source path-to-objective
   *  line. Omitted (e.g. in isolated tests) → the reachability line simply doesn't show. */
  nodeId?: string;
  graph?: ExportedGraph;
}) {
  const sig = nodeSignificance(props, nodeType);
  const prov = nodeProvenance(props);

  const reachability = useMemo(
    () => (nodeId && graph ? reachableObjectives(nodeId, graph.nodes, graph.edges) : null),
    [nodeId, graph],
  );
  // A node that is itself an objective doesn't need a "path to an objective" line.
  const showReach = reachability?.nearest && sig.role !== 'objective';

  const provParts = [
    prov.confidencePct !== null ? `${prov.confidencePct}% confidence` : null,
    prov.discoveredAgo ? `found ${prov.discoveredAgo}` : null,
    prov.discoveredBy ? `by ${prov.discoveredBy}` : null,
  ].filter((part): part is string => !!part);

  return (
    <div className="space-y-2 text-xs">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className={cn('rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', ROLE_CLASS[sig.role])}>
          {sig.roleLabel}
        </span>
        {sig.tier !== 'unknown' && (
          <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
            {sig.tier} tier
          </span>
        )}
        {sig.role === 'objective' && (
          <span className={cn(
            'rounded border px-1.5 py-0.5 text-[9px] uppercase tracking-wide',
            sig.achieved ? 'border-success/40 text-success' : 'border-warning/40 text-warning',
          )}>
            {sig.achieved ? 'reached' : 'not yet reached'}
          </span>
        )}
      </div>

      {sig.roleDetail && <div className="text-foreground">{sig.roleDetail}</div>}

      {/* Path to objective — how close this node sits to a goal, so its blast radius is
          legible at a glance. Computed single-source from this node. */}
      {showReach && reachability?.nearest && (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-muted-foreground">
            → {reachability.nearest.hops} hop{reachability.nearest.hops === 1 ? '' : 's'} to nearest objective:
          </span>
          <span className={cn('h-1.5 w-1.5 flex-shrink-0 rounded-full', TIER_DOT_CLASS[reachability.nearest.tier] || TIER_DOT_CLASS.unknown)} />
          <span className="min-w-0 truncate text-foreground">{reachability.nearest.label}</span>
          {reachability.count > 1 && (
            <span className="text-muted-foreground">· reaches {reachability.count} in all</span>
          )}
        </div>
      )}

      {/* Provenance — how we know this node exists and how far to trust it. */}
      {(prov.sourceTrust || provParts.length > 0) && (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
          {prov.sourceTrust && <TrustBadge trust={prov.sourceTrust} />}
          {provParts.length > 0 && <span>{provParts.join(' · ')}</span>}
        </div>
      )}

      {prov.traceable && (
        <div className="text-[10px] text-muted-foreground">Traceable to the action that found it (explain_action).</div>
      )}
    </div>
  );
}
