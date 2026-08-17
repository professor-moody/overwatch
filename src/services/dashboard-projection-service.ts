import type { ExportedGraph } from '../types.js';
import type { GraphEngine } from './graph-engine.js';
import { attachDerivedTrust } from './source-trust.js';

interface CachedGraphProjection {
  key: string;
  graph: ExportedGraph;
}

/** Process-local cache for the expensive complete dashboard graph projection.
 * Incremental updates use exportGraphSelection and never pass through here. */
export class DashboardProjectionService {
  private cachedGraph: CachedGraphProjection | undefined;

  constructor(private readonly engine: GraphEngine) {}

  getFullGraph(): ExportedGraph {
    const revisions = this.engine.getProjectionRevisions();
    const configRevision = this.engine.getConfig().config_revision ?? 0;
    const coldRevision = this.engine.getColdInventoryRevision();
    // State revision participates because credential projection includes
    // playbook-run compatibility aliases that can change without graph IDs.
    const key = `${revisions.graph}:${revisions.state}:${configRevision}:${coldRevision}`;
    // The cache holds only the time-INSENSITIVE base topology (no sourceTrust), keyed by revisions.
    let base = this.cachedGraph?.key === key ? this.cachedGraph.graph : undefined;
    if (!base) {
      base = this.engine.exportGraph({ includeDerivedCommunities: true });
      this.cachedGraph = { key, graph: base };
    }
    // The derived honesty labels (claim_state / source_trust) are TIME-SENSITIVE — a promotion
    // whose valid_until has elapsed must read `stale` even when no revision changed — so they are
    // re-attached against `now` on every read rather than frozen in the revision-keyed cache. The
    // expensive base build stays cached; only the cheap per-element re-derivation runs per poll.
    return attachDerivedTrust(base, this.engine.now());
  }

  clear(): void {
    this.cachedGraph = undefined;
  }
}
