import type { ExportedGraph } from '../types.js';
import type { GraphEngine } from './graph-engine.js';

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
    if (this.cachedGraph?.key === key) return this.cachedGraph.graph;
    const graph = this.engine.exportGraph({ includeDerivedCommunities: true });
    this.cachedGraph = { key, graph };
    return graph;
  }

  clear(): void {
    this.cachedGraph = undefined;
  }
}
