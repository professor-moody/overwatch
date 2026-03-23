import type { GraphUpdateDetail } from './engine-context.js';

const DETAIL_KEYS = ['new_nodes', 'new_edges', 'updated_nodes', 'updated_edges', 'inferred_edges', 'removed_nodes', 'removed_edges'] as const;

export class DeltaAccumulator {
  private pending: Record<(typeof DETAIL_KEYS)[number], Set<string>> = {
    new_nodes: new Set<string>(),
    new_edges: new Set<string>(),
    updated_nodes: new Set<string>(),
    updated_edges: new Set<string>(),
    inferred_edges: new Set<string>(),
    removed_nodes: new Set<string>(),
    removed_edges: new Set<string>(),
  };

  push(detail: GraphUpdateDetail): void {
    for (const key of DETAIL_KEYS) {
      for (const value of detail[key] || []) {
        this.pending[key].add(value);
      }
    }
  }

  drain(): GraphUpdateDetail | null {
    const result: GraphUpdateDetail = {};
    let hasValues = false;

    for (const key of DETAIL_KEYS) {
      const values = [...this.pending[key]];
      if (values.length > 0) {
        result[key] = values;
        hasValues = true;
      }
      this.pending[key].clear();
    }

    return hasValues ? result : null;
  }
}
