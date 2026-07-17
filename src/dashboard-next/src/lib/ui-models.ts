import type { ColdNodeDto } from '@overwatch/dashboard-contracts';

/**
 * Browser-only normalized models. These are deliberately separate from the
 * compatibility-v1 wire DTOs: transport data keeps wrapped `properties`, while
 * the graph renderer consumes flattened nodes and edges.
 */
export interface GraphNodeViewModel extends Record<string, unknown> {
  id: string;
  type: string;
  label: string;
}

export interface GraphEdgeViewModel extends Record<string, unknown> {
  id?: string;
  source: string;
  target: string;
  type: string;
}

export interface GraphViewModel {
  nodes: GraphNodeViewModel[];
  edges: GraphEdgeViewModel[];
  coldInventory: ColdNodeDto[];
}
