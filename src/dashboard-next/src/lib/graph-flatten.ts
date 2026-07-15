import { NODE_TYPES } from './types';
import { RawGraphEdgeDtoSchema, RawGraphNodeDtoSchema } from '@overwatch/dashboard-contracts';
import type {
  ExportedEdge,
  ExportedGraph,
  ExportedNode,
  NodeType,
  RawGraphDto,
  RawGraphEdgeDto,
  RawGraphNodeDto,
} from './types';

function isRawNode(node: RawGraphNodeDto | ExportedNode): node is RawGraphNodeDto {
  return 'properties' in node && !!node.properties && typeof node.properties === 'object';
}

function isRawEdge(edge: RawGraphEdgeDto | ExportedEdge): edge is RawGraphEdgeDto {
  return 'properties' in edge && !!edge.properties && typeof edge.properties === 'object';
}

/** Convert the wrapped backend node into the dashboard's flat view model. */
export function flattenNode(node: RawGraphNodeDto | ExportedNode): ExportedNode {
  if (!isRawNode(node)) return node;
  const parsedNode = RawGraphNodeDtoSchema.parse(node);
  const properties = parsedNode.properties;
  if (typeof properties.type !== 'string' || !NODE_TYPES.includes(properties.type as NodeType)) {
    throw new Error(`Raw graph node ${parsedNode.id} has an invalid node type`);
  }
  const { properties: _nestedProperties, ...flatProperties } = properties;
  return {
    ...flatProperties,
    id: parsedNode.id,
    type: properties.type as NodeType,
    label: String(properties.label ?? node.id),
    confidence: typeof properties.confidence === 'number' ? properties.confidence : 0,
    discovered_at: typeof properties.discovered_at === 'string' ? properties.discovered_at : '',
  };
}

/** Convert the wrapped backend edge into the dashboard's flat view model. */
export function flattenEdge(edge: RawGraphEdgeDto | ExportedEdge): ExportedEdge {
  if (!isRawEdge(edge)) return edge;
  const parsedEdge = RawGraphEdgeDtoSchema.parse(edge);
  const properties = parsedEdge.properties;
  return {
    ...properties,
    id: parsedEdge.id,
    source: parsedEdge.source,
    target: parsedEdge.target,
    type: String(properties.type ?? 'unknown'),
  };
}

/** Project raw HTTP/WS graph data without folding cold inventory into hot nodes. */
export function projectRawGraph(graph: RawGraphDto): ExportedGraph {
  return {
    nodes: graph.nodes.map(flattenNode),
    edges: graph.edges.map(flattenEdge),
    coldInventory: [...(graph.cold_nodes ?? [])],
  };
}
