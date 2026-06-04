import type Graph from 'graphology';
import { getNeighborhood } from './graph-utils';
import type { ResolvedGraphTarget, GraphTargetKind } from './graph-target';

export interface GraphFocusApplication {
  kind: GraphTargetKind;
  label: string;
  primaryNode: string;
  focusNodes: Set<string>;
  inspectedEdges: Set<string>;
  pathNodes: Set<string>;
  pathEdges: Set<string>;
  noRenderableReason?: string;
}

export function buildGraphFocusApplication(
  graph: Graph,
  resolved: ResolvedGraphTarget,
): GraphFocusApplication | null {
  if (!resolved.primaryNode || resolved.nodes.size === 0 || !graph.hasNode(resolved.primaryNode)) {
    return null;
  }

  const shouldExpandSingleContext =
    resolved.nodes.size === 1 &&
    (resolved.kind === 'evidence' || resolved.kind === 'finding' || resolved.kind === 'frontier');
  const shouldExpandNode = resolved.kind === 'node' && resolved.hops > 0;
  const focusNodes = shouldExpandNode || shouldExpandSingleContext
    ? getNeighborhood(graph, resolved.primaryNode, shouldExpandNode ? resolved.hops : 1)
    : new Set(resolved.nodes);

  const inspectedEdges = new Set<string>();
  const pathEdges = new Set<string>();
  const pathNodes = new Set<string>();

  if (resolved.edges.size > 0) {
    for (const edge of resolved.edges) {
      if (!graph.hasEdge(edge)) continue;
      inspectedEdges.add(edge);
      pathEdges.add(edge);
    }
    for (const node of focusNodes) pathNodes.add(node);
  } else {
    graph.edges(resolved.primaryNode).forEach(edge => inspectedEdges.add(edge));
  }

  const renderableCount = [...focusNodes].filter(nodeId => hasFiniteNodePosition(graph, nodeId)).length;

  return {
    kind: resolved.kind,
    label: resolved.label,
    primaryNode: resolved.primaryNode,
    focusNodes,
    inspectedEdges,
    pathNodes,
    pathEdges,
    noRenderableReason: renderableCount > 0
      ? undefined
      : `Graph target has no renderable node positions: ${resolved.label}`,
  };
}

export function hasFiniteNodePosition(graph: Graph, nodeId: string): boolean {
  if (!graph.hasNode(nodeId)) return false;
  const attrs = graph.getNodeAttributes(nodeId);
  return Number.isFinite(attrs.x) && Number.isFinite(attrs.y);
}
