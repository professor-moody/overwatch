import type { FrontierItem } from './types';
import { getFrontierKey, getFrontierNodeIds } from './frontier-workspace';

export type GraphTargetKind = 'node' | 'edge' | 'frontier' | 'evidence' | 'finding' | 'path' | 'filter';

export type GraphNavigationTarget =
  | { kind: 'node'; nodeId: string; hops?: number; label?: string }
  | { kind: 'edge'; edgeId?: string; source: string; target: string; edgeType?: string; label?: string }
  | { kind: 'frontier'; frontierItemId?: string; nodeIds?: string[]; label?: string }
  | { kind: 'evidence'; nodeId: string; label?: string }
  | { kind: 'finding'; findingId?: string; nodeIds: string[]; label?: string }
  | { kind: 'path'; nodeIds: string[]; edgeIds?: string[]; label?: string }
  | { kind: 'filter'; filter: string; label?: string };

export interface ParsedGraphTarget {
  kind: GraphTargetKind;
  nodeId?: string;
  hops?: number;
  edgeId?: string;
  source?: string;
  target?: string;
  edgeType?: string;
  frontierItemId?: string;
  findingId?: string;
  nodeIds?: string[];
  edgeIds?: string[];
  filter?: string;
  label?: string;
}

export interface ResolvedGraphTarget {
  kind: GraphTargetKind;
  label: string;
  nodes: Set<string>;
  edges: Set<string>;
  primaryNode: string | null;
  hops: number;
  filter?: string;
  missingReason?: string;
}

interface GraphLike {
  hasNode(node: string): boolean;
  hasEdge(edge: string): boolean;
  source(edge: string): string;
  target(edge: string): string;
  getEdgeAttribute(edge: string, attribute: string): unknown;
  forEachEdge(callback: (edge: string, attrs: Record<string, unknown>, source: string, target: string) => void): void;
}

function cleanList(values: Array<string | undefined | null>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const clean = value?.trim();
    if (!clean || seen.has(clean)) continue;
    seen.add(clean);
    out.push(clean);
  }
  return out;
}

function splitList(value: string | null): string[] {
  if (!value) return [];
  return cleanList(value.split(','));
}

function encodeList(values: string[] | undefined): string | undefined {
  const clean = cleanList(values || []);
  return clean.length > 0 ? clean.join(',') : undefined;
}

function firstNode(target: GraphNavigationTarget): string | undefined {
  if ('nodeId' in target) return target.nodeId;
  if ('nodeIds' in target) return target.nodeIds?.[0];
  if (target.kind === 'edge') return target.source;
  return undefined;
}

export function graphTargetDisplayLabel(target: GraphNavigationTarget): string {
  if (target.label) return target.label;
  switch (target.kind) {
    case 'node': return `Focused on ${target.nodeId}`;
    case 'edge': return `Edge ${target.edgeType || target.source}`;
    case 'frontier': return 'Frontier item';
    case 'evidence': return `Evidence for ${target.nodeId}`;
    case 'finding': return 'Finding';
    case 'path': return 'Attack path';
    case 'filter': return `${target.filter} nodes`;
  }
}

export function buildGraphTargetSearch(target: GraphNavigationTarget): string {
  const params = new URLSearchParams();

  if (target.kind === 'node') {
    params.set('node', target.nodeId);
    if (target.hops) params.set('hops', String(target.hops));
  } else if (target.kind === 'filter') {
    params.set('filter', target.filter);
  } else {
    params.set('context', target.kind);
    if (target.label) params.set('label', target.label);
    const node = firstNode(target);
    if (node) params.set('node', node);
    if (target.kind === 'edge') {
      if (target.edgeId) params.set('edge', target.edgeId);
      params.set('source', target.source);
      params.set('target', target.target);
      if (target.edgeType) params.set('edge_type', target.edgeType);
    } else if (target.kind === 'frontier') {
      if (target.frontierItemId) params.set('frontier', target.frontierItemId);
      const nodes = encodeList(target.nodeIds);
      if (nodes) params.set('nodes', nodes);
    } else if (target.kind === 'finding') {
      if (target.findingId) params.set('finding', target.findingId);
      const nodes = encodeList(target.nodeIds);
      if (nodes) params.set('nodes', nodes);
    } else if (target.kind === 'path') {
      const nodes = encodeList(target.nodeIds);
      const edges = encodeList(target.edgeIds);
      if (nodes) params.set('nodes', nodes);
      if (edges) params.set('edges', edges);
    }
  }

  return params.toString();
}

export function buildGraphTargetPath(target: GraphNavigationTarget): string {
  const search = buildGraphTargetSearch(target);
  return `/graph${search ? `?${search}` : ''}`;
}

export function parseGraphTargetParams(params: URLSearchParams): ParsedGraphTarget | null {
  const context = params.get('context') as GraphTargetKind | null;
  const legacyNode = params.get('node') || undefined;
  const filter = params.get('filter') || undefined;
  const label = params.get('label') || undefined;
  const hops = Number.parseInt(params.get('hops') || '0', 10) || undefined;

  if (filter && !context) return { kind: 'filter', filter, label };
  if (legacyNode && !context) return { kind: 'node', nodeId: legacyNode, hops, label };

  switch (context) {
    case 'node':
      return legacyNode ? { kind: 'node', nodeId: legacyNode, hops, label } : null;
    case 'edge':
      return {
        kind: 'edge',
        nodeId: legacyNode,
        edgeId: params.get('edge') || undefined,
        source: params.get('source') || undefined,
        target: params.get('target') || undefined,
        edgeType: params.get('edge_type') || undefined,
        label,
      };
    case 'frontier':
      return {
        kind: 'frontier',
        nodeId: legacyNode,
        frontierItemId: params.get('frontier') || undefined,
        nodeIds: splitList(params.get('nodes')),
        label,
      };
    case 'evidence':
      return legacyNode ? { kind: 'evidence', nodeId: legacyNode, label } : null;
    case 'finding':
      return {
        kind: 'finding',
        nodeId: legacyNode,
        findingId: params.get('finding') || undefined,
        nodeIds: splitList(params.get('nodes')),
        label,
      };
    case 'path':
      return {
        kind: 'path',
        nodeId: legacyNode,
        nodeIds: splitList(params.get('nodes')),
        edgeIds: splitList(params.get('edges')),
        label,
      };
    case 'filter':
      return filter ? { kind: 'filter', filter, label } : null;
    default:
      return null;
  }
}

export function resolveGraphTarget(
  graph: GraphLike,
  target: ParsedGraphTarget,
  options: { frontier?: FrontierItem[] } = {},
): ResolvedGraphTarget {
  if (target.kind === 'filter') {
    return {
      kind: 'filter',
      label: target.label || `${target.filter || 'Filtered'} nodes`,
      nodes: new Set(),
      edges: new Set(),
      primaryNode: null,
      hops: 0,
      filter: target.filter,
      missingReason: target.filter ? undefined : 'filter missing',
    };
  }

  const nodes = new Set<string>();
  const edges = new Set<string>();
  let primaryNode: string | null = null;
  let missingReason: string | undefined;

  const addNode = (nodeId: string | undefined) => {
    if (!nodeId) return;
    if (graph.hasNode(nodeId)) {
      nodes.add(nodeId);
      if (!primaryNode) primaryNode = nodeId;
    }
  };

  if (target.kind === 'node') {
    addNode(target.nodeId);
    if (!primaryNode) missingReason = `node not found: ${target.nodeId || 'unknown'}`;
  } else if (target.kind === 'edge') {
    if (target.edgeId && graph.hasEdge(target.edgeId)) {
      edges.add(target.edgeId);
      addNode(graph.source(target.edgeId));
      addNode(graph.target(target.edgeId));
    } else if (target.source && target.target) {
      graph.forEachEdge((edge, attrs, source, dest) => {
        if (source !== target.source || dest !== target.target) return;
        if (target.edgeType && attrs.edgeType !== target.edgeType) return;
        edges.add(edge);
        addNode(source);
        addNode(dest);
      });
    }
    if (edges.size === 0) {
      addNode(target.source);
      addNode(target.target);
    }
    if (nodes.size === 0) missingReason = `edge target not found: ${target.edgeId || target.source || 'unknown'}`;
  } else if (target.kind === 'frontier') {
    let nodeIds = target.nodeIds || [];
    if (nodeIds.length === 0 && target.frontierItemId && options.frontier) {
      const item = options.frontier.find(candidate => getFrontierKey(candidate) === target.frontierItemId);
      nodeIds = item ? getFrontierNodeIds(item) : [];
    }
    cleanList([target.nodeId, ...nodeIds]).forEach(addNode);
    if (nodes.size === 0) missingReason = `frontier target not found: ${target.frontierItemId || target.nodeId || 'unknown'}`;
  } else if (target.kind === 'evidence') {
    addNode(target.nodeId);
    if (!primaryNode) missingReason = `evidence node not found: ${target.nodeId || 'unknown'}`;
  } else if (target.kind === 'finding') {
    cleanList([target.nodeId, ...(target.nodeIds || [])]).forEach(addNode);
    if (nodes.size === 0) missingReason = `finding target not found: ${target.findingId || target.nodeId || 'unknown'}`;
  } else if (target.kind === 'path') {
    cleanList([target.nodeId, ...(target.nodeIds || [])]).forEach(addNode);
    for (const edgeId of target.edgeIds || []) {
      if (!graph.hasEdge(edgeId)) continue;
      edges.add(edgeId);
      addNode(graph.source(edgeId));
      addNode(graph.target(edgeId));
    }
    if (edges.size === 0 && nodes.size > 1) {
      const ordered = [...nodes];
      for (let i = 0; i < ordered.length - 1; i++) {
        const source = ordered[i];
        const dest = ordered[i + 1];
        graph.forEachEdge((edge, _attrs, edgeSource, edgeTarget) => {
          if (
            (edgeSource === source && edgeTarget === dest) ||
            (edgeSource === dest && edgeTarget === source)
          ) {
            edges.add(edge);
          }
        });
      }
    }
    if (nodes.size === 0) missingReason = 'path target not found';
  }

  const baseLabel = target.label || defaultResolvedLabel(target, primaryNode, nodes.size);
  return {
    kind: target.kind,
    label: baseLabel,
    nodes,
    edges,
    primaryNode,
    hops: target.hops || (target.kind === 'node' ? 2 : 0),
    missingReason,
  };
}

function defaultResolvedLabel(target: ParsedGraphTarget, primaryNode: string | null, count: number): string {
  switch (target.kind) {
    case 'node': return `Focused on ${target.nodeId}`;
    case 'edge': return target.edgeType ? `Edge ${target.edgeType}` : 'Edge';
    case 'frontier': return target.frontierItemId ? `Frontier ${target.frontierItemId}` : `Frontier context (${count} nodes)`;
    case 'evidence': return `Evidence for ${target.nodeId}`;
    case 'finding': return target.findingId ? `Finding ${target.findingId}` : `Finding context (${count} nodes)`;
    case 'path': return `Attack path (${count} nodes)`;
    case 'filter': return target.filter || 'Filtered graph';
    default: return primaryNode || 'Graph focus';
  }
}
