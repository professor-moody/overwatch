// ============================================================
// useGraph — graphology Graph instance + data sync
// ============================================================

import { useRef, useCallback } from 'react';
import Graph from 'graphology';
import type { ExportedGraph, ExportedNode, ExportedEdge } from '../lib/types';
import { NODE_COLORS, NODE_BASE_SIZES, EDGE_CATEGORIES, DEFAULT_EDGE_COLOR, DETAIL_NODE_TYPES, SUPPORTING_NODE_TYPES } from '../lib/graph-constants';
import { dimColor } from '../lib/graph-utils';
import { getNodeDisplayLabel } from '../lib/node-display';

// ---- Edge helpers ----

function getEdgeKey(edge: ExportedEdge): string {
  if (edge.id) return edge.id;
  return `${edge.source}--${edge.type || ''}--${edge.target}`;
}

// Normalization helpers shared with the engagement store live in
// lib/graph-flatten — keep useGraph using the same code path so the
// shape contract is single-source.
import { flattenNode, flattenEdge } from '../lib/graph-flatten';

function getEdgeColor(edgeType: string, confidence: number): string {
  if (confidence < 1.0) {
    const base = EDGE_CATEGORIES[edgeType] || '#afa9ec';
    return dimColor(base, 0.3);
  }
  return EDGE_CATEGORIES[edgeType] || DEFAULT_EDGE_COLOR;
}

interface EdgeAttrs {
  color: string;
  size: number;
  type: string;
  confidence: number;
  edgeType: string;
  label: string;
  inferredByRule: string | null;
}

function buildEdgeAttributes(edge: ExportedEdge): EdgeAttrs {
  const confidence = edge.confidence ?? 1.0;
  const edgeType = edge.type || '';
  return {
    color: getEdgeColor(edgeType, confidence),
    size: confidence >= 1.0 ? 1 : 0.5,
    type: 'arrow',
    confidence,
    edgeType,
    label: edgeType,
    inferredByRule: (edge as Record<string, unknown>).inferred_by_rule as string | null ?? null,
  };
}

// ---- Node sizing ----

function computeNodeSize(nodeType: string, degree: number): number {
  const base = NODE_BASE_SIZES[nodeType] || 5;
  return base + Math.log2(degree + 1) * 1.5;
}

// ---- Initial layout positions ----

function hashId(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
  }
  return hash;
}

function groupInitialPositions(
  nodes: ExportedNode[],
  edges: ExportedEdge[],
): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const domains = nodes.filter(n => n.type === 'domain');
  const hosts = nodes.filter(n => n.type === 'host');
  const objectives = nodes.filter(n => n.type === 'objective');
  const domainAnchors = new Map<string, { x: number; y: number }>();

  domains.forEach((d, idx) => {
    const x = (idx - (domains.length - 1) / 2) * 12;
    const y = -12;
    positions[d.id] = { x, y };
    domainAnchors.set(d.id, { x, y });
  });

  objectives.forEach((o, idx) => {
    positions[o.id] = { x: 18 + idx * 5, y: 12 + idx * 3 };
  });

  const domainHostBuckets = new Map<string, ExportedNode[]>();
  const domainLabels = domains.map(d => ({
    id: d.id,
    label: (d.label || '').toLowerCase(),
  }));

  hosts.forEach((h, hostIndex) => {
    const hostLabel = `${(h as Record<string, unknown>).hostname || ''} ${h.label || ''}`.toLowerCase();
    let match = domainLabels.find(d => d.label && hostLabel.includes(d.label));
    if (!match && domainLabels.length > 0) match = domainLabels[hostIndex % domainLabels.length];
    const domainId = match?.id || 'ungrouped';
    const bucket = domainHostBuckets.get(domainId) || [];
    bucket.push(h);
    domainHostBuckets.set(domainId, bucket);
  });

  [...domainHostBuckets.entries()].forEach(([domainId, bucket], bucketIndex) => {
    const anchor = domainAnchors.get(domainId) || {
      x: (bucketIndex - (domainHostBuckets.size - 1) / 2) * 12,
      y: -12,
    };
    bucket.forEach((h, idx) => {
      const column = idx % 3;
      const row = Math.floor(idx / 3);
      positions[h.id] = { x: anchor.x + (column - 1) * 7, y: anchor.y + 8 + row * 7 };
    });
  });

  // Orbit remaining nodes around their connected anchors
  const preferredAnchorTypes: Record<string, Set<string>> = {
    service: new Set(['host']),
    share: new Set(['host']),
    credential: new Set(['host', 'domain']),
    certificate: new Set(['host', 'domain']),
    ca: new Set(['domain', 'host']),
    cert_template: new Set(['ca', 'domain']),
    pki_store: new Set(['ca', 'domain']),
    user: new Set(['domain', 'host']),
    group: new Set(['domain']),
    ou: new Set(['domain']),
    gpo: new Set(['domain']),
  };

  function findAnchorId(nodeId: string, type: string): string | null {
    const preferred = preferredAnchorTypes[type] || new Set(['host', 'domain', 'objective']);
    const related = edges
      .filter(e => e.source === nodeId || e.target === nodeId)
      .map(e => e.source === nodeId ? e.target : e.source)
      .filter(id => positions[id]);
    const preferredMatch = related.find(id => preferred.has(nodeMap.get(id)?.type || ''));
    return preferredMatch || related[0] || null;
  }

  function getOrbitRadius(type: string): number {
    if (type === 'service') return 4.5;
    if (type === 'share') return 5.2;
    if (type === 'credential' || type === 'certificate' || type === 'ca') return 5.8;
    if (type === 'cert_template') return 4.8;
    if (type === 'user') return 6.6;
    if (type === 'group' || type === 'ou' || type === 'gpo' || type === 'pki_store') return 8.2;
    return 6;
  }

  const buckets = new Map<string, { anchorId: string; type: string; nodes: ExportedNode[] }>();
  const unanchored: ExportedNode[] = [];

  nodes.forEach(n => {
    if (positions[n.id]) return;
    const type = n.type || 'host';
    const anchorId = findAnchorId(n.id, type);
    if (!anchorId) { unanchored.push(n); return; }
    const key = `${anchorId}::${type}`;
    if (!buckets.has(key)) buckets.set(key, { anchorId, type, nodes: [] });
    buckets.get(key)!.nodes.push(n);
  });

  buckets.forEach(bucket => {
    const anchor = positions[bucket.anchorId];
    if (!anchor) return;
    bucket.nodes.sort((a, b) => a.id.localeCompare(b.id)).forEach((n, idx) => {
      const hash = hashId(n.id);
      const baseRadius = getOrbitRadius(bucket.type);
      const radius = baseRadius + ((hash % 5) - 2) * 0.18;
      const isHostSatellite = bucket.type === 'service' || bucket.type === 'share';
      const start = isHostSatellite ? -Math.PI * 0.9 : -Math.PI;
      const sweep = isHostSatellite ? Math.PI * 1.8 : Math.PI * 2;
      const slotRatio = bucket.nodes.length <= 1 ? (hash % 360) / 360 : idx / Math.max(bucket.nodes.length - 1, 1);
      const angle = start + sweep * slotRatio + (((hash >> 3) % 13) - 6) * 0.012;
      positions[n.id] = { x: anchor.x + radius * Math.cos(angle), y: anchor.y + radius * Math.sin(angle) };
    });
  });

  unanchored.forEach((n, idx) => {
    positions[n.id] = { x: (idx % 6) * 5 - 12, y: 6 + Math.floor(idx / 6) * 5 };
  });

  return positions;
}

// ============================================================
// Hook
// ============================================================

export interface UseGraphReturn {
  graph: Graph;
  loadGraphData: (data: ExportedGraph) => void;
  mergeGraphDelta: (delta: {
    nodes: ExportedNode[];
    edges: ExportedEdge[];
    removed_nodes: string[];
    removed_edges: string[];
  }) => void;
  invalidateReachableOnlyCache: () => void;
  reachableOnlyCacheRef: React.MutableRefObject<Set<string> | null>;
}

export function useGraph(): UseGraphReturn {
  const graphRef = useRef<Graph>(
    new Graph({ type: 'directed', multi: true, allowSelfLoops: false }),
  );
  const reachableOnlyCacheRef = useRef<Set<string> | null>(null);

  const graph = graphRef.current;

  const invalidateReachableOnlyCache = useCallback(() => {
    reachableOnlyCacheRef.current = null;
  }, []);

  const loadGraphData = useCallback((data: ExportedGraph) => {
    if (!data || !data.nodes) return;
    reachableOnlyCacheRef.current = null;
    graph.clear();

    const flatNodes = data.nodes.map(flattenNode);
    const flatEdges = (data.edges || []).map(flattenEdge);
    const positions = groupInitialPositions(flatNodes, flatEdges);

    flatNodes.forEach(node => {
      const nodeType = node.type || 'host';
      const pos = positions[node.id] || { x: Math.random() * 10, y: Math.random() * 10 };
      graph.addNode(node.id, {
        label: getNodeDisplayLabel(node as Record<string, unknown>, node.id),
        x: pos.x,
        y: pos.y,
        size: NODE_BASE_SIZES[nodeType] || 5,
        color: NODE_COLORS[nodeType] || '#888',
        nodeType,
        community: node.community_id,
        _props: node,
      });
    });

    flatEdges.forEach(edge => {
      if (!graph.hasNode(edge.source) || !graph.hasNode(edge.target)) return;
      const edgeKey = getEdgeKey(edge);
      const attrs = buildEdgeAttributes(edge);
      try {
        graph.addEdgeWithKey(edgeKey, edge.source, edge.target, attrs);
      } catch { /* skip duplicate */ }
    });

    // Compute degree-based sizes
    graph.forEachNode((id, attrs) => {
      graph.setNodeAttribute(id, 'size', computeNodeSize(attrs.nodeType as string, graph.degree(id)));
    });
  }, [graph]);

  const mergeGraphDelta = useCallback((delta: {
    nodes: ExportedNode[];
    edges: ExportedEdge[];
    removed_nodes: string[];
    removed_edges: string[];
  }) => {
    if (!delta) return;
    reachableOnlyCacheRef.current = null;
    const deltaEdges = (delta.edges || []).map(flattenEdge);
    const deltaNodes = (delta.nodes || []).map(flattenNode);
    let structureChanged = false;

    // Remove edges first
    for (const edgeId of (delta.removed_edges || [])) {
      if (graph.hasEdge(edgeId)) { graph.dropEdge(edgeId); structureChanged = true; }
    }

    // Remove nodes
    for (const nodeId of (delta.removed_nodes || [])) {
      if (graph.hasNode(nodeId)) { graph.dropNode(nodeId); structureChanged = true; }
    }

    // Upsert nodes
    deltaNodes.forEach(n => {
      const nodeType = n.type || 'host';
      if (graph.hasNode(n.id)) {
        graph.mergeNodeAttributes(n.id, {
          label: getNodeDisplayLabel(n as Record<string, unknown>, n.id),
          color: NODE_COLORS[nodeType] || '#888',
          nodeType,
          community: n.community_id,
          _props: n,
        });
      } else {
        // Place new node near its connected neighbors
        const neighborPositions: { x: number; y: number }[] = [];
        for (const edge of deltaEdges) {
          const peerId = edge.source === n.id ? edge.target : (edge.target === n.id ? edge.source : null);
          if (peerId && graph.hasNode(peerId)) {
            const peerAttrs = graph.getNodeAttributes(peerId);
            if (typeof peerAttrs.x === 'number' && typeof peerAttrs.y === 'number') {
              neighborPositions.push({ x: peerAttrs.x as number, y: peerAttrs.y as number });
            }
          }
        }

        const hash = hashId(n.id);
        const baseRadius = DETAIL_NODE_TYPES.has(nodeType) ? 4.5 : SUPPORTING_NODE_TYPES.has(nodeType) ? 6.4 : 5.4;
        const radius = baseRadius + ((hash % 5) - 2) * 0.18;
        const angle = ((hash % 360) / 360) * Math.PI * 2 - Math.PI;
        let startX: number, startY: number;

        if (neighborPositions.length >= 2) {
          const cx = neighborPositions.reduce((s, p) => s + p.x, 0) / neighborPositions.length;
          const cy = neighborPositions.reduce((s, p) => s + p.y, 0) / neighborPositions.length;
          startX = cx + radius * 0.5 * Math.cos(angle);
          startY = cy + radius * 0.5 * Math.sin(angle);
        } else if (neighborPositions.length === 1) {
          startX = neighborPositions[0].x + radius * Math.cos(angle);
          startY = neighborPositions[0].y + radius * Math.sin(angle);
        } else {
          startX = radius * Math.cos(angle);
          startY = radius * Math.sin(angle);
        }

        graph.addNode(n.id, {
          label: getNodeDisplayLabel(n as Record<string, unknown>, n.id),
          x: startX,
          y: startY,
          size: NODE_BASE_SIZES[nodeType] || 5,
          color: NODE_COLORS[nodeType] || '#888',
          nodeType,
          community: n.community_id,
          _props: n,
        });
        structureChanged = true;
      }
    });

    // Upsert edges
    deltaEdges.forEach(e => {
      if (!graph.hasNode(e.source) || !graph.hasNode(e.target)) return;
      const edgeKey = getEdgeKey(e);
      const attrs = buildEdgeAttributes(e);
      if (graph.hasEdge(edgeKey)) {
        graph.mergeEdgeAttributes(edgeKey, attrs);
      } else {
        try { graph.addEdgeWithKey(edgeKey, e.source, e.target, attrs); structureChanged = true; } catch { /* skip */ }
      }
    });

    // Recompute sizes
    if (structureChanged) {
      graph.forEachNode((id, attrs) => {
        graph.setNodeAttribute(id, 'size', computeNodeSize(attrs.nodeType as string, graph.degree(id)));
      });
    }
  }, [graph]);

  return { graph, loadGraphData, mergeGraphDelta, invalidateReachableOnlyCache, reachableOnlyCacheRef };
}
