// ============================================================
// useGraphReducers — node/edge reducer functions for Sigma
// Ported from legacy graph.js nodeReducer / edgeReducer
// ============================================================

import { useRef, useCallback } from 'react';
import type Graph from 'graphology';
import {
  NODE_COLORS,
  EDGE_CATEGORIES,
  DEFAULT_EDGE_COLOR,
  HIGH_SIGNAL_NODE_TYPES,
  DETAIL_NODE_TYPES,
  SUPPORTING_NODE_TYPES,
  ZOOM_REVEAL_THRESHOLDS,
} from '../lib/graph-constants';
import { dimColor } from '../lib/graph-utils';
import { getNodeDisplayLabel } from '../lib/node-display';
import { isReachableOnlyEdge } from '../lib/graph-layers';

// ---- State interface held in a mutable ref for per-frame access ----

export interface GraphInteractionState {
  // Mode
  graphMode: 'overview' | 'focused' | 'raw';
  labelDensity: 'minimal' | 'balanced' | 'verbose';
  // What the node color encodes. The stored node `color` attr is rewritten on
  // change (recolorNodes in GraphPage), so the reducer itself doesn't branch on this
  // — it's here so the toolbar/legend can read the active encoding.
  colorMode: 'type' | 'community' | 'tier';

  // Selection
  selectedNode: string | null;
  selectedNeighborhood: Set<string> | null;
  inspectedEdgeIds: Set<string>;

  // Hover
  hoveredNode: string | null;
  hoveredNeighbors: Set<string> | null;
  hoveredEdge: string | null;

  // Path
  pathSource: string | null;
  pathTarget: string | null;
  pathNodes: Set<string>;
  pathEdges: Set<string>;

  // Focus
  focusNode: string | null;
  focusNeighborhood: Set<string> | null;
  focusLabel: string | null;
  focusKind: string | null;
  emphasizedNodeTypes: Set<string>;

  // Filters
  activeFilters: Set<string>;
  edgeTypeFilter: { type: string } | null;
  edgeSourceFilter: 'confirmed' | 'inferred' | null;
  hideOrphans: boolean;
  hideReachableOnly: boolean;

  // Overlays
  attackPathOverlay: {
    actual: { nodes: Set<string>; edges: Set<string> };
    theoretical: { nodes: Set<string>; edges: Set<string> } | null;
  } | null;
  credentialFlowMode: boolean;
  credFlowData: { flowEdges: Set<string>; flowNodes: Set<string> } | null;

  // Focus preset
  activeFocusPreset: string | null;

  // New node animation
  newNodeIds: Set<string>;

  // Camera
  cameraRatio: number;
}

export function createInitialInteractionState(): GraphInteractionState {
  return {
    graphMode: 'overview',
    labelDensity: 'balanced',
    colorMode: 'type',
    selectedNode: null,
    selectedNeighborhood: null,
    inspectedEdgeIds: new Set(),
    hoveredNode: null,
    hoveredNeighbors: null,
    hoveredEdge: null,
    pathSource: null,
    pathTarget: null,
    pathNodes: new Set(),
    pathEdges: new Set(),
    focusNode: null,
    focusNeighborhood: null,
    focusLabel: null,
    focusKind: null,
    emphasizedNodeTypes: new Set(),
    activeFilters: new Set(Object.keys(NODE_COLORS)),
    edgeTypeFilter: null,
    edgeSourceFilter: null,
    hideOrphans: false,
    hideReachableOnly: false,
    attackPathOverlay: null,
    credentialFlowMode: false,
    credFlowData: null,
    activeFocusPreset: null,
    newNodeIds: new Set(),
    cameraRatio: 1,
  };
}

// ============================================================
// Hook
// ============================================================

export function useGraphReducers(graph: Graph, reachableOnlyCacheRef: React.MutableRefObject<Set<string> | null>) {
  const stateRef = useRef<GraphInteractionState>(createInitialInteractionState());

  // ---- Visibility helpers ----

  const isReachableOnlyNode = useCallback((node: string): boolean => {
    if (!reachableOnlyCacheRef.current) {
      reachableOnlyCacheRef.current = new Set();
      graph.forEachNode((id) => {
        const deg = graph.degree(id);
        if (deg === 0) return;
        let allReachable = true;
        graph.forEachEdge(id, (_edge, attrs) => {
          if (allReachable && !isReachableOnlyEdge(attrs)) allReachable = false;
        });
        if (allReachable) reachableOnlyCacheRef.current!.add(id);
      });
    }
    return reachableOnlyCacheRef.current.has(node);
  }, [graph, reachableOnlyCacheRef]);

  const isNodeContextuallyRelevant = useCallback((node: string): boolean => {
    const s = stateRef.current;
    if (node === s.selectedNode) return true;
    if (s.pathNodes.has(node)) return true;
    if (s.focusNeighborhood?.has(node)) return true;
    if (s.selectedNeighborhood?.has(node)) return true;
    return false;
  }, []);

  const isNodeVisible = useCallback((node: string, attrs?: Record<string, unknown>): boolean => {
    const s = stateRef.current;
    const nodeAttrs = attrs || graph.getNodeAttributes(node);
    if (!nodeAttrs) return false;

    // Always show contextually-relevant nodes (selected, in path, focus neighborhood).
    if (isNodeContextuallyRelevant(node)) return true;

    // Explicit user filters — the ONLY automatic hide mechanisms.
    if (s.hideOrphans && graph.degree(node) === 0) return false;
    if (s.hideReachableOnly && isReachableOnlyNode(node)) return false;
    if (!s.activeFilters.has(nodeAttrs.nodeType as string)) return false;

    // Focus neighborhood (when active) constrains the view to the chosen subgraph.
    if (s.focusNeighborhood && !s.focusNeighborhood.has(node)) return false;

    // 'focused' mode with an explicit selection narrows to that neighborhood.
    if (s.graphMode === 'focused' && s.selectedNeighborhood) {
      return s.selectedNeighborhood.has(node);
    }

    // Otherwise show everything that passed the explicit filters.
    // No node-type or zoom-based auto-hiding — the frontier needs full visibility.
    return true;
  }, [graph, isReachableOnlyNode, isNodeContextuallyRelevant]);

  const shouldShowLabel = useCallback((node: string, nodeAttrs: Record<string, unknown>): boolean => {
    const s = stateRef.current;
    if (node === s.selectedNode || node === s.hoveredNode || s.pathNodes.has(node)) return true;
    if (s.focusNeighborhood?.has(node)) return true;
    if (s.selectedNeighborhood?.has(node)) return true;

    const nodeType = nodeAttrs.nodeType as string;
    if (s.emphasizedNodeTypes.has(nodeType)) {
      return s.cameraRatio <= 0.18 || nodeType === 'host' || nodeType === 'domain';
    }

    const ratio = s.cameraRatio;
    if (s.labelDensity === 'minimal') {
      return HIGH_SIGNAL_NODE_TYPES.has(nodeType) && ratio <= 0.18;
    }
    if (s.labelDensity === 'verbose') {
      if (DETAIL_NODE_TYPES.has(nodeType)) return ratio <= 0.18;
      if (SUPPORTING_NODE_TYPES.has(nodeType)) return ratio <= 0.08;
      return true;
    }

    if (DETAIL_NODE_TYPES.has(nodeType)) return ratio <= 0.08;
    if (SUPPORTING_NODE_TYPES.has(nodeType)) return ratio <= 0.04;
    return HIGH_SIGNAL_NODE_TYPES.has(nodeType) && ratio <= 0.28;
  }, []);

  // ---- Reducers (called per-frame by sigma) ----

  const nodeReducer = useCallback((node: string, data: Record<string, unknown>): Record<string, unknown> => {
    const res = { ...data };
    if (!isNodeVisible(node, data)) {
      res.hidden = true;
      return res;
    }

    const s = stateRef.current;

    if (!shouldShowLabel(node, data)) {
      res.label = '';
    } else if (s.graphMode === 'overview' && data.nodeType === 'host') {
      const props = (data._props as Record<string, unknown>) || {};
      const baseLabel = getNodeDisplayLabel(props, node);
      const serviceCount = graph.outEdges(node).filter(eid => graph.getEdgeAttributes(eid).edgeType === 'RUNS').length;
      if (serviceCount > 0) res.label = `${baseLabel} · svc:${serviceCount}`;
    }
    // Fan-out badge for credentials
    if (res.label && data.nodeType === 'credential') {
      const authCount = graph.outEdges(node).filter(eid => graph.getEdgeAttributes(eid).edgeType === 'POTENTIAL_AUTH').length;
      if (authCount > 0) res.label = `${res.label} · auth:${authCount}`;
    }

    // Credential flow mode
    if (s.credentialFlowMode && s.credFlowData) {
      if (data.nodeType === 'credential') {
        res.zIndex = 2;
        res.highlighted = true;
        res.size = ((data.size as number) || 5) * 1.4;
        res.label = (data.label as string) || (data._props as Record<string, unknown>)?.label || node;
        const status = (data._props as Record<string, unknown>)?.credential_status;
        if (status === 'active') res.color = '#3ecf8e';
        else if (status === 'stale') res.color = '#eab308';
        else if (status === 'expired') res.color = '#ef4444';
        else if (status === 'rotated') res.color = '#a78bfa';
      } else if (s.credFlowData.flowNodes.has(node)) {
        res.zIndex = 1;
      } else {
        res.color = dimColor(data.color as string, 0.12);
        res.label = '';
        res.zIndex = 0;
      }
      return res;
    }

    // Attack path overlay
    if (s.attackPathOverlay) {
      const inActual = s.attackPathOverlay.actual.nodes.has(node);
      const inTheoretical = s.attackPathOverlay.theoretical?.nodes.has(node);
      if (inActual) { res.highlighted = true; res.zIndex = 3; res.color = '#f0b54a'; }
      else if (inTheoretical) { res.highlighted = true; res.zIndex = 2; res.color = '#6e9eff'; }
      else { res.color = dimColor(data.color as string, 0.1); res.label = ''; res.zIndex = 0; }
      return res;
    }

    // Path highlighting
    if (s.pathNodes.size > 0) {
      if (s.pathNodes.has(node)) { res.zIndex = 2; res.highlighted = true; }
      else { res.color = dimColor(data.color as string, 0.12); res.label = ''; res.zIndex = 0; }
    }

    // Hover highlighting
    if (s.hoveredNode && !s.pathNodes.size) {
      if (node === s.hoveredNode) { res.highlighted = true; res.zIndex = 2; }
      else if (s.hoveredNeighbors?.has(node)) { res.zIndex = 1; }
      else { res.color = dimColor(data.color as string, 0.12); res.label = ''; res.zIndex = 0; }
    }

    // Selection
    if (s.selectedNode && !s.hoveredNode && !s.pathNodes.size) {
      if (node === s.selectedNode) {
        res.highlighted = true;
        res.zIndex = 4;
        res.forceLabel = true;
        res.size = ((data.size as number) || 5) * 1.3;
      }
      else if (s.selectedNeighborhood?.has(node)) {
        res.zIndex = 2;
        res.forceLabel = true;
        res.size = ((data.size as number) || 5) * 1.1;
      }
      else { res.color = dimColor(data.color as string, 0.1); res.label = ''; res.zIndex = 0; }
    }

    // Path source/target
    if (node === s.pathSource) { res.highlighted = true; res.color = '#5dcaa5'; }
    if (node === s.pathTarget) { res.highlighted = true; res.color = '#f07b6e'; }

    // New node pulse
    if (s.newNodeIds.has(node)) { res.highlighted = true; res.zIndex = 3; }

    return res;
  }, [graph, isNodeVisible, shouldShowLabel]);

  const edgeReducer = useCallback((edge: string, data: Record<string, unknown>): Record<string, unknown> => {
    const res = { ...data };
    const s = stateRef.current;

    // Inferred edges: line instead of arrow
    if (data.inferredByRule) res.type = 'line';

    // Hide edge labels when zoomed out
    if (s.cameraRatio > ZOOM_REVEAL_THRESHOLDS.detail) {
      if (edge !== s.hoveredEdge) res.label = '';
    }

    // Visibility
    const source = graph.source(edge);
    const target = graph.target(edge);
    if (!isNodeVisible(source) || !isNodeVisible(target)) { res.hidden = true; return res; }

    // Hide POTENTIAL_AUTH unless focused
    if (data.edgeType === 'POTENTIAL_AUTH') {
      const isFocused = s.credentialFlowMode
        || (s.edgeTypeFilter?.type === 'POTENTIAL_AUTH')
        || (s.edgeSourceFilter !== null)
        || source === s.focusNode || target === s.focusNode
        || s.pathNodes.has(source) || s.pathNodes.has(target)
        || s.inspectedEdgeIds.has(edge);
      if (!isFocused) { res.hidden = true; return res; }
    }

    // Edge type filter
    if (s.edgeTypeFilter) {
      if (data.edgeType === s.edgeTypeFilter.type) {
        res.color = EDGE_CATEGORIES[data.edgeType as string] || DEFAULT_EDGE_COLOR;
        res.size = 2.5; res.zIndex = 3;
      } else {
        res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0;
      }
      return res;
    }

    // Edge source filter
    if (s.edgeSourceFilter) {
      const isInferred = !!data.inferredByRule;
      const matches = (s.edgeSourceFilter === 'inferred' && isInferred) || (s.edgeSourceFilter === 'confirmed' && !isInferred);
      if (matches) {
        res.color = EDGE_CATEGORIES[data.edgeType as string] || DEFAULT_EDGE_COLOR;
        res.size = 2; res.zIndex = 2;
      } else {
        res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0;
      }
      return res;
    }

    // Credential flow
    if (s.credentialFlowMode && s.credFlowData) {
      if (s.credFlowData.flowEdges.has(edge)) {
        const et = data.edgeType;
        if (et === 'DERIVED_FROM') { res.color = '#ff8c42'; res.size = 3; res.zIndex = 3; }
        else if (et === 'OWNS_CRED') { res.color = '#f0b54a'; res.size = 2; res.zIndex = 2; }
        else { res.color = '#eab308'; res.size = 1.5; res.zIndex = 1; }
      } else {
        res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0;
      }
      return res;
    }

    // Attack path
    if (s.attackPathOverlay) {
      const inActual = s.attackPathOverlay.actual.edges.has(edge);
      const inTheoretical = s.attackPathOverlay.theoretical?.edges.has(edge);
      if (inActual) { res.color = '#f0b54a'; res.size = 3; res.zIndex = 3; }
      else if (inTheoretical) { res.color = '#6e9eff'; res.size = 2; res.zIndex = 2; }
      else { res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0; }
      return res;
    }

    // Path highlighting
    if (s.pathEdges.size > 0) {
      if (s.pathEdges.has(edge)) { res.size = 3; res.zIndex = 2; res.color = '#f0b54a'; }
      else { res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0; }
      return res;
    }

    // Hover
    if (s.hoveredNode) {
      if (source === s.hoveredNode || target === s.hoveredNode) { res.size = 2; res.zIndex = 1; }
      else { res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0; }
    }

    // Selection
    if (s.selectedNode && !s.hoveredNode && !s.pathEdges.size) {
      if (s.inspectedEdgeIds.has(edge)) { res.size = 3; res.zIndex = 3; res.color = '#f0b54a'; }
      else if (source === s.selectedNode || target === s.selectedNode) { res.size = 1.8; res.zIndex = 2; }
      else if (s.selectedNeighborhood?.has(source) && s.selectedNeighborhood?.has(target)) {
        res.size = 1.1; res.zIndex = 1;
        res.color = dimColor((data.color as string) || DEFAULT_EDGE_COLOR, 0.6);
      } else {
        res.color = 'rgba(255,255,255,0.02)'; res.size = 0.25; res.zIndex = 0;
      }
    }

    return res;
  }, [graph, isNodeVisible]);

  return { stateRef, nodeReducer, edgeReducer, isNodeVisible };
}
