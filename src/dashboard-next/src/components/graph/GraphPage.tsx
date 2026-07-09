// ============================================================
// GraphPage — Full Graph Explorer (Phase 3)
// ============================================================

import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { NODE_COLORS, FOCUS_PRESETS } from '../../lib/graph-constants';
import { colorForNode, type ColorMode } from '../../lib/graph-color';
import { ColorModeLegend } from './ColorModeLegend';
import noverlap from 'graphology-layout-noverlap';
import { explodeHubs } from '../../lib/graph-hub-layout';
import { computeHierarchical, computeTiered, type LayoutType } from '../../lib/graph-layouts';
import { getNeighborhood } from '../../lib/graph-utils';
import { useGraph } from '../../hooks/useGraph';
import { useSigma } from '../../hooks/useSigma';
import { useGraphReducers } from '../../hooks/useGraphReducers';
import { useGraphInteractions } from '../../hooks/useGraphInteractions';
import { useLayout } from '../../hooks/useLayout';
import { GraphContainer } from './GraphContainer';
import { GraphToolbar } from './GraphToolbar';
import { GraphSearch } from './GraphSearch';
import { NodeDetailDrawer } from './NodeDetailDrawer';
import { NodeFilters } from './NodeFilters';
import { PathInfoBar } from './PathInfoBar';
import { FocusBanner } from './FocusBanner';
import { Minimap } from './Minimap';
import { EdgeLegend } from './EdgeLegend';
import { exportScreenshot, exportSVG } from './GraphExport';
import { NodeContextMenu, type ContextMenuState } from './NodeContextMenu';
import { EdgeDetailPanel } from './EdgeDetailPanel';
import { correctGraph, type GraphCorrectionOperation } from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';
import { useDashboardUiStore } from '../../stores/dashboard-ui-store';
import { buildGraphLayerStates, edgeMatchesSemanticType, isCredentialFlowEdge, type GraphLayerId } from '../../lib/graph-layers';
import { clearGraphPositions, loadGraphPositions, saveGraphNodePosition } from '../../lib/graph-position-store';
import { parseGraphTargetParams, resolveGraphTarget, type ResolvedGraphTarget } from '../../lib/graph-target';
import { buildGraphFocusApplication } from '../../lib/graph-focus';

const GRAPH_DRAWER_WIDTH = 384;
const GRAPH_OVERLAY_GUTTER = 12;
const MAX_AUTO_LAYOUT_SPAN = 160;
const TARGET_AUTO_LAYOUT_SPAN = 90;

export function GraphPage() {
  // ---- Graph data layer ----
  const { graph, loadGraphData, mergeGraphDelta, reachableOnlyCacheRef } = useGraph();

  // ---- Reducers ----
  const { stateRef, nodeReducer, edgeReducer } = useGraphReducers(graph, reachableOnlyCacheRef);

  // ---- Camera ratio tracking ----
  const onCameraUpdate = useCallback((ratio: number) => {
    stateRef.current.cameraRatio = ratio;
  }, [stateRef]);

  // ---- Sigma renderer ----
  const { rendererRef, mount, refresh, zoomToFit, zoomIn, zoomOut, zoomToNodes } =
    useSigma({ graph, nodeReducer, edgeReducer, onCameraUpdate });

  // ---- Layout ----
  const layout = useLayout(graph, rendererRef);

  // ---- UI state ----
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const setGraphInspectorOpen = useDashboardUiStore(s => s.setGraphInspectorOpen);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [layoutRunning, setLayoutRunning] = useState(false);
  const [showEdgeLabels, setShowEdgeLabels] = useState(true);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);
  const [renderIssue, setRenderIssue] = useState<string | null>(null);
  const [layoutMode, setLayoutMode] = useState<'auto' | 'manual' | 'paused'>('auto');
  const [layoutType, setLayoutType] = useState<LayoutType>('force');
  // Mirror of layoutType readable inside the (non-reactive) data-load effect so a
  // delta re-applies the ACTIVE layout, not always force.
  const layoutTypeRef = useRef<LayoutType>('force');
  const [showManualHint, setShowManualHint] = useState(true);
  const [uiRevision, setUiRevision] = useState(0);
  const userPinnedLayoutRef = useRef(false);
  const engagementId = useEngagementStore(s => s.engagement?.id || 'default');
  const frontier = useEngagementStore(s => s.frontier);
  const forceGraphUi = useCallback(() => setUiRevision(v => v + 1), []);
  const graphFitPadding = useCallback((drawerOpen = !!selectedNodeId) => ({
    top: 96,
    right: drawerOpen ? GRAPH_DRAWER_WIDTH + 64 : 96,
    bottom: 152,
    left: 112,
  }), [selectedNodeId]);
  const fitVisibleGraph = useCallback((duration: number | unknown = 300, drawerOpen = !!selectedNodeId) => {
    return zoomToFit(duration, {
      paddingFactor: 0.45,
      padding: graphFitPadding(drawerOpen),
      minRatio: 0.035,
      maxRatio: 500,
    });
  }, [graphFitPadding, selectedNodeId, zoomToFit]);
  const focusedFitOptions = useCallback((kind?: string | null) => ({
    paddingFactor: kind === 'node' ? 1.05 : 1.25,
    padding: graphFitPadding(true),
    minRatio: kind === 'node' ? 0.05 : 0.04,
    maxRatio: 500,
  }), [graphFitPadding]);
  const fitCurrentGraphContext = useCallback((duration: number | unknown = 300, drawerOpen = !!selectedNodeId) => {
    const s = stateRef.current;
    let focusedNodes: Set<string> | null = null;
    if (s.graphMode === 'focused' && s.selectedNeighborhood?.size) {
      focusedNodes = s.selectedNeighborhood;
    } else if (s.focusNeighborhood?.size) {
      focusedNodes = s.focusNeighborhood;
    }

    if (focusedNodes?.size) {
      return zoomToNodes(focusedNodes, {
        ...focusedFitOptions(s.focusKind),
        duration: typeof duration === 'number' && Number.isFinite(duration) ? duration : undefined,
      });
    }

    return fitVisibleGraph(duration, drawerOpen);
  }, [fitVisibleGraph, focusedFitOptions, selectedNodeId, stateRef, zoomToNodes]);
  const normalizeAutoLayout = useCallback(() => {
    if (graph.order === 0) return false;
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    graph.forEachNode((_nodeId, attrs) => {
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      minX = Math.min(minX, x);
      maxX = Math.max(maxX, x);
      minY = Math.min(minY, y);
      maxY = Math.max(maxY, y);
    });
    if (!Number.isFinite(minX) || !Number.isFinite(minY)) return false;

    const span = Math.max(maxX - minX, maxY - minY);
    if (span <= MAX_AUTO_LAYOUT_SPAN) return false;

    const scale = TARGET_AUTO_LAYOUT_SPAN / span;
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    graph.forEachNode((nodeId, attrs) => {
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      graph.setNodeAttribute(nodeId, 'x', (x - cx) * scale);
      graph.setNodeAttribute(nodeId, 'y', (y - cy) * scale);
    });
    return true;
  }, [graph]);

  // Anti-overlap pass: nudge nodes apart so they stop stacking on top of each other
  // and their connected neighbors (ForceAtlas2 gets close but doesn't guarantee no
  // overlap). `margin` is the extra gap kept between nodes; `ratio` scales the node
  // size used for collision. Only runs on the auto-layout path (no user-pinned
  // nodes there), but we still snapshot/restore any `fixed` node defensively.
  const applyNoverlap = useCallback(() => {
    if (graph.order === 0) return;
    const pinned = new Map<string, { x: number; y: number }>();
    graph.forEachNode((id, attrs) => {
      if (attrs.fixed) pinned.set(id, { x: attrs.x as number, y: attrs.y as number });
    });
    noverlap.assign(graph, {
      maxIterations: 60,
      settings: { margin: 6, ratio: 1.4, gridSize: 20, speed: 3 },
    });
    for (const [id, pos] of pinned) {
      graph.setNodeAttribute(id, 'x', pos.x);
      graph.setNodeAttribute(id, 'y', pos.y);
    }
  }, [graph]);

  // Apply a deterministic (non-force) layout: write positions, de-overlap, refresh.
  // Transient — it never writes to the saved-position store, so a reload restores
  // whatever the user pinned.
  const applyComputedLayout = useCallback((type: 'hierarchical' | 'tiered') => {
    if (graph.order === 0) return;
    if (type === 'hierarchical') computeHierarchical(graph); else computeTiered(graph);
    normalizeAutoLayout();
    applyNoverlap();
    refresh();
  }, [graph, normalizeAutoLayout, applyNoverlap, refresh]);

  // Run whichever layout is active for a fresh/merged graph. Force = the FA2 burst +
  // explode/noverlap finalize; computed = apply it synchronously. No-op when the user
  // has pinned a manual layout.
  const runActiveLayout = useCallback((fitDuration: number, opts?: { isDelta?: boolean }) => {
    if (userPinnedLayoutRef.current) return;
    if (layoutTypeRef.current === 'force') {
      layout.start();
      setLayoutRunning(true);
      setTimeout(() => {
        layout.stop();
        setLayoutRunning(false);
        // Re-check BOTH: the user may have pinned OR switched to a computed layout
        // during the 1500ms burst — don't stomp a just-applied hierarchical/tiered view.
        if (userPinnedLayoutRef.current || layoutTypeRef.current !== 'force') return;
        normalizeAutoLayout();
        explodeHubs(graph);
        applyNoverlap();
        refresh();
        fitCurrentGraphContext(fitDuration, !!selectedNodeId);
      }, 1500);
    } else if (!opts?.isDelta) {
      // Computed layouts recompute the WHOLE graph deterministically (dagre / grid).
      // Doing that on every streamed delta would block the main thread and jump every
      // node, so only run it on a full load / explicit switch — not per delta. New
      // nodes from a delta keep their seed position until the next full load or the
      // operator re-picks the layout.
      applyComputedLayout(layoutTypeRef.current);
      fitCurrentGraphContext(fitDuration, !!selectedNodeId);
    }
  }, [graph, layout, normalizeAutoLayout, applyNoverlap, refresh, fitCurrentGraphContext, applyComputedLayout, selectedNodeId]);

  // ---- Edit mode ----
  const [editMode, setEditMode] = useState(false);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const undoStackRef = useRef<Array<{ reason: string; reverse: GraphCorrectionOperation[] }>>([]);
  const toast = useToastStore((s) => s.addToast);

  useEffect(() => {
    setGraphInspectorOpen(!!selectedNodeId);
    return () => setGraphInspectorOpen(false);
  }, [selectedNodeId, setGraphInspectorOpen]);

  const handleUndoPush = useCallback((op: { reason: string; reverse: GraphCorrectionOperation[] }) => {
    undoStackRef.current = [...undoStackRef.current.slice(-19), op];
  }, []);

  const handleUndo = useCallback(async () => {
    const last = undoStackRef.current.pop();
    if (!last) return;
    try {
      await correctGraph(last.reason, last.reverse);
      toast({ type: 'info', title: 'Undo applied', message: last.reason });
    } catch {
      toast({ type: 'error', title: 'Undo failed' });
    }
  }, [toast]);

  // ---- Interactions ----
  const { selectNode, clearSelection, clearPathHighlight, enterNeighborhoodFocus, exitNeighborhoodFocus } =
    useGraphInteractions({
      graph,
      rendererRef,
      stateRef,
      refresh,
      onUserLayoutChange: () => {
        if (!userPinnedLayoutRef.current) {
          toast({
            type: 'info',
            title: 'Manual layout',
            message: 'Node positions will stay pinned in this browser until reset.',
          });
        }
        userPinnedLayoutRef.current = true;
        setLayoutMode('manual');
        setShowManualHint(false);
        layout.stop();
        setLayoutRunning(false);
        forceGraphUi();
      },
      onNodePositionCommit: (nodeId, position) => {
        saveGraphNodePosition(engagementId, nodeId, position);
      },
      onNodeSelect: (nodeId) => { setSelectedNodeId(nodeId); if (nodeId) setSelectedEdgeId(null); },
      onEdgeSelect: (edgeId) => { setSelectedEdgeId(edgeId); if (edgeId) setSelectedNodeId(null); },
      onNodeFocus: (nodeId, hops) => {
        // Zoom to the focus neighborhood
        const neighborhood = getNeighborhood(graph, nodeId, hops);
        const moved = zoomToNodes(neighborhood, {
          ...focusedFitOptions('node'),
          duration: 300,
        });
        if (!moved) {
          toast({
            type: 'warning',
            title: 'Graph focus unavailable',
            message: 'The focused nodes are not renderable yet.',
          });
        }
      },
    });

  // ---- Sync graph data from store ----
  const storeGraph = useEngagementStore(s => s.graph);
  const graphVersion = useEngagementStore(s => s.graphVersion);
  const lastDelta = useEngagementStore(s => s.lastDelta);
  const loadedVersionRef = useRef(-1);
  const loadedEngagementRef = useRef<string | null>(null);

  useEffect(() => {
    if (graphVersion === loadedVersionRef.current && engagementId === loadedEngagementRef.current) return;
    loadedVersionRef.current = graphVersion;
    loadedEngagementRef.current = engagementId;

    if (lastDelta && graph.order > 0) {
      // Incremental delta merge
      mergeGraphDelta(lastDelta);
      setNodeCount(graph.order);
      setEdgeCount(graph.size);
      // Re-run the active layout for new nodes. Force does its worker burst; computed
      // layouts skip delta recompute (isDelta) to avoid janking/jumping the whole graph.
      if ((lastDelta.nodes?.length || 0) > 0) {
        runActiveLayout(250, { isDelta: true });
      }
      refresh();
    } else if (storeGraph && storeGraph.nodes && storeGraph.nodes.length > 0) {
      // Full reload
      const savedPositions = loadGraphPositions(engagementId);
      const hasSavedPositions = Object.keys(savedPositions).length > 0;
      if (hasSavedPositions) {
        userPinnedLayoutRef.current = true;
        setLayoutMode('manual');
        setShowManualHint(false);
      }
      loadGraphData(storeGraph, { savedPositions });
      setNodeCount(graph.order);
      setEdgeCount(graph.size);
      setRenderIssue(null);
      setTimeout(() => {
        refresh();
        if (!userPinnedLayoutRef.current) {
          fitCurrentGraphContext(250, false);
          runActiveLayout(300);
        }
      }, 50);
    }
  }, [graphVersion, lastDelta, storeGraph, loadGraphData, mergeGraphDelta, graph, layout, refresh, fitCurrentGraphContext, normalizeAutoLayout, runActiveLayout, engagementId, selectedNodeId]);

  useEffect(() => {
    if (!storeGraph?.nodes?.length) {
      setRenderIssue(null);
      return;
    }

    const timer = setTimeout(() => {
      const renderer = rendererRef.current;
      if (!renderer) {
        setRenderIssue('Graph renderer is not mounted.');
        return;
      }
      if (graph.order === 0) {
        setRenderIssue('Graph data is loaded, but no renderable nodes were added.');
        return;
      }
      setRenderIssue(null);
      refresh();
    }, 700);

    return () => clearTimeout(timer);
  }, [graph, graphVersion, refresh, rendererRef, storeGraph?.nodes?.length]);

  // Track layout running state for toolbar feedback.
  useEffect(() => {
    const interval = setInterval(() => {
      const running = layout.running;
      setLayoutRunning(running);
      setNodeCount(graph.order);
      setEdgeCount(graph.size);
    }, 200);
    return () => clearInterval(interval);
  }, [layout, graph]);

  // ---- Query param navigation (from frontier/overview/agents) ----
  const [searchParams, setSearchParams] = useSearchParams();
  const appliedParamsRef = useRef<string | null>(null);

  const applyGraphFocusTarget = useCallback((resolved: ResolvedGraphTarget) => {
    if (resolved.filter) {
      const s = stateRef.current;
      const focusNodes = new Set<string>();
      graph.forEachNode((nodeId, attrs) => {
        if (attrs.nodeType === resolved.filter) focusNodes.add(nodeId);
      });
      if (focusNodes.size === 0) {
        setRenderIssue(`No graph nodes match filter: ${resolved.filter}`);
        return false;
      }
      s.activeFilters = new Set([resolved.filter]);
      s.graphMode = 'focused';
      s.emphasizedNodeTypes = new Set([resolved.filter]);
      s.focusNode = null;
      s.focusNeighborhood = focusNodes;
      s.focusLabel = resolved.label;
      s.focusKind = resolved.kind;
      s.selectedNode = null;
      s.selectedNeighborhood = focusNodes;
      s.inspectedEdgeIds.clear();
      s.pathNodes.clear();
      s.pathEdges.clear();
      setSelectedNodeId(null);
      refresh();
      const moved = zoomToNodes(focusNodes, {
        ...focusedFitOptions('filter'),
        padding: graphFitPadding(false),
        duration: 300,
      });
      if (!moved) {
        setRenderIssue(`Graph filter has no renderable node positions: ${resolved.label}`);
        return false;
      }
      setRenderIssue(null);
      forceGraphUi();
      return true;
    }

    const focus = buildGraphFocusApplication(graph, resolved);
    if (!focus) return false;
    if (focus.noRenderableReason) {
      setRenderIssue(focus.noRenderableReason);
      return false;
    }

    const s = stateRef.current;
    s.graphMode = 'focused';
    s.focusNode = focus.primaryNode;
    s.focusNeighborhood = focus.focusNodes;
    s.focusLabel = focus.label;
    s.focusKind = focus.kind;
    s.selectedNode = focus.primaryNode;
    s.selectedNeighborhood = focus.focusNodes;
    s.inspectedEdgeIds.clear();
    s.pathNodes.clear();
    s.pathEdges.clear();
    for (const edge of focus.inspectedEdges) s.inspectedEdgeIds.add(edge);
    for (const edge of focus.pathEdges) s.pathEdges.add(edge);
    for (const node of focus.pathNodes) s.pathNodes.add(node);
    setSelectedNodeId(focus.primaryNode);
    refresh();
    const moved = zoomToNodes(focus.focusNodes, {
      ...focusedFitOptions(focus.kind),
      duration: 300,
    });
    if (!moved) {
      setRenderIssue(`Graph target is not visible yet: ${focus.label}`);
      return false;
    }
    setRenderIssue(null);
    forceGraphUi();
    return true;
  }, [forceGraphUi, graph, focusedFitOptions, graphFitPadding, refresh, stateRef, toast, zoomToNodes]);

  useEffect(() => {
    const key = searchParams.toString();
    if (!key || appliedParamsRef.current === key || graph.order === 0 || !rendererRef.current) return;

    const target = parseGraphTargetParams(searchParams);
    if (!target) return;

    const resolved = resolveGraphTarget(graph, target, { frontier });
    if (resolved.missingReason) {
      appliedParamsRef.current = key;
      toast({ type: 'warning', title: 'Graph target not found', message: resolved.missingReason });
      setSearchParams({}, { replace: true });
      return;
    }

    if (applyGraphFocusTarget(resolved)) {
      appliedParamsRef.current = key;
      setSearchParams({}, { replace: true });
    }
  }, [applyGraphFocusTarget, frontier, graph, graphVersion, layoutRunning, nodeCount, rendererRef, searchParams, setSearchParams, toast]);

  // ---- Toolbar callbacks ----
  const handleReset = useCallback(() => {
    const s = stateRef.current;
    s.activeFilters = new Set(Object.keys(NODE_COLORS));
    s.graphMode = 'overview';
    s.labelDensity = 'balanced';
    s.edgeTypeFilter = null;
    s.edgeSourceFilter = null;
    s.emphasizedNodeTypes = new Set();
    s.activeFocusPreset = null;
    s.hideOrphans = false;
    s.hideReachableOnly = false;
    clearSelection();
    clearPathHighlight();
    exitNeighborhoodFocus();
    refresh();
    if (!fitVisibleGraph()) {
      toast({ type: 'warning', title: 'Graph fit unavailable', message: 'No visible graph nodes can be framed yet.' });
    }
    forceGraphUi();
  }, [stateRef, clearSelection, clearPathHighlight, exitNeighborhoodFocus, refresh, fitVisibleGraph, forceGraphUi, toast]);

  const handleToggleLayout = useCallback(() => {
    if (layout.running) {
      layout.stop();
      setLayoutRunning(false);
      setLayoutMode('paused');
      forceGraphUi();
      return;
    }
    userPinnedLayoutRef.current = false;
    setLayoutMode('auto');
    layout.start();
    setLayoutRunning(true);
    forceGraphUi();
  }, [layout, forceGraphUi]);

  const handleResumeLayout = useCallback(() => {
    userPinnedLayoutRef.current = false;
    setLayoutMode('auto');
    layout.start();
    setLayoutRunning(true);
    forceGraphUi();
  }, [layout, forceGraphUi]);

  // Switch the layout algorithm. Force resumes the physics sim; Hierarchical/Tiered
  // compute deterministic positions once (and re-apply on future deltas via
  // layoutTypeRef). Switching un-pins so the chosen layout takes effect; saved manual
  // positions still restore on a full reload (computed layouts are transient views).
  const handleSetLayout = useCallback((typeStr: string) => {
    const type = typeStr as LayoutType;
    layoutTypeRef.current = type;
    setLayoutType(type);
    userPinnedLayoutRef.current = false;
    setLayoutMode('auto');
    if (type === 'force') {
      layout.start();
      setLayoutRunning(true);
    } else {
      layout.stop();
      setLayoutRunning(false);
      applyComputedLayout(type);
      fitCurrentGraphContext(400, !!selectedNodeId);
    }
    forceGraphUi();
  }, [layout, applyComputedLayout, fitCurrentGraphContext, selectedNodeId, forceGraphUi]);

  const handleResetPositions = useCallback(() => {
    clearGraphPositions(engagementId);
    userPinnedLayoutRef.current = false;
    setLayoutMode('auto');
    setShowManualHint(true);
    if (storeGraph?.nodes?.length) {
      loadGraphData(storeGraph, { savedPositions: {}, preserveExisting: false });
    }
    setTimeout(() => {
      refresh();
      fitVisibleGraph();
      layout.start();
      setLayoutRunning(true);
    }, 50);
    toast({ type: 'info', title: 'Positions reset', message: 'Auto layout is running again.' });
    forceGraphUi();
  }, [engagementId, storeGraph, loadGraphData, refresh, fitVisibleGraph, layout, toast, forceGraphUi]);

  const handleSetGraphMode = useCallback((mode: string) => {
    stateRef.current.graphMode = mode as 'overview' | 'focused' | 'raw';
    refresh();
  }, [stateRef, refresh]);

  const handleSetLabelDensity = useCallback((density: string) => {
    stateRef.current.labelDensity = density as 'minimal' | 'balanced' | 'verbose';
    refresh();
  }, [stateRef, refresh]);

  // Rewrite every node's stored `color` attr for the active color mode. Rewriting
  // the attr (rather than branching the per-frame reducer) keeps the reducer lean and
  // keeps the minimap + all `dimColor(data.color,…)` paths automatically consistent.
  const recolorNodes = useCallback(() => {
    const mode = stateRef.current.colorMode;
    graph.forEachNode((id, attrs) => {
      graph.setNodeAttribute(id, 'color', colorForNode(attrs as { nodeType?: string; community?: number; _props?: unknown }, mode));
    });
    refresh();
  }, [graph, stateRef, refresh]);

  const handleSetColorMode = useCallback((mode: string) => {
    stateRef.current.colorMode = mode as ColorMode;
    recolorNodes();
    forceGraphUi();
  }, [stateRef, recolorNodes, forceGraphUi]);

  const handleTogglePathMode = useCallback(() => {
    const s = stateRef.current;
    s.pathMode = !s.pathMode;
    // Leaving path mode clears any half-built or completed path so a normal click
    // resumes selecting.
    if (!s.pathMode) clearPathHighlight();
    forceGraphUi();
  }, [stateRef, clearPathHighlight, forceGraphUi]);

  // Re-apply the active (non-type) color encoding after a data load/merge so newly
  // arrived nodes — which load with their default type color — pick up the mode.
  useEffect(() => {
    if (stateRef.current.colorMode !== 'type') recolorNodes();
  }, [graphVersion, recolorNodes, stateRef]);

  const handleSetFocusPreset = useCallback((presetName: string) => {
    const s = stateRef.current;
    if (!presetName) {
      if (s.activeFocusPreset) {
        s.activeFocusPreset = null;
        handleReset();
      }
      return;
    }
    const preset = FOCUS_PRESETS[presetName];
    if (!preset) return;

    s.activeFocusPreset = presetName;
    clearPathHighlight();
    s.focusNode = null;
    s.focusNeighborhood = null;
    s.focusLabel = null;
    s.focusKind = null;
    s.selectedNode = null;
    s.inspectedEdgeIds.clear();
    s.graphMode = 'focused';
    s.activeFilters = new Set(preset.nodeTypes.filter(t => NODE_COLORS[t]));
    s.emphasizedNodeTypes = new Set(preset.nodeTypes);
    s.edgeTypeFilter = null;
    s.edgeSourceFilter = null;

    // Build neighborhood
    const neighborhood = new Set<string>();
    graph.forEachNode((id, attrs) => {
      if (preset.nodeTypes.includes(attrs.nodeType as string)) neighborhood.add(id);
    });
    for (const nodeId of [...neighborhood]) {
      graph.forEachEdge(nodeId, (_edge, attrs, src, tgt) => {
        if (edgeMatchesSemanticType(attrs, preset.edgeHighlight)) {
          neighborhood.add(src);
          neighborhood.add(tgt);
        }
      });
    }
    s.selectedNeighborhood = neighborhood;
    refresh();
    const moved = zoomToNodes(neighborhood, {
      ...focusedFitOptions('preset'),
      padding: graphFitPadding(false),
      duration: 300,
    });
    if (!moved) {
      toast({ type: 'warning', title: 'Graph focus unavailable', message: 'No preset nodes can be framed yet.' });
    }
  }, [graph, stateRef, clearPathHighlight, refresh, zoomToNodes, handleReset, graphFitPadding, focusedFitOptions, toast]);

  const handleToggleFilter = useCallback((type: string) => {
    const s = stateRef.current;
    if (s.activeFilters.has(type)) s.activeFilters.delete(type);
    else s.activeFilters.add(type);
    refresh();
  }, [stateRef, refresh]);

  const handleToggleAttackPath = useCallback(() => {
    const s = stateRef.current;
    if (s.attackPathOverlay) {
      s.attackPathOverlay = null;
    } else if (s.pathEdges.size > 0) {
      s.attackPathOverlay = {
        actual: { nodes: new Set(s.pathNodes), edges: new Set(s.pathEdges) },
        theoretical: null,
      };
    } else {
      toast({
        type: 'info',
        title: 'No attack path selected',
        message: 'Shift-click two nodes to create a path before enabling this layer.',
      });
    }
    refresh();
    forceGraphUi();
  }, [stateRef, refresh, toast, forceGraphUi]);

  const handleToggleCredFlow = useCallback(() => {
    const s = stateRef.current;
    if (s.credentialFlowMode) {
      s.credentialFlowMode = false;
      s.credFlowData = null;
    } else {
      s.credentialFlowMode = true;
      // Build credential flow data
      const flowEdges = new Set<string>();
      const flowNodes = new Set<string>();
      graph.forEachEdge((_edge, attrs, src, tgt) => {
        if (isCredentialFlowEdge(attrs.edgeType)) {
          flowEdges.add(_edge);
          flowNodes.add(src);
          flowNodes.add(tgt);
        }
      });
      s.credFlowData = { flowEdges, flowNodes };
    }
    refresh();
    forceGraphUi();
  }, [graph, stateRef, refresh, forceGraphUi]);

  const handleToggleLayer = useCallback((id: GraphLayerId) => {
    const s = stateRef.current;
    if (id === 'edgeLabels') {
      const next = !showEdgeLabels;
      setShowEdgeLabels(next);
      rendererRef.current?.setSetting('renderEdgeLabels', next);
      forceGraphUi();
      return;
    }
    if (id === 'credentialFlow') {
      handleToggleCredFlow();
      return;
    }
    if (id === 'attackPath') {
      handleToggleAttackPath();
      return;
    }
    if (id === 'hideOrphans') {
      s.hideOrphans = !s.hideOrphans;
      refresh();
      forceGraphUi();
      return;
    }
    if (id === 'hideReachableOnly') {
      s.hideReachableOnly = !s.hideReachableOnly;
      refresh();
      forceGraphUi();
    }
  }, [
    stateRef,
    showEdgeLabels,
    rendererRef,
    handleToggleCredFlow,
    handleToggleAttackPath,
    refresh,
    forceGraphUi,
  ]);

  const handleSearchSelect = useCallback((nodeId: string) => {
    selectNode(nodeId);
    const moved = zoomToNodes(new Set([nodeId]), {
      padding: graphFitPadding(true),
      minRatio: 0.08,
      maxRatio: 0.22,
    });
    if (!moved) {
      toast({ type: 'warning', title: 'Graph focus unavailable', message: `${nodeId} is not renderable yet.` });
    }
  }, [selectNode, zoomToNodes, graphFitPadding, toast]);

  const handleFitCurrentContext = useCallback(() => {
    if (!fitCurrentGraphContext()) {
      toast({ type: 'warning', title: 'Graph fit unavailable', message: 'No visible graph nodes can be framed yet.' });
    }
  }, [fitCurrentGraphContext, toast]);

  // ---- Keyboard shortcuts ----
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      switch (e.key) {
        case 'f': case 'F': e.preventDefault(); handleFitCurrentContext(); break;
        case ' ': e.preventDefault(); handleToggleLayout(); break;
        case 'Escape':
          e.preventDefault();
          setShowShortcuts(false);
          setSelectedEdgeId(null);
          clearSelection();
          clearPathHighlight();
          break;
        case 'r': case 'R': e.preventDefault(); handleReset(); break;
        case '+': case '=': e.preventDefault(); zoomIn(); break;
        case '-': e.preventDefault(); zoomOut(); break;
        case '?': e.preventDefault(); setShowShortcuts(v => !v); break;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [handleFitCurrentContext, zoomIn, zoomOut, handleToggleLayout, clearSelection, clearPathHighlight, handleReset]);

  const s = stateRef.current;
  const layers = useMemo(() => buildGraphLayerStates({
    graph,
    edgeLabels: showEdgeLabels,
        credentialFlow: s.credentialFlowMode,
    attackPath: !!s.attackPathOverlay,
    hideOrphans: s.hideOrphans,
    hideReachableOnly: s.hideReachableOnly,
    pathEdgeCount: s.pathEdges.size,
  }), [graph, showEdgeLabels, s, graphVersion, nodeCount, edgeCount, uiRevision]);

  // ---- Right-click context menu ----
  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer || !editMode) return;
    const onRightClick = ({ node, event }: { node: string; event: { original: MouseEvent } }) => {
      event.original.preventDefault();
      setContextMenu({ x: event.original.clientX, y: event.original.clientY, nodeId: node });
    };
    renderer.on('rightClickNode', onRightClick as never);
    return () => { renderer.off('rightClickNode', onRightClick as never); };
  }, [rendererRef, editMode]);

  return (
    <div className="h-screen flex flex-col bg-background">
      <GraphToolbar
        nodeCount={nodeCount}
        edgeCount={edgeCount}
        layoutRunning={layoutRunning}
        layoutMode={layoutMode}
        graphMode={s.graphMode}
        labelDensity={s.labelDensity}
        colorMode={s.colorMode}
        pathMode={s.pathMode}
        layoutType={layoutType}
        activeFocusPreset={s.activeFocusPreset}
        layers={layers}
        onZoomIn={zoomIn}
        onZoomOut={zoomOut}
        onFit={handleFitCurrentContext}
        onToggleLayout={handleToggleLayout}
        onResumeLayout={handleResumeLayout}
        onReset={handleReset}
        onResetPositions={handleResetPositions}
        onExportPNG={() => exportScreenshot(rendererRef.current)}
        onExportSVG={() => exportSVG(rendererRef.current, graph)}
        onSetGraphMode={handleSetGraphMode}
        onSetLabelDensity={handleSetLabelDensity}
        onSetColorMode={handleSetColorMode}
        onSetLayout={handleSetLayout}
        onSetFocusPreset={handleSetFocusPreset}
        onToggleLayer={handleToggleLayer}
        onTogglePathMode={handleTogglePathMode}
        onToggleShortcuts={() => setShowShortcuts(v => !v)}
        editMode={editMode}
        onToggleEditMode={() => setEditMode(v => !v)}
        onUndo={handleUndo}
        undoCount={undoStackRef.current.length}
      />

      {/* Edit mode banner */}
      {editMode && (
        <div className="bg-warning/10 border-b border-warning/30 px-4 py-1.5 text-xs text-warning flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-warning animate-pulse" />
          Edit Mode — Right-click nodes to annotate or mark. Changes are persisted.
        </div>
      )}

      {/* Main graph area */}
      <div className="flex-1 relative overflow-hidden">
        <GraphContainer onMount={mount} rendererRef={rendererRef} />

        {renderIssue && (
          <div className="pointer-events-none absolute top-16 left-1/2 -translate-x-1/2 z-40 bg-warning/10 border border-warning/30 text-warning rounded px-3 py-2 text-xs shadow-lg">
            {renderIssue}
          </div>
        )}

        {/* Overlays */}
        <div
          className="pointer-events-none absolute inset-y-0 left-0 z-30 grid grid-rows-[auto_1fr_auto] gap-3 p-3"
          style={{ right: selectedNodeId ? GRAPH_DRAWER_WIDTH + GRAPH_OVERLAY_GUTTER : GRAPH_OVERLAY_GUTTER }}
        >
          <div className="grid grid-cols-[minmax(14rem,18rem)_minmax(16rem,1fr)_minmax(8rem,18rem)] items-start gap-3">
            <GraphSearch graph={graph} onSelect={handleSearchSelect} />
            <div className="flex min-w-0 flex-col items-center gap-2">
              <PathInfoBar
                graph={graph}
                pathSource={s.pathSource}
                pathTarget={s.pathTarget}
                pathEdges={s.pathEdges}
                onClear={clearPathHighlight}
                className="max-w-full"
              />
              <FocusBanner
                focusNode={s.focusNode}
                focusSize={s.focusNeighborhood?.size || 0}
                label={s.focusLabel}
                kind={s.focusKind}
                onFit={handleFitCurrentContext}
                onExit={exitNeighborhoodFocus}
                className="max-w-full"
              />
            </div>
            <div />
          </div>

          <div />

          <div className="grid grid-cols-[minmax(14rem,1fr)_auto_minmax(10rem,12rem)] items-end gap-3">
            <div className="flex min-w-0 flex-col items-start gap-2">
              <ColorModeLegend colorMode={s.colorMode} graph={graph} graphVersion={graphVersion} />
              <EdgeLegend defaultCollapsed={true} className="max-w-[14rem]" />
              <NodeFilters
                graph={graph}
                activeFilters={s.activeFilters}
                onToggle={handleToggleFilter}
              />
            </div>
            <div className="flex justify-center">
              {showManualHint && layoutMode === 'auto' && nodeCount > 0 && (
                <div className="pointer-events-none bg-surface/95 border border-border text-muted-foreground rounded px-3 py-1.5 text-xs shadow-lg">
                  Drag a node to pin the layout.
                </div>
              )}

              {layoutMode === 'manual' && (
                <div className="pointer-events-none bg-warning/10 border border-warning/30 text-warning rounded px-3 py-1.5 text-xs shadow-lg">
                  Manual layout: positions are saved in this browser.
                </div>
              )}

              {s.pathMode && (
                <div className="pointer-events-none bg-accent/10 border border-accent/30 text-accent rounded px-3 py-1.5 text-xs shadow-lg">
                  Path mode: click a source node, then a target.
                </div>
              )}
            </div>
            <div className="hidden sm:block">
              <Minimap graph={graph} rendererRef={rendererRef} />
            </div>
          </div>
        </div>

        {/* Edge detail panel */}
        <EdgeDetailPanel
          graph={graph}
          edgeId={selectedEdgeId}
          onClose={() => { setSelectedEdgeId(null); stateRef.current.inspectedEdgeIds.clear(); refresh(); }}
          onFocusNode={enterNeighborhoodFocus}
        />

        {/* Keyboard shortcuts overlay */}
        {showShortcuts && (
          <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setShowShortcuts(false)}>
            <div className="bg-surface border border-border rounded-lg p-5 max-w-xs" onClick={e => e.stopPropagation()}>
              <h3 className="text-sm font-semibold mb-3">Keyboard Shortcuts</h3>
              <div className="space-y-1.5 text-xs">
                {[
                  ['F', 'Fit to screen'],
                  ['Space', 'Pause/resume graph layout'],
                  ['Esc', 'Clear selection'],
                  ['R', 'Reset filters'],
                  ['+ / −', 'Zoom'],
                  ['Drag', 'Pin a manual node position'],
                  ['?', 'Toggle this help'],
                  ['Shift+Click', 'Path highlight'],
                  ['Dbl-Click', 'Neighborhood focus'],
                ].map(([key, desc]) => (
                  <div key={key} className="flex items-center gap-3">
                    <kbd className="px-1.5 py-0.5 rounded bg-elevated border border-border font-mono text-accent min-w-[3rem] text-center text-[10px]">{key}</kbd>
                    <span className="text-muted-foreground">{desc}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Node detail drawer */}
      <NodeDetailDrawer
        graph={graph}
        nodeId={selectedNodeId}
        onClose={() => clearSelection()}
        onFocus={enterNeighborhoodFocus}
        editMode={editMode}
        onUndoPush={handleUndoPush}
      />

      {/* Context menu (edit mode) */}
      {editMode && (
        <NodeContextMenu
          menu={contextMenu}
          onClose={() => setContextMenu(null)}
          onFocus={enterNeighborhoodFocus}
          onUndoPush={handleUndoPush}
        />
      )}
    </div>
  );
}
