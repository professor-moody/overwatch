// ============================================================
// GraphPage — Full Graph Explorer (Phase 3)
// ============================================================

import { useState, useCallback, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { NODE_COLORS, FOCUS_PRESETS } from '../../lib/graph-constants';
import { getNeighborhood } from '../../lib/graph-utils';
import { useGraph } from '../../hooks/useGraph';
import { useSigma } from '../../hooks/useSigma';
import { useGraphReducers } from '../../hooks/useGraphReducers';
import { useGraphInteractions } from '../../hooks/useGraphInteractions';
import { useLayout } from '../../hooks/useLayout';
import { useCommunityHulls } from '../../hooks/useCommunityHulls';
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
import { correctGraph, type GraphCorrectionOperation } from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';

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
  const { rendererRef, mount, refresh, zoomToFit, zoomIn, zoomOut, zoomToNodes, selectAndCenter } =
    useSigma({ graph, nodeReducer, edgeReducer, onCameraUpdate });

  // ---- Layout ----
  const layout = useLayout(graph, rendererRef);

  // ---- UI state ----
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [layoutRunning, setLayoutRunning] = useState(false);
  const [communityHullsActive, setCommunityHullsActive] = useState(true);
  useCommunityHulls(rendererRef, graph, communityHullsActive);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);

  // ---- Edit mode ----
  const [editMode, setEditMode] = useState(false);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const undoStackRef = useRef<Array<{ reason: string; reverse: GraphCorrectionOperation[] }>>([]);
  const toast = useToastStore((s) => s.addToast);

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
      onNodeSelect: setSelectedNodeId,
      onNodeFocus: (nodeId, hops) => {
        // Zoom to the focus neighborhood
        const neighborhood = getNeighborhood(graph, nodeId, hops);
        zoomToNodes(neighborhood, { paddingFactor: 1.9, minRatio: 0.08, maxRatio: 1.6 });
      },
    });

  // ---- Sync graph data from store ----
  const storeGraph = useEngagementStore(s => s.graph);
  const graphVersion = useEngagementStore(s => s.graphVersion);
  const lastDelta = useEngagementStore(s => s.lastDelta);
  const loadedVersionRef = useRef(0);

  useEffect(() => {
    if (graphVersion === loadedVersionRef.current) return;
    loadedVersionRef.current = graphVersion;

    if (lastDelta && graph.order > 0) {
      // Incremental delta merge
      mergeGraphDelta(lastDelta);
      setNodeCount(graph.order);
      setEdgeCount(graph.size);
      // Brief layout burst for new nodes
      if ((lastDelta.nodes?.length || 0) > 0) {
        layout.start();
        setLayoutRunning(true);
        setTimeout(() => { layout.stop(); setLayoutRunning(false); }, 1500);
      }
      refresh();
    } else if (storeGraph && storeGraph.nodes && storeGraph.nodes.length > 0) {
      // Full reload
      loadGraphData(storeGraph);
      setNodeCount(graph.order);
      setEdgeCount(graph.size);
      setTimeout(() => {
        layout.start();
        setLayoutRunning(true);
      }, 50);
    }
  }, [graphVersion, lastDelta, storeGraph, loadGraphData, mergeGraphDelta, graph, layout, refresh]);

  // Track layout running state; detect running→stopped transitions so the
  // zoom-to-node effect can wait until FA2 has positioned nodes.
  const [layoutCompletedCount, setLayoutCompletedCount] = useState(0);
  const prevLayoutRunningRef = useRef(false);
  useEffect(() => {
    const interval = setInterval(() => {
      const running = layout.running;
      setLayoutRunning(running);
      setNodeCount(graph.order);
      setEdgeCount(graph.size);
      // Detect running→stopped transition
      if (prevLayoutRunningRef.current && !running) {
        setLayoutCompletedCount(c => c + 1);
      }
      prevLayoutRunningRef.current = running;
    }, 200);
    return () => clearInterval(interval);
  }, [layout, graph]);

  // ---- Query param navigation (from frontier/overview/agents) ----
  const [searchParams, setSearchParams] = useSearchParams();
  const appliedParamsRef = useRef(false);

  useEffect(() => {
    if (appliedParamsRef.current || graph.order === 0) return;
    const nodeParam = searchParams.get('node');
    const filterParam = searchParams.get('filter');
    const hopsParam = parseInt(searchParams.get('hops') || '0', 10);

    if (nodeParam && graph.hasNode(nodeParam)) {
      // Wait until FA2 has run at least once so node positions are non-zero.
      if (layoutCompletedCount === 0) return;
      appliedParamsRef.current = true;
      if (hopsParam > 0) {
        enterNeighborhoodFocus(nodeParam, hopsParam);
      } else {
        selectNode(nodeParam);
        selectAndCenter(nodeParam);
      }
      setSearchParams({}, { replace: true });
    } else if (filterParam) {
      appliedParamsRef.current = true;
      const s = stateRef.current;
      s.activeFilters = new Set([filterParam]);
      s.graphMode = 'focused';
      s.emphasizedNodeTypes = new Set([filterParam]);
      refresh();
      setSearchParams({}, { replace: true });
    }
  }, [graph, searchParams, setSearchParams, stateRef, refresh, selectNode, selectAndCenter, enterNeighborhoodFocus, layoutCompletedCount]);

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
    zoomToFit();
  }, [stateRef, clearSelection, clearPathHighlight, exitNeighborhoodFocus, zoomToFit]);

  const handleSetGraphMode = useCallback((mode: string) => {
    stateRef.current.graphMode = mode as 'overview' | 'focused' | 'raw';
    refresh();
  }, [stateRef, refresh]);

  const handleSetLabelDensity = useCallback((density: string) => {
    stateRef.current.labelDensity = density as 'minimal' | 'balanced' | 'verbose';
    refresh();
  }, [stateRef, refresh]);

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
        if (preset.edgeHighlight.has(attrs.type as string)) {
          neighborhood.add(src);
          neighborhood.add(tgt);
        }
      });
    }
    s.selectedNeighborhood = neighborhood;
    refresh();
    zoomToNodes(neighborhood, { paddingFactor: 1.6 });
  }, [graph, stateRef, clearPathHighlight, refresh, zoomToNodes, handleReset]);

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
    } else {
      // Placeholder — real implementation would fetch from API
      s.attackPathOverlay = { actual: { nodes: new Set(), edges: new Set() }, theoretical: null };
    }
    refresh();
  }, [stateRef, refresh]);

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
      const credTypes = new Set(['DERIVED_FROM', 'DUMPED_FROM', 'OWNS_CRED', 'SHARED_CREDENTIAL', 'VALID_ON', 'TESTED_CRED']);
      graph.forEachEdge((_edge, attrs, src, tgt) => {
        if (credTypes.has(attrs.edgeType as string)) {
          flowEdges.add(_edge);
          flowNodes.add(src);
          flowNodes.add(tgt);
        }
      });
      s.credFlowData = { flowEdges, flowNodes };
    }
    refresh();
  }, [graph, stateRef, refresh]);

  const handleSearchSelect = useCallback((nodeId: string) => {
    selectNode(nodeId);
    selectAndCenter(nodeId);
  }, [selectNode, selectAndCenter]);

  // ---- Keyboard shortcuts ----
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      switch (e.key) {
        case 'f': case 'F': e.preventDefault(); zoomToFit(); break;
        case ' ': e.preventDefault(); layout.toggle(); break;
        case 'Escape':
          e.preventDefault();
          setShowShortcuts(false);
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
  }, [zoomToFit, zoomIn, zoomOut, layout, clearSelection, clearPathHighlight, handleReset]);

  const s = stateRef.current;

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
        graphMode={s.graphMode}
        labelDensity={s.labelDensity}
        activeFocusPreset={s.activeFocusPreset}
        attackPathActive={!!s.attackPathOverlay}
        credFlowActive={s.credentialFlowMode}
        communityHullsActive={communityHullsActive}
        hideOrphans={s.hideOrphans}
        hideReachableOnly={s.hideReachableOnly}
        onZoomIn={zoomIn}
        onZoomOut={zoomOut}
        onFit={zoomToFit}
        onToggleLayout={() => { layout.toggle(); setLayoutRunning(layout.running); }}
        onReset={handleReset}
        onExportPNG={() => exportScreenshot(rendererRef.current)}
        onExportSVG={() => exportSVG(rendererRef.current, graph)}
        onSetGraphMode={handleSetGraphMode}
        onSetLabelDensity={handleSetLabelDensity}
        onSetFocusPreset={handleSetFocusPreset}
        onToggleAttackPath={handleToggleAttackPath}
        onToggleCredFlow={handleToggleCredFlow}
        onToggleCommunityHulls={() => setCommunityHullsActive(v => !v)}
        onToggleHideOrphans={() => { s.hideOrphans = !s.hideOrphans; refresh(); }}
        onToggleHideReachableOnly={() => { s.hideReachableOnly = !s.hideReachableOnly; refresh(); }}
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

        {/* Overlays */}
        <GraphSearch graph={graph} onSelect={handleSearchSelect} />

        <NodeFilters
          graph={graph}
          activeFilters={s.activeFilters}
          onToggle={handleToggleFilter}
        />

        <PathInfoBar
          graph={graph}
          pathSource={s.pathSource}
          pathTarget={s.pathTarget}
          pathEdges={s.pathEdges}
          onClear={clearPathHighlight}
        />

        <FocusBanner
          focusNode={s.focusNode}
          focusSize={s.focusNeighborhood?.size || 0}
          onExit={exitNeighborhoodFocus}
        />

        <Minimap graph={graph} rendererRef={rendererRef} />

        <EdgeLegend />

        {/* Keyboard shortcuts overlay */}
        {showShortcuts && (
          <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setShowShortcuts(false)}>
            <div className="bg-surface border border-border rounded-lg p-5 max-w-xs" onClick={e => e.stopPropagation()}>
              <h3 className="text-sm font-semibold mb-3">Keyboard Shortcuts</h3>
              <div className="space-y-1.5 text-xs">
                {[
                  ['F', 'Fit to screen'],
                  ['Space', 'Toggle layout'],
                  ['Esc', 'Clear selection'],
                  ['R', 'Reset filters'],
                  ['+ / −', 'Zoom'],
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
