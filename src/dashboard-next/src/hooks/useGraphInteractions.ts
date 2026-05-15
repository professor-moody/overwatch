// ============================================================
// useGraphInteractions — drag, hover, click, shift-click path
// ============================================================

import { useCallback, useEffect, useRef } from 'react';
import type Sigma from 'sigma';
import type Graph from 'graphology';
import type { GraphInteractionState } from './useGraphReducers';
import { getNeighborhood, findShortestPath, exceededDragThreshold } from '../lib/graph-utils';

export interface UseGraphInteractionsOptions {
  graph: Graph;
  rendererRef: React.MutableRefObject<Sigma | null>;
  stateRef: React.MutableRefObject<GraphInteractionState>;
  refresh: () => void;
  onNodeSelect?: (nodeId: string | null) => void;
  onNodeFocus?: (nodeId: string, hops: number) => void;
  onUserLayoutChange?: () => void;
  onNodePositionCommit?: (nodeId: string, position: { x: number; y: number }) => void;
}

export function useGraphInteractions({
  graph,
  rendererRef,
  stateRef,
  refresh,
  onNodeSelect,
  onNodeFocus,
  onUserLayoutChange,
  onNodePositionCommit,
}: UseGraphInteractionsOptions) {
  const suppressNextClickRef = useRef(false);

  // ---- Interaction Methods ----

  const selectNode = useCallback((node: string | null) => {
    const s = stateRef.current;
    s.selectedNode = node;
    s.inspectedEdgeIds.clear();
    if (!node || !graph.hasNode(node)) {
      s.selectedNeighborhood = null;
      refresh();
      onNodeSelect?.(null);
      return;
    }
    s.selectedNeighborhood = getNeighborhood(graph, node, 1);
    graph.edges(node).forEach(eid => s.inspectedEdgeIds.add(eid));
    refresh();
    onNodeSelect?.(node);
  }, [graph, stateRef, refresh, onNodeSelect]);

  const clearSelection = useCallback(() => {
    const s = stateRef.current;
    s.selectedNode = null;
    s.selectedNeighborhood = null;
    s.inspectedEdgeIds.clear();
    refresh();
    onNodeSelect?.(null);
  }, [stateRef, refresh, onNodeSelect]);

  const clearPathHighlight = useCallback(() => {
    const s = stateRef.current;
    s.pathSource = null;
    s.pathTarget = null;
    s.pathNodes.clear();
    s.pathEdges.clear();
    refresh();
  }, [stateRef, refresh]);

  const handlePathClick = useCallback((node: string) => {
    const s = stateRef.current;
    if (!s.pathSource) {
      s.pathSource = node;
      s.pathTarget = null;
      s.pathEdges.clear();
      s.pathNodes.clear();
      s.pathNodes.add(node);
      refresh();
      return;
    }
    if (s.pathSource === node) {
      clearPathHighlight();
      return;
    }
    s.pathTarget = node;
    const result = findShortestPath(graph, s.pathSource, node);
    s.pathNodes = result.nodes;
    s.pathEdges = result.edges;
    refresh();
  }, [graph, stateRef, refresh, clearPathHighlight]);

  const enterNeighborhoodFocus = useCallback((node: string, hops = 2) => {
    const s = stateRef.current;
    s.focusNode = node;
    s.focusNeighborhood = getNeighborhood(graph, node, hops);
    selectNode(node);
    onNodeFocus?.(node, hops);
  }, [graph, stateRef, selectNode, onNodeFocus]);

  const exitNeighborhoodFocus = useCallback(() => {
    const s = stateRef.current;
    s.focusNode = null;
    s.focusNeighborhood = null;
    refresh();
  }, [stateRef, refresh]);

  // ---- Wire up sigma events ----

  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer) return;

    const s = stateRef.current;
    const container = renderer.getContainer();
    let draggedNode: string | null = null;
    let isDragging = false;
    let hasMoved = false;
    let dragStartX = 0;
    let dragStartY = 0;

    // ---- Drag ----
    const onDownNode = (e: { node: string; event: { original: MouseEvent } }) => {
      onUserLayoutChange?.();
      isDragging = true;
      hasMoved = false;
      draggedNode = e.node;
      dragStartX = e.event.original.clientX;
      dragStartY = e.event.original.clientY;
      graph.setNodeAttribute(draggedNode, 'fixed', true);
      renderer.getCamera().disable();
      container.classList.add('node-grabbed');
      container.classList.add('dragging');
    };

    const onMouseMove = (e: { x: number; y: number; original: MouseEvent }) => {
      if (!isDragging || !draggedNode) return;
      const pos = renderer.viewportToGraph(e);
      graph.setNodeAttribute(draggedNode, 'x', pos.x);
      graph.setNodeAttribute(draggedNode, 'y', pos.y);
      hasMoved = hasMoved || exceededDragThreshold(dragStartX, dragStartY, e.original.clientX, e.original.clientY);
      s.hoveredNode = null;
      s.hoveredNeighbors = null;
    };

    const endDrag = () => {
      if (isDragging && draggedNode && hasMoved) {
        suppressNextClickRef.current = true;
        const attrs = graph.getNodeAttributes(draggedNode);
        const x = attrs.x as number;
        const y = attrs.y as number;
        if (Number.isFinite(x) && Number.isFinite(y)) {
          onNodePositionCommit?.(draggedNode, { x, y });
        }
      }
      isDragging = false;
      draggedNode = null;
      hasMoved = false;
      container.classList.remove('node-grabbed');
      container.classList.remove('dragging');
      renderer.getCamera().enable();
    };

    // ---- Hover ----
    const onEnterNode = ({ node }: { node: string }) => {
      s.hoveredNode = node;
      s.hoveredNeighbors = new Set(graph.neighbors(node));
      container.classList.add('node-grabbable');
      renderer.refresh();
    };

    const onLeaveNode = () => {
      s.hoveredNode = null;
      s.hoveredNeighbors = null;
      container.classList.remove('node-grabbable');
      renderer.refresh();
    };

    const onEnterEdge = ({ edge }: { edge: string }) => {
      s.hoveredEdge = edge;
      renderer.refresh();
    };

    const onLeaveEdge = () => {
      s.hoveredEdge = null;
      renderer.refresh();
    };

    // ---- Click ----
    const onClickNode = ({ node, event }: { node: string; event: { original: MouseEvent } }) => {
      if (suppressNextClickRef.current) {
        suppressNextClickRef.current = false;
        return;
      }
      if (event.original.shiftKey) {
        handlePathClick(node);
        return;
      }
      if (node === s.selectedNode) {
        selectNode(node);
        return;
      }
      selectNode(node);
    };

    const onDoubleClickNode = ({ node }: { node: string }) => {
      enterNeighborhoodFocus(node, 2);
    };

    const onClickStage = () => {
      clearSelection();
    };

    const onDoubleClickStage = (e: { preventSigmaDefault: () => void }) => {
      e.preventSigmaDefault();
    };

    // Wire events
    renderer.on('downNode', onDownNode as never);
    renderer.getMouseCaptor().on('mousemovebody', onMouseMove as never);
    renderer.getMouseCaptor().on('mouseup', endDrag);
    renderer.getMouseCaptor().on('mouseleave', endDrag);
    renderer.on('enterNode', onEnterNode as never);
    renderer.on('leaveNode', onLeaveNode as never);
    renderer.on('enterEdge', onEnterEdge as never);
    renderer.on('leaveEdge', onLeaveEdge as never);
    renderer.on('clickNode', onClickNode as never);
    renderer.on('doubleClickNode', onDoubleClickNode as never);
    renderer.on('clickStage', onClickStage as never);
    renderer.on('doubleClickStage', onDoubleClickStage as never);

    return () => {
      renderer.off('downNode', onDownNode as never);
      renderer.getMouseCaptor().off('mousemovebody', onMouseMove as never);
      renderer.getMouseCaptor().off('mouseup', endDrag);
      renderer.getMouseCaptor().off('mouseleave', endDrag);
      renderer.off('enterNode', onEnterNode as never);
      renderer.off('leaveNode', onLeaveNode as never);
      renderer.off('enterEdge', onEnterEdge as never);
      renderer.off('leaveEdge', onLeaveEdge as never);
      renderer.off('clickNode', onClickNode as never);
      renderer.off('doubleClickNode', onDoubleClickNode as never);
      renderer.off('clickStage', onClickStage as never);
      renderer.off('doubleClickStage', onDoubleClickStage as never);
    };
  }, [graph, rendererRef, stateRef, selectNode, clearSelection, handlePathClick, enterNeighborhoodFocus, onUserLayoutChange, onNodePositionCommit]);

  return {
    selectNode,
    clearSelection,
    clearPathHighlight,
    enterNeighborhoodFocus,
    exitNeighborhoodFocus,
  };
}
