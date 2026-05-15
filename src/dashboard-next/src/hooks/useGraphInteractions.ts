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
  const onNodeSelectRef = useRef(onNodeSelect);
  const onNodeFocusRef = useRef(onNodeFocus);
  const onUserLayoutChangeRef = useRef(onUserLayoutChange);
  const onNodePositionCommitRef = useRef(onNodePositionCommit);

  useEffect(() => {
    onNodeSelectRef.current = onNodeSelect;
  }, [onNodeSelect]);

  useEffect(() => {
    onNodeFocusRef.current = onNodeFocus;
  }, [onNodeFocus]);

  useEffect(() => {
    onUserLayoutChangeRef.current = onUserLayoutChange;
  }, [onUserLayoutChange]);

  useEffect(() => {
    onNodePositionCommitRef.current = onNodePositionCommit;
  }, [onNodePositionCommit]);

  const getOriginalMouseEvent = (event: {
    original?: MouseEvent | PointerEvent;
    event?: { original?: MouseEvent | PointerEvent };
  }): MouseEvent | PointerEvent | null => event.original || event.event?.original || null;

  // ---- Interaction Methods ----

  const selectNode = useCallback((node: string | null) => {
    const s = stateRef.current;
    s.selectedNode = node;
    s.inspectedEdgeIds.clear();
    if (!node || !graph.hasNode(node)) {
      s.selectedNeighborhood = null;
      refresh();
      onNodeSelectRef.current?.(null);
      return;
    }
    s.selectedNeighborhood = getNeighborhood(graph, node, 1);
    graph.edges(node).forEach(eid => s.inspectedEdgeIds.add(eid));
    refresh();
    onNodeSelectRef.current?.(node);
  }, [graph, stateRef, refresh]);

  const clearSelection = useCallback(() => {
    const s = stateRef.current;
    s.selectedNode = null;
    s.selectedNeighborhood = null;
    s.inspectedEdgeIds.clear();
    refresh();
    onNodeSelectRef.current?.(null);
  }, [stateRef, refresh]);

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
    onNodeFocusRef.current?.(node, hops);
  }, [graph, stateRef, selectNode]);

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
    let lastDragPosition: { x: number; y: number } | null = null;

    // ---- Drag ----
    const onDownNode = (e: { node: string; event: { original: MouseEvent }; preventSigmaDefault?: () => void }) => {
      e.preventSigmaDefault?.();
      e.event.original.preventDefault();
      e.event.original.stopPropagation();
      onUserLayoutChangeRef.current?.();
      isDragging = true;
      hasMoved = false;
      lastDragPosition = null;
      draggedNode = e.node;
      dragStartX = e.event.original.clientX;
      dragStartY = e.event.original.clientY;
      graph.setNodeAttribute(draggedNode, 'fixed', true);
      renderer.getCamera().disable();
      container.classList.add('node-grabbed');
      container.classList.add('dragging');
      window.addEventListener('mousemove', onWindowMouseMove, true);
      window.addEventListener('pointermove', onWindowPointerMove, true);
      window.addEventListener('mouseup', endDrag, { capture: true, once: true });
      window.addEventListener('pointerup', endDrag, { capture: true, once: true });
      window.addEventListener('blur', endDrag, { once: true });
      renderer.refresh();
    };

    const onMouseMove = (e: {
      x?: number;
      y?: number;
      original?: MouseEvent | PointerEvent;
      event?: { x?: number; y?: number; original?: MouseEvent | PointerEvent };
      preventSigmaDefault?: () => void;
    }) => {
      if (!isDragging || !draggedNode) return;
      e.preventSigmaDefault?.();
      const original = getOriginalMouseEvent(e);
      original?.preventDefault();
      original?.stopPropagation();
      const coords = typeof e.x === 'number' && typeof e.y === 'number' ? e : e.event;
      if (!coords || typeof coords.x !== 'number' || typeof coords.y !== 'number') return;
      const pos = renderer.viewportToGraph({ x: coords.x, y: coords.y });
      graph.mergeNodeAttributes(draggedNode, { x: pos.x, y: pos.y, fixed: true });
      lastDragPosition = pos;
      hasMoved = hasMoved || !original || exceededDragThreshold(dragStartX, dragStartY, original.clientX, original.clientY);
      s.hoveredNode = null;
      s.hoveredNeighbors = null;
      renderer.refresh();
    };

    const onWindowMouseMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      onMouseMove({
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        original: event,
      });
    };

    const onWindowPointerMove = (event: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      onMouseMove({
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        original: event,
      });
    };

    const endDrag = () => {
      if (isDragging && draggedNode && hasMoved) {
        suppressNextClickRef.current = true;
        const attrs = graph.getNodeAttributes(draggedNode);
        const x = lastDragPosition?.x ?? (attrs.x as number);
        const y = lastDragPosition?.y ?? (attrs.y as number);
        if (Number.isFinite(x) && Number.isFinite(y)) {
          onNodePositionCommitRef.current?.(draggedNode, { x, y });
        }
      }
      isDragging = false;
      draggedNode = null;
      hasMoved = false;
      lastDragPosition = null;
      container.classList.remove('node-grabbed');
      container.classList.remove('dragging');
      renderer.getCamera().enable();
      window.removeEventListener('mousemove', onWindowMouseMove, true);
      window.removeEventListener('pointermove', onWindowPointerMove, true);
      window.removeEventListener('mouseup', endDrag, true);
      window.removeEventListener('pointerup', endDrag, true);
      window.removeEventListener('blur', endDrag);
      renderer.refresh();
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
    renderer.on('moveBody', onMouseMove as never);
    renderer.on('upNode', endDrag as never);
    renderer.on('upStage', endDrag as never);
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
      renderer.off('moveBody', onMouseMove as never);
      renderer.off('upNode', endDrag as never);
      renderer.off('upStage', endDrag as never);
      renderer.getMouseCaptor().off('mousemovebody', onMouseMove as never);
      renderer.getMouseCaptor().off('mouseup', endDrag);
      renderer.getMouseCaptor().off('mouseleave', endDrag);
      window.removeEventListener('mousemove', onWindowMouseMove, true);
      window.removeEventListener('pointermove', onWindowPointerMove, true);
      window.removeEventListener('mouseup', endDrag, true);
      window.removeEventListener('pointerup', endDrag, true);
      window.removeEventListener('blur', endDrag);
      renderer.off('enterNode', onEnterNode as never);
      renderer.off('leaveNode', onLeaveNode as never);
      renderer.off('enterEdge', onEnterEdge as never);
      renderer.off('leaveEdge', onLeaveEdge as never);
      renderer.off('clickNode', onClickNode as never);
      renderer.off('doubleClickNode', onDoubleClickNode as never);
      renderer.off('clickStage', onClickStage as never);
      renderer.off('doubleClickStage', onDoubleClickStage as never);
    };
  }, [graph, rendererRef, stateRef, selectNode, clearSelection, handlePathClick, enterNeighborhoodFocus]);

  return {
    selectNode,
    clearSelection,
    clearPathHighlight,
    enterNeighborhoodFocus,
    exitNeighborhoodFocus,
  };
}
