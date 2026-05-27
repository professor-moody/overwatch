// ============================================================
// useSigma — Sigma renderer lifecycle + camera controls
// ============================================================

import { useRef, useCallback, useEffect } from 'react';
import Sigma from 'sigma';
import type Graph from 'graphology';
import { computeGraphCameraFit, safeCameraDuration, type GraphFitPadding } from '../lib/graph-camera';

export interface UseSigmaOptions {
  graph: Graph;
  nodeReducer: (node: string, data: Record<string, unknown>) => Record<string, unknown>;
  edgeReducer: (edge: string, data: Record<string, unknown>) => Record<string, unknown>;
  onCameraUpdate?: (ratio: number) => void;
}

export interface UseSigmaReturn {
  rendererRef: React.MutableRefObject<Sigma | null>;
  mount: (container: HTMLElement) => void;
  unmount: () => void;
  refresh: () => void;
  zoomToFit: (duration?: number) => void;
  zoomIn: () => void;
  zoomOut: () => void;
  zoomToNodes: (nodeIds: Set<string> | string[], opts?: ZoomToNodesOptions) => void;
  selectAndCenter: (nodeId: string) => void;
}

interface ZoomToNodesOptions {
  paddingFactor?: number;
  padding?: GraphFitPadding;
  minRatio?: number;
  maxRatio?: number;
  duration?: number;
}

export function useSigma({ graph, nodeReducer, edgeReducer, onCameraUpdate }: UseSigmaOptions): UseSigmaReturn {
  const rendererRef = useRef<Sigma | null>(null);

  const mount = useCallback((container: HTMLElement) => {
    if (rendererRef.current) return;

    const renderer = new Sigma(graph, container, {
      renderLabels: true,
      labelFont: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      labelSize: 11,
      labelColor: { color: '#9b99a3' },
      labelDensity: 0.4,
      labelGridCellSize: 120,
      labelRenderedSizeThreshold: 5,
      renderEdgeLabels: true,
      edgeLabelFont: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      edgeLabelSize: 9,
      edgeLabelColor: { color: '#7a7886' },
      defaultEdgeColor: 'rgba(110,158,255,0.25)',
      defaultEdgeType: 'arrow',
      nodeReducer: nodeReducer as never,
      edgeReducer: edgeReducer as never,
      zIndex: true,
      minCameraRatio: 0.02,
      maxCameraRatio: 10,
      stagePadding: 30,
    });

    rendererRef.current = renderer;

    // Camera updates
    const camera = renderer.getCamera();
    camera.on('updated', () => {
      onCameraUpdate?.(camera.getState().ratio);
    });
  }, [graph, nodeReducer, edgeReducer, onCameraUpdate]);

  const unmount = useCallback(() => {
    if (rendererRef.current) {
      rendererRef.current.kill();
      rendererRef.current = null;
    }
  }, []);

  // Cleanup on component unmount
  useEffect(() => {
    return () => { unmount(); };
  }, [unmount]);

  const refresh = useCallback(() => {
    rendererRef.current?.refresh();
  }, []);

  const zoomToFit = useCallback((duration: number | unknown = 300) => {
    const renderer = rendererRef.current;
    if (!renderer) return;
    renderer.getCamera().animatedReset({ duration: safeCameraDuration(duration) });
  }, []);

  const zoomIn = useCallback(() => {
    const renderer = rendererRef.current;
    if (!renderer) return;
    const camera = renderer.getCamera();
    const state = camera.getState();
    camera.animate({ ratio: state.ratio / 1.5 }, { duration: 200 });
  }, []);

  const zoomOut = useCallback(() => {
    const renderer = rendererRef.current;
    if (!renderer) return;
    const camera = renderer.getCamera();
    const state = camera.getState();
    camera.animate({ ratio: state.ratio * 1.5 }, { duration: 200 });
  }, []);

  const zoomToNodes = useCallback((
    nodeIds: Set<string> | string[],
    opts: ZoomToNodesOptions = {},
  ) => {
    const renderer = rendererRef.current;
    if (!renderer) return;

    const ids = nodeIds instanceof Set ? nodeIds : new Set(nodeIds);
    if (ids.size === 0) return;

    const positions: Array<{ x: number; y: number }> = [];
    for (const nodeId of ids) {
      if (!graph.hasNode(nodeId)) continue;
      const display = renderer.getNodeDisplayData(nodeId);
      const attrs = display || graph.getNodeAttributes(nodeId);
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (typeof x !== 'number' || typeof y !== 'number') continue;
      positions.push({ x, y });
    }

    const container = renderer.getContainer();
    const fit = computeGraphCameraFit(positions, {
      width: container.clientWidth,
      height: container.clientHeight,
    }, opts);
    if (!fit) return;

    const camera = renderer.getCamera();
    camera.animate(
      fit,
      { duration: safeCameraDuration(opts.duration) },
    );
  }, [graph]);

  const selectAndCenter = useCallback((nodeId: string) => {
    if (!graph.hasNode(nodeId)) return;
    const renderer = rendererRef.current;
    if (!renderer) return;
    const display = renderer.getNodeDisplayData(nodeId);
    const attrs = display || graph.getNodeAttributes(nodeId);

    const camera = renderer.getCamera();
    camera.animate(
      { x: attrs.x as number, y: attrs.y as number, ratio: 0.15 },
      { duration: 300 },
    );
  }, [graph]);

  return { rendererRef, mount, unmount, refresh, zoomToFit, zoomIn, zoomOut, zoomToNodes, selectAndCenter };
}
