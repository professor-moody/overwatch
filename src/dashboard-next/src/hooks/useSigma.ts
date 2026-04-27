// ============================================================
// useSigma — Sigma renderer lifecycle + camera controls
// ============================================================

import { useRef, useCallback, useEffect } from 'react';
import Sigma from 'sigma';
import type Graph from 'graphology';

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

  const zoomToFit = useCallback((duration = 300) => {
    const renderer = rendererRef.current;
    if (!renderer) return;
    renderer.getCamera().animatedReset({ duration });
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

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const nodeId of ids) {
      if (!graph.hasNode(nodeId)) continue;
      const attrs = graph.getNodeAttributes(nodeId);
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (typeof x !== 'number' || typeof y !== 'number') continue;
      minX = Math.min(minX, x);
      maxX = Math.max(maxX, x);
      minY = Math.min(minY, y);
      maxY = Math.max(maxY, y);
    }

    if (!isFinite(minX)) return;

    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    const paddingFactor = opts.paddingFactor ?? 1.6;
    const rangeX = (maxX - minX) * paddingFactor || 1;
    const rangeY = (maxY - minY) * paddingFactor || 1;
    const ratio = Math.max(rangeX, rangeY) / Math.min(renderer.getContainer().clientWidth, renderer.getContainer().clientHeight) * 200;

    const clamped = Math.max(opts.minRatio ?? 0.02, Math.min(opts.maxRatio ?? 10, ratio));

    const camera = renderer.getCamera();
    const viewportCenter = renderer.viewportToFramedGraph({
      x: renderer.getContainer().clientWidth / 2,
      y: renderer.getContainer().clientHeight / 2,
    });

    // Use sigma's animated camera
    camera.animate(
      { x: cx - (viewportCenter.x - cx) * 0.001, y: cy - (viewportCenter.y - cy) * 0.001, ratio: clamped },
      { duration: opts.duration ?? 300 },
    );
  }, [graph]);

  const selectAndCenter = useCallback((nodeId: string) => {
    if (!graph.hasNode(nodeId)) return;
    const attrs = graph.getNodeAttributes(nodeId);
    const renderer = rendererRef.current;
    if (!renderer) return;

    const camera = renderer.getCamera();
    camera.animate(
      { x: attrs.x as number, y: attrs.y as number, ratio: 0.15 },
      { duration: 300 },
    );
  }, [graph]);

  return { rendererRef, mount, unmount, refresh, zoomToFit, zoomIn, zoomOut, zoomToNodes, selectAndCenter };
}
