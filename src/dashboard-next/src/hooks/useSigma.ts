// ============================================================
// useSigma — Sigma renderer lifecycle + camera controls
// ============================================================

import { useRef, useCallback, useEffect } from 'react';
import Sigma from 'sigma';
import type Graph from 'graphology';
import { safeCameraDuration, type GraphFitPadding } from '../lib/graph-camera';

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
  zoomToFit: (duration?: number | unknown, opts?: ZoomToNodesOptions) => void;
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

interface SigmaNormalizationInternals {
  normalizationFunction?: (point: { x: number; y: number }) => { x: number; y: number };
}

const DEFAULT_FIT_PADDING = 48;

function normalizeFitPadding(padding: GraphFitPadding = {}): Required<GraphFitPadding> {
  return {
    top: padding.top ?? DEFAULT_FIT_PADDING,
    right: padding.right ?? DEFAULT_FIT_PADDING,
    bottom: padding.bottom ?? DEFAULT_FIT_PADDING,
    left: padding.left ?? DEFAULT_FIT_PADDING,
  };
}

function computeSigmaCameraFit(
  renderer: Sigma,
  positions: Array<{ x: number; y: number }>,
  opts: ZoomToNodesOptions = {},
) {
  const valid = positions.filter(position =>
    Number.isFinite(position.x) && Number.isFinite(position.y),
  );
  if (valid.length === 0) return null;

  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const position of valid) {
    minX = Math.min(minX, position.x);
    maxX = Math.max(maxX, position.x);
    minY = Math.min(minY, position.y);
    maxY = Math.max(maxY, position.y);
  }

  const container = renderer.getContainer();
  const width = container.clientWidth;
  const height = container.clientHeight;
  if (width <= 0 || height <= 0) return null;

  const padding = normalizeFitPadding(opts.padding);
  const availableWidth = Math.max(160, width - padding.left - padding.right);
  const availableHeight = Math.max(160, height - padding.top - padding.bottom);
  const desiredViewportCenter = {
    x: padding.left + availableWidth / 2,
    y: padding.top + availableHeight / 2,
  };
  const viewportCenter = { x: width / 2, y: height / 2 };
  const rawCenter = {
    x: (minX + maxX) / 2,
    y: (minY + maxY) / 2,
  };
  const paddingFactor = opts.paddingFactor ?? 1.45;
  const fitPositions = valid.map(position => ({
    x: rawCenter.x + (position.x - rawCenter.x) * paddingFactor,
    y: rawCenter.y + (position.y - rawCenter.y) * paddingFactor,
  }));

  const normalize = (renderer as unknown as SigmaNormalizationInternals).normalizationFunction;
  const framedCenter = typeof normalize === 'function' ? normalize(rawCenter) : rawCenter;
  const camera = renderer.getCamera();
  const currentState = camera.getState();
  const minRatio = opts.minRatio ?? 0.035;
  const maxRatio = opts.maxRatio ?? 2.4;

  const cameraStateForRatio = (ratio: number) => {
    const centeredState = {
      ...currentState,
      x: framedCenter.x,
      y: framedCenter.y,
      ratio,
    };

    const centerFrame = renderer.viewportToFramedGraph(viewportCenter, { cameraState: centeredState });
    const desiredFrame = renderer.viewportToFramedGraph(desiredViewportCenter, { cameraState: centeredState });
    return {
      ...centeredState,
      x: framedCenter.x - (desiredFrame.x - centerFrame.x),
      y: framedCenter.y - (desiredFrame.y - centerFrame.y),
    };
  };

  const measure = (ratio: number) => {
    const cameraState = cameraStateForRatio(ratio);
    let viewportMinX = Infinity;
    let viewportMaxX = -Infinity;
    let viewportMinY = Infinity;
    let viewportMaxY = -Infinity;

    for (const position of fitPositions) {
      const viewport = renderer.graphToViewport(position, { cameraState });
      viewportMinX = Math.min(viewportMinX, viewport.x);
      viewportMaxX = Math.max(viewportMaxX, viewport.x);
      viewportMinY = Math.min(viewportMinY, viewport.y);
      viewportMaxY = Math.max(viewportMaxY, viewport.y);
    }

    return {
      cameraState,
      fits: viewportMaxX - viewportMinX <= availableWidth && viewportMaxY - viewportMinY <= availableHeight,
    };
  };

  let best = measure(maxRatio);
  const minMeasure = measure(minRatio);
  if (minMeasure.fits) return minMeasure.cameraState;

  let low = minRatio;
  let high = maxRatio;
  for (let i = 0; i < 24; i++) {
    const mid = (low + high) / 2;
    const candidate = measure(mid);
    if (candidate.fits) {
      best = candidate;
      high = mid;
    } else {
      low = mid;
    }
  }

  return best.cameraState;
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
      maxCameraRatio: 500,
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

  const zoomToFit = useCallback((duration: number | unknown = 300, opts: ZoomToNodesOptions = {}) => {
    const renderer = rendererRef.current;
    if (!renderer) return;

    const positions: Array<{ x: number; y: number }> = [];
    graph.forEachNode((nodeId, attrs) => {
      const reduced = nodeReducer(nodeId, attrs as Record<string, unknown>);
      if (reduced.hidden) return;
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (typeof x === 'number' && typeof y === 'number') positions.push({ x, y });
    });

    if (positions.length === 0) {
      renderer.getCamera().animatedReset({ duration: safeCameraDuration(duration) });
      return;
    }

    const fit = computeSigmaCameraFit(renderer, positions, opts);
    if (!fit) return;

    const camera = renderer.getCamera();
    camera.animate(
      fit,
      { duration: safeCameraDuration(duration) },
    );
  }, [graph, nodeReducer]);

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
      const attrs = graph.getNodeAttributes(nodeId);
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (typeof x !== 'number' || typeof y !== 'number') continue;
      positions.push({ x, y });
    }

    const fit = computeSigmaCameraFit(renderer, positions, opts);
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
    const attrs = graph.getNodeAttributes(nodeId);

    const fit = computeSigmaCameraFit(
      renderer,
      [{ x: attrs.x as number, y: attrs.y as number }],
      { minRatio: 0.15, maxRatio: 0.15 },
    );
    if (!fit) return;

    renderer.getCamera().animate(fit, { duration: 300 });
  }, [graph]);

  return { rendererRef, mount, unmount, refresh, zoomToFit, zoomIn, zoomOut, zoomToNodes, selectAndCenter };
}
