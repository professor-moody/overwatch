export function safeCameraDuration(value: unknown, fallback = 300): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

export interface GraphFitPosition {
  x: number;
  y: number;
}

export interface GraphFitViewport {
  width: number;
  height: number;
}

export interface GraphFitPadding {
  top?: number;
  right?: number;
  bottom?: number;
  left?: number;
}

export interface GraphFitOptions {
  paddingFactor?: number;
  padding?: GraphFitPadding;
  minRatio?: number;
  maxRatio?: number;
}

export interface GraphCameraFit {
  x: number;
  y: number;
  ratio: number;
}

const DEFAULT_PADDING = 48;

export function computeGraphCameraFit(
  positions: GraphFitPosition[],
  viewport: GraphFitViewport,
  opts: GraphFitOptions = {},
): GraphCameraFit | null {
  const valid = positions.filter(position =>
    Number.isFinite(position.x) && Number.isFinite(position.y),
  );
  if (valid.length === 0 || viewport.width <= 0 || viewport.height <= 0) return null;

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

  const padding = normalizePadding(opts.padding);
  const availableWidth = Math.max(160, viewport.width - padding.left - padding.right);
  const availableHeight = Math.max(160, viewport.height - padding.top - padding.bottom);
  const paddingFactor = opts.paddingFactor ?? 1.45;
  const rangeX = Math.max(maxX - minX, 0.01) * paddingFactor;
  const rangeY = Math.max(maxY - minY, 0.01) * paddingFactor;
  const graphUnitPixels = Math.min(viewport.width, viewport.height);
  const rawRatio = Math.max(rangeX / availableWidth, rangeY / availableHeight) * graphUnitPixels;
  const ratio = clamp(rawRatio, opts.minRatio ?? 0.035, opts.maxRatio ?? 2.4);
  const pxToGraph = ratio / graphUnitPixels;

  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
  const horizontalOffset = (padding.right - padding.left) / 2;
  const verticalOffset = (padding.bottom - padding.top) / 2;

  return {
    x: cx + horizontalOffset * pxToGraph,
    y: cy + verticalOffset * pxToGraph,
    ratio,
  };
}

function normalizePadding(padding: GraphFitPadding = {}): Required<GraphFitPadding> {
  return {
    top: padding.top ?? DEFAULT_PADDING,
    right: padding.right ?? DEFAULT_PADDING,
    bottom: padding.bottom ?? DEFAULT_PADDING,
    left: padding.left ?? DEFAULT_PADDING,
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
