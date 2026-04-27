// ============================================================
// Minimap — canvas minimap with viewport rectangle
// ============================================================

import { useRef, useEffect, useCallback } from 'react';
import type Graph from 'graphology';
import type Sigma from 'sigma';
import { NODE_COLORS } from '../../lib/graph-constants';

interface MinimapProps {
  graph: Graph;
  rendererRef: React.MutableRefObject<Sigma | null>;
}

const MINIMAP_W = 160;
const MINIMAP_H = 120;

export function Minimap({ graph, rendererRef }: MinimapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const renderer = rendererRef.current;
    if (!canvas || !renderer) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, MINIMAP_W, MINIMAP_H);
    ctx.fillStyle = '#0e1118';
    ctx.fillRect(0, 0, MINIMAP_W, MINIMAP_H);

    if (graph.order === 0) return;

    // Compute bounding box
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    graph.forEachNode((_id, attrs) => {
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (typeof x !== 'number' || typeof y !== 'number') return;
      minX = Math.min(minX, x);
      maxX = Math.max(maxX, x);
      minY = Math.min(minY, y);
      maxY = Math.max(maxY, y);
    });

    if (!isFinite(minX)) return;

    const rangeX = maxX - minX || 1;
    const rangeY = maxY - minY || 1;
    const padding = 8;
    const scale = Math.min((MINIMAP_W - 2 * padding) / rangeX, (MINIMAP_H - 2 * padding) / rangeY);
    const ox = (MINIMAP_W - rangeX * scale) / 2;
    const oy = (MINIMAP_H - rangeY * scale) / 2;

    // Draw nodes
    graph.forEachNode((_id, attrs) => {
      const x = attrs.x as number;
      const y = attrs.y as number;
      if (typeof x !== 'number' || typeof y !== 'number') return;
      const color = NODE_COLORS[(attrs.nodeType as string)] || '#888';
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(ox + (x - minX) * scale, oy + (y - minY) * scale, 1.5, 0, Math.PI * 2);
      ctx.fill();
    });

    // Draw viewport rectangle
    const camera = renderer.getCamera();
    const state = camera.getState();
    const halfW = state.ratio * 0.5;
    const halfH = state.ratio * 0.5;
    ctx.strokeStyle = '#5b8def';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(
      ox + (state.x - halfW - minX) * scale,
      oy + (state.y - halfH - minY) * scale,
      halfW * 2 * scale,
      halfH * 2 * scale,
    );
  }, [graph, rendererRef]);

  // Redraw periodically and on graph changes
  useEffect(() => {
    const interval = setInterval(draw, 500);
    return () => clearInterval(interval);
  }, [draw]);

  return (
    <div className="absolute bottom-3 right-3 z-20 border border-border rounded overflow-hidden shadow-lg">
      <canvas ref={canvasRef} width={MINIMAP_W} height={MINIMAP_H} className="block" />
    </div>
  );
}
