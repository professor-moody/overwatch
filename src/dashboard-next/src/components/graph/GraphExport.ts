// ============================================================
// GraphExport — PNG and SVG export
// ============================================================

import type Sigma from 'sigma';
import type Graph from 'graphology';

export function exportScreenshot(renderer: Sigma | null): void {
  if (!renderer) return;

  const layers = renderer.getCanvases();
  const mainCanvas = (layers as Record<string, HTMLCanvasElement>).edges
    || (layers as Record<string, HTMLCanvasElement>).nodes
    || Object.values(layers)[0];

  if (!mainCanvas) return;

  const container = renderer.getContainer();
  const exportCanvas = document.createElement('canvas');
  exportCanvas.width = container.clientWidth * 2;
  exportCanvas.height = container.clientHeight * 2;
  const ctx = exportCanvas.getContext('2d');
  if (!ctx) return;

  ctx.fillStyle = '#080a0f';
  ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);

  for (const canvas of Object.values(layers as Record<string, HTMLCanvasElement>)) {
    ctx.drawImage(canvas, 0, 0, exportCanvas.width, exportCanvas.height);
  }

  const link = document.createElement('a');
  link.download = `overwatch-graph-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.png`;
  link.href = exportCanvas.toDataURL('image/png');
  link.click();
}

export function exportSVG(renderer: Sigma | null, graph: Graph): void {
  if (!renderer || !graph) return;

  const nodeData: { x: number; y: number; size: number; color: string; label: string }[] = [];
  graph.forEachNode((nodeId) => {
    const dd = renderer.getNodeDisplayData(nodeId);
    if (!dd || dd.hidden) return;
    const attrs = graph.getNodeAttributes(nodeId);
    nodeData.push({
      x: dd.x,
      y: dd.y,
      size: dd.size || 5,
      color: dd.color || (attrs.color as string) || '#888',
      label: (dd.label as string) || '',
    });
  });

  if (nodeData.length === 0) {
    triggerSVGDownload('<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600"><rect width="800" height="600" fill="#080a0f"/></svg>');
    return;
  }

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of nodeData) {
    minX = Math.min(minX, n.x - n.size);
    maxX = Math.max(maxX, n.x + n.size);
    minY = Math.min(minY, n.y - n.size);
    maxY = Math.max(maxY, n.y + n.size);
  }

  const padding = 40;
  const vbX = minX - padding;
  const vbY = minY - padding;
  const vbW = (maxX - minX) + padding * 2;
  const vbH = (maxY - minY) + padding * 2;

  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const edgeLines: string[] = [];
  graph.forEachEdge((edgeId) => {
    const src = graph.source(edgeId);
    const tgt = graph.target(edgeId);
    const srcDD = renderer.getNodeDisplayData(src);
    const tgtDD = renderer.getNodeDisplayData(tgt);
    if (!srcDD || !tgtDD || srcDD.hidden || tgtDD.hidden) return;
    const edgeDD = renderer.getEdgeDisplayData(edgeId);
    const edgeAttrs = graph.getEdgeAttributes(edgeId);
    const color = edgeDD?.color || (edgeAttrs.color as string) || '#444';
    const size = edgeDD?.size || (edgeAttrs.size as number) || 0.5;
    edgeLines.push(`<line x1="${srcDD.x}" y1="${srcDD.y}" x2="${tgtDD.x}" y2="${tgtDD.y}" stroke="${esc(color)}" stroke-width="${size}" stroke-opacity="0.8"/>`);
  });

  const circles: string[] = [];
  const labels: string[] = [];
  for (const n of nodeData) {
    circles.push(`<circle cx="${n.x}" cy="${n.y}" r="${n.size}" fill="${esc(n.color)}"/>`);
    if (n.label) {
      labels.push(`<text x="${n.x}" y="${n.y - n.size - 3}" text-anchor="middle" fill="#c8cdd3" font-size="${Math.max(n.size * 0.8, 4)}" font-family="Inter, system-ui, sans-serif">${esc(n.label)}</text>`);
    }
  }

  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vbX} ${vbY} ${vbW} ${vbH}" width="${Math.round(vbW)}" height="${Math.round(vbH)}">`,
    `<rect x="${vbX}" y="${vbY}" width="${vbW}" height="${vbH}" fill="#080a0f"/>`,
    `<g class="edges">${edgeLines.join('')}</g>`,
    `<g class="nodes">${circles.join('')}</g>`,
    `<g class="labels">${labels.join('')}</g>`,
    `</svg>`,
  ].join('\n');

  triggerSVGDownload(svg);
}

function triggerSVGDownload(svgString: string): void {
  const blob = new Blob([svgString], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.download = `overwatch-graph-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.svg`;
  link.href = url;
  link.click();
  URL.revokeObjectURL(url);
}
