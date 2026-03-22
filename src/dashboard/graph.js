// ============================================================
// Overwatch Dashboard — Graph Module
// sigma.js init, animated ForceAtlas2, drag, hover, paths
// ============================================================

const NODE_COLORS = {
  host:        '#6e9eff',
  service:     '#5dcaa5',
  credential:  '#f0b54a',
  user:        '#afa9ec',
  group:       '#ed93b1',
  domain:      '#97c459',
  objective:   '#f07b6e',
  certificate: '#85b7eb',
  share:       '#e0a86e',
  gpo:         '#b0b0b0',
  ou:          '#b0b0b0',
  subnet:      '#b0b0b0',
};

const NODE_BASE_SIZES = {
  host: 8,
  service: 5,
  credential: 7,
  user: 6,
  group: 7,
  domain: 14,
  objective: 10,
  certificate: 6,
  share: 5,
  gpo: 5,
  ou: 5,
  subnet: 5,
};

// Edge colors by category
const EDGE_CATEGORIES = {
  // Network
  REACHABLE: '#6e9eff', RUNS: '#6e9eff',
  // Access
  ADMIN_TO: '#5dcaa5', HAS_SESSION: '#5dcaa5', CAN_RDPINTO: '#5dcaa5', CAN_PSREMOTE: '#5dcaa5',
  // Credentials
  VALID_ON: '#f0b54a', OWNS_CRED: '#f0b54a', POTENTIAL_AUTH: '#f0b54a',
  // AD Attack Paths
  CAN_DCSYNC: '#f07b6e', DELEGATES_TO: '#f07b6e', WRITEABLE_BY: '#f07b6e',
  GENERIC_ALL: '#f07b6e', GENERIC_WRITE: '#f07b6e', WRITE_OWNER: '#f07b6e',
  WRITE_DACL: '#f07b6e', ADD_MEMBER: '#f07b6e', FORCE_CHANGE_PASSWORD: '#f07b6e',
  ALLOWED_TO_ACT: '#f07b6e',
  // ADCS
  CAN_ENROLL: '#afa9ec', ESC1: '#afa9ec', ESC2: '#afa9ec', ESC3: '#afa9ec',
  ESC4: '#afa9ec', ESC6: '#afa9ec', ESC8: '#afa9ec',
  // Lateral movement
  RELAY_TARGET: '#ed93b1', NULL_SESSION: '#ed93b1',
  // Domain
  MEMBER_OF: '#6b6977', MEMBER_OF_DOMAIN: '#6b6977', TRUSTS: '#97c459',
  SAME_DOMAIN: '#6b6977',
};

const DEFAULT_EDGE_COLOR = 'rgba(110,158,255,0.25)';
const INFERRED_EDGE_COLOR = 'rgba(175,169,236,0.25)';

// ============================================================
// Graph State
// ============================================================

let graph = null;
let renderer = null;
let layoutRunning = false;
let layoutAnimId = null;
let layoutIterationCount = 0;
const LAYOUT_MAX_ITERATIONS = 600; // ~10s at 60fps * 5 iters/frame
const LAYOUT_ITERS_PER_FRAME = 5;

// Interaction state
let activeFilters = new Set(Object.keys(NODE_COLORS));
let hoveredNode = null;
let hoveredNeighbors = null;
let draggedNode = null;
let isDragging = false;
const DRAG_THRESHOLD_PX = 6;

// Path highlighting
let pathSource = null;
let pathTarget = null;
let pathEdges = new Set();
let pathNodes = new Set();

// Neighborhood focus
let focusNode = null;
let focusNeighborhood = null; // Set of visible node IDs when focused

// New node animation
let newNodeIds = new Set();
let newNodeTimer = null;

// ============================================================
// Init
// ============================================================

function initGraph() {
  graph = new graphology.Graph({ type: 'directed', multi: true, allowSelfLoops: false });
  return graph;
}

function initRenderer() {
  const container = document.getElementById('sigma-container');

  renderer = new Sigma(graph, container, {
    renderLabels: true,
    labelFont: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    labelSize: 11,
    labelColor: { color: '#9b99a3' },
    labelDensity: 0.4,
    labelGridCellSize: 120,
    labelRenderedSizeThreshold: 5,
    defaultEdgeColor: DEFAULT_EDGE_COLOR,
    defaultEdgeType: 'arrow',
    edgeReducer: edgeReducer,
    nodeReducer: nodeReducer,
    zIndex: true,
    minCameraRatio: 0.02,
    maxCameraRatio: 10,
  });

  // Wire up interactions
  setupDrag();
  setupHover();
  setupClick();

  return renderer;
}

function isNodeVisible(node, attrs = null) {
  const nodeAttrs = attrs || graph.getNodeAttributes(node);
  if (!nodeAttrs) return false;

  if (!activeFilters.has(nodeAttrs.nodeType)) {
    return false;
  }

  if (focusNeighborhood && !focusNeighborhood.has(node)) {
    return false;
  }

  return true;
}

function isEdgeVisible(edge) {
  const source = graph.source(edge);
  const target = graph.target(edge);
  return isNodeVisible(source) && isNodeVisible(target);
}

function getVisibleNodeIds() {
  if (!graph) return [];

  const visible = [];
  graph.forEachNode((id, attrs) => {
    if (isNodeVisible(id, attrs)) visible.push(id);
  });
  return visible;
}

function getVisibleEdgeIds() {
  if (!graph) return [];

  const visible = [];
  graph.forEachEdge((edge) => {
    if (isEdgeVisible(edge)) visible.push(edge);
  });
  return visible;
}

// ============================================================
// Reducers — control node/edge appearance per frame
// ============================================================

function nodeReducer(node, data) {
  const res = { ...data };
  if (!isNodeVisible(node, data)) {
    res.hidden = true;
    return res;
  }

  // Path highlighting
  if (pathNodes.size > 0) {
    if (pathNodes.has(node)) {
      res.zIndex = 2;
      res.highlighted = true;
    } else {
      res.color = dimColor(data.color, 0.12);
      res.label = '';
      res.zIndex = 0;
    }
  }

  // Hover highlighting
  if (hoveredNode && !pathNodes.size) {
    if (node === hoveredNode) {
      res.highlighted = true;
      res.zIndex = 2;
    } else if (hoveredNeighbors && hoveredNeighbors.has(node)) {
      res.zIndex = 1;
    } else {
      res.color = dimColor(data.color, 0.12);
      res.label = '';
      res.zIndex = 0;
    }
  }

  // Path source/target indicators
  if (node === pathSource) {
    res.highlighted = true;
    res.color = '#5dcaa5'; // green ring
  }
  if (node === pathTarget) {
    res.highlighted = true;
    res.color = '#f07b6e'; // red ring
  }

  // New node pulse effect
  if (newNodeIds.has(node)) {
    res.highlighted = true;
    res.zIndex = 3;
  }

  return res;
}

function edgeReducer(edge, data) {
  const res = { ...data };

  if (!isEdgeVisible(edge)) {
    res.hidden = true;
    return res;
  }

  // Path highlighting
  if (pathEdges.size > 0) {
    if (pathEdges.has(edge)) {
      res.size = 3;
      res.zIndex = 2;
      res.color = '#f0b54a';
    } else {
      res.color = 'rgba(255,255,255,0.03)';
      res.size = 0.3;
      res.zIndex = 0;
    }
    return res;
  }

  // Hover highlighting
  if (hoveredNode) {
    const src = graph.source(edge);
    const tgt = graph.target(edge);
    if (src === hoveredNode || tgt === hoveredNode) {
      res.size = 2;
      res.zIndex = 1;
    } else {
      res.color = 'rgba(255,255,255,0.03)';
      res.size = 0.3;
      res.zIndex = 0;
    }
  }

  return res;
}

// ============================================================
// Drag
// ============================================================

function setupDrag() {
  const container = document.getElementById('sigma-container');
  let dragStartX, dragStartY;
  let hasMoved = false;

  renderer.on('downNode', (e) => {
    isDragging = true;
    hasMoved = false;
    draggedNode = e.node;
    // Record start position for move detection
    const pointer = getPointerPosition(e);
    dragStartX = pointer.x;
    dragStartY = pointer.y;
    // Mark node as fixed so layout preserves its position
    graph.setNodeAttribute(draggedNode, 'fixed', true);
    // Disable sigma camera drag while we're dragging a node
    renderer.getCamera().disable();
    container.classList.add('dragging');
  });

  renderer.getMouseCaptor().on('mousemovebody', (e) => {
    if (!isDragging || !draggedNode) return;

    // Convert viewport coords to graph coords
    const pos = renderer.viewportToGraph(e);
    graph.setNodeAttribute(draggedNode, 'x', pos.x);
    graph.setNodeAttribute(draggedNode, 'y', pos.y);
    const pointer = getPointerPosition(e);
    hasMoved = hasMoved || exceededDragThreshold(dragStartX, dragStartY, pointer.x, pointer.y);

    // Prevent hover from interfering during drag
    hoveredNode = null;
    hoveredNeighbors = null;
    hideTooltip();
  });

  const endDrag = () => {
    if (isDragging && draggedNode) {
      container.classList.remove('dragging');
      // Suppress the click event that fires after drag
      if (hasMoved) {
        suppressNextClick = true;
      }
    }
    isDragging = false;
    draggedNode = null;
    hasMoved = false;
    renderer.getCamera().enable();
  };

  renderer.getMouseCaptor().on('mouseup', endDrag);
  renderer.getMouseCaptor().on('mouseleave', endDrag);
}

// ============================================================
// Hover
// ============================================================

function setupHover() {
  renderer.on('enterNode', ({ node }) => {
    hoveredNode = node;
    hoveredNeighbors = new Set(graph.neighbors(node));
    renderer.refresh();
    showTooltip(node);
  });

  renderer.on('leaveNode', () => {
    hoveredNode = null;
    hoveredNeighbors = null;
    renderer.refresh();
    hideTooltip();
  });
}

// ============================================================
// Click
// ============================================================

let suppressNextClick = false;

function setupClick() {
  renderer.on('clickNode', ({ node, event }) => {
    // Suppress click that fires after a drag release
    if (suppressNextClick) {
      suppressNextClick = false;
      return;
    }
    // Shift+click: path highlighting
    if (event.original.shiftKey) {
      handlePathClick(node);
      return;
    }
    // Regular click: show detail
    if (typeof showNodeDetail === 'function') {
      showNodeDetail(node);
    }
  });

  renderer.on('doubleClickNode', ({ node }) => {
    enterNeighborhoodFocus(node, 2);
  });

  renderer.on('clickStage', () => {
    if (typeof hideDetail === 'function') hideDetail();
  });

  // Prevent default double-click zoom
  renderer.on('doubleClickStage', (e) => {
    e.preventSigmaDefault();
  });
}

// ============================================================
// Path Highlighting
// ============================================================

function handlePathClick(node) {
  if (!pathSource) {
    // First click: set source
    pathSource = node;
    pathTarget = null;
    pathEdges.clear();
    pathNodes.clear();
    pathNodes.add(node);
    renderer.refresh();
    return;
  }

  if (pathSource === node) {
    clearPathHighlight();
    return;
  }

  // Second click: find shortest path
  pathTarget = node;
  findAndHighlightPath();
}

function findAndHighlightPath() {
  if (!pathSource || !pathTarget) return;

  pathEdges.clear();
  pathNodes.clear();
  pathNodes.add(pathSource);
  pathNodes.add(pathTarget);

  // BFS shortest path (undirected traversal)
  const visited = new Map(); // node → parent
  const edgeUsed = new Map(); // node → edge that led here
  const queue = [pathSource];
  visited.set(pathSource, null);

  let found = false;
  while (queue.length > 0 && !found) {
    const current = queue.shift();
    const edges = graph.edges(current);
    for (const edge of edges) {
      const neighbor = graph.opposite(current, edge);
      if (!visited.has(neighbor)) {
        visited.set(neighbor, current);
        edgeUsed.set(neighbor, edge);
        queue.push(neighbor);
        if (neighbor === pathTarget) {
          found = true;
          break;
        }
      }
    }
  }

  if (found) {
    // Trace back from target to source
    let current = pathTarget;
    while (current !== pathSource) {
      pathNodes.add(current);
      const edge = edgeUsed.get(current);
      if (edge) pathEdges.add(edge);
      current = visited.get(current);
    }

    // Show path info bar
    showPathInfo();
  }

  renderer.refresh();
}

function showPathInfo() {
  const bar = document.getElementById('path-info-bar');
  if (!bar) return;

  const edgeTypes = [];
  for (const edge of pathEdges) {
    const attrs = graph.getEdgeAttributes(edge);
    edgeTypes.push(attrs.edgeType || '?');
  }

  const srcLabel = graph.getNodeAttribute(pathSource, 'label') || pathSource;
  const tgtLabel = graph.getNodeAttribute(pathTarget, 'label') || pathTarget;

  bar.querySelector('.path-label').textContent = `${srcLabel} → ${tgtLabel} (${pathEdges.size} hops)`;
  bar.querySelector('.path-edges').textContent = edgeTypes.join(' → ');
  bar.classList.add('visible');
}

function clearPathHighlight() {
  pathSource = null;
  pathTarget = null;
  pathEdges.clear();
  pathNodes.clear();

  const bar = document.getElementById('path-info-bar');
  if (bar) bar.classList.remove('visible');

  if (renderer) renderer.refresh();
}

// ============================================================
// Neighborhood Focus
// ============================================================

function enterNeighborhoodFocus(node, hops) {
  focusNode = node;
  focusNeighborhood = new Set([node]);

  // BFS N-hop neighborhood
  let frontier = [node];
  for (let i = 0; i < hops; i++) {
    const next = [];
    for (const n of frontier) {
      for (const neighbor of graph.neighbors(n)) {
        if (!focusNeighborhood.has(neighbor)) {
          focusNeighborhood.add(neighbor);
          next.push(neighbor);
        }
      }
    }
    frontier = next;
  }

  // Show banner
  const banner = document.getElementById('focus-banner');
  if (banner) {
    const label = graph.getNodeAttribute(node, 'label') || node;
    banner.querySelector('.focus-label').textContent = `Focused on "${label}" (${hops}-hop, ${focusNeighborhood.size} nodes)`;
    banner.classList.add('visible');
  }

  if (renderer) renderer.refresh();

  // Zoom to fit the focused neighborhood
  zoomToNodes(focusNeighborhood);
}

function exitNeighborhoodFocus() {
  focusNode = null;
  focusNeighborhood = null;

  const banner = document.getElementById('focus-banner');
  if (banner) banner.classList.remove('visible');

  if (renderer) renderer.refresh();
  zoomToFit();
}

// ============================================================
// Tooltip
// ============================================================

function showTooltip(node) {
  const tooltip = document.getElementById('graph-tooltip');
  if (!tooltip) return;

  const attrs = graph.getNodeAttributes(node);
  const props = attrs._props || {};
  const nodeType = attrs.nodeType || 'unknown';
  const color = NODE_COLORS[nodeType] || '#888';
  const degree = graph.degree(node);

  let infoHtml = `${degree} connection${degree !== 1 ? 's' : ''}`;
  if (props.ip) infoHtml = `${props.ip} · ${infoHtml}`;
  if (props.port) infoHtml = `Port ${props.port} · ${infoHtml}`;
  if (props.hostname && props.hostname !== props.label) infoHtml = `${props.hostname} · ${infoHtml}`;

  tooltip.innerHTML = `
    <div class="tt-type" style="background:${color}22;color:${color}">${nodeType}</div>
    <div class="tt-label">${props.label || node}</div>
    <div class="tt-info">${infoHtml}</div>
  `;

  // Position near cursor
  const nodePos = renderer.graphToViewport(attrs);
  const rect = document.getElementById('sigma-container').getBoundingClientRect();

  let left = nodePos.x + 16;
  let top = nodePos.y - 10;

  // Keep within bounds
  if (left + 260 > rect.width) left = nodePos.x - 270;
  if (top + 80 > rect.height) top = rect.height - 80;
  if (top < 0) top = 10;

  tooltip.style.left = left + 'px';
  tooltip.style.top = top + 'px';
  tooltip.classList.add('visible');
}

function hideTooltip() {
  const tooltip = document.getElementById('graph-tooltip');
  if (tooltip) tooltip.classList.remove('visible');
}

// ============================================================
// Layout — Animated ForceAtlas2
// ============================================================

function getLayoutSettings() {
  const order = graph.order;
  return {
    gravity: 0.3,
    scalingRatio: order > 50 ? 60 : 30,
    linLogMode: true,
    adjustSizes: true,
    barnesHutOptimize: true,
    barnesHutTheta: 0.5,
    slowDown: 8,
    strongGravityMode: false,
    outboundAttractionDistribution: true,
  };
}

function startLayout() {
  if (layoutRunning) return;
  if (graph.order === 0) return;

  layoutRunning = true;
  layoutIterationCount = 0;

  const fa2 = window.graphologyLayoutForceAtlas2 || globalThis.graphologyLayoutForceAtlas2;
  if (!fa2 || !fa2.assign) {
    console.warn('ForceAtlas2 not available');
    layoutRunning = false;
    return;
  }

  const settings = getLayoutSettings();

  function frame() {
    if (!layoutRunning) return;

    // Save positions of fixed nodes (FA2 doesn't respect 'fixed')
    const fixedPositions = new Map();
    graph.forEachNode((id, attrs) => {
      if (attrs.fixed) {
        fixedPositions.set(id, { x: attrs.x, y: attrs.y });
      }
    });

    // Run a few iterations per frame
    fa2.assign(graph, { iterations: LAYOUT_ITERS_PER_FRAME, settings });
    layoutIterationCount += LAYOUT_ITERS_PER_FRAME;

    // Restore fixed node positions
    for (const [id, pos] of fixedPositions) {
      graph.setNodeAttribute(id, 'x', pos.x);
      graph.setNodeAttribute(id, 'y', pos.y);
    }

    if (renderer) renderer.refresh();
    updateMinimap();

    // Auto-stop after max iterations
    if (layoutIterationCount >= LAYOUT_MAX_ITERATIONS) {
      stopLayout();
      return;
    }

    layoutAnimId = requestAnimationFrame(frame);
  }

  layoutAnimId = requestAnimationFrame(frame);
  updateLayoutButton();
}

function stopLayout() {
  layoutRunning = false;
  if (layoutAnimId) {
    cancelAnimationFrame(layoutAnimId);
    layoutAnimId = null;
  }
  updateLayoutButton();
}

function toggleLayout() {
  if (layoutRunning) {
    stopLayout();
  } else {
    startLayout();
  }
}

function updateLayoutButton() {
  const btn = document.getElementById('btn-layout');
  if (!btn) return;
  if (layoutRunning) {
    btn.textContent = '⏸ Layout';
    btn.classList.add('active');
  } else {
    btn.textContent = '▶ Layout';
    btn.classList.remove('active');
  }
}

// ============================================================
// Graph Data Loading
// ============================================================

function getEdgeKey(edge) {
  if (edge && edge.id) return edge.id;
  const props = edge?.properties || {};
  return edge.source + '--' + (props.type || '') + '--' + edge.target;
}

function getEdgeColor(edgeType, confidence) {
  if (confidence < 1.0) {
    const base = EDGE_CATEGORIES[edgeType] || '#afa9ec';
    return dimColor(base, 0.3);
  }
  return EDGE_CATEGORIES[edgeType] || DEFAULT_EDGE_COLOR;
}

function buildEdgeAttributes(props) {
  const confidence = props.confidence || 1.0;
  const edgeType = props.type || '';
  return {
    color: getEdgeColor(edgeType, confidence),
    size: confidence >= 1.0 ? 1 : 0.5,
    type: 'arrow',
    confidence: confidence,
    edgeType: edgeType,
    label: edgeType,
  };
}

function getNodePosition(nodeId, fallbackPosition, preservePositions) {
  if (preservePositions && graph.hasNode(nodeId)) {
    const current = graph.getNodeAttributes(nodeId);
    return { x: current.x, y: current.y, fixed: current.fixed === true };
  }
  return { ...fallbackPosition, fixed: false };
}

function reconcileInteractionState() {
  if (focusNode && !graph.hasNode(focusNode)) {
    exitNeighborhoodFocus();
  } else if (focusNeighborhood) {
    focusNeighborhood = new Set([...focusNeighborhood].filter(nodeId => graph.hasNode(nodeId)));
    if (focusNeighborhood.size === 0) {
      exitNeighborhoodFocus();
    }
  }

  if ((pathSource && !graph.hasNode(pathSource)) || (pathTarget && !graph.hasNode(pathTarget))) {
    clearPathHighlight();
  } else if (pathNodes.size > 0) {
    pathNodes = new Set([...pathNodes].filter(nodeId => graph.hasNode(nodeId)));
    pathEdges = new Set([...pathEdges].filter(edgeId => graph.hasEdge(edgeId)));
  }

  if (hoveredNode && !graph.hasNode(hoveredNode)) {
    hoveredNode = null;
    hoveredNeighbors = null;
    hideTooltip();
  } else if (hoveredNeighbors) {
    hoveredNeighbors = new Set([...hoveredNeighbors].filter(nodeId => graph.hasNode(nodeId)));
  }
}

function syncGraphData(graphData, options = {}) {
  if (!graphData || !graphData.nodes) return;

  const preservePositions = options.preservePositions !== false;
  const shouldResetLayout = options.resetLayout === true;

  if (shouldResetLayout) {
    graph.clear();
    stopLayout();
    clearPathHighlight();
    focusNode = null;
    focusNeighborhood = null;
    hoveredNode = null;
    hoveredNeighbors = null;
    hideTooltip();
  }

  const positions = groupInitialPositions(graphData.nodes);
  const nextNodeIds = new Set(graphData.nodes.map((node) => node.id));
  const nextEdgeKeys = new Set((graphData.edges || []).map((edge) => getEdgeKey(edge)));

  let structureChanged = false;
  let addedNodes = false;
  let addedEdges = false;
  const addedNodeIds = [];

  if (!shouldResetLayout) {
    const edgesToRemove = [];
    graph.forEachEdge((edgeId) => {
      if (!nextEdgeKeys.has(edgeId)) edgesToRemove.push(edgeId);
    });
    for (const edgeId of edgesToRemove) {
      graph.dropEdge(edgeId);
      structureChanged = true;
    }

    const nodesToRemove = [];
    graph.forEachNode((nodeId) => {
      if (!nextNodeIds.has(nodeId)) nodesToRemove.push(nodeId);
    });
    for (const nodeId of nodesToRemove) {
      graph.dropNode(nodeId);
      structureChanged = true;
    }
  }

  graphData.nodes.forEach((node) => {
    const props = node.properties || {};
    const nodeType = props.type || 'host';
    const fallbackPosition = positions[node.id] || { x: Math.random() * 10, y: Math.random() * 10 };
    const position = getNodePosition(node.id, fallbackPosition, preservePositions && !shouldResetLayout);

    if (graph.hasNode(node.id)) {
      const updates = {
        label: props.label || node.id,
        color: NODE_COLORS[nodeType] || '#888',
        nodeType,
        _props: props,
      };
      if (!preservePositions || shouldResetLayout) {
        updates.x = position.x;
        updates.y = position.y;
      }
      graph.mergeNodeAttributes(node.id, updates);
    } else {
      graph.addNode(node.id, {
        label: props.label || node.id,
        x: position.x,
        y: position.y,
        fixed: position.fixed,
        size: NODE_BASE_SIZES[nodeType] || 5,
        color: NODE_COLORS[nodeType] || '#888',
        nodeType,
        _props: props,
      });
      structureChanged = true;
      addedNodes = true;
      addedNodeIds.push(node.id);
    }
  });

  (graphData.edges || []).forEach((edge) => {
    if (!graph.hasNode(edge.source) || !graph.hasNode(edge.target)) return;

    const props = edge.properties || {};
    const edgeKey = getEdgeKey(edge);
    const attrs = buildEdgeAttributes(props);

    if (graph.hasEdge(edgeKey)) {
      graph.mergeEdgeAttributes(edgeKey, attrs);
    } else {
      try {
        graph.addEdgeWithKey(edgeKey, edge.source, edge.target, attrs);
        structureChanged = true;
        addedEdges = true;
      } catch { /* skip duplicate */ }
    }
  });

  if (structureChanged) {
    graph.forEachNode((id, attrs) => {
      const degree = graph.degree(id);
      graph.setNodeAttribute(id, 'size', computeNodeSize(attrs.nodeType, degree));
    });
    buildFilterButtons();
  }

  if (addedNodeIds.length > 0) {
    pulseNewNodes(addedNodeIds);
  }

  reconcileInteractionState();

  if ((shouldResetLayout || addedNodes || addedEdges) && !layoutRunning) {
    startLayout();
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function computeNodeSize(nodeType, degree) {
  const base = NODE_BASE_SIZES[nodeType] || 5;
  return base + Math.log2(degree + 1) * 1.5;
}

function groupInitialPositions(nodes) {
  // Group nodes by type for better initial layout
  const groups = {};
  nodes.forEach((n, i) => {
    const type = (n.properties || {}).type || 'host';
    if (!groups[type]) groups[type] = [];
    groups[type].push(n);
  });

  const typeKeys = Object.keys(groups);
  const positions = {};

  typeKeys.forEach((type, groupIdx) => {
    const groupAngle = (2 * Math.PI * groupIdx) / typeKeys.length;
    const groupRadius = 10;
    const cx = groupRadius * Math.cos(groupAngle);
    const cy = groupRadius * Math.sin(groupAngle);

    groups[type].forEach((n, i) => {
      const nodeAngle = (2 * Math.PI * i) / groups[type].length;
      const nodeRadius = 2 + Math.random() * 3;
      positions[n.id] = {
        x: cx + nodeRadius * Math.cos(nodeAngle),
        y: cy + nodeRadius * Math.sin(nodeAngle),
      };
    });
  });

  return positions;
}

function loadGraphData(graphData) {
  syncGraphData(graphData, { preservePositions: false, resetLayout: true });
}

function mergeGraphDelta(delta) {
  if (!delta) return;
  let added = false;
  const addedNodeIds = [];

  // Upsert nodes
  if (delta.nodes) {
    delta.nodes.forEach((n) => {
      const props = n.properties || {};
      const nodeType = props.type || 'host';
      if (graph.hasNode(n.id)) {
        graph.mergeNodeAttributes(n.id, {
          label: props.label || n.id,
          color: NODE_COLORS[nodeType] || '#888',
          nodeType: nodeType,
          _props: props,
        });
      } else {
        const angle = Math.random() * 2 * Math.PI;
        const radius = 3 + Math.random() * 3;
        graph.addNode(n.id, {
          label: props.label || n.id,
          x: radius * Math.cos(angle),
          y: radius * Math.sin(angle),
          size: NODE_BASE_SIZES[nodeType] || 5,
          color: NODE_COLORS[nodeType] || '#888',
          nodeType: nodeType,
          _props: props,
        });
        added = true;
        addedNodeIds.push(n.id);
      }
    });
  }

  // Upsert edges
  if (delta.edges) {
    delta.edges.forEach((e) => {
      if (!graph.hasNode(e.source) || !graph.hasNode(e.target)) return;
      const props = e.properties || {};
      const edgeKey = getEdgeKey(e);
      const attrs = buildEdgeAttributes(props);
      if (graph.hasEdge(edgeKey)) {
        graph.mergeEdgeAttributes(edgeKey, attrs);
      } else {
        try {
          graph.addEdgeWithKey(edgeKey, e.source, e.target, attrs);
          added = true;
        } catch { /* skip duplicate */ }
      }
    });
  }

  // Update sizes for affected nodes
  if (added) {
    graph.forEachNode((id, attrs) => {
      const degree = graph.degree(id);
      graph.setNodeAttribute(id, 'size', computeNodeSize(attrs.nodeType, degree));
    });
  }

  // Animate new nodes
  if (addedNodeIds.length > 0) {
    pulseNewNodes(addedNodeIds);
  }

  if (added) {
    startLayout();
    buildFilterButtons();
  }

  reconcileInteractionState();

  if (renderer) renderer.refresh();
  updateMinimap();
}

// ============================================================
// New Node Pulse
// ============================================================

function pulseNewNodes(nodeIds) {
  for (const id of nodeIds) {
    newNodeIds.add(id);
  }
  if (renderer) renderer.refresh();

  // Clear pulse after 2s
  if (newNodeTimer) clearTimeout(newNodeTimer);
  newNodeTimer = setTimeout(() => {
    newNodeIds.clear();
    if (renderer) renderer.refresh();
    newNodeTimer = null;
  }, 2000);
}

// ============================================================
// Filters
// ============================================================

function buildFilterButtons() {
  const container = document.getElementById('node-filters');
  if (!container) return;

  // Count nodes by type
  const typeCounts = {};
  graph.forEachNode((id, attrs) => {
    const t = attrs.nodeType;
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });

  container.innerHTML = '';
  const types = Object.keys(typeCounts).sort();

  for (const type of types) {
    const color = NODE_COLORS[type] || '#888';
    const count = typeCounts[type] || 0;
    const btn = document.createElement('button');
    btn.className = activeFilters.has(type) ? 'active' : '';
    btn.innerHTML = `<span class="dot" style="background:${color}"></span>${type}<span class="count">${count}</span>`;
    btn.onclick = () => toggleFilter(type, btn);
    container.appendChild(btn);
  }
}

function toggleFilter(type, btn) {
  if (activeFilters.has(type)) {
    activeFilters.delete(type);
    if (btn) btn.classList.remove('active');
  } else {
    activeFilters.add(type);
    if (btn) btn.classList.add('active');
  }
  if (!btn) buildFilterButtons();
  if (renderer) renderer.refresh();
  updateMinimap();
}

function setActiveFilters(filterTypes) {
  activeFilters = new Set(filterTypes);
  buildFilterButtons();
  if (renderer) renderer.refresh();
  updateMinimap();
}

function resetFilters() {
  activeFilters = new Set(Object.keys(NODE_COLORS));
  buildFilterButtons();
  clearPathHighlight();
  exitNeighborhoodFocus();
  if (renderer) renderer.refresh();
}

// ============================================================
// Camera Controls
// ============================================================

function zoomToFit() {
  if (renderer) {
    renderer.getCamera().animatedReset({ duration: 300 });
  }
}

function zoomIn() {
  if (renderer) {
    const camera = renderer.getCamera();
    camera.animatedZoom({ duration: 200, factor: 1.5 });
  }
}

function zoomOut() {
  if (renderer) {
    const camera = renderer.getCamera();
    camera.animatedUnzoom({ duration: 200, factor: 1.5 });
  }
}

function zoomToNodes(nodeSet) {
  if (!renderer || nodeSet.size === 0) return;

  let minX = Infinity, maxX = -Infinity;
  let minY = Infinity, maxY = -Infinity;

  for (const nodeId of nodeSet) {
    if (!graph.hasNode(nodeId)) continue;
    const attrs = graph.getNodeAttributes(nodeId);
    minX = Math.min(minX, attrs.x);
    maxX = Math.max(maxX, attrs.x);
    minY = Math.min(minY, attrs.y);
    maxY = Math.max(maxY, attrs.y);
  }

  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
  const dx = maxX - minX || 1;
  const dy = maxY - minY || 1;

  // Estimate ratio
  const container = document.getElementById('sigma-container');
  const aspectGraph = dx / dy;
  const aspectView = container.clientWidth / container.clientHeight;
  const ratio = aspectGraph > aspectView
    ? dx / (container.clientWidth * 0.0015)
    : dy / (container.clientHeight * 0.0015);

  renderer.getCamera().animate({ x: cx, y: cy, ratio: Math.max(ratio, 0.05) }, { duration: 400 });
}

// ============================================================
// Minimap
// ============================================================

function updateMinimap() {
  const canvas = document.getElementById('minimap-canvas');
  if (!canvas || !renderer) return;

  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.clientWidth * 2; // retina
  const h = canvas.height = canvas.clientHeight * 2;
  ctx.clearRect(0, 0, w, h);

  if (graph.order === 0) return;

  const visibleNodeIds = getVisibleNodeIds();
  if (visibleNodeIds.length === 0) return;

  // Compute bounds
  let minX = Infinity, maxX = -Infinity;
  let minY = Infinity, maxY = -Infinity;
  visibleNodeIds.forEach((nodeId) => {
    const attrs = graph.getNodeAttributes(nodeId);
    minX = Math.min(minX, attrs.x);
    maxX = Math.max(maxX, attrs.x);
    minY = Math.min(minY, attrs.y);
    maxY = Math.max(maxY, attrs.y);
  });

  const dx = maxX - minX || 1;
  const dy = maxY - minY || 1;
  const pad = 10;
  const scale = Math.min((w - 2 * pad) / dx, (h - 2 * pad) / dy);
  const ox = pad + ((w - 2 * pad) - dx * scale) / 2;
  const oy = pad + ((h - 2 * pad) - dy * scale) / 2;

  // Draw edges
  ctx.lineWidth = 0.5;
  ctx.strokeStyle = 'rgba(110,158,255,0.15)';
  ctx.beginPath();
  getVisibleEdgeIds().forEach((edgeId) => {
    const src = graph.source(edgeId);
    const tgt = graph.target(edgeId);
    const sa = graph.getNodeAttributes(src);
    const ta = graph.getNodeAttributes(tgt);
    ctx.moveTo(ox + (sa.x - minX) * scale, oy + (sa.y - minY) * scale);
    ctx.lineTo(ox + (ta.x - minX) * scale, oy + (ta.y - minY) * scale);
  });
  ctx.stroke();

  // Draw nodes
  visibleNodeIds.forEach((nodeId) => {
    const attrs = graph.getNodeAttributes(nodeId);
    const nx = ox + (attrs.x - minX) * scale;
    const ny = oy + (attrs.y - minY) * scale;
    ctx.fillStyle = attrs.color || '#888';
    ctx.beginPath();
    ctx.arc(nx, ny, 2, 0, 2 * Math.PI);
    ctx.fill();
  });

  // Draw viewport rectangle
  const camera = renderer.getCamera();
  const state = camera.getState();
  const container = document.getElementById('sigma-container');
  const viewW = container.clientWidth;
  const viewH = container.clientHeight;

  // Camera state: x, y (graph coords), ratio
  const halfW = (viewW * state.ratio) / (2 * scale) * 0.8;
  const halfH = (viewH * state.ratio) / (2 * scale) * 0.8;
  const vpX = ox + (state.x - minX) * scale - halfW * scale;
  const vpY = oy + (state.y - minY) * scale - halfH * scale;

  ctx.strokeStyle = '#6e9eff';
  ctx.lineWidth = 2;
  ctx.strokeRect(
    Math.max(0, ox + (state.x - minX - halfW) * scale),
    Math.max(0, oy + (state.y - minY - halfH) * scale),
    halfW * 2 * scale,
    halfH * 2 * scale
  );
}

// ============================================================
// Screenshot Export
// ============================================================

function exportScreenshot() {
  if (!renderer) return;

  // Use sigma's underlying canvas layers
  const layers = renderer.getCanvases();
  const mainCanvas = layers.edges || layers.nodes || Object.values(layers)[0];

  if (!mainCanvas) {
    console.warn('Could not get canvas for export');
    return;
  }

  // Create a combined canvas
  const sigmaContainer = document.getElementById('sigma-container');
  const exportCanvas = document.createElement('canvas');
  exportCanvas.width = sigmaContainer.clientWidth * 2;
  exportCanvas.height = sigmaContainer.clientHeight * 2;
  const ctx = exportCanvas.getContext('2d');

  // Dark background
  ctx.fillStyle = '#080a0f';
  ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);

  // Draw each sigma layer
  for (const [name, canvas] of Object.entries(layers)) {
    ctx.drawImage(canvas, 0, 0, exportCanvas.width, exportCanvas.height);
  }

  // Trigger download
  const link = document.createElement('a');
  link.download = `overwatch-graph-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.png`;
  link.href = exportCanvas.toDataURL('image/png');
  link.click();
}

// ============================================================
// Utilities
// ============================================================

function dimColor(hex, alpha) {
  // Convert hex color to rgba with given alpha
  if (!hex || hex.startsWith('rgba')) return hex;
  const r = parseInt(hex.slice(1, 3), 16) || 0;
  const g = parseInt(hex.slice(3, 5), 16) || 0;
  const b = parseInt(hex.slice(5, 7), 16) || 0;
  return `rgba(${r},${g},${b},${alpha})`;
}

function getPointerPosition(eventLike) {
  const source = eventLike?.event || eventLike;
  if (typeof source?.x === 'number' && typeof source?.y === 'number') {
    return { x: source.x, y: source.y };
  }
  const pos = renderer?.viewportToGraph ? renderer.viewportToGraph(eventLike) : { x: 0, y: 0 };
  return { x: pos.x, y: pos.y };
}

function exceededDragThreshold(startX, startY, currentX, currentY) {
  if ([startX, startY, currentX, currentY].some(v => typeof v !== 'number' || Number.isNaN(v))) {
    return false;
  }
  const dx = currentX - startX;
  const dy = currentY - startY;
  return Math.hypot(dx, dy) >= DRAG_THRESHOLD_PX;
}

// ============================================================
// Exports (global)
// ============================================================

window.OverwatchGraph = {
  init: initGraph,
  initRenderer,
  loadGraphData,
  syncGraphData,
  mergeGraphDelta,
  startLayout,
  stopLayout,
  toggleLayout,
  zoomToFit,
  zoomIn,
  zoomOut,
  resetFilters,
  clearPathHighlight,
  exitNeighborhoodFocus,
  enterNeighborhoodFocus,
  setActiveFilters,
  exportScreenshot,
  updateMinimap,
  getVisibleNodeIds,
  getVisibleEdgeIds,
  exceededDragThreshold,
  get graph() { return graph; },
  get renderer() { return renderer; },
  get layoutRunning() { return layoutRunning; },
  NODE_COLORS,
  NODE_BASE_SIZES,
};
