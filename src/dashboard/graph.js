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
  ca:          '#79b9f2',
  cert_template:'#c69bf7',
  pki_store:   '#8f95a8',
  share:       '#e0a86e',
  gpo:         '#d08770',
  ou:          '#7fb1a8',
  subnet:      '#8fabb8',
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
  ca: 8,
  cert_template: 6,
  pki_store: 5,
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
  // Credential derivation / provenance
  DERIVED_FROM: '#ff8c42', DUMPED_FROM: '#ff8c42',
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
let selectedNode = null;
let selectedNeighborhood = null;
let inspectedEdgeIds = new Set();
let graphMode = 'overview';
let labelDensity = 'balanced';
let emphasizedNodeTypes = new Set();

const HIGH_SIGNAL_NODE_TYPES = new Set(['domain', 'host', 'objective', 'credential', 'certificate', 'ca', 'subnet']);
const DETAIL_NODE_TYPES = new Set(['service', 'share', 'cert_template']);
const SUPPORTING_NODE_TYPES = new Set(['user', 'group', 'ou', 'gpo', 'pki_store']);

// Path highlighting
let pathSource = null;
let pathTarget = null;
let pathEdges = new Set();
let pathNodes = new Set();

// Attack path overlay
let attackPathOverlay = null; // null | { actual: { nodes: Set, edges: Set }, theoretical: { nodes: Set, edges: Set } | null }
let activityHistoryCache = null; // { entries: [], knownTotal: N } | null

// Credential flow
let credentialFlowMode = false;
let credFlowData = null; // { flowEdges: Set, flowNodes: Set, chains: [] }

// Edge type filter
let edgeTypeFilter = null; // null | { type: string } — highlight all edges of this type
let edgeSourceFilter = null; // null | 'confirmed' | 'inferred'

// Neighborhood focus
let focusNode = null;
let focusNeighborhood = null; // Set of visible node IDs when focused

const ZOOM_REVEAL_THRESHOLDS = {
  detail: 0.24,
  supporting: 0.12,
};

const FILTER_PRESETS = {
  host: ['host', 'domain', 'objective', 'credential', 'certificate'],
  domain: ['domain', 'host', 'objective', 'credential', 'certificate', 'user'],
  objective: ['objective', 'host', 'domain', 'credential'],
  credential: ['credential', 'user', 'host', 'domain', 'objective', 'certificate'],
  certificate: ['certificate', 'credential', 'host', 'domain', 'objective'],
  ca: ['ca', 'cert_template', 'certificate', 'domain', 'host', 'objective'],
  cert_template: ['cert_template', 'ca', 'certificate', 'domain', 'user', 'group'],
  pki_store: ['pki_store', 'ca', 'cert_template', 'domain'],
  service: ['service', 'host', 'domain', 'objective', 'share'],
  share: ['share', 'host', 'domain', 'objective', 'service'],
  user: ['user', 'credential', 'domain', 'host', 'objective', 'group'],
  group: ['group', 'user', 'domain', 'host', 'objective'],
  ou: ['ou', 'domain', 'group', 'user'],
  gpo: ['gpo', 'ou', 'domain', 'host', 'user'],
  subnet: ['subnet', 'host', 'domain', 'objective'],
};

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

  if (isNodeContextuallyRelevant(node)) {
    return true;
  }

  if (!activeFilters.has(nodeAttrs.nodeType)) {
    return false;
  }

  if (graphMode === 'raw') {
    return true;
  }

  if (focusNeighborhood && !focusNeighborhood.has(node)) {
    return false;
  }

  if (graphMode === 'focused') {
    if (selectedNeighborhood) return selectedNeighborhood.has(node);
    return HIGH_SIGNAL_NODE_TYPES.has(nodeAttrs.nodeType);
  }

  if (emphasizedNodeTypes.has(nodeAttrs.nodeType)) {
    return true;
  }

  if (HIGH_SIGNAL_NODE_TYPES.has(nodeAttrs.nodeType)) {
    return true;
  }

  return shouldRevealDetailNodeAtCurrentZoom(nodeAttrs);
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

function getCurrentCameraRatio() {
  return renderer?.getCamera ? renderer.getCamera().getState().ratio : 1;
}

function shouldRevealDetailNodeAtCurrentZoom(nodeAttrs) {
  const ratio = getCurrentCameraRatio();
  if (DETAIL_NODE_TYPES.has(nodeAttrs.nodeType)) return ratio <= ZOOM_REVEAL_THRESHOLDS.detail;
  if (SUPPORTING_NODE_TYPES.has(nodeAttrs.nodeType)) return ratio <= ZOOM_REVEAL_THRESHOLDS.supporting;
  return true;
}

function isNodeContextuallyRelevant(node) {
  if (node === selectedNode) return true;
  if (pathNodes.has(node)) return true;
  if (focusNeighborhood?.has(node)) return true;
  if (selectedNeighborhood?.has(node)) return true;
  return false;
}

function shouldShowLabel(node, nodeAttrs) {
  if (node === selectedNode || node === hoveredNode || pathNodes.has(node)) return true;
  if (focusNeighborhood?.has(node)) return true;
  if (selectedNeighborhood?.has(node)) return true;
  if (emphasizedNodeTypes.has(nodeAttrs.nodeType)) {
    return getCurrentCameraRatio() <= 0.18 || nodeAttrs.nodeType === 'host' || nodeAttrs.nodeType === 'domain';
  }

  const ratio = getCurrentCameraRatio();
  const type = nodeAttrs.nodeType;
  if (labelDensity === 'minimal') {
    return HIGH_SIGNAL_NODE_TYPES.has(type) && ratio <= 0.18;
  }
  if (labelDensity === 'verbose') {
    if (DETAIL_NODE_TYPES.has(type)) return ratio <= 0.18;
    if (SUPPORTING_NODE_TYPES.has(type)) return ratio <= 0.08;
    return true;
  }

  if (DETAIL_NODE_TYPES.has(type)) return ratio <= 0.08;
  if (SUPPORTING_NODE_TYPES.has(type)) return ratio <= 0.04;
  return HIGH_SIGNAL_NODE_TYPES.has(type) && ratio <= 0.28;
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

  if (!shouldShowLabel(node, data)) {
    res.label = '';
  } else if (graphMode === 'overview' && data.nodeType === 'host') {
    const baseLabel = window.OverwatchNodeDisplay.getNodeDisplayLabel(data._props || {}, node);
    const serviceCount = graph.outEdges(node).filter((edgeId) => graph.getEdgeAttributes(edgeId).edgeType === 'RUNS').length;
    if (serviceCount > 0) {
      res.label = `${baseLabel} · svc:${serviceCount}`;
    }
  }
  // Fan-out badge for credential nodes (POTENTIAL_AUTH edges are hidden by default)
  if (res.label && data.nodeType === 'credential') {
    const authCount = graph.outEdges(node).filter((edgeId) => graph.getEdgeAttributes(edgeId).edgeType === 'POTENTIAL_AUTH').length;
    if (authCount > 0) {
      res.label = `${res.label} · auth:${authCount}`;
    }
  }

  // Credential flow mode
  if (credentialFlowMode && credFlowData) {
    if (data.nodeType === 'credential') {
      res.zIndex = 2;
      res.highlighted = true;
      res.size = (data.size || 5) * 1.4;
      res.label = data.label || data._props?.label || node;
      const status = data._props?.credential_status;
      if (status === 'active') res.color = '#3ecf8e';
      else if (status === 'stale') res.color = '#eab308';
      else if (status === 'expired') res.color = '#ef4444';
      else if (status === 'rotated') res.color = '#a78bfa';
    } else if (credFlowData.flowNodes.has(node)) {
      res.zIndex = 1;
    } else {
      res.color = dimColor(data.color, 0.12);
      res.label = '';
      res.zIndex = 0;
    }
    return res;
  }

  // Attack path overlay
  if (attackPathOverlay) {
    const inActual = attackPathOverlay.actual.nodes.has(node);
    const inTheoretical = attackPathOverlay.theoretical?.nodes.has(node);
    if (inActual) {
      res.highlighted = true;
      res.zIndex = 3;
      res.color = '#f0b54a';
    } else if (inTheoretical) {
      res.highlighted = true;
      res.zIndex = 2;
      res.color = '#6e9eff';
    } else {
      res.color = dimColor(data.color, 0.1);
      res.label = '';
      res.zIndex = 0;
    }
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

  if (selectedNode && !hoveredNode && !pathNodes.size) {
    if (node === selectedNode) {
      res.highlighted = true;
      res.zIndex = 3;
    } else if (selectedNeighborhood?.has(node)) {
      res.zIndex = 2;
    } else {
      res.color = dimColor(data.color, 0.1);
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

function isEdgeEndpointActive(edge) {
  const src = graph.source(edge);
  const tgt = graph.target(edge);
  return src === selectedNode || tgt === selectedNode
    || src === hoveredNode || tgt === hoveredNode
    || src === focusNode || tgt === focusNode
    || pathNodes.has(src) || pathNodes.has(tgt)
    || inspectedEdgeIds.has(edge);
}

function edgeReducer(edge, data) {
  const res = { ...data };

  if (!isEdgeVisible(edge)) {
    res.hidden = true;
    return res;
  }

  // Hide POTENTIAL_AUTH edges unless an endpoint is in focus/path mode or credential flow/edge filter is active
  if (data.edgeType === 'POTENTIAL_AUTH') {
    const src = graph.source(edge);
    const tgt = graph.target(edge);
    const isFocused = credentialFlowMode
      || (edgeTypeFilter && edgeTypeFilter.type === 'POTENTIAL_AUTH')
      || (edgeSourceFilter !== null)
      || src === focusNode || tgt === focusNode
      || pathNodes.has(src) || pathNodes.has(tgt)
      || inspectedEdgeIds.has(edge);
    if (!isFocused) {
      res.hidden = true;
      return res;
    }
  }

  // Edge type filter
  if (edgeTypeFilter) {
    if (data.edgeType === edgeTypeFilter.type) {
      res.color = EDGE_CATEGORIES[data.edgeType] || DEFAULT_EDGE_COLOR;
      res.size = 2.5;
      res.zIndex = 3;
    } else {
      res.color = 'rgba(255,255,255,0.03)';
      res.size = 0.3;
      res.zIndex = 0;
    }
    return res;
  }

  // Edge source filter (confirmed vs inferred)
  if (edgeSourceFilter) {
    const isInferred = !!data.inferredByRule;
    const matches = (edgeSourceFilter === 'inferred' && isInferred) || (edgeSourceFilter === 'confirmed' && !isInferred);
    if (matches) {
      res.color = EDGE_CATEGORIES[data.edgeType] || DEFAULT_EDGE_COLOR;
      res.size = 2;
      res.zIndex = 2;
    } else {
      res.color = 'rgba(255,255,255,0.03)';
      res.size = 0.3;
      res.zIndex = 0;
    }
    return res;
  }

  // Credential flow mode
  if (credentialFlowMode && credFlowData) {
    if (credFlowData.flowEdges.has(edge)) {
      const et = data.edgeType;
      if (et === 'DERIVED_FROM') { res.color = '#ff8c42'; res.size = 3; res.zIndex = 3; }
      else if (et === 'OWNS_CRED') { res.color = '#f0b54a'; res.size = 2; res.zIndex = 2; }
      else { res.color = '#eab308'; res.size = 1.5; res.zIndex = 1; }
    } else {
      res.color = 'rgba(255,255,255,0.03)';
      res.size = 0.3;
      res.zIndex = 0;
    }
    return res;
  }

  // Attack path overlay
  if (attackPathOverlay) {
    const inActual = attackPathOverlay.actual.edges.has(edge);
    const inTheoretical = attackPathOverlay.theoretical?.edges.has(edge);
    if (inActual) { res.color = '#f0b54a'; res.size = 3; res.zIndex = 3; }
    else if (inTheoretical) { res.color = '#6e9eff'; res.size = 2; res.zIndex = 2; }
    else { res.color = 'rgba(255,255,255,0.03)'; res.size = 0.3; res.zIndex = 0; }
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

  if (selectedNode && !hoveredNode && !pathEdges.size) {
    const src = graph.source(edge);
    const tgt = graph.target(edge);
    if (inspectedEdgeIds.has(edge)) {
      res.size = 3;
      res.zIndex = 3;
      res.color = '#f0b54a';
    } else if (src === selectedNode || tgt === selectedNode) {
      res.size = 1.8;
      res.zIndex = 2;
    } else if (selectedNeighborhood?.has(src) && selectedNeighborhood?.has(tgt)) {
      res.size = 1.1;
      res.zIndex = 1;
      res.color = dimColor(data.color || DEFAULT_EDGE_COLOR, 0.6);
    } else {
      res.color = 'rgba(255,255,255,0.02)';
      res.size = 0.25;
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

function selectNode(node) {
  selectedNode = node;
  inspectedEdgeIds.clear();
  if (!node || !graph.hasNode(node)) {
    selectedNeighborhood = null;
    if (renderer) renderer.refresh();
    return;
  }

  selectedNeighborhood = getNeighborhood(node, 1);
  graph.edges(node).forEach((edgeId) => inspectedEdgeIds.add(edgeId));
  if (renderer) renderer.refresh();
  updateMinimap();
}

function clearSelection() {
  selectedNode = null;
  selectedNeighborhood = null;
  inspectedEdgeIds.clear();
  if (renderer) renderer.refresh();
  updateMinimap();
}

function highlightEdges(edgeIds = []) {
  inspectedEdgeIds = new Set(edgeIds.filter((edgeId) => graph.hasEdge(edgeId)));
  if (renderer) renderer.refresh();
  updateMinimap();
}

function getNeighborhood(node, hops = 1) {
  if (!graph || !node || !graph.hasNode(node)) return new Set();

  const visited = new Set([node]);
  let frontier = [node];
  for (let depth = 0; depth < hops; depth++) {
    const next = [];
    for (const current of frontier) {
      for (const neighbor of graph.neighbors(current)) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          next.push(neighbor);
        }
      }
    }
    frontier = next;
    if (frontier.length === 0) break;
  }
  return visited;
}

function showSelection() {
  if (focusNeighborhood?.size) {
    zoomToNodes(focusNeighborhood, { paddingFactor: 1.9, minRatio: 0.08, maxRatio: 1.6 });
    return;
  }
  if (selectedNeighborhood?.size) {
    zoomToNodes(selectedNeighborhood, { paddingFactor: 1.8, minRatio: 0.08, maxRatio: 1.4 });
    return;
  }
  zoomToFit();
}

function getNodeIdsByType(nodeType) {
  const ids = [];
  if (!graph) return ids;
  graph.forEachNode((id, attrs) => {
    if (attrs.nodeType === nodeType) ids.push(id);
  });
  return ids;
}

function getNodeTypeContext(nodeType) {
  const seedIds = getNodeIdsByType(nodeType);
  const visible = new Set(seedIds);
  const presetTypes = new Set(FILTER_PRESETS[nodeType] || [nodeType]);
  for (const nodeId of seedIds) {
    for (const neighbor of graph.neighbors(nodeId)) {
      const neighborType = graph.getNodeAttribute(neighbor, 'nodeType');
      if (neighborType === nodeType || HIGH_SIGNAL_NODE_TYPES.has(neighborType) || presetTypes.has(neighborType)) {
        visible.add(neighbor);
      }
    }
  }
  return visible;
}

function fitVisibleGraph(preferredNodeIds = null, options = {}) {
  const preferred = preferredNodeIds
    ? new Set([...preferredNodeIds].filter((nodeId) => graph.hasNode(nodeId) && isNodeVisible(nodeId)))
    : null;

  if (preferred && preferred.size > 0) {
    zoomToNodes(preferred, { paddingFactor: 1.7, minRatio: 0.08, maxRatio: 2.5, ...options });
    return;
  }

  const visibleNodes = new Set(getVisibleNodeIds());
  if (visibleNodes.size > 0) {
    zoomToNodes(visibleNodes, { paddingFactor: 1.6, minRatio: 0.08, maxRatio: 2.5, ...options });
    return;
  }

  if (renderer) renderer.getCamera().animatedReset({ duration: options.duration || 300 });
}

function focusNodeType(nodeType) {
  emphasizedNodeTypes = new Set([nodeType]);
  clearPathHighlight();
  focusNode = null;
  focusNeighborhood = null;
  selectedNode = null;
  selectedNeighborhood = getNodeTypeContext(nodeType);
  inspectedEdgeIds.clear();
  graphMode = 'overview';

  const graphModeSelect = document.getElementById('graph-mode-select');
  if (graphModeSelect) graphModeSelect.value = 'overview';

  const preset = FILTER_PRESETS[nodeType] || [nodeType];
  activeFilters = new Set(preset.filter((type) => NODE_COLORS[type]));
  buildFilterButtons();
  if (renderer) renderer.refresh();
  fitVisibleGraph(selectedNeighborhood);
  updateMinimap();
}

function focusNodeContext(node, options = {}) {
  if (!graph || !graph.hasNode(node)) return new Set();

  const hops = Math.max(1, options.hops || 1);
  const edgeIds = Array.isArray(options.edgeIds) ? options.edgeIds : [];
  const persistent = options.persistent === true || graphMode === 'focused';

  if (persistent) {
    enterNeighborhoodFocus(node, hops);
  } else {
    selectNode(node);
    zoomToNodes(getNeighborhood(node, hops), {
      paddingFactor: options.paddingFactor || 1.9,
      minRatio: options.minRatio || 0.08,
      maxRatio: options.maxRatio || 1.4,
    });
  }

  if (edgeIds.length > 0) {
    highlightEdges(edgeIds);
  }

  return persistent ? new Set(focusNeighborhood || []) : new Set(selectedNeighborhood || []);
}

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
      if (node === selectedNode) {
        showSelection();
        showNodeDetail(node);
        return;
      }
      selectNode(node);
      showNodeDetail(node);
    }
  });

  renderer.on('doubleClickNode', ({ node }) => {
    enterNeighborhoodFocus(node, 2);
  });

  renderer.on('clickStage', () => {
    clearSelection();
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

function findShortestPath(source, target) {
  if (!graph || !source || !target || !graph.hasNode(source) || !graph.hasNode(target)) {
    return { nodes: new Set(), edges: new Set() };
  }

  const resultNodes = new Set([source, target]);
  const resultEdges = new Set();

  // BFS shortest path (undirected traversal)
  const visited = new Map(); // node → parent
  const edgeUsed = new Map(); // node → edge that led here
  const queue = [source];
  visited.set(source, null);

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
        if (neighbor === target) {
          found = true;
          break;
        }
      }
    }
  }

  if (found) {
    let current = target;
    while (current !== source) {
      resultNodes.add(current);
      const edge = edgeUsed.get(current);
      if (edge) resultEdges.add(edge);
      current = visited.get(current);
    }
  }

  return { nodes: resultNodes, edges: resultEdges };
}

function findAndHighlightPath() {
  if (!pathSource || !pathTarget) return;

  const result = findShortestPath(pathSource, pathTarget);
  pathNodes = result.nodes;
  pathEdges = result.edges;

  if (pathEdges.size > 0) {
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
// Attack Path Overlay
// ============================================================

async function fetchActivityHistory() {
  if (activityHistoryCache) return activityHistoryCache.entries;
  const PAGE_SIZE = 500;
  let allEntries = [];
  let after = undefined;
  try {
    while (true) {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
      if (after) params.set('after', after);
      const res = await fetch(`/api/history?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const page = data.entries || [];
      allEntries = allEntries.concat(page);
      if (page.length < PAGE_SIZE) break; // last page
      after = page[page.length - 1].timestamp;
    }
    activityHistoryCache = { entries: allEntries, knownTotal: allEntries.length };
    return allEntries;
  } catch (err) {
    console.warn('[Overwatch] Failed to fetch activity history:', err);
    return [];
  }
}

function invalidateHistoryCache() {
  activityHistoryCache = null;
}

async function refreshAttackPathIfActive() {
  if (!attackPathOverlay) return;
  invalidateHistoryCache();
  const entries = await fetchActivityHistory();
  const actual = buildActualPath(entries);
  if (actual.nodes.size === 0) return;
  const hadTheoretical = !!attackPathOverlay.theoretical;
  attackPathOverlay = { actual, theoretical: null };
  if (hadTheoretical) {
    showTheoreticalComparison();
  } else {
    const bar = document.getElementById('path-info-bar');
    if (bar) {
      bar.querySelector('.path-label').textContent = `Actual path: ${actual.nodes.size} nodes · ${actual.edges.size} hops`;
      bar.querySelector('.path-edges').textContent = '';
    }
  }
  if (renderer) renderer.refresh();
  updateMinimap();
}

function buildActualPath(activityEntries) {
  if (!graph || !activityEntries || activityEntries.length === 0) {
    return { nodes: new Set(), edges: new Set() };
  }

  const relevantCategories = new Set(['finding', 'inference']);
  const relevantEvents = new Set(['action_completed', 'finding_ingested']);

  // Filter and sort chronologically
  const relevant = activityEntries
    .filter(e => {
      if (!e.target_node_ids || e.target_node_ids.length === 0) return false;
      const catMatch = !e.category || relevantCategories.has(e.category);
      const evtMatch = !e.event_type || relevantEvents.has(e.event_type);
      return catMatch || evtMatch;
    })
    .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

  const orderedNodes = [];
  const seen = new Set();
  for (const entry of relevant) {
    for (const nodeId of entry.target_node_ids) {
      if (graph.hasNode(nodeId) && !seen.has(nodeId)) {
        seen.add(nodeId);
        orderedNodes.push(nodeId);
      }
    }
  }

  const resultNodes = new Set(orderedNodes);
  const resultEdges = new Set();

  // Connect consecutive nodes via graph edges
  for (let i = 0; i < orderedNodes.length - 1; i++) {
    const a = orderedNodes[i];
    const b = orderedNodes[i + 1];
    const edges = graph.edges(a);
    for (const edgeId of edges) {
      const opposite = graph.opposite(a, edgeId);
      if (opposite === b) {
        resultEdges.add(edgeId);
        break;
      }
    }
  }

  return { nodes: resultNodes, edges: resultEdges };
}

async function showAttackPath() {
  clearPathHighlight();
  clearCredentialFlowMode();

  const entries = await fetchActivityHistory();
  const actual = buildActualPath(entries);

  if (actual.nodes.size === 0) {
    console.warn('[Overwatch] No attack path nodes found in activity history');
    return;
  }

  attackPathOverlay = { actual, theoretical: null };

  // Show info in path bar
  const bar = document.getElementById('path-info-bar');
  if (bar) {
    bar.querySelector('.path-label').textContent = `Actual path: ${actual.nodes.size} nodes · ${actual.edges.size} hops`;
    bar.querySelector('.path-edges').textContent = '';
    bar.classList.add('visible');
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function showTheoreticalComparison() {
  if (!attackPathOverlay || attackPathOverlay.actual.nodes.size < 2) return;

  // Find first and last nodes of the actual path
  const nodeArr = [...attackPathOverlay.actual.nodes];
  const source = nodeArr[0];
  const target = nodeArr[nodeArr.length - 1];

  const theoretical = findShortestPath(source, target);
  attackPathOverlay = { ...attackPathOverlay, theoretical };

  // Update info bar
  const bar = document.getElementById('path-info-bar');
  if (bar) {
    bar.querySelector('.path-label').textContent =
      `Actual: ${attackPathOverlay.actual.edges.size} hops │ Shortest: ${theoretical.edges.size} hops`;
    bar.querySelector('.path-edges').textContent = '';
    bar.classList.add('visible');
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function clearTheoreticalComparison() {
  if (!attackPathOverlay) return;
  attackPathOverlay = { ...attackPathOverlay, theoretical: null };

  const bar = document.getElementById('path-info-bar');
  if (bar) {
    bar.querySelector('.path-label').textContent =
      `Actual path: ${attackPathOverlay.actual.nodes.size} nodes · ${attackPathOverlay.actual.edges.size} hops`;
    bar.querySelector('.path-edges').textContent = '';
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function clearAttackPathOverlay() {
  attackPathOverlay = null;

  const bar = document.getElementById('path-info-bar');
  if (bar) bar.classList.remove('visible');

  if (renderer) renderer.refresh();
  updateMinimap();
}

// ============================================================
// Credential Flow Visualization
// ============================================================

function buildCredentialFlowData() {
  if (!graph) return { flowEdges: new Set(), flowNodes: new Set(), chains: [] };

  const CRED_EDGE_TYPES = new Set(['DERIVED_FROM', 'OWNS_CRED', 'VALID_ON', 'POTENTIAL_AUTH', 'DUMPED_FROM']);
  const flowEdges = new Set();
  const flowNodes = new Set();

  // Collect all credential-related edges and their endpoint nodes
  graph.forEachEdge((edgeId, attrs) => {
    if (CRED_EDGE_TYPES.has(attrs.edgeType)) {
      flowEdges.add(edgeId);
      flowNodes.add(graph.source(edgeId));
      flowNodes.add(graph.target(edgeId));
    }
  });

  // Always include all credential nodes
  graph.forEachNode((nodeId, attrs) => {
    if (attrs.nodeType === 'credential') flowNodes.add(nodeId);
  });

  // Build DERIVED_FROM chains using DFS to capture all branches
  const chains = [];
  const credNodes = [...flowNodes].filter(id => graph.hasNode(id) && graph.getNodeAttribute(id, 'nodeType') === 'credential');
  const hasInboundDerivation = new Set();
  graph.forEachEdge((edgeId, attrs) => {
    if (attrs.edgeType === 'DERIVED_FROM') {
      hasInboundDerivation.add(graph.source(edgeId)); // source is the derived cred (points from child → parent)
    }
  });

  // DFS from root credentials (those with no inbound DERIVED_FROM)
  for (const rootId of credNodes) {
    if (hasInboundDerivation.has(rootId)) continue;

    const treeNodes = [];
    const visited = new Set();

    function dfs(nodeId) {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      treeNodes.push({
        id: nodeId,
        label: graph.getNodeAttribute(nodeId, 'label') || nodeId,
        method: graph.getNodeAttribute(nodeId, '_props')?.derivation_method || null,
      });
      for (const edgeId of graph.edges(nodeId)) {
        const attrs = graph.getEdgeAttributes(edgeId);
        if (attrs.edgeType !== 'DERIVED_FROM') continue;
        const neighbor = graph.opposite(nodeId, edgeId);
        if (!visited.has(neighbor) && graph.getNodeAttribute(neighbor, 'nodeType') === 'credential') {
          dfs(neighbor);
        }
      }
    }

    dfs(rootId);
    if (treeNodes.length > 1) {
      chains.push(treeNodes);
    }
  }

  return { flowEdges, flowNodes, chains };
}

function showCredentialFlow() {
  clearPathHighlight();
  clearAttackPathOverlay();

  credFlowData = buildCredentialFlowData();
  credentialFlowMode = true;

  // Auto-enable credential filter if hidden
  if (!activeFilters.has('credential')) {
    activeFilters.add('credential');
    buildFilterButtons();
  }

  // Show info in path bar
  const bar = document.getElementById('path-info-bar');
  if (bar) {
    const credCount = [...credFlowData.flowNodes].filter(id =>
      graph.hasNode(id) && graph.getNodeAttribute(id, 'nodeType') === 'credential'
    ).length;
    bar.querySelector('.path-label').textContent =
      `${credCount} credentials · ${credFlowData.chains.length} derivation chains · ${credFlowData.flowEdges.size} auth edges`;
    bar.querySelector('.path-edges').textContent = '';
    bar.classList.add('visible');
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function clearCredentialFlowMode() {
  credentialFlowMode = false;
  credFlowData = null;

  const bar = document.getElementById('path-info-bar');
  if (bar) bar.classList.remove('visible');

  if (renderer) renderer.refresh();
  updateMinimap();
}

function clearAllOverlays() {
  // Clear all three overlay modes without redundant refreshes
  pathSource = null;
  pathTarget = null;
  pathEdges.clear();
  pathNodes.clear();
  attackPathOverlay = null;
  credentialFlowMode = false;
  credFlowData = null;
  edgeTypeFilter = null;
  edgeSourceFilter = null;

  const bar = document.getElementById('path-info-bar');
  if (bar) bar.classList.remove('visible');

  // Reset Layers dropdown button states
  const ap = document.getElementById('btn-layer-attack-path');
  const cs = document.getElementById('btn-layer-compare-shortest');
  const cf = document.getElementById('btn-layer-cred-flow');
  if (ap) ap.dataset.active = 'false';
  if (cs) { cs.dataset.active = 'false'; cs.disabled = true; }
  if (cf) cf.dataset.active = 'false';

  // Reset edge filter UI
  document.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
  const confBtn = document.getElementById('btn-edge-confirmed');
  const infBtn = document.getElementById('btn-edge-inferred');
  if (confBtn) confBtn.dataset.active = 'false';
  if (infBtn) infBtn.dataset.active = 'false';

  if (renderer) renderer.refresh();
  updateMinimap();
}

// ============================================================
// Edge Type Filter
// ============================================================

function setEdgeTypeFilter(edgeType) {
  // Toggle off if same type
  if (edgeTypeFilter && edgeTypeFilter.type === edgeType) {
    clearEdgeFilter();
    return;
  }
  // Clear other overlays
  attackPathOverlay = null;
  credentialFlowMode = false;
  credFlowData = null;
  pathEdges.clear();
  pathNodes.clear();
  edgeSourceFilter = null;
  edgeTypeFilter = { type: edgeType };

  // Count matching edges
  let count = 0;
  graph.forEachEdge((edge, attrs) => {
    if (attrs.edgeType === edgeType) count++;
  });

  const bar = document.getElementById('path-info-bar');
  if (bar) {
    bar.querySelector('.path-label').textContent = `Showing: ${count} ${edgeType} edge${count !== 1 ? 's' : ''}`;
    bar.querySelector('.path-edges').textContent = '';
    bar.classList.add('visible');
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function setEdgeSourceFilter(source) {
  // Toggle off if same source
  if (edgeSourceFilter === source) {
    clearEdgeFilter();
    return;
  }
  // Clear other overlays
  attackPathOverlay = null;
  credentialFlowMode = false;
  credFlowData = null;
  pathEdges.clear();
  pathNodes.clear();
  edgeTypeFilter = null;
  edgeSourceFilter = source;

  let count = 0;
  graph.forEachEdge((edge, attrs) => {
    const isInferred = !!attrs.inferredByRule;
    if ((source === 'inferred' && isInferred) || (source === 'confirmed' && !isInferred)) count++;
  });

  const label = source === 'confirmed' ? 'confirmed' : 'inferred';
  const bar = document.getElementById('path-info-bar');
  if (bar) {
    bar.querySelector('.path-label').textContent = `Showing: ${count} ${label} edge${count !== 1 ? 's' : ''}`;
    bar.querySelector('.path-edges').textContent = '';
    bar.classList.add('visible');
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function clearEdgeFilter() {
  edgeTypeFilter = null;
  edgeSourceFilter = null;

  if (typeof document !== 'undefined') {
    const bar = document.getElementById('path-info-bar');
    if (bar) bar.classList.remove('visible');
    document.querySelectorAll('.edge-type-row.active').forEach(el => el.classList.remove('active'));
    const confBtn = document.getElementById('btn-edge-confirmed');
    const infBtn = document.getElementById('btn-edge-inferred');
    if (confBtn) confBtn.dataset.active = 'false';
    if (infBtn) infBtn.dataset.active = 'false';
  }

  if (renderer) renderer.refresh();
  updateMinimap();
}

function getEdgeTypeCounts() {
  const counts = new Map();
  if (!graph) return counts;
  graph.forEachEdge((edge, attrs) => {
    const et = attrs.edgeType || '?';
    if (!counts.has(et)) counts.set(et, { total: 0, confirmed: 0, inferred: 0 });
    const entry = counts.get(et);
    entry.total++;
    if (attrs.inferredByRule) entry.inferred++;
    else entry.confirmed++;
  });
  return counts;
}

// ============================================================
// Neighborhood Focus
// ============================================================

function enterNeighborhoodFocus(node, hops) {
  selectNode(node);
  focusNode = node;
  focusNeighborhood = getNeighborhood(node, hops);

  // Show banner
  const banner = document.getElementById('focus-banner');
  if (banner) {
    const label = graph.getNodeAttribute(node, 'label') || node;
    banner.querySelector('.focus-label').textContent = `Focused on "${label}" (${hops}-hop, ${focusNeighborhood.size} nodes)`;
    banner.classList.add('visible');
  }

  if (renderer) renderer.refresh();

  // Zoom to fit the focused neighborhood
  zoomToNodes(focusNeighborhood, { paddingFactor: 2, minRatio: 0.08, maxRatio: 1.6 });
}

function clearFocusState() {
  focusNode = null;
  focusNeighborhood = null;

  const banner = document.getElementById('focus-banner');
  if (banner) banner.classList.remove('visible');
}

function exitNeighborhoodFocus() {
  clearFocusState();

  if (renderer) renderer.refresh();
  if (graphMode === 'focused') {
    zoomToNodes(selectedNeighborhood || new Set(getVisibleNodeIds()));
  } else {
    showSelection();
  }
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
    inferredByRule: props.inferred_by_rule || null,
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
  if (selectedNode && !graph.hasNode(selectedNode)) {
    clearSelection();
  } else if (selectedNeighborhood) {
    selectedNeighborhood = new Set([...selectedNeighborhood].filter(nodeId => graph.hasNode(nodeId)));
  }

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

  const positions = groupInitialPositions(graphData.nodes, graphData.edges || []);
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
        label: window.OverwatchNodeDisplay.getNodeDisplayLabel(props, node.id),
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
        label: window.OverwatchNodeDisplay.getNodeDisplayLabel(props, node.id),
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

function groupInitialPositions(nodes, edges = []) {
  const positions = {};
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const domains = nodes.filter(node => (node.properties || {}).type === 'domain');
  const hosts = nodes.filter(node => (node.properties || {}).type === 'host');
  const objectives = nodes.filter(node => (node.properties || {}).type === 'objective');
  const hostAnchors = new Map();
  const domainAnchors = new Map();

  domains.forEach((domainNode, idx) => {
    const x = (idx - (domains.length - 1) / 2) * 12;
    const y = -12;
    positions[domainNode.id] = { x, y };
    domainAnchors.set(domainNode.id, { x, y });
  });

  objectives.forEach((objectiveNode, idx) => {
    positions[objectiveNode.id] = { x: 18 + idx * 5, y: 12 + idx * 3 };
  });

  const domainHostBuckets = new Map();
  const domainLabels = domains.map(domainNode => ({
    id: domainNode.id,
    label: ((domainNode.properties || {}).label || '').toLowerCase(),
  }));

  function resolveDomainAnchorForHost(hostNode, hostIndex) {
    const props = hostNode.properties || {};
    const hostLabel = `${props.hostname || ''} ${props.label || ''}`.toLowerCase();
    let match = domainLabels.find(domain => domain.label && hostLabel.includes(domain.label));
    if (!match && domainLabels.length > 0) {
      match = domainLabels[hostIndex % domainLabels.length];
    }
    return match?.id;
  }

  hosts.forEach((hostNode, hostIndex) => {
    const domainId = resolveDomainAnchorForHost(hostNode, hostIndex) || 'ungrouped';
    const bucket = domainHostBuckets.get(domainId) || [];
    bucket.push(hostNode);
    domainHostBuckets.set(domainId, bucket);
  });

  [...domainHostBuckets.entries()].forEach(([domainId, bucket], bucketIndex) => {
    const anchor = domainAnchors.get(domainId) || { x: (bucketIndex - (domainHostBuckets.size - 1) / 2) * 12, y: -12 };
    bucket.forEach((hostNode, idx) => {
      const column = idx % 3;
      const row = Math.floor(idx / 3);
      const x = anchor.x + (column - 1) * 7;
      const y = anchor.y + 8 + row * 7;
      positions[hostNode.id] = { x, y };
      hostAnchors.set(hostNode.id, { x, y });
    });
  });

  const preferredAnchorTypes = {
    service: new Set(['host']),
    share: new Set(['host']),
    credential: new Set(['host', 'domain']),
    certificate: new Set(['host', 'domain']),
    ca: new Set(['domain', 'host']),
    cert_template: new Set(['ca', 'domain']),
    pki_store: new Set(['ca', 'domain']),
    user: new Set(['domain', 'host']),
    group: new Set(['domain']),
    ou: new Set(['domain']),
    gpo: new Set(['domain']),
  };

  function hashId(value) {
    let hash = 0;
    for (let i = 0; i < value.length; i++) {
      hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
    }
    return hash;
  }

  function findAnchorId(nodeId, type) {
    const preferred = preferredAnchorTypes[type] || new Set(['host', 'domain', 'objective']);
    const related = edges
      .filter(edge => edge.source === nodeId || edge.target === nodeId)
      .map(edge => edge.source === nodeId ? edge.target : edge.source)
      .filter(counterpartId => positions[counterpartId]);

    const preferredMatch = related.find(counterpartId => preferred.has((nodeMap.get(counterpartId)?.properties || {}).type));
    return preferredMatch || related[0] || null;
  }

  function getOrbitRadius(type) {
    if (type === 'service') return 4.5;
    if (type === 'share') return 5.2;
    if (type === 'credential' || type === 'certificate' || type === 'ca') return 5.8;
    if (type === 'cert_template') return 6.4;
    if (type === 'user') return 6.6;
    if (type === 'group' || type === 'ou' || type === 'gpo' || type === 'pki_store') return 8.2;
    return 6;
  }

  function getOrbitalPosition(anchor, nodeId, type, index, total) {
    const baseRadius = getOrbitRadius(type);
    const hash = hashId(nodeId);
    const radius = baseRadius + ((hash % 5) - 2) * 0.18;
    const isHostSatellite = type === 'service' || type === 'share';
    const start = isHostSatellite ? -Math.PI * 0.9 : -Math.PI;
    const sweep = isHostSatellite ? Math.PI * 1.8 : Math.PI * 2;
    const slotRatio = total <= 1 ? (hash % 360) / 360 : index / Math.max(total - 1, 1);
    const angle = start + sweep * slotRatio + (((hash >> 3) % 13) - 6) * 0.012;
    return {
      x: anchor.x + radius * Math.cos(angle),
      y: anchor.y + radius * Math.sin(angle),
    };
  }

  const buckets = new Map();
  const unanchored = [];

  nodes.forEach((node) => {
    if (positions[node.id]) return;
    const type = (node.properties || {}).type || 'host';
    const anchorId = findAnchorId(node.id, type);
    if (!anchorId) {
      unanchored.push(node);
      return;
    }
    const bucketKey = `${anchorId}::${type}`;
    if (!buckets.has(bucketKey)) {
      buckets.set(bucketKey, { anchorId, type, nodes: [] });
    }
    buckets.get(bucketKey).nodes.push(node);
  });

  buckets.forEach((bucket) => {
    const anchor = positions[bucket.anchorId];
    if (!anchor) return;
    bucket.nodes
      .sort((a, b) => a.id.localeCompare(b.id))
      .forEach((node, idx) => {
        positions[node.id] = getOrbitalPosition(anchor, node.id, bucket.type, idx, bucket.nodes.length);
      });
  });

  unanchored.forEach((node, idx) => {
    positions[node.id] = {
      x: (idx % 6) * 5 - 12,
      y: 6 + Math.floor(idx / 6) * 5,
    };
  });

  return positions;
}

function loadGraphData(graphData) {
  syncGraphData(graphData, { preservePositions: false, resetLayout: true });
}

function mergeGraphDelta(delta) {
  if (!delta) return;
  let added = false;
  let structureChanged = false;
  const addedNodeIds = [];
  const deltaEdges = delta.edges || [];

  // Remove edges first (before removing nodes, since edges reference them)
  if (delta.removed_edges && delta.removed_edges.length > 0) {
    for (const edgeId of delta.removed_edges) {
      if (graph.hasEdge(edgeId)) {
        graph.dropEdge(edgeId);
        structureChanged = true;
      }
    }
  }

  // Remove nodes
  if (delta.removed_nodes && delta.removed_nodes.length > 0) {
    for (const nodeId of delta.removed_nodes) {
      if (graph.hasNode(nodeId)) {
        graph.dropNode(nodeId);
        structureChanged = true;
      }
    }
  }

  // Upsert nodes
  if (delta.nodes) {
    delta.nodes.forEach((n) => {
      const props = n.properties || {};
      const nodeType = props.type || 'host';
      if (graph.hasNode(n.id)) {
        graph.mergeNodeAttributes(n.id, {
          label: window.OverwatchNodeDisplay.getNodeDisplayLabel(props, n.id),
          color: NODE_COLORS[nodeType] || '#888',
          nodeType: nodeType,
          _props: props,
        });
      } else {
        const anchorEdge = deltaEdges.find((edge) =>
          (edge.source === n.id && graph.hasNode(edge.target)) ||
          (edge.target === n.id && graph.hasNode(edge.source))
        );
        const anchorId = anchorEdge
          ? (anchorEdge.source === n.id ? anchorEdge.target : anchorEdge.source)
          : null;
        const anchorPos = anchorId && graph.hasNode(anchorId)
          ? graph.getNodeAttributes(anchorId)
          : null;
        const siblingCount = anchorId
          ? graph.edges(anchorId).filter((edgeId) => {
              const oppositeId = graph.opposite(anchorId, edgeId);
              return graph.hasNode(oppositeId) && graph.getNodeAttribute(oppositeId, 'nodeType') === nodeType;
            }).length
          : 0;
        const hash = n.id.split('').reduce((acc, ch) => ((acc * 31) + ch.charCodeAt(0)) >>> 0, 0);
        const baseRadius = DETAIL_NODE_TYPES.has(nodeType) ? 4.5 : SUPPORTING_NODE_TYPES.has(nodeType) ? 6.4 : 5.4;
        const radius = baseRadius + ((hash % 5) - 2) * 0.18;
        const angleSpread = DETAIL_NODE_TYPES.has(nodeType) ? Math.PI * 1.7 : Math.PI * 2;
        const angleStart = DETAIL_NODE_TYPES.has(nodeType) ? -Math.PI * 0.85 : -Math.PI;
        const slotRatio = siblingCount === 0 ? (hash % 360) / 360 : siblingCount / (siblingCount + 1);
        const angle = angleStart + angleSpread * slotRatio;
        graph.addNode(n.id, {
          label: window.OverwatchNodeDisplay.getNodeDisplayLabel(props, n.id),
          x: anchorPos ? anchorPos.x + radius * Math.cos(angle) : radius * Math.cos(angle),
          y: anchorPos ? anchorPos.y + radius * Math.sin(angle) : radius * Math.sin(angle),
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
  if (added || structureChanged) {
    graph.forEachNode((id, attrs) => {
      const degree = graph.degree(id);
      graph.setNodeAttribute(id, 'size', computeNodeSize(attrs.nodeType, degree));
    });
    buildFilterButtons();
  }

  // Animate new nodes
  if (addedNodeIds.length > 0) {
    pulseNewNodes(addedNodeIds);
  }

  if (added) {
    startLayout();
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
  emphasizedNodeTypes.clear();
  activeFilters = new Set(Object.keys(NODE_COLORS));
  buildFilterButtons();
  clearPathHighlight();
  clearFocusState();
  selectedNode = null;
  selectedNeighborhood = null;
  inspectedEdgeIds.clear();
  graphMode = 'overview';
  labelDensity = 'balanced';
  const graphModeSelect = document.getElementById('graph-mode-select');
  if (graphModeSelect) graphModeSelect.value = 'overview';
  const labelDensitySelect = document.getElementById('label-density-select');
  if (labelDensitySelect) labelDensitySelect.value = 'balanced';
  if (typeof clearFrontierTypeFilter === 'function') clearFrontierTypeFilter();
  if (renderer) renderer.refresh();
  fitVisibleGraph();
  updateMinimap();
}

function setGraphMode(mode) {
  graphMode = ['overview', 'focused', 'raw'].includes(mode) ? mode : 'overview';
  if (graphMode === 'focused' && selectedNode && !focusNeighborhood) {
    enterNeighborhoodFocus(selectedNode, 1);
  }
  if (graphMode !== 'focused' && focusNeighborhood) {
    clearFocusState();
  }
  if (renderer) renderer.refresh();
  updateMinimap();
}

function setLabelDensity(mode) {
  labelDensity = ['minimal', 'balanced', 'verbose'].includes(mode) ? mode : 'balanced';
  if (renderer) renderer.refresh();
}

// ============================================================
// Camera Controls
// ============================================================

function zoomToFit() {
  fitVisibleGraph();
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

function zoomToNodes(nodeSet, options = {}) {
  if (!renderer || nodeSet.size === 0) return;

  // Use getNodeDisplayData to get positions in sigma's camera coordinate space
  let minX = Infinity, maxX = -Infinity;
  let minY = Infinity, maxY = -Infinity;
  let count = 0;

  for (const nodeId of nodeSet) {
    if (!graph.hasNode(nodeId)) continue;
    const displayData = renderer.getNodeDisplayData(nodeId);
    if (!displayData || displayData.hidden) continue;
    minX = Math.min(minX, displayData.x);
    maxX = Math.max(maxX, displayData.x);
    minY = Math.min(minY, displayData.y);
    maxY = Math.max(maxY, displayData.y);
    count++;
  }

  if (count === 0) return;

  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
  const dx = maxX - minX;
  const dy = maxY - minY;

  const paddingFactor = options.paddingFactor || 1.5;
  const minRatio = options.minRatio || 0.05;
  const maxRatio = options.maxRatio || 2.5;

  // In sigma's normalized space, ratio controls zoom (1 = full graph visible)
  // The spread in display coords directly maps to the needed ratio
  const spread = Math.max(dx, dy);
  const ratio = spread > 0.001
    ? Math.min(Math.max(spread * paddingFactor, minRatio), maxRatio)
    : minRatio * 3; // Single node or tight cluster: moderate zoom

  renderer.getCamera().animate({ x: cx, y: cy, ratio }, { duration: options.duration || 400 });
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

  // Use display data (sigma's camera coordinate space) for all minimap rendering
  const visibleNodeIds = getVisibleNodeIds();
  if (visibleNodeIds.length === 0) return;

  // Collect display positions for visible nodes
  const nodeDisplayPositions = [];
  visibleNodeIds.forEach((nodeId) => {
    const dd = renderer.getNodeDisplayData(nodeId);
    if (!dd || dd.hidden) return;
    nodeDisplayPositions.push({ id: nodeId, x: dd.x, y: dd.y, color: dd.color || graph.getNodeAttribute(nodeId, 'color') || '#888' });
  });
  if (nodeDisplayPositions.length === 0) return;

  // Compute bounds in display space
  let minX = Infinity, maxX = -Infinity;
  let minY = Infinity, maxY = -Infinity;
  nodeDisplayPositions.forEach(({ x, y }) => {
    minX = Math.min(minX, x);
    maxX = Math.max(maxX, x);
    minY = Math.min(minY, y);
    maxY = Math.max(maxY, y);
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
    const sd = renderer.getNodeDisplayData(src);
    const td = renderer.getNodeDisplayData(tgt);
    if (!sd || !td) return;
    ctx.moveTo(ox + (sd.x - minX) * scale, oy + (sd.y - minY) * scale);
    ctx.lineTo(ox + (td.x - minX) * scale, oy + (td.y - minY) * scale);
  });
  ctx.stroke();

  // Draw nodes
  nodeDisplayPositions.forEach(({ x, y, color }) => {
    const nx = ox + (x - minX) * scale;
    const ny = oy + (y - minY) * scale;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(nx, ny, 2, 0, 2 * Math.PI);
    ctx.fill();
  });

  // Draw viewport rectangle — camera state is in the same display space
  const camera = renderer.getCamera();
  const state = camera.getState();
  const halfW = state.ratio * 0.5;
  const halfH = state.ratio * 0.5;
  ctx.strokeStyle = '#6e9eff';
  ctx.lineWidth = 2;
  ctx.strokeRect(
    ox + (state.x - halfW - minX) * scale,
    oy + (state.y - halfH - minY) * scale,
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

function exportSVG() {
  if (!renderer || !graph) return;

  const visibleNodes = getVisibleNodeIds();
  const visibleEdges = getVisibleEdgeIds();

  if (visibleNodes.length === 0) {
    // Empty graph — export blank SVG
    const emptySvg = `<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600"><rect width="800" height="600" fill="#080a0f"/></svg>`;
    triggerSVGDownload(emptySvg);
    return;
  }

  // Collect display data for visible nodes
  const nodeData = [];
  for (const nodeId of visibleNodes) {
    const dd = renderer.getNodeDisplayData(nodeId);
    if (!dd || dd.hidden) continue;
    const attrs = graph.getNodeAttributes(nodeId);
    const showLabel = shouldShowLabel(nodeId, attrs);
    nodeData.push({
      id: nodeId,
      x: dd.x,
      y: dd.y,
      size: dd.size || 5,
      color: dd.color || attrs.color || '#888',
      label: showLabel ? (dd.label || attrs.label || '') : '',
    });
  }

  if (nodeData.length === 0) {
    const emptySvg = `<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600"><rect width="800" height="600" fill="#080a0f"/></svg>`;
    triggerSVGDownload(emptySvg);
    return;
  }

  // Compute bounding box
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

  const escXml = (str) => str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  // Build edges SVG
  const edgeLines = [];
  for (const edgeId of visibleEdges) {
    const src = graph.source(edgeId);
    const tgt = graph.target(edgeId);
    const srcDD = renderer.getNodeDisplayData(src);
    const tgtDD = renderer.getNodeDisplayData(tgt);
    if (!srcDD || !tgtDD || srcDD.hidden || tgtDD.hidden) continue;
    const edgeDD = renderer.getEdgeDisplayData(edgeId);
    const edgeAttrs = graph.getEdgeAttributes(edgeId);
    const color = (edgeDD && edgeDD.color) || edgeAttrs.color || '#444';
    const size = (edgeDD && edgeDD.size) || edgeAttrs.size || 0.5;
    edgeLines.push(`<line x1="${srcDD.x}" y1="${srcDD.y}" x2="${tgtDD.x}" y2="${tgtDD.y}" stroke="${escXml(color)}" stroke-width="${size}" stroke-opacity="0.8"/>`);
  }

  // Build nodes SVG
  const nodeCircles = [];
  const nodeLabels = [];
  for (const n of nodeData) {
    nodeCircles.push(`<circle cx="${n.x}" cy="${n.y}" r="${n.size}" fill="${escXml(n.color)}"/>`);
    if (n.label) {
      nodeLabels.push(`<text x="${n.x}" y="${n.y - n.size - 3}" text-anchor="middle" fill="#c8cdd3" font-size="${Math.max(n.size * 0.8, 4)}" font-family="Inter, system-ui, sans-serif">${escXml(n.label)}</text>`);
    }
  }

  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vbX} ${vbY} ${vbW} ${vbH}" width="${Math.round(vbW)}" height="${Math.round(vbH)}">`,
    `<rect x="${vbX}" y="${vbY}" width="${vbW}" height="${vbH}" fill="#080a0f"/>`,
    `<g class="edges">${edgeLines.join('')}</g>`,
    `<g class="nodes">${nodeCircles.join('')}</g>`,
    `<g class="labels">${nodeLabels.join('')}</g>`,
    `</svg>`,
  ].join('\n');

  triggerSVGDownload(svg);
}

function triggerSVGDownload(svgString) {
  const blob = new Blob([svgString], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.download = `overwatch-graph-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.svg`;
  link.href = url;
  link.click();
  URL.revokeObjectURL(url);
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
  fitVisibleGraph,
  clearPathHighlight,
  exitNeighborhoodFocus,
  enterNeighborhoodFocus,
  focusNodeType,
  setActiveFilters,
  exportScreenshot,
  exportSVG,
  updateMinimap,
  getVisibleNodeIds,
  getVisibleEdgeIds,
  exceededDragThreshold,
  selectNode,
  clearSelection,
  highlightEdges,
  focusNodeContext,
  showSelection,
  setGraphMode,
  setLabelDensity,
  // Attack path overlay
  fetchActivityHistory,
  invalidateHistoryCache,
  refreshAttackPathIfActive,
  showAttackPath,
  clearAttackPathOverlay,
  showTheoreticalComparison,
  clearTheoreticalComparison,
  // Credential flow
  showCredentialFlow,
  clearCredentialFlowMode,
  clearAllOverlays,
  buildCredentialFlowData,
  // Path helpers
  findShortestPath,
  buildActualPath,
  // Edge type filter
  setEdgeTypeFilter,
  setEdgeSourceFilter,
  clearEdgeFilter,
  getEdgeTypeCounts,
  get graph() { return graph; },
  get renderer() { return renderer; },
  get layoutRunning() { return layoutRunning; },
  get graphMode() { return graphMode; },
  get attackPathOverlay() { return attackPathOverlay; },
  get activityHistoryCacheTotal() { return activityHistoryCache ? activityHistoryCache.knownTotal : 0; },
  get credentialFlowMode() { return credentialFlowMode; },
  get credFlowData() { return credFlowData; },
  get edgeTypeFilter() { return edgeTypeFilter; },
  get edgeSourceFilter() { return edgeSourceFilter; },
  EDGE_CATEGORIES,
  NODE_COLORS,
  NODE_BASE_SIZES,
};
