// ============================================================
// Graph node/edge shape normalization.
//
// The backend's engine.exportGraph() emits the wrapped form
// `{ id, properties: {...} }` for both nodes and edges. The dashboard
// panel code (IdentityPanel, AttackPathsPanel, EvidencePanel, etc.)
// was written against the flat form `{ id, type, label, ... }` — the
// shape ExportedNode declares.
//
// The store applies these flatteners on every full_state /
// graph_update push so panels can read flat fields without each
// one knowing about the wire shape. Idempotent for already-flat
// inputs.
// ============================================================

import type { ExportedNode, ExportedEdge } from './types';

export function flattenNode(
  n: ExportedNode | (ExportedNode & { properties?: Record<string, unknown> }),
): ExportedNode {
  const props = (n as { properties?: Record<string, unknown> }).properties;
  if (props && typeof props === 'object') {
    // Spread props twice so any explicit top-level keys win on the
    // outside but defaults flow from props on the inside, while id
    // remains canonical from the wrapper.
    return { ...(props as Record<string, unknown>), ...n, ...props, id: n.id } as ExportedNode;
  }
  return n as ExportedNode;
}

export function flattenEdge(
  e: ExportedEdge | (ExportedEdge & { properties?: Record<string, unknown> }),
): ExportedEdge {
  const props = (e as { properties?: Record<string, unknown> }).properties;
  if (props && typeof props === 'object') {
    return {
      ...(props as Record<string, unknown>),
      ...e,
      ...props,
      id: e.id,
      source: e.source,
      target: e.target,
    } as ExportedEdge;
  }
  return e as ExportedEdge;
}
