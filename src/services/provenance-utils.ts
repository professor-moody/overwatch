import type { NodeProperties } from '../types.js';

export function getNodeFirstSeenAt(node: NodeProperties): string | undefined {
  return node.first_seen_at || node.discovered_at;
}

export function getNodeLastSeenAt(node: NodeProperties): string | undefined {
  return node.last_seen_at || getNodeFirstSeenAt(node);
}

export function getNodeSources(node: NodeProperties): string[] {
  const values = Array.isArray(node.sources) ? node.sources : [];
  if (node.discovered_by && !values.includes(node.discovered_by)) {
    return [...values, node.discovered_by];
  }
  return [...values];
}

export function normalizeNodeProvenance(node: NodeProperties): Partial<NodeProperties> {
  const firstSeenAt = getNodeFirstSeenAt(node);
  const lastSeenAt = getNodeLastSeenAt(node);
  const sources = getNodeSources(node);

  return {
    first_seen_at: firstSeenAt,
    last_seen_at: lastSeenAt,
    sources: sources.length > 0 ? sources : undefined,
    discovered_at: node.discovered_at || firstSeenAt,
    discovered_by: node.discovered_by,
  };
}
