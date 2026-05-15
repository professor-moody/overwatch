import type { ExportedGraph, FrontierItem, PendingAction, SessionInfo } from './types';
import type { FindingDto } from './api';

export interface NodeRelationshipInput {
  graph?: ExportedGraph;
  sessions?: SessionInfo[];
  pendingActions?: PendingAction[];
  frontier?: FrontierItem[];
  findings?: FindingDto[];
}

export interface NodeRelationships {
  sessions: SessionInfo[];
  pendingActions: PendingAction[];
  frontier: FrontierItem[];
  findings: FindingDto[];
}

function clean(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function getSessionNodeIds(session: SessionInfo): string[] {
  return [
    session.target_node,
    session.principal_node,
    session.credential_node,
  ].map(clean).filter((v): v is string => !!v);
}

export function getActionNodeIds(action: PendingAction): string[] {
  return [
    action.target_node,
    action.target,
  ].map(clean).filter((v): v is string => !!v);
}

export function getFrontierNodeIds(item: FrontierItem): string[] {
  return [
    item.target_node,
    item.source_node,
    item.node_id,
    item.edge_source,
    item.edge_target,
  ].map(clean).filter((v): v is string => !!v);
}

export function buildAssetNodeMatcher(graph: ExportedGraph | undefined): (asset: string, nodeId: string) => boolean {
  const byNode = new Map<string, Set<string>>();
  for (const node of graph?.nodes || []) {
    const values = new Set<string>();
    for (const value of [
      node.id,
      node.label,
      node.hostname,
      node.ip,
      node.username,
      node.domain,
    ]) {
      const text = clean(value);
      if (text) values.add(text.toLowerCase());
    }
    byNode.set(node.id, values);
  }

  return (asset, nodeId) => {
    const needle = asset.toLowerCase();
    if (needle === nodeId.toLowerCase()) return true;
    const values = byNode.get(nodeId);
    return !!values?.has(needle);
  };
}

export function resolveAssetToNodeId(asset: string, graph: ExportedGraph | undefined): string | null {
  const matcher = buildAssetNodeMatcher(graph);
  for (const node of graph?.nodes || []) {
    if (matcher(asset, node.id)) return node.id;
  }
  return null;
}

export function findingMatchesNode(finding: FindingDto, nodeId: string, graph?: ExportedGraph): boolean {
  const matches = buildAssetNodeMatcher(graph);
  return finding.affected_assets.some(asset => matches(asset, nodeId));
}

export function deriveNodeRelationships(nodeId: string, input: NodeRelationshipInput): NodeRelationships {
  return {
    sessions: (input.sessions || []).filter(session => getSessionNodeIds(session).includes(nodeId)),
    pendingActions: (input.pendingActions || []).filter(action => getActionNodeIds(action).includes(nodeId)),
    frontier: (input.frontier || []).filter(item => getFrontierNodeIds(item).includes(nodeId)),
    findings: (input.findings || []).filter(finding => findingMatchesNode(finding, nodeId, input.graph)),
  };
}

export function nodeHasRelationships(relationships: NodeRelationships): boolean {
  return relationships.sessions.length > 0
    || relationships.pendingActions.length > 0
    || relationships.frontier.length > 0
    || relationships.findings.length > 0;
}
