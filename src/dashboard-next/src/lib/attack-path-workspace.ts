import type { AttackPath, AttackPathNode, ExportedNode } from './types';
import { tierForNode, tiersForPath, type Tier } from './tier';

export type AttackPathGroup = 'fast_wins' | 'cloud_reach' | 'identity_pivots' | 'higher_risk';
export type AttackPathLaneFilter = 'all' | AttackPathGroup;
export type AttackPathRiskTone = 'success' | 'warning' | 'danger';

export interface ComputedAttackPathLike {
  nodes: string[];
  edge_types: string[];
  edge_ids?: string[];
  total_confidence: number;
  total_opsec_noise: number;
  tiers?: Set<Tier>;
  weight?: number;
}

export interface DisplayPathNode {
  id: string;
  label: string;
  type?: string;
  tier: Tier;
}

export interface DisplayPathEdge {
  id?: string;
  rawType: string;
  label: string;
}

export interface DisplayAttackPath {
  id: string;
  group: AttackPathGroup;
  groupLabel: string;
  groupDescription: string;
  headline: string;
  reason: string;
  source: DisplayPathNode;
  target: DisplayPathNode;
  nodes: DisplayPathNode[];
  edges: DisplayPathEdge[];
  nodeIds: string[];
  edgeIds: string[];
  rawEdgeTypes: string[];
  tiers: Tier[];
  hopCount: number;
  totalConfidence: number;
  totalNoise: number;
  confidenceLabel: string;
  riskLabel: string;
  riskTone: AttackPathRiskTone;
}

export const ATTACK_PATH_GROUPS: Array<{
  key: AttackPathGroup;
  label: string;
  description: string;
}> = [
  { key: 'fast_wins', label: 'Fast wins', description: 'Short, lower-noise routes from current access.' },
  { key: 'cloud_reach', label: 'Cloud reach', description: 'Routes that cross into cloud identities, policies, or resources.' },
  { key: 'identity_pivots', label: 'Identity pivots', description: 'Routes that use SSO, principals, groups, or token relationships.' },
  { key: 'higher_risk', label: 'Higher risk', description: 'Noisier or lower-confidence routes that need OPSEC review.' },
];

const EDGE_LABELS: Record<string, string> = {
  ADMIN_TO: 'admin path',
  ASSIGNED_TO_APP: 'assigned app',
  ASSUMES_ROLE: 'assumes role',
  AUTHENTICATES_VIA: 'SSO',
  BACKED_BY: 'backend',
  CAN_REACH: 'reaches',
  CAN_RDPINTO: 'RDP',
  CAN_PSREMOTE: 'PowerShell',
  FEDERATES_WITH: 'federation',
  HAS_POLICY: 'policy',
  HAS_SESSION: 'session',
  HOSTS: 'hosts',
  ISSUES_TOKENS_FOR: 'token issue',
  MANAGED_BY: 'managed by',
  MEMBER_OF: 'member',
  MEMBER_OF_DOMAIN: 'domain member',
  OWNS_CRED: 'credential',
  POLICY_ALLOWS: 'policy allows',
  RUNS: 'runs',
  TESTED_CRED: 'tested cred',
  VALID_FOR_APP: 'app access',
  VALID_FOR_IDP_PRINCIPAL: 'valid identity',
  VALID_ON: 'valid on',
  VULNERABLE_TO: 'vulnerable',
};

function pathNodeId(node: AttackPathNode | string): string {
  return typeof node === 'string' ? node : node.id;
}

function nodeFromApi(node: AttackPathNode | string, byId: Map<string, ExportedNode>): DisplayPathNode {
  const id = pathNodeId(node);
  const known = byId.get(id);
  const objectNode = typeof node === 'string' ? undefined : node;
  const type = known?.type || objectNode?.type;
  const label = objectNode?.label || known?.label || id;
  const tier = known
    ? tierForNode(known)
    : tierForNode(type ? ({ id, label, type } as ExportedNode) : undefined);
  return { id, label, type, tier };
}

function nodeFromId(id: string, byId: Map<string, ExportedNode>): DisplayPathNode {
  const known = byId.get(id);
  return {
    id,
    label: known?.label || id,
    type: known?.type,
    tier: tierForNode(known),
  };
}

function edgeLabel(type: string | undefined): string {
  if (!type) return 'link';
  return EDGE_LABELS[type] || type.toLowerCase().replace(/_/g, ' ');
}

function confidenceLabel(confidence: number): string {
  if (confidence >= 0.85) return 'strong confidence';
  if (confidence >= 0.7) return 'moderate confidence';
  return 'weak confidence';
}

function risk(noise: number, confidence: number): { label: string; tone: AttackPathRiskTone } {
  if (noise >= 1 || confidence < 0.65) return { label: 'high risk', tone: 'danger' };
  if (noise >= 0.7 || confidence < 0.8) return { label: 'review OPSEC', tone: 'warning' };
  return { label: 'low friction', tone: 'success' };
}

function groupFor(tiers: Tier[], hopCount: number, noise: number, confidence: number): AttackPathGroup {
  if (noise >= 1 || confidence < 0.65) return 'higher_risk';
  if (tiers.includes('cloud')) return 'cloud_reach';
  if (tiers.includes('identity')) return 'identity_pivots';
  if (hopCount <= 3 && noise <= 0.6) return 'fast_wins';
  return 'fast_wins';
}

function groupMeta(group: AttackPathGroup) {
  return ATTACK_PATH_GROUPS.find(item => item.key === group) || ATTACK_PATH_GROUPS[0];
}

function reasonFor(group: AttackPathGroup, hopCount: number, noise: number, confidence: number): string {
  if (group === 'higher_risk') {
    if (confidence < 0.65) return 'Low confidence route; verify before relying on it.';
    return 'Noisy route; review OPSEC before acting.';
  }
  if (group === 'cloud_reach') return 'Cloud endpoint is reachable from current access.';
  if (group === 'identity_pivots') return 'Identity relationship can extend current access.';
  return hopCount <= 2 && noise <= 0.6
    ? 'Short route with low observed noise.'
    : 'Direct route from current access.';
}

function buildDisplayPath(args: {
  nodes: DisplayPathNode[];
  edgeTypes: string[];
  edgeIds: string[];
  totalConfidence: number;
  totalNoise: number;
}): DisplayAttackPath | null {
  if (args.nodes.length < 2) return null;
  const source = args.nodes[0];
  const target = args.nodes[args.nodes.length - 1];
  const nodeIds = args.nodes.map(node => node.id);
  const tiers = [...tiersForPath(nodeIds, new Map(args.nodes.map(node => [
    node.id,
    { id: node.id, label: node.label, type: node.type, confidence: 1, discovered_at: '' } as ExportedNode,
  ])))];
  const hopCount = Math.max(0, args.nodes.length - 1);
  const group = groupFor(tiers, hopCount, args.totalNoise, args.totalConfidence);
  const groupInfo = groupMeta(group);
  const riskInfo = risk(args.totalNoise, args.totalConfidence);
  const edges = args.edgeTypes.map((type, index) => ({
    id: args.edgeIds[index],
    rawType: type,
    label: edgeLabel(type),
  }));

  return {
    id: `${nodeIds.join('>')}|${args.edgeTypes.join(',')}`,
    group,
    groupLabel: groupInfo.label,
    groupDescription: groupInfo.description,
    headline: `${source.label} can reach ${target.label}`,
    reason: reasonFor(group, hopCount, args.totalNoise, args.totalConfidence),
    source,
    target,
    nodes: args.nodes,
    edges,
    nodeIds,
    edgeIds: args.edgeIds.filter(Boolean),
    rawEdgeTypes: args.edgeTypes,
    tiers,
    hopCount,
    totalConfidence: args.totalConfidence,
    totalNoise: args.totalNoise,
    confidenceLabel: confidenceLabel(args.totalConfidence),
    riskLabel: riskInfo.label,
    riskTone: riskInfo.tone,
  };
}

export function normalizeComputedAttackPath(
  path: ComputedAttackPathLike,
  byId: Map<string, ExportedNode>,
): DisplayAttackPath | null {
  return buildDisplayPath({
    nodes: path.nodes.map(id => nodeFromId(id, byId)),
    edgeTypes: path.edge_types,
    edgeIds: path.edge_ids || [],
    totalConfidence: path.total_confidence,
    totalNoise: path.total_opsec_noise,
  });
}

export function normalizeApiAttackPath(
  path: AttackPath,
  byId: Map<string, ExportedNode>,
): DisplayAttackPath | null {
  const nodes = path.nodes.map(node => nodeFromApi(node, byId));
  const edgeTypes = path.nodes.slice(1)
    .map(node => (typeof node === 'string' ? undefined : node.edge_type))
    .filter((value): value is string => !!value);
  const confidence = path.confidence ?? path.total_confidence ?? 1;
  const noise = path.opsec_noise ?? path.total_opsec_noise ?? 0;
  return buildDisplayPath({
    nodes,
    edgeTypes,
    edgeIds: path.edges || [],
    totalConfidence: confidence,
    totalNoise: noise,
  });
}

export function groupDisplayAttackPaths(paths: DisplayAttackPath[]): Array<{
  key: AttackPathGroup;
  label: string;
  description: string;
  paths: DisplayAttackPath[];
}> {
  return ATTACK_PATH_GROUPS
    .map(group => ({
      ...group,
      paths: paths.filter(path => path.group === group.key),
    }))
    .filter(group => group.paths.length > 0);
}

export function filterDisplayAttackPaths(paths: DisplayAttackPath[], filter: AttackPathLaneFilter): DisplayAttackPath[] {
  if (filter === 'all') return paths;
  return paths.filter(path => path.group === filter);
}

export function attackPathLaneCounts(paths: DisplayAttackPath[]): Record<AttackPathLaneFilter, number> {
  const counts = {
    all: paths.length,
    fast_wins: 0,
    cloud_reach: 0,
    identity_pivots: 0,
    higher_risk: 0,
  } satisfies Record<AttackPathLaneFilter, number>;

  for (const path of paths) {
    counts[path.group] += 1;
  }

  return counts;
}
