import { FRONTIER_TYPES, type FrontierType } from '@overwatch/dashboard-contracts';
import type { FrontierItem } from './types';

export const FRONTIER_TYPE_ORDER = FRONTIER_TYPES;

export const FRONTIER_SECTION_LABELS: Record<FrontierType, string> = {
  incomplete_node: 'Incomplete Node',
  untested_edge: 'Untested Edge',
  inferred_edge: 'Inferred Opportunity',
  network_discovery: 'Network Discovery',
  network_pivot: 'Network Pivot',
  credential_test: 'Credential Test',
  idp_enumeration: 'Identity Provider Enumeration',
  mfa_bypass_candidate: 'MFA Bypass Candidate',
  cross_tier_pivot: 'Cross-tier Pivot',
  cve_research: 'CVE Research',
  domain_enumeration: 'Domain Enumeration',
};

export interface FrontierSection {
  key: string;
  title: string;
  items: FrontierItem[];
  total: number;
}

export interface FrontierSectionOptions {
  typeFilter?: string | null;
  nodeFilter?: string | null;
}

function clean(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function field(item: FrontierItem, key: string): string | null {
  return clean((item as Record<string, unknown>)[key]);
}

export function getFrontierKey(item: FrontierItem): string {
  return item.id;
}

/** Canonical graph participants, ordered by their role in the frontier item. */
export function getFrontierNodeIds(item: FrontierItem): string[] {
  const ids = [
    field(item, 'node_id'),
    field(item, 'credential_id'),
    field(item, 'edge_source'),
    field(item, 'edge_target'),
    field(item, 'pivot_host_id'),
    field(item, 'via_pivot'),
  ].filter((value): value is string => value !== null);
  return [...new Set(ids)];
}

export function getFrontierTargetCidr(item: FrontierItem): string | null {
  return field(item, 'target_cidr');
}

export function getFrontierPrimaryNodeId(item: FrontierItem): string | null {
  return getFrontierNodeIds(item)[0] ?? null;
}

export function frontierReferencesNode(item: FrontierItem, nodeId: string): boolean {
  return getFrontierNodeIds(item).includes(nodeId);
}

/** Compatibility helper: server candidate order is already authoritative. */
export function sortFrontierItems(items: FrontierItem[]): FrontierItem[] {
  return [...items];
}

export function filterFrontierItems(
  items: FrontierItem[],
  typeFilter?: string | null,
  nodeFilter?: string | null,
): FrontierItem[] {
  return items
    .filter(item => !typeFilter || item.type === typeFilter)
    .filter(item => !nodeFilter || frontierReferencesNode(item, nodeFilter));
}

/** One list preserves the exact server candidate ordering across frontier kinds. */
export function buildFrontierSections(
  items: FrontierItem[],
  options: FrontierSectionOptions = {},
): FrontierSection[] {
  const list = filterFrontierItems(items, options.typeFilter, options.nodeFilter);
  return [{
    key: options.nodeFilter ? 'matching' : 'candidates',
    title: options.nodeFilter ? 'Matching Candidates' : 'Candidates',
    items: list,
    total: list.length,
  }];
}

export function frontierScoreMultiplier(item: FrontierItem): number {
  return item.graph_metrics.confidence;
}

export function formatFrontierScore(item: FrontierItem): string {
  return `×${frontierScoreMultiplier(item).toFixed(2)}`;
}
