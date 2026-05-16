import type { FrontierItem } from './types';

export const FRONTIER_TYPE_ORDER = [
  'incomplete_node',
  'untested_edge',
  'inferred_edge',
  'network_discovery',
  'credential_test',
] as const;

export const FRONTIER_SECTION_LABELS: Record<string, string> = {
  incomplete_node: 'Incomplete Nodes',
  untested_edge: 'Untested Edges',
  inferred_edge: 'Inferred Opportunities',
  network_discovery: 'Network Discovery',
  credential_test: 'Credential Tests',
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
  priorityLimit?: number;
}

function clean(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function getFrontierKey(item: FrontierItem): string {
  return item.frontier_item_id || item.id;
}

export function getFrontierNodeIds(item: FrontierItem): string[] {
  return [
    item.target_node,
    item.node_id,
    item.edge_source,
    item.edge_target,
    item.source_node,
  ].map(clean).filter((v): v is string => !!v);
}

export function getFrontierPrimaryNodeId(item: FrontierItem): string | null {
  return getFrontierNodeIds(item)[0] || null;
}

export function frontierReferencesNode(item: FrontierItem, nodeId: string): boolean {
  return getFrontierNodeIds(item).includes(nodeId);
}

export function sortFrontierItems(items: FrontierItem[]): FrontierItem[] {
  return [...items].sort((a, b) => {
    const priority = (b.priority ?? 0) - (a.priority ?? 0);
    if (priority !== 0) return priority;
    return getFrontierKey(a).localeCompare(getFrontierKey(b));
  });
}

export function filterFrontierItems(items: FrontierItem[], typeFilter?: string | null, nodeFilter?: string | null): FrontierItem[] {
  return sortFrontierItems(items)
    .filter(item => !typeFilter || item.type === typeFilter)
    .filter(item => !nodeFilter || frontierReferencesNode(item, nodeFilter));
}

export function buildFrontierSections(items: FrontierItem[], options: FrontierSectionOptions = {}): FrontierSection[] {
  const priorityLimit = options.priorityLimit ?? 8;
  const list = filterFrontierItems(items, options.typeFilter, options.nodeFilter);

  if (options.nodeFilter) {
    return [{ key: 'matching', title: 'Matching Items', items: list, total: list.length }];
  }

  const topPriority = list.slice(0, priorityLimit);
  const topIds = new Set(topPriority.map(getFrontierKey));
  const sections: FrontierSection[] = [
    { key: 'priority', title: 'Top Priority', items: topPriority, total: topPriority.length },
  ];

  for (const type of FRONTIER_TYPE_ORDER) {
    const typeItems = list.filter(item => item.type === type);
    const visibleItems = typeItems.filter(item => !topIds.has(getFrontierKey(item)));
    if (typeItems.length > 0) {
      sections.push({
        key: type,
        title: FRONTIER_SECTION_LABELS[type] || type,
        items: visibleItems,
        total: typeItems.length,
      });
    }
  }

  return sections;
}
