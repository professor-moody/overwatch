import { useState, useMemo, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { parseHash } from '../../hooks/useNavigation';
import type { FrontierItem } from '../../lib/types';
import { cn } from '../../lib/utils';

const SECTION_PRIORITY_LIMIT = 8;
const SECTION_DEFAULT_LIMIT = 5;

const SECTION_LABELS: Record<string, string> = {
  incomplete_node: 'Incomplete Nodes',
  untested_edge: 'Untested Edges',
  inferred_edge: 'Inferred Opportunities',
  network_discovery: 'Network Discovery',
  credential_test: 'Credential Tests',
};

const TYPE_BADGE: Record<string, { label: string; cls: string }> = {
  incomplete_node: { label: 'node', cls: 'bg-elevated text-muted-foreground' },
  untested_edge: { label: 'test', cls: 'bg-warning/10 text-warning' },
  inferred_edge: { label: 'infer', cls: 'bg-purple-dim text-purple' },
  network_discovery: { label: 'net', cls: 'bg-accent-dim text-accent' },
  credential_test: { label: 'cred', cls: 'bg-success/10 text-success' },
};

const TYPE_FILTER_OPTIONS = [
  { value: null, label: 'All' },
  { value: 'incomplete_node', label: 'Nodes' },
  { value: 'untested_edge', label: 'Edges' },
  { value: 'inferred_edge', label: 'Inferred' },
  { value: 'network_discovery', label: 'Network' },
  { value: 'credential_test', label: 'Creds' },
] as const;

function getNoiseColor(noise: number): string {
  if (noise <= 0.3) return '#3ecf8e';
  if (noise <= 0.6) return '#eab308';
  return '#ef4444';
}

function metric(item: FrontierItem, key: string): string {
  const v = item.graph_metrics?.[key];
  return v !== undefined && v !== null ? String(v) : '—';
}

function itemReferencesNode(item: FrontierItem, nodeId: string): boolean {
  return (
    item.target_node === nodeId ||
    item.node_id === nodeId ||
    item.edge_source === nodeId ||
    item.edge_target === nodeId ||
    (item as unknown as Record<string, unknown>).source_node === nodeId
  );
}

interface Section {
  key: string;
  title: string;
  items: FrontierItem[];
  total: number;
}

function buildSections(frontier: FrontierItem[], typeFilter: string | null, nodeFilter: string | null): Section[] {
  let list = frontier;
  if (typeFilter) list = list.filter(i => i.type === typeFilter);
  if (nodeFilter) list = list.filter(i => itemReferencesNode(i, nodeFilter));

  const topPriority = list.slice(0, SECTION_PRIORITY_LIMIT);
  const topIds = new Set(topPriority.map(i => i.id));

  // When a node filter is active, skip the type sub-sections and just show everything.
  if (nodeFilter) {
    return [{ key: 'priority', title: 'Matching Items', items: topPriority, total: list.length }];
  }

  const sections: Section[] = [
    { key: 'priority', title: 'Top Priority', items: topPriority, total: topPriority.length },
  ];
  for (const type of ['incomplete_node', 'untested_edge', 'inferred_edge', 'network_discovery', 'credential_test'] as const) {
    const typeItems = list.filter(i => i.type === type && !topIds.has(i.id));
    const total = list.filter(i => i.type === type).length;
    if (total > 0) sections.push({ key: type, title: SECTION_LABELS[type] || type, items: typeItems, total });
  }
  return sections;
}

export function FrontierPanel() {
  const frontier = useEngagementStore(s => s.frontier);
  const { navigateToGraph } = useNavigation();
  const location = useLocation();

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [nodeFilter, setNodeFilter] = useState<string | null>(null);

  // Read node filter from URL hash (item= param set by navigateToFrontier).
  useEffect(() => {
    const target = parseHash(location.hash);
    if (target?.panel === 'frontier' && target.item) {
      setNodeFilter(target.item);
    } else {
      setNodeFilter(null);
    }
  }, [location.hash]);

  const sections = useMemo(
    () => buildSections(frontier, typeFilter, nodeFilter),
    [frontier, typeFilter, nodeFilter],
  );

  const totalVisible = useMemo(() => {
    let list = frontier;
    if (typeFilter) list = list.filter(i => i.type === typeFilter);
    if (nodeFilter) list = list.filter(i => itemReferencesNode(i, nodeFilter));
    return list.length;
  }, [frontier, typeFilter, nodeFilter]);

  const toggleCollapse = (key: string) => {
    setCollapsed(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };
  const toggleExpand = (key: string) => {
    setExpanded(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };

  const handleZoom = (item: FrontierItem) => {
    const nodeId = item.target_node || item.node_id || item.edge_source || item.edge_target;
    if (nodeId) navigateToGraph(nodeId, 1);
  };

  const handleFocus = (item: FrontierItem) => {
    const nodeId = item.target_node || item.node_id || item.edge_source || item.edge_target;
    if (nodeId) navigateToGraph(nodeId, 2);
  };

  const clearNodeFilter = () => {
    setNodeFilter(null);
    // Also clear the hash item param so Back works sensibly.
    const params = new URLSearchParams(location.hash.replace(/^#/, ''));
    params.delete('item');
    const newHash = params.toString() ? `#${params.toString()}` : '#panel=frontier';
    window.history.replaceState(null, '', `/${newHash}`);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-lg font-semibold">
          Frontier <span className="text-muted-foreground font-normal text-sm">
            {(typeFilter || nodeFilter) ? `(${totalVisible}/${frontier.length})` : `(${frontier.length})`}
          </span>
        </h2>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Type filter chips */}
          <div className="flex gap-1">
            {TYPE_FILTER_OPTIONS.map(opt => (
              <button
                key={String(opt.value)}
                onClick={() => setTypeFilter(opt.value)}
                className={cn(
                  'text-[10px] px-2 py-0.5 rounded border transition-colors',
                  typeFilter === opt.value
                    ? 'bg-accent text-accent-foreground border-accent'
                    : 'border-border bg-surface text-muted-foreground hover:text-foreground',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
          {/* Node filter chip */}
          {nodeFilter && (
            <div className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-accent/10 text-accent border border-accent/30">
              <span className="font-mono truncate max-w-32">{nodeFilter}</span>
              <button onClick={clearNodeFilter} className="text-accent hover:text-foreground ml-1">✕</button>
            </div>
          )}
        </div>
      </div>

      {frontier.length === 0 ? (
        <div className="bg-surface border border-border rounded-lg p-8 text-center text-sm text-muted-foreground">
          Frontier empty — ingest data to generate candidates
        </div>
      ) : totalVisible === 0 ? (
        <div className="bg-surface border border-border rounded-lg p-8 text-center text-sm text-muted-foreground">
          No frontier items match the current filter.
        </div>
      ) : (
        <div className="space-y-3">
          {sections.map(section => {
            const isCollapsed = collapsed.has(section.key);
            const isExpanded = expanded.has(section.key);
            const limit = section.key === 'priority' ? SECTION_PRIORITY_LIMIT : SECTION_DEFAULT_LIMIT;
            const visible = isExpanded ? section.items : section.items.slice(0, limit);
            const hasMore = section.items.length > limit;

            return (
              <div key={section.key} className="bg-surface border border-border rounded-lg overflow-hidden">
                <button
                  onClick={() => toggleCollapse(section.key)}
                  className="w-full px-3 py-2 flex items-center justify-between text-xs hover:bg-hover transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <span className="text-muted-foreground">{isCollapsed ? '▸' : '▾'}</span>
                    <span className="font-medium text-foreground">{section.title}</span>
                  </span>
                  <span className="text-muted-foreground font-mono">{section.total}</span>
                </button>

                {!isCollapsed && (
                  <div className="border-t border-border">
                    {visible.map((item, idx) => (
                      <FrontierItemCard
                        key={item.frontier_item_id || item.id || idx}
                        item={item}
                        onZoom={() => handleZoom(item)}
                        onFocus={() => handleFocus(item)}
                      />
                    ))}
                    {hasMore && (
                      <button
                        onClick={() => toggleExpand(section.key)}
                        className="w-full px-3 py-1.5 text-[10px] text-accent hover:bg-hover transition-colors text-center"
                      >
                        {isExpanded ? 'Show Less' : `Show ${section.items.length - visible.length} More`}
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function FrontierItemCard({
  item,
  onZoom,
  onFocus,
}: {
  item: FrontierItem;
  onZoom: () => void;
  onFocus: () => void;
}) {
  const badge = TYPE_BADGE[item.type] || TYPE_BADGE.incomplete_node;
  const noise = item.opsec_noise ?? 0;
  const noisePercent = Math.round(noise * 100);
  const hops = metric(item, 'hops_to_objective');
  const fanOut = metric(item, 'fan_out_estimate');
  const confidence = Number(metric(item, 'confidence') || 0);
  const confStr = confidence ? confidence.toFixed(1) : '—';
  const degree = item.graph_metrics?.node_degree;

  const label = item.description || item.id;
  const chips: { text: string; cls: string }[] = [];
  if (item.missing_properties?.length) {
    for (const prop of item.missing_properties) {
      chips.push({ text: prop, cls: 'bg-warning/10 text-warning' });
    }
  }
  if (item.edge_type) chips.push({ text: item.edge_type, cls: 'bg-accent-dim text-accent' });
  if (degree != null) chips.push({ text: `deg ${degree}`, cls: 'bg-elevated text-muted-foreground' });

  return (
    <div className="px-3 py-2 border-b border-border last:border-b-0 hover:bg-hover/50 transition-colors">
      <div className="flex items-center gap-2 mb-1">
        <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', badge.cls)}>
          {badge.label}
        </span>
        <span className="text-xs text-foreground flex-1 truncate" title={item.description}>
          {label}
        </span>
        <span className="text-xs font-mono text-foreground flex-shrink-0">{(item.priority ?? 0).toFixed(1)}</span>
      </div>

      {chips.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-1.5">
          {chips.map((c, i) => (
            <span key={i} className={cn('text-[10px] px-1 py-0.5 rounded', c.cls)}>{c.text}</span>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1">
            <span className="w-12 h-1.5 rounded-full bg-elevated overflow-hidden">
              <span
                className="block h-full rounded-full transition-all"
                style={{ width: `${noisePercent}%`, backgroundColor: getNoiseColor(noise) }}
              />
            </span>
            <span>noise {(noise ?? 0).toFixed(1)}</span>
          </span>
          <span>hops {hops}</span>
          <span>fan {fanOut}</span>
          <span>conf {confStr}</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={e => { e.stopPropagation(); onZoom(); }}
            className="text-[10px] px-1.5 py-0.5 rounded text-accent hover:bg-accent/10 transition-colors"
          >
            Zoom
          </button>
          <button
            onClick={e => { e.stopPropagation(); onFocus(); }}
            className="text-[10px] px-1.5 py-0.5 rounded text-accent hover:bg-accent/10 transition-colors"
          >
            Focus
          </button>
        </div>
      </div>
    </div>
  );
}
