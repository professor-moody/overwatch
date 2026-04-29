import { useState, useMemo } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import type { FrontierItem } from '../../lib/types';
import { cn } from '../../lib/utils';

const SECTION_PRIORITY_LIMIT = 8;
const SECTION_DEFAULT_LIMIT = 5;

const SECTION_LABELS: Record<string, string> = {
  incomplete_node: 'Incomplete Nodes',
  untested_edge: 'Untested Edges',
  inferred_edge: 'Inferred Opportunities',
  network_discovery: 'Network Discovery',
};

const TYPE_BADGE: Record<string, { label: string; cls: string }> = {
  incomplete_node: { label: 'node', cls: 'bg-elevated text-muted-foreground' },
  untested_edge: { label: 'test', cls: 'bg-warning/10 text-warning' },
  inferred_edge: { label: 'infer', cls: 'bg-purple-dim text-purple' },
  network_discovery: { label: 'net', cls: 'bg-accent-dim text-accent' },
};

function getNoiseColor(noise: number): string {
  if (noise <= 0.3) return '#3ecf8e';
  if (noise <= 0.6) return '#eab308';
  return '#ef4444';
}

function metric(item: FrontierItem, key: string): string {
  const v = item.graph_metrics?.[key];
  return v !== undefined && v !== null ? String(v) : '—';
}

interface Section {
  key: string;
  title: string;
  items: FrontierItem[];
  total: number;
}

function buildSections(frontier: FrontierItem[]): Section[] {
  const topPriority = frontier.slice(0, SECTION_PRIORITY_LIMIT);
  const topIds = new Set(topPriority.map(i => i.id));
  const sections: Section[] = [
    { key: 'priority', title: 'Top Priority', items: topPriority, total: topPriority.length },
  ];
  for (const type of ['incomplete_node', 'untested_edge', 'inferred_edge', 'network_discovery'] as const) {
    const items = frontier.filter(i => i.type === type && !topIds.has(i.id));
    const total = frontier.filter(i => i.type === type).length;
    if (total > 0) sections.push({ key: type, title: SECTION_LABELS[type] || type, items, total });
  }
  return sections;
}

export function FrontierPanel() {
  const frontier = useEngagementStore(s => s.frontier);
  const { navigateToGraph } = useNavigation();

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (!typeFilter) return frontier;
    const f = frontier.filter(item => {
      if (item.type === 'incomplete_node' && item.node_id) return true; // would need graph check
      const targets = [item.edge_source, item.edge_target, item.target_node, item.source_node].filter(Boolean);
      return targets.length > 0; // basic passthrough — real filtering when graph is available
    });
    return f.length > 0 ? f : frontier;
  }, [frontier, typeFilter]);

  const sections = useMemo(() => buildSections(filtered), [filtered]);

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

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Frontier <span className="text-muted-foreground font-normal text-sm">
            {typeFilter ? `(${filtered.length}/${frontier.length})` : `(${frontier.length})`}
          </span>
        </h2>
        {typeFilter && (
          <button
            onClick={() => setTypeFilter(null)}
            className="text-xs px-2 py-0.5 rounded border border-border text-muted-foreground hover:text-foreground"
          >
            Clear filter ✕
          </button>
        )}
      </div>

      {frontier.length === 0 ? (
        <div className="bg-surface border border-border rounded-lg p-8 text-center text-sm text-muted-foreground">
          Frontier empty — ingest data to generate candidates
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
          {/* Noise bar */}
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
