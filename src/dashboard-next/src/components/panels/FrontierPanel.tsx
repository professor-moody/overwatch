import { useState, useMemo, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import type { FrontierItem } from '../../lib/types';
import { cn } from '../../lib/utils';
import { ActionButton, EmptyPanelState, FilterBar, PageHeader, PanelSection, SegmentedControl, StatusPill } from '../shared/primitives';
import { deriveNodeRelationships } from '../../lib/relationships';
import {
  buildFrontierSections,
  filterFrontierItems,
  getFrontierKey,
  getFrontierPrimaryNodeId,
  getFrontierNodeIds,
} from '../../lib/frontier-workspace';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { getFindings, type FindingDto } from '../../lib/api';

const SECTION_PRIORITY_LIMIT = 8;
const SECTION_DEFAULT_LIMIT = 5;

const TYPE_BADGE: Record<string, { label: string; cls: string }> = {
  incomplete_node: { label: 'node', cls: 'bg-elevated text-muted-foreground' },
  untested_edge: { label: 'test', cls: 'bg-warning/10 text-warning' },
  inferred_edge: { label: 'infer', cls: 'bg-purple-dim text-purple' },
  network_discovery: { label: 'net', cls: 'bg-accent-dim text-accent' },
  credential_test: { label: 'cred', cls: 'bg-success/10 text-success' },
};

const TYPE_FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'incomplete_node', label: 'Nodes' },
  { value: 'untested_edge', label: 'Edges' },
  { value: 'inferred_edge', label: 'Inferred' },
  { value: 'network_discovery', label: 'Network' },
  { value: 'credential_test', label: 'Creds' },
] as const;
type TypeFilterValue = typeof TYPE_FILTER_OPTIONS[number]['value'];

function getNoiseColor(noise: number): string {
  if (noise <= 0.3) return '#3ecf8e';
  if (noise <= 0.6) return '#eab308';
  return '#ef4444';
}

function metric(item: FrontierItem, key: string): string {
  const v = item.graph_metrics?.[key];
  return v !== undefined && v !== null ? String(v) : '—';
}

export function FrontierPanel() {
  const frontier = useEngagementStore(s => s.frontier);
  const graph = useEngagementStore(s => s.graph);
  const sessions = useEngagementStore(s => s.sessions);
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const [searchParams, setSearchParams] = useSearchParams();

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [typeFilterValue, setTypeFilterValue] = useState<TypeFilterValue>('all');
  const [nodeFilter, setNodeFilter] = useState<string | null>(null);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const typeFilter = typeFilterValue === 'all' ? null : typeFilterValue;

  // Read node filter from route query (node= param set by navigateToFrontier).
  useEffect(() => {
    const node = searchParams.get('node');
    if (node) {
      setNodeFilter(node);
    } else {
      setNodeFilter(null);
    }
  }, [searchParams]);

  useEffect(() => {
    let cancelled = false;
    getFindings()
      .then(data => { if (!cancelled) setFindings(data.findings || []); })
      .catch(() => { if (!cancelled) setFindings([]); });
    return () => { cancelled = true; };
  }, []);

  const sections = useMemo(
    () => buildFrontierSections(frontier, { typeFilter, nodeFilter, priorityLimit: SECTION_PRIORITY_LIMIT }),
    [frontier, typeFilter, nodeFilter],
  );

  const totalVisible = useMemo(() => {
    return filterFrontierItems(frontier, typeFilter, nodeFilter).length;
  }, [frontier, typeFilter, nodeFilter]);

  const toggleCollapse = (key: string) => {
    setCollapsed(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };
  const toggleExpand = (key: string) => {
    setExpanded(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };

  const clearNodeFilter = () => {
    setNodeFilter(null);
    setSearchParams({}, { replace: true });
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Frontier"
        meta={(typeFilter || nodeFilter) ? `(${totalVisible}/${frontier.length})` : `(${frontier.length})`}
        actions={(
          <FilterBar>
            <SegmentedControl
              value={typeFilterValue}
              onChange={setTypeFilterValue}
              options={TYPE_FILTER_OPTIONS.map(opt => ({ value: opt.value, label: opt.label }))}
            />
            {nodeFilter && (
              <div className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-accent/10 text-accent border border-accent/30">
                <span className="font-mono truncate max-w-32">{nodeFilter}</span>
                <ActionButton onClick={clearNodeFilter} variant="ghost" size="xs" className="h-4 min-w-4 px-0 text-accent hover:text-foreground">✕</ActionButton>
              </div>
            )}
          </FilterBar>
        )}
      />

      {frontier.length === 0 ? (
        <EmptyPanelState message="Frontier empty. Ingest data to generate candidates." />
      ) : totalVisible === 0 ? (
        <EmptyPanelState message="No frontier items match the current filter." />
      ) : (
        <div className="space-y-3">
          {sections.map(section => {
            const isCollapsed = collapsed.has(section.key);
            const isExpanded = expanded.has(section.key);
            const limit = section.key === 'priority' ? SECTION_PRIORITY_LIMIT : SECTION_DEFAULT_LIMIT;
            const visible = isExpanded ? section.items : section.items.slice(0, limit);
            const hasMore = section.items.length > limit;

            return (
              <PanelSection key={section.key} className="p-0 overflow-hidden">
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
                        related={(() => {
                          const nodeId = getFrontierPrimaryNodeId(item);
                          return nodeId ? deriveNodeRelationships(nodeId, { graph, sessions, pendingActions, frontier, findings }) : null;
                        })()}
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
              </PanelSection>
            );
          })}
        </div>
      )}
    </div>
  );
}

function FrontierItemCard({
  item,
  related,
}: {
  item: FrontierItem;
  related?: ReturnType<typeof deriveNodeRelationships> | null;
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
  if (related?.sessions.length) chips.push({ text: `${related.sessions.length} session`, cls: 'bg-success/10 text-success' });
  if (related?.pendingActions.length) chips.push({ text: `${related.pendingActions.length} action`, cls: 'bg-warning/10 text-warning' });
  if (related?.findings.length) chips.push({ text: `${related.findings.length} finding`, cls: 'bg-destructive/10 text-destructive' });
  const nodeIds = getFrontierNodeIds(item);
  const frontierKey = getFrontierKey(item);

  return (
    <div className="px-3 py-2 border-b border-border last:border-b-0 hover:bg-hover/50 transition-colors">
      <div className="flex items-center gap-2 mb-1">
        <StatusPill className={badge.cls}>{badge.label}</StatusPill>
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

      {nodeIds.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-1.5">
          {nodeIds.slice(0, 3).map((nodeId, index) => (
            <GraphNodeLinks
              key={`${nodeId}-${index}`}
              nodeId={nodeId}
              className="rounded bg-background/60 px-1 py-0.5"
              graphTarget={{ kind: 'frontier', frontierItemId: frontierKey, nodeIds, label: 'Frontier item' }}
            />
          ))}
          {nodeIds.length > 3 && <span className="text-[10px] text-muted-foreground">+{nodeIds.length - 3} nodes</span>}
        </div>
      )}

      <div className="flex items-center justify-between gap-3">
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
      </div>
    </div>
  );
}
