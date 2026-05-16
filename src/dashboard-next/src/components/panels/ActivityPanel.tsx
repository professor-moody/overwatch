import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import * as api from '../../lib/api';
import type { ActivityEntry } from '../../lib/types';
import { formatRelativeTime, formatTimestamp, cn } from '../../lib/utils';
import { EmptyState } from '../shared';
import { FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { classifyActivity, extractActivityLinks, filterActivity, type ActivityClass } from '../../lib/activity-console';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { useNavigation } from '../../hooks/useNavigation';

const CLASS_OPTIONS: { value: ActivityClass | ''; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'approval', label: 'Approvals' },
  { value: 'session', label: 'Sessions' },
  { value: 'started', label: 'Started' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'finding', label: 'Findings' },
];

export function ActivityPanel() {
  const connected = useEngagementStore((s) => s.connected);
  const initialized = useEngagementStore((s) => s.initialized);
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [classFilter, setClassFilter] = useState<ActivityClass | ''>('');
  const [search, setSearch] = useState('');
  const [selectedEntryOverride, setSelectedEntryOverride] = useState<ActivityEntry | null>(null);
  const [autoScroll] = useState(true);
  const listRef = useRef<HTMLDivElement>(null);
  const hoverRef = useRef(false);
  const hasLoaded = useRef(false);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getHistory({ limit: 250 });
      setEntries(data.entries || []);
      hasLoaded.current = true;
    } catch { /* keep current stream visible */ }
  }, []);

  useEffect(() => {
    loadHistory();
    const timer = setInterval(() => {
      if (connected) loadHistory();
    }, 5000);
    return () => clearInterval(timer);
  }, [loadHistory, connected]);

  const filtered = useMemo(() => filterActivity(entries, { classFilter, search }), [entries, classFilter, search]);
  const selectedEntry = selectedEntryOverride && filtered.includes(selectedEntryOverride)
    ? selectedEntryOverride
    : filtered[filtered.length - 1] || null;
  const classCounts = useMemo(() => {
    const counts: Record<ActivityClass, number> = {
      approval: 0,
      session: 0,
      started: 0,
      completed: 0,
      failed: 0,
      finding: 0,
      default: 0,
    };
    for (const entry of entries) counts[classifyActivity(entry)]++;
    return counts;
  }, [entries]);

  useEffect(() => {
    if (autoScroll && !hoverRef.current && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [filtered, autoScroll]);

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[680px] flex flex-col gap-4">
      <PageHeader
        title="Activity"
        meta={`(${filtered.length}/${entries.length})`}
        actions={(
          <FilterBar>
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter action, agent, node, text..."
              className="settings-input w-72"
            />
            <button onClick={loadHistory} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground">
              Refresh
            </button>
          </FilterBar>
        )}
      />

      <div className="grid grid-cols-[minmax(420px,1fr)_minmax(360px,440px)] gap-4 flex-1 min-h-0">
        <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
          <div className="border-b border-border p-2">
            <div className="flex gap-1 flex-wrap">
              {CLASS_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setClassFilter(opt.value)}
                  className={cn(
                    'text-[10px] px-2 py-0.5 rounded border transition-colors',
                    classFilter === opt.value ? 'bg-accent text-accent-foreground border-accent' : 'border-border text-muted-foreground hover:text-foreground hover:bg-hover',
                  )}
                >
                  {opt.label}
                  {opt.value && <span className="ml-1 opacity-70">{classCounts[opt.value]}</span>}
                </button>
              ))}
            </div>
          </div>

          {!initialized && !hasLoaded.current ? (
            <div className="p-4 text-sm text-muted-foreground animate-pulse">Loading activity...</div>
          ) : filtered.length === 0 ? (
            <EmptyState message={entries.length === 0 ? 'No activity yet.' : 'No matches.'} className="m-3" />
          ) : (
            <div
              ref={listRef}
              className="overflow-y-auto p-2 space-y-1"
              onMouseEnter={() => { hoverRef.current = true; }}
              onMouseLeave={() => { hoverRef.current = false; }}
            >
              {filtered.map((entry, index) => (
                <ActivityRow
                  key={activityKey(entry, index)}
                  entry={entry}
                  selected={selectedEntry === entry}
                  onSelect={() => setSelectedEntryOverride(entry)}
                />
              ))}
            </div>
          )}
        </PanelSection>

        <ActivityDetail entry={selectedEntry} />
      </div>
    </div>
  );
}

function activityKey(entry: ActivityEntry, index: number): string {
  const eventId = (entry as ActivityEntry & { event_id?: string }).event_id;
  return eventId || entry.id || `${entry.timestamp}-${entry.event_type}-${index}`;
}

function ActivityRow({ entry, selected, onSelect }: { entry: ActivityEntry; selected: boolean; onSelect: () => void }) {
  const cls = classifyActivity(entry);
  const links = extractActivityLinks(entry);

  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full rounded border border-border bg-surface p-2.5 text-left text-xs transition-colors hover:border-accent/40 hover:bg-hover/40 border-l-2',
        classBorderClass(cls),
        selected && 'border-accent/60 bg-accent/5',
      )}
    >
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground font-mono w-16">{formatTimestamp(entry.timestamp)}</span>
        <StatusPill className={classPillClass(cls)}>{cls}</StatusPill>
        <span className="truncate text-foreground">{entry.event_type}</span>
        <span className="ml-auto text-[10px] text-muted-foreground">{formatRelativeTime(entry.timestamp)}</span>
      </div>
      <div className="mt-1 text-muted-foreground line-clamp-2">{entry.description}</div>
      {(links.actionId || links.agentId || links.nodeIds.length > 0) && (
        <div className="mt-1 flex flex-wrap gap-1">
          {links.actionId && <span className="text-[10px] font-mono text-accent">action {links.actionId.slice(0, 10)}</span>}
          {links.agentId && <span className="text-[10px] font-mono text-muted-foreground">agent {links.agentId.slice(0, 10)}</span>}
          {links.nodeIds.slice(0, 2).map(nodeId => <span key={nodeId} className="text-[10px] font-mono text-muted-foreground">{nodeId}</span>)}
        </div>
      )}
    </button>
  );
}

function ActivityDetail({ entry }: { entry: ActivityEntry | null }) {
  const { navigateToPanel } = useNavigation();

  if (!entry) {
    return (
      <PanelSection>
        <EmptyState message="Select an activity event to inspect its links and details." />
      </PanelSection>
    );
  }

  const cls = classifyActivity(entry);
  const links = extractActivityLinks(entry);

  return (
    <PanelSection title="Event Detail" className="overflow-y-auto">
      <div className="space-y-3">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <StatusPill className={classPillClass(cls)}>{cls}</StatusPill>
            <span className="text-xs text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
          </div>
          <h3 className="text-sm font-semibold text-foreground">{entry.event_type}</h3>
          <p className="mt-1 text-xs text-muted-foreground">{entry.description}</p>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <DetailFact label="Action" value={links.actionId || '—'} onClick={links.actionId ? () => navigateToPanel('actions') : undefined} />
          <DetailFact label="Agent" value={links.agentId || '—'} onClick={links.agentId ? () => navigateToPanel('agents', links.agentId) : undefined} />
          <DetailFact label="Frontier" value={links.frontierItemId || '—'} onClick={links.frontierItemId ? () => navigateToPanel('frontier') : undefined} />
          <DetailFact label="Age" value={formatRelativeTime(entry.timestamp)} />
        </div>

        {links.nodeIds.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Graph Links</div>
            <div className="flex flex-wrap gap-1">
              {links.nodeIds.slice(0, 6).map(nodeId => <GraphNodeLinks key={nodeId} nodeId={nodeId} />)}
            </div>
          </div>
        )}

        {entry.details && Object.keys(entry.details).length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Details</div>
            <pre className="max-h-72 overflow-auto rounded border border-border bg-background p-2 text-[11px] text-muted-foreground">
              {JSON.stringify(entry.details, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </PanelSection>
  );
}

function DetailFact({ label, value, onClick }: { label: string; value: string; onClick?: () => void }) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp onClick={onClick} className={cn('rounded border border-border bg-elevated px-2 py-1.5 text-left min-w-0', onClick && 'hover:border-accent/40 hover:bg-hover')}>
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="text-xs text-foreground font-mono truncate">{value}</div>
    </Comp>
  );
}

function classPillClass(cls: ActivityClass): string {
  if (cls === 'approval') return 'bg-accent/10 text-accent';
  if (cls === 'session') return 'bg-purple-dim text-purple';
  if (cls === 'started') return 'bg-accent/10 text-accent';
  if (cls === 'completed') return 'bg-success/10 text-success';
  if (cls === 'failed') return 'bg-destructive/10 text-destructive';
  if (cls === 'finding') return 'bg-warning/10 text-warning';
  return 'bg-elevated text-muted-foreground';
}

function classBorderClass(cls: ActivityClass): string {
  if (cls === 'approval') return 'border-l-accent';
  if (cls === 'session') return 'border-l-purple';
  if (cls === 'started') return 'border-l-accent';
  if (cls === 'completed') return 'border-l-success';
  if (cls === 'failed') return 'border-l-destructive';
  if (cls === 'finding') return 'border-l-warning';
  return 'border-l-border';
}
