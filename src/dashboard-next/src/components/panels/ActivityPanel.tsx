import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import * as api from '../../lib/api';
import type { ActivityEntry } from '../../lib/types';
import { formatTimestamp, cn } from '../../lib/utils';
import { EmptyState } from '../shared';

type ColorClass = 'started' | 'completed' | 'failed' | 'finding' | 'default';

const COLOR_MAP: Record<ColorClass, string> = {
  started: 'border-l-accent',
  completed: 'border-l-success',
  failed: 'border-l-destructive',
  finding: 'border-l-warning',
  default: 'border-l-border',
};

function getActivityColor(entry: ActivityEntry): ColorClass {
  const desc = (entry.description || '').toLowerCase();
  const type = (entry.event_type || '').toLowerCase();
  if (type.includes('started') || desc.includes('started')) return 'started';
  if (type.includes('completed') || desc.includes('completed')) return 'completed';
  if (type.includes('failed') || desc.includes('failed')) return 'failed';
  if (type.includes('finding') || desc.includes('finding') || desc.includes('reported') || desc.includes('parsed')) return 'finding';
  return 'default';
}

const FILTER_OPTIONS: { value: ColorClass | ''; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'started', label: 'Started' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'finding', label: 'Findings' },
];

export function ActivityPanel() {
  const connected = useEngagementStore((s) => s.connected);
  const initialized = useEngagementStore((s) => s.initialized);
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [filter, setFilter] = useState<ColorClass | ''>('');
  const [search, setSearch] = useState('');
  const [autoScroll] = useState(true);
  const listRef = useRef<HTMLDivElement>(null);
  const hoverRef = useRef(false);
  const hasLoaded = useRef(false);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getHistory({ limit: 200 });
      setEntries(data.entries || []);
      hasLoaded.current = true;
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    loadHistory();
    const timer = setInterval(() => {
      if (connected) loadHistory();
    }, 5000);
    return () => clearInterval(timer);
  }, [loadHistory, connected]);

  // Auto-scroll to bottom when new entries arrive
  useEffect(() => {
    if (autoScroll && !hoverRef.current && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [entries, autoScroll]);

  const filtered = useMemo(() => {
    let list = entries;
    if (filter) {
      list = list.filter(e => getActivityColor(e) === filter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(e =>
        (e.description || '').toLowerCase().includes(q) ||
        (e.event_type || '').toLowerCase().includes(q)
      );
    }
    return list;
  }, [entries, filter, search]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Activity <span className="text-muted-foreground font-normal text-sm">({filtered.length})</span>
        </h2>
        <div className="flex items-center gap-2">
          {/* Filter chips */}
          <div className="flex gap-0.5">
            {FILTER_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setFilter(opt.value)}
                className={cn(
                  'text-[10px] px-1.5 py-0.5 rounded transition-colors',
                  filter === opt.value
                    ? 'bg-accent/20 text-accent'
                    : 'text-muted-foreground hover:text-foreground hover:bg-hover',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
          {/* Search */}
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter…"
            className="w-28 text-[11px] px-2 py-0.5 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground"
          />
        </div>
      </div>

      {!initialized && !hasLoaded.current ? (
        <div className="text-sm text-muted-foreground animate-pulse">Loading…</div>
      ) : filtered.length === 0 ? (
        <EmptyState message={entries.length === 0 ? 'No activity yet.' : 'No matches.'} />
      ) : (
        <div
          ref={listRef}
          className="space-y-0.5 max-h-[calc(100vh-12rem)] overflow-y-auto"
          onMouseEnter={() => { hoverRef.current = true; }}
          onMouseLeave={() => { hoverRef.current = false; }}
        >
          {filtered.map((e) => {
            const color = getActivityColor(e);
            return (
              <div
                key={e.id}
                className={cn(
                  'bg-surface border border-border rounded-md p-2.5 flex items-start gap-3 text-xs border-l-2',
                  COLOR_MAP[color],
                )}
              >
                <span className="text-muted-foreground font-mono flex-shrink-0 w-16">
                  {formatTimestamp(e.timestamp)}
                </span>
                <span className={cn(
                  'font-medium flex-shrink-0 w-28 truncate',
                  color === 'started' && 'text-accent',
                  color === 'completed' && 'text-success',
                  color === 'failed' && 'text-destructive',
                  color === 'finding' && 'text-warning',
                  color === 'default' && 'text-muted-foreground',
                )}>
                  {e.event_type}
                </span>
                <span className="text-muted-foreground flex-1">{e.description}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
