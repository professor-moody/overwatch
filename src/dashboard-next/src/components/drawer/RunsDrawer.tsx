import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, RefreshCw, Search } from 'lucide-react';
import * as api from '../../lib/api';
import { buildActionRuns, filterRuns, runLabel, type ActionRun, type RunStatus } from '../../lib/action-runs';
import type { ActivityEntry } from '../../lib/types';
import { cn, formatRelativeTime, formatTimestamp } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import { StatusPill } from '../shared/primitives';
import { ExecutionOutputView } from './ExecutionOutputView';

const STATUS_FILTERS: Array<{ value: RunStatus | ''; label: string }> = [
  { value: '', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'success', label: 'Success' },
  { value: 'partial', label: 'Partial' },
  { value: 'failure', label: 'Failure' },
];

export function RunsDrawer({
  selectedItem,
  onSelect,
  onOpenActivity,
}: {
  selectedItem?: string;
  onSelect: (item: string | null) => void;
  onOpenActivity: (actionId: string) => void;
}) {
  const connected = useEngagementStore(state => state.connected);
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [status, setStatus] = useState<RunStatus | ''>('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [stale, setStale] = useState(false);
  const initializedSelection = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const response = await api.getHistory({ limit: 1000, eventTypes: ['action_started', 'action_completed', 'action_failed'] });
      setEntries(response.entries || []);
      setStale(false);
    } catch {
      setStale(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { if (connected) void refresh(); }, 5000);
    return () => window.clearInterval(timer);
  }, [connected, refresh]);

  useEffect(() => { if (!connected) setStale(true); }, [connected]);

  const runs = useMemo(() => buildActionRuns(entries), [entries]);
  const filtered = useMemo(() => filterRuns(runs, { status, search }), [runs, search, status]);
  const selectedKnown = selectedItem ? runs.find(run => run.actionId === selectedItem) : undefined;
  const selected = selectedItem ? (selectedKnown ?? outOfWindowRun(selectedItem)) : null;

  useEffect(() => {
    if (loading || initializedSelection.current) return;
    initializedSelection.current = true;
    if (!selectedItem && filtered[0]) onSelect(filtered[0].actionId);
  }, [filtered, loading, onSelect, selectedItem]);

  const counts = useMemo(() => {
    const value: Partial<Record<RunStatus, number>> = {};
    for (const run of runs) value[run.status] = (value[run.status] || 0) + 1;
    return value;
  }, [runs]);

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="runs-drawer">
      <div className="flex min-h-10 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-2">
        <label className="flex h-7 min-w-[170px] flex-1 items-center gap-1.5 rounded border border-border-subtle bg-background/60 px-2 focus-within:border-accent/50 sm:max-w-72">
          <Search className="h-3 w-3 text-muted-foreground" />
          <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Tool, command, agent, target…" className="min-w-0 flex-1 bg-transparent text-[10px] outline-none placeholder:text-muted" />
        </label>
        <div className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto" role="tablist" aria-label="Run status">
          {STATUS_FILTERS.map(option => (
            <button key={option.value || 'all'} type="button" role="tab" aria-selected={status === option.value} onClick={() => setStatus(option.value)} className={cn('h-7 flex-shrink-0 rounded px-2 text-[9px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70', status === option.value ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover hover:text-foreground')}>{option.label}{option.value && counts[option.value] ? <span className="ml-1 tabular-nums text-muted">{counts[option.value]}</span> : null}</button>
          ))}
        </div>
        <span className="hidden whitespace-nowrap text-[9px] tabular-nums text-muted-foreground xl:inline">{filtered.length} / {runs.length}</span>
        <button type="button" onClick={() => void refresh()} className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-hover hover:text-foreground" title="Refresh runs"><RefreshCw className={cn('h-3 w-3', loading && 'animate-spin')} /></button>
      </div>

      {stale && <div className="flex flex-shrink-0 items-center gap-2 border-b border-warning/20 bg-warning/5 px-3 py-1 text-[10px] text-warning"><AlertTriangle className="h-3 w-3" />{connected ? 'Run history could not be refreshed; showing the last good list.' : 'Disconnected — showing the last good run list and output.'}</div>}

      <div className="flex min-h-0 flex-1">
        <div className="flex w-[clamp(300px,31vw,360px)] flex-shrink-0 flex-col overflow-y-auto border-r border-border-subtle">
          {loading && entries.length === 0 ? <DrawerState title="Loading runs" detail="Reading action lifecycle events…" />
            : filtered.length === 0 ? <DrawerState title={runs.length ? 'No matching runs' : 'No runs yet'} detail={runs.length ? 'Change the run filter or search query.' : 'Instrumented actions appear here once they start.'} />
              : filtered.map(run => <RunRow key={run.actionId} run={run} selected={run.actionId === selectedItem} onSelect={() => onSelect(run.actionId)} />)}
        </div>
        <div className="min-w-0 flex-1">
          {selected ? (
            <div className="flex h-full min-h-0 flex-col">
              {!selectedKnown && <div className="flex-shrink-0 border-b border-accent/20 bg-accent/5 px-3 py-1 text-[9px] text-accent">Loaded directly by action ID; this run is outside the recent lifecycle window.</div>}
              <div className="min-h-0 flex-1"><ExecutionOutputView key={selected.actionId} actionId={selected.actionId} showOpenInRuns={false} /></div>
              <button type="button" onClick={() => onOpenActivity(selected.actionId)} className="h-7 flex-shrink-0 border-t border-border-subtle text-[9px] text-muted-foreground hover:bg-hover hover:text-foreground">Show lifecycle in Activity</button>
            </div>
          ) : <DrawerState title="Select a run" detail="Inspect command, lifecycle metadata, stdout, stderr, evidence, and findings." />}
        </div>
      </div>
    </div>
  );
}

function RunRow({ run, selected, onSelect }: { run: ActionRun; selected: boolean; onSelect: () => void }) {
  return (
    <button type="button" onClick={onSelect} className={cn('relative flex w-full min-w-0 flex-col gap-1 border-b border-border-subtle px-2.5 py-2 text-left transition-colors hover:bg-hover/45 focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/70', selected && 'bg-accent/[0.08] before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:bg-accent')}>
      <div className="flex min-w-0 items-center gap-2">
        <StatusPill tone={runTone(run.status)}>{runCue(run.status)} {run.status}</StatusPill>
        <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-foreground">{run.tool || 'instrumented action'}</span>
        <span className="flex-shrink-0 font-mono text-[9px] text-muted-foreground">{formatTimestamp(run.timestamp)}</span>
      </div>
      <div className="truncate font-mono text-[9px] text-muted-foreground">{runLabel(run)}</div>
      <div className="flex min-w-0 items-center gap-1.5 text-[8px] text-muted">
        {run.agentId && <span className="truncate font-mono">{run.agentId}</span>}
        {run.campaignId && <span className="truncate">· {run.campaignId}</span>}
        {run.targets[0] && <span className="truncate font-mono text-accent">· {run.targets[0]}</span>}
        <span className="ml-auto flex-shrink-0">{formatRelativeTime(run.timestamp)}</span>
      </div>
    </button>
  );
}

function outOfWindowRun(actionId: string): ActionRun {
  return { actionId, tool: null, command: null, status: 'neutral', agentId: null, campaignId: null, targets: [], timestamp: '', startedAt: null, description: '' };
}

function runTone(status: RunStatus): 'accent' | 'success' | 'warning' | 'danger' | 'muted' {
  if (status === 'running') return 'accent';
  if (status === 'success') return 'success';
  if (status === 'partial') return 'warning';
  if (status === 'failure') return 'danger';
  return 'muted';
}

function runCue(status: RunStatus): string {
  if (status === 'running') return '●';
  if (status === 'success') return '✓';
  if (status === 'partial') return '△';
  if (status === 'failure') return '×';
  return '–';
}

function DrawerState({ title, detail }: { title: string; detail: string }) {
  return <div className="flex h-full min-h-28 flex-col items-center justify-center px-6 text-center"><div className="text-xs font-medium text-foreground">{title}</div><div className="mt-1 max-w-md text-[10px] leading-4 text-muted-foreground">{detail}</div></div>;
}
