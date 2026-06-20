import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import * as api from '../../lib/api';
import type { ActionExplanation, ActivityEntry, DecisionLogEntry, TimelineEntry } from '../../lib/types';
import { formatRelativeTime, formatTimestamp, cn } from '../../lib/utils';
import { EmptyState } from '../shared';
import { ActionButton, FilterBar, PageHeader, PanelSection, SegmentedControl, StatusPill } from '../shared/primitives';
import { classifyActivity, extractActivityLinks, filterActivity, selectDefaultActivityEntry, type ActivityClass } from '../../lib/activity-console';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { useNavigation } from '../../hooks/useNavigation';
import { extractActivityTrustSignals } from '../../lib/trust-signals';
import { TrustSignalList, TrustSignalPills } from '../shared/TrustSignals';

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
  const [decisions, setDecisions] = useState<DecisionLogEntry[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [classFilter, setClassFilter] = useState<ActivityClass | ''>('');
  const [search, setSearch] = useState('');
  const [trustOnly, setTrustOnly] = useState(false);
  const [selectedEntryOverride, setSelectedEntryOverride] = useState<ActivityEntry | null>(null);
  const hasLoaded = useRef(false);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getHistory({ limit: 250 });
      setEntries(data.entries || []);
      const [decisionData, timelineData] = await Promise.allSettled([
        api.getDecisionLog({ limit: 50 }),
        api.getTimeline({ limit: 50 }),
      ]);
      if (decisionData.status === 'fulfilled') setDecisions(decisionData.value.decisions || []);
      if (timelineData.status === 'fulfilled') setTimeline(timelineData.value.entries || []);
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

  const filtered = useMemo(() => {
    const base = filterActivity(entries, { classFilter, search });
    const scoped = trustOnly ? base.filter(entry => extractActivityTrustSignals(entry).length > 0) : base;
    // Newest first: history arrives oldest-first, so sort descending by timestamp.
    return [...scoped].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  }, [entries, classFilter, search, trustOnly]);
  const selectedEntry = selectedEntryOverride && filtered.includes(selectedEntryOverride)
    ? selectedEntryOverride
    : selectDefaultActivityEntry(filtered);
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
            <ActionButton onClick={() => setTrustOnly(value => !value)} active={trustOnly} variant="secondary">
              Trust
            </ActionButton>
            <ActionButton onClick={loadHistory} variant="secondary">
              Refresh
            </ActionButton>
          </FilterBar>
        )}
      />

      <div className="grid grid-cols-[minmax(420px,1fr)_minmax(360px,440px)] gap-4 flex-1 min-h-0">
        <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
          <div className="border-b border-border p-2">
            <SegmentedControl
              value={classFilter}
              onChange={setClassFilter}
              options={CLASS_OPTIONS.map(opt => ({
                value: opt.value,
                label: opt.label,
                count: opt.value ? classCounts[opt.value] : undefined,
              }))}
            />
          </div>

          {!initialized && !hasLoaded.current ? (
            <div className="p-4 text-sm text-muted-foreground animate-pulse">Loading activity...</div>
          ) : filtered.length === 0 ? (
            <EmptyState message={entries.length === 0 ? 'No activity yet.' : 'No matches.'} className="m-3" />
          ) : (
            <div className="overflow-y-auto p-2 space-y-1">
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

        <ActivityDetail entry={selectedEntry} decisions={decisions} timeline={timeline} />
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
  const trustSignals = extractActivityTrustSignals(entry);

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
      <TrustSignalPills signals={trustSignals} className="mt-1" />
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

function ActivityDetail({ entry, decisions, timeline }: {
  entry: ActivityEntry | null;
  decisions: DecisionLogEntry[];
  timeline: TimelineEntry[];
}) {
  const { navigateToPanel } = useNavigation();
  const [explanation, setExplanation] = useState<ActionExplanation | null>(null);

  const links = entry ? extractActivityLinks(entry) : null;

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!links?.actionId) {
        setExplanation(null);
        return;
      }
      try {
        const data = await api.explainAction(links.actionId);
        if (!cancelled) setExplanation(data);
      } catch {
        if (!cancelled) setExplanation(null);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [links?.actionId]);

  if (!entry) {
    return (
      <PanelSection>
        <EmptyState message="Select an activity event to inspect its links and details." />
      </PanelSection>
    );
  }

  const cls = classifyActivity(entry);
  const eventLinks = links || extractActivityLinks(entry);
  const trustSignals = extractActivityTrustSignals(entry);
  const matchingDecision = decisions.find(decision =>
    (!!eventLinks.actionId && decision.action_id === eventLinks.actionId)
    || (!!eventLinks.frontierItemId && decision.frontier_item_id === eventLinks.frontierItemId),
  );
  const matchingTimeline = timeline.filter(item => eventLinks.nodeIds.includes(item.entity_id)).slice(0, 3);

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
          <DetailFact label="Action" value={eventLinks.actionId || '—'} onClick={eventLinks.actionId ? () => navigateToPanel('actions') : undefined} />
          <DetailFact label="Agent" value={eventLinks.agentId || '—'} onClick={eventLinks.agentId ? () => navigateToPanel('agents', eventLinks.agentId) : undefined} />
          <DetailFact label="Frontier" value={eventLinks.frontierItemId || '—'} onClick={eventLinks.frontierItemId ? () => navigateToPanel('frontier') : undefined} />
          <DetailFact label="Age" value={formatRelativeTime(entry.timestamp)} />
        </div>

        {trustSignals.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Trust Signals</div>
            <TrustSignalList signals={trustSignals} />
          </div>
        )}

        {eventLinks.nodeIds.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Graph Links</div>
            <div className="flex flex-wrap gap-1">
              {eventLinks.nodeIds.slice(0, 6).map(nodeId => <GraphNodeLinks key={nodeId} nodeId={nodeId} />)}
            </div>
          </div>
        )}

        {(matchingDecision || explanation || matchingTimeline.length > 0) && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Introspection</div>
            <div className="space-y-1.5">
              {matchingDecision && (
                <div className="rounded border border-border bg-elevated px-2 py-1.5 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-foreground truncate">{matchingDecision.decision_id}</span>
                    <StatusPill className="bg-accent/10 text-accent">{matchingDecision.outcome || 'open'}</StatusPill>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">{matchingDecision.stages.length} stages · opened {formatRelativeTime(matchingDecision.opened_at)}</div>
                </div>
              )}
              {explanation?.found && (
                <div className="rounded border border-border bg-elevated px-2 py-1.5 text-xs">
                  <div className="text-foreground">Why this action</div>
                  <div className="mt-1 text-[11px] text-muted-foreground line-clamp-3">
                    {explanation.log_thought_chain[0]?.description || explanation.validation?.validation_result || explanation.outcome?.description || 'No reasoning chain recorded.'}
                  </div>
                </div>
              )}
              {matchingTimeline.map(item => (
                <div key={`${item.kind}:${item.entity_id}`} className="rounded border border-border bg-elevated px-2 py-1.5 text-xs">
                  <div className="font-mono text-foreground truncate">{item.entity_id}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    {item.kind} · true {formatRelativeTime(item.became_true_at)}{item.became_false_at ? ` · ended ${formatRelativeTime(item.became_false_at)}` : ''}
                  </div>
                </div>
              ))}
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
