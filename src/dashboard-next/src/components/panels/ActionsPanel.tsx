import { useMemo, useState, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { CountdownTimer, EmptyState } from '../shared';
import { getPendingActions } from '../../lib/api';
import type { PendingAction } from '../../lib/types';
import { FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import {
  actionNodeId,
  actionNoise,
  classifyActionLifecycle,
  computeActionRisk,
  groupActionsByTechnique,
  sortActionsForQueue,
  sortTechniqueGroups,
  terminalApprovalCommand,
  terminalApprovalSummary,
  type ActionLifecycle,
  type ActionSortMode,
} from '../../lib/action-queue';
import { deriveNodeRelationships } from '../../lib/relationships';
import { useNavigation } from '../../hooks/useNavigation';

export function ActionsPanel() {
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const graph = useEngagementStore((s) => s.graph);
  const sessions = useEngagementStore((s) => s.sessions);
  const frontier = useEngagementStore((s) => s.frontier);
  const [sortMode, setSortMode] = useState<ActionSortMode>('risk');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [copied, setCopied] = useState<string | null>(null);
  const { navigateToPanel } = useNavigation();

  const sorted = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? pendingActions.filter(action => [
        action.action_id,
        action.technique,
        action.target,
        action.target_node,
        action.target_ip,
        action.description,
      ].some(value => typeof value === 'string' && value.toLowerCase().includes(q)))
      : pendingActions;
    return sortActionsForQueue(list, sortMode);
  }, [pendingActions, query, sortMode]);

  const groups = useMemo(() => groupActionsByTechnique(sorted), [sorted]);
  const groupEntries = useMemo(() => sortTechniqueGroups(groups), [groups]);
  const selectedAction = sorted.find(action => action.action_id === selectedId) || sorted[0] || null;

  const refresh = useCallback(async () => {
    try {
      const data = await getPendingActions();
      useEngagementStore.setState({ pendingActions: data.pending || [] });
    } catch { /* keep current queue visible */ }
  }, []);

  const copyText = useCallback(async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);
    }
  }, []);

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[680px] flex flex-col gap-4">
      <PageHeader
        title="Actions"
        meta={`(${pendingActions.length} pending)`}
        actions={(
          <FilterBar>
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Filter actions..."
              className="settings-input w-56"
            />
            <select value={sortMode} onChange={e => setSortMode(e.target.value as ActionSortMode)} className="settings-input w-auto text-xs">
              <option value="risk">Risk</option>
              <option value="arrival">Arrival</option>
              <option value="noise-desc">Noise</option>
              <option value="timeout-asc">Timeout</option>
            </select>
            <button onClick={refresh} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground">
              Refresh
            </button>
          </FilterBar>
        )}
      />

      {pendingActions.length === 0 ? (
        <EmptyState
          title="No pending actions"
          description="Approvals still happen from the terminal. When an action waits for review, this workspace will show the context to make that terminal decision."
        />
      ) : (
        <div className="grid grid-cols-[minmax(360px,460px)_1fr] gap-4 flex-1 min-h-0">
          <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
            <div className="grid grid-cols-3 border-b border-border text-center text-xs">
              <ActionStat label="High" value={pendingActions.filter(a => computeActionRisk(a).label === 'HIGH').length} tone="destructive" />
              <ActionStat label="Warnings" value={pendingActions.filter(a => a.validation_result === 'warning_only').length} tone="warning" />
              <ActionStat label="Terminal" value={pendingActions.length} tone="accent" />
            </div>
            <div className="overflow-y-auto p-2 space-y-3">
              {groupEntries.map(([technique, actions]) => (
                <div key={technique} className="space-y-1.5">
                  <div className="flex items-center justify-between px-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <span>{technique}</span>
                    <span>{actions.length}</span>
                  </div>
                  {actions.map(action => (
                    <ActionQueueRow
                      key={action.action_id}
                      action={action}
                      selected={selectedAction?.action_id === action.action_id}
                      onSelect={() => setSelectedId(action.action_id)}
                    />
                  ))}
                </div>
              ))}
              {sorted.length === 0 && <div className="px-2 py-6 text-center text-sm text-muted-foreground">No actions match the filter.</div>}
            </div>
          </PanelSection>

          {selectedAction ? (
            <ActionDetail
              action={selectedAction}
              graph={graph}
              sessions={sessions}
              frontier={frontier}
              copied={copied}
              onCopy={copyText}
              onOpenSessions={() => navigateToPanel('sessions')}
              onOpenFrontier={(nodeId) => navigateToPanel('frontier', nodeId)}
            />
          ) : (
            <PanelSection>
              <EmptyState message="Select an action to inspect terminal approval context." />
            </PanelSection>
          )}
        </div>
      )}
    </div>
  );
}

function ActionQueueRow({ action, selected, onSelect }: { action: PendingAction; selected: boolean; onSelect: () => void }) {
  const risk = computeActionRisk(action);
  const lifecycle = classifyActionLifecycle(action);
  const node = actionNodeId(action);

  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full rounded border border-border bg-surface px-2.5 py-2 text-left transition-colors hover:border-accent/40 hover:bg-hover/40',
        selected && 'border-accent/50 bg-accent/5',
      )}
    >
      <div className="flex items-center gap-2">
        <StatusPill className={risk.cls}>{risk.label}</StatusPill>
        <StatusPill className={lifecycleClass(lifecycle)}>{lifecycleLabel(lifecycle)}</StatusPill>
        <span className="ml-auto text-[10px] text-muted-foreground">{formatRelativeTime(action.submitted_at)}</span>
      </div>
      <div className="mt-1 text-xs font-medium text-foreground line-clamp-2">{action.description}</div>
      <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
        <span className="font-mono truncate">{action.action_id.slice(0, 12)}</span>
        {node && <span className="font-mono truncate">{node}</span>}
        <span>noise {actionNoise(action).toFixed(2)}</span>
      </div>
    </button>
  );
}

function ActionDetail({
  action,
  graph,
  sessions,
  frontier,
  copied,
  onCopy,
  onOpenSessions,
  onOpenFrontier,
}: {
  action: PendingAction;
  graph: ReturnType<typeof useEngagementStore.getState>['graph'];
  sessions: ReturnType<typeof useEngagementStore.getState>['sessions'];
  frontier: ReturnType<typeof useEngagementStore.getState>['frontier'];
  copied: string | null;
  onCopy: (key: string, text: string) => void;
  onOpenSessions: () => void;
  onOpenFrontier: (nodeId?: string) => void;
}) {
  const risk = computeActionRisk(action);
  const node = actionNodeId(action);
  const related = node ? deriveNodeRelationships(node, { graph, sessions, pendingActions: [action], frontier }) : null;
  const budgetPct = action.opsec_context?.noise_budget_remaining !== undefined ? Math.round(action.opsec_context.noise_budget_remaining * 100) : null;
  const approveCommand = terminalApprovalCommand(action, 'approve');
  const denyCommand = terminalApprovalCommand(action, 'deny');
  const summary = terminalApprovalSummary(action);
  const signals = action.opsec_context?.defensive_signals || [];

  return (
    <div className="min-w-0 min-h-0 flex flex-col gap-3 overflow-y-auto">
      <PanelSection title="Terminal Approval Context">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-2">
              <StatusPill className={risk.cls}>{risk.label}</StatusPill>
              <StatusPill className={lifecycleClass(classifyActionLifecycle(action))}>{lifecycleLabel(classifyActionLifecycle(action))}</StatusPill>
              {action.timeout_at && <CountdownTimer targetIso={action.timeout_at} className="ml-auto" />}
            </div>
            <h3 className="text-base font-semibold text-foreground">{action.technique}</h3>
            <p className="mt-1 text-sm text-muted-foreground">{action.description}</p>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
          <DetailFact label="Action" value={action.action_id} mono />
          <DetailFact label="Noise" value={actionNoise(action).toFixed(2)} />
          <DetailFact label="Budget" value={budgetPct !== null ? `${budgetPct}%` : '—'} />
          <DetailFact label="Approach" value={action.opsec_context?.recommended_approach || 'terminal'} />
        </div>

        <div className="mt-3 rounded border border-accent/20 bg-accent/5 p-3">
          <div className="text-xs font-medium text-accent mb-1">Terminal-forward review</div>
          <div className="text-xs text-muted-foreground mb-2">
            Use the terminal as the approval surface for this slice. The dashboard is preparing context, not taking over execution.
          </div>
          <CommandCopy label="Context" value={summary} copied={copied === 'summary'} onCopy={() => onCopy('summary', summary)} />
          <CommandCopy label="Approve" value={approveCommand} copied={copied === 'approve'} onCopy={() => onCopy('approve', approveCommand)} />
          <CommandCopy label="Deny" value={denyCommand} copied={copied === 'deny'} onCopy={() => onCopy('deny', denyCommand)} />
        </div>
      </PanelSection>

      <PanelSection title="Related Workspace">
        <div className="space-y-2">
          {node && <GraphNodeLinks nodeId={node} />}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
            <RelationshipButton label="Sessions" count={related?.sessions.length || 0} onClick={onOpenSessions} />
            <RelationshipButton label="Frontier" count={related?.frontier.length || 0} onClick={() => onOpenFrontier(node || undefined)} />
            <RelationshipButton label="Target IP" count={action.target_ip ? 1 : 0} value={action.target_ip || '—'} />
            <RelationshipButton label="Validation" count={action.validation_result ? 1 : 0} value={action.validation_result || '—'} />
          </div>
          {signals.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {signals.map(signal => (
                <span key={signal} className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">{signal}</span>
              ))}
            </div>
          )}
        </div>
      </PanelSection>

      <PanelSection title="Future Dashboard Approval">
        <div className="rounded border border-dashed border-border bg-background/40 p-3">
          <div className="text-xs text-muted-foreground mb-2">
            UI approval controls are intentionally staged but disabled. Terminal approval remains canonical until operator flow and audit semantics are finalized.
          </div>
          <div className="flex gap-2">
            <button disabled className="text-xs px-3 py-1 rounded bg-success/10 text-success border border-success/20 opacity-50 cursor-not-allowed">Approve in dashboard</button>
            <button disabled className="text-xs px-3 py-1 rounded bg-destructive/10 text-destructive border border-destructive/20 opacity-50 cursor-not-allowed">Deny in dashboard</button>
          </div>
        </div>
      </PanelSection>
    </div>
  );
}

function ActionStat({ label, value, tone }: { label: string; value: number; tone?: 'destructive' | 'warning' | 'accent' }) {
  return (
    <div className="py-2 border-r border-border last:border-r-0">
      <div className={cn(
        'text-base font-semibold tabular-nums',
        tone === 'destructive' && 'text-destructive',
        tone === 'warning' && 'text-warning',
        tone === 'accent' && 'text-accent',
      )}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}

function DetailFact({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="rounded border border-border bg-elevated px-2 py-1.5 min-w-0">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className={cn('text-xs text-foreground truncate', mono && 'font-mono')}>{value}</div>
    </div>
  );
}

function RelationshipButton({ label, count, value, onClick }: { label: string; count: number; value?: string; onClick?: () => void }) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp onClick={onClick} className={cn('rounded border border-border bg-elevated px-2 py-1.5 text-left', onClick && 'hover:border-accent/40 hover:bg-hover')}>
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="text-xs text-foreground truncate">{value ?? count}</div>
    </Comp>
  );
}

function CommandCopy({ label, value, copied, onCopy }: { label: string; value: string; copied: boolean; onCopy: () => void }) {
  return (
    <div className="mt-1 flex items-center gap-2">
      <span className="w-14 text-[10px] uppercase text-muted-foreground">{label}</span>
      <code className="flex-1 rounded bg-background px-2 py-1 text-[11px] text-foreground overflow-x-auto">{value}</code>
      <button onClick={onCopy} className="text-[10px] px-2 py-1 rounded bg-elevated text-muted-foreground hover:text-foreground">
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

function lifecycleLabel(lifecycle: ActionLifecycle): string {
  if (lifecycle === 'timeout_soon') return 'timeout soon';
  if (lifecycle === 'blocked_warning') return 'warning';
  if (lifecycle === 'high_risk') return 'high risk';
  return 'terminal approval';
}

function lifecycleClass(lifecycle: ActionLifecycle): string {
  if (lifecycle === 'timeout_soon') return 'bg-destructive/10 text-destructive';
  if (lifecycle === 'blocked_warning') return 'bg-warning/10 text-warning';
  if (lifecycle === 'high_risk') return 'bg-destructive/10 text-destructive';
  return 'bg-accent/10 text-accent';
}
