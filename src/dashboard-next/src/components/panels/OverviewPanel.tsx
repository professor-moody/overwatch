import { useEffect, useCallback, useMemo, useState } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { NODE_COLORS } from '../../lib/graph-constants';
import { cn, formatTimestamp } from '../../lib/utils';
import { SkeletonPanel } from '../shared/Skeleton';
import { TelemetrySection } from './TelemetrySection';
import * as api from '../../lib/api';
import type { TrustSignalDto } from '../../lib/api';
import type { OpsecBudget, Campaign, ActivityEntry } from '../../lib/types';
import { MetricTile, PageHeader, PanelSection } from '../shared/primitives';
import { deriveAccessFacts, deriveAttentionItems, deriveRecentChanges, deriveVerificationItems, type AttentionItem } from '../../lib/overview-workspace';

export function OverviewPanel() {
  const { navigateToGraph, navigateToGraphFilter, navigateToPanel, navigateToEvidence } = useNavigation();
  const graphSummary = useEngagementStore((s) => s.graphSummary);
  const objectives = useEngagementStore((s) => s.objectives);
  const frontier = useEngagementStore((s) => s.frontier);
  const agents = useEngagementStore((s) => s.agents);
  const readiness = useEngagementStore((s) => s.readiness);
  const phases = useEngagementStore((s) => s.phases);
  const campaigns = useEngagementStore((s) => s.campaigns);
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const sessions = useEngagementStore((s) => s.sessions);
  const accessSummary = useEngagementStore((s) => s.accessSummary);
  const opsecBudget = useEngagementStore((s) => s.opsecBudget);
  const recentActivity = useEngagementStore((s) => s.recentActivity);
  const setOpsecBudget = useEngagementStore((s) => s.setOpsecBudget);

  const initialized = useEngagementStore((s) => s.initialized);
  const achievedCount = objectives.filter((o) => o.achieved).length;
  const [trustSignals, setTrustSignals] = useState<TrustSignalDto[]>([]);

  const fetchBudget = useCallback(async () => {
    try {
      const data = await api.getOpsecBudget();
      setOpsecBudget(data);
    } catch { /* silent */ }
  }, [setOpsecBudget]);

  useEffect(() => {
    fetchBudget();
    const timer = setInterval(fetchBudget, 10_000);
    return () => clearInterval(timer);
  }, [fetchBudget]);

  const fetchTrustSignals = useCallback(async () => {
    try {
      const data = await api.getTrustSignals({ limit: 8 });
      setTrustSignals(data.signals || []);
    } catch {
      setTrustSignals([]);
    }
  }, []);

  useEffect(() => {
    fetchTrustSignals();
    const timer = setInterval(fetchTrustSignals, 10_000);
    return () => clearInterval(timer);
  }, [fetchTrustSignals]);

  const recentFindings = useMemo(() => {
    return recentActivity
      .filter(e => e.event_type?.includes('finding') || e.description?.toLowerCase().includes('finding'))
      .slice(-10)
      .reverse();
  }, [recentActivity]);

  const activeCampaigns = useMemo(() => {
    return campaigns.filter(c => c.status === 'active' || c.status === 'paused');
  }, [campaigns]);

  const attentionItems = useMemo(() => deriveAttentionItems({
    pendingActions,
    readinessIssues: readiness?.issues || [],
    frontier,
  }), [frontier, pendingActions, readiness]);

  const accessFacts = useMemo(() => deriveAccessFacts(accessSummary, sessions), [accessSummary, sessions]);
  const recentChanges = useMemo(() => deriveRecentChanges(recentActivity), [recentActivity]);
  const verificationItems = useMemo(() => deriveVerificationItems(trustSignals, 4), [trustSignals]);

  const engagement = useEngagementStore((s) => s.engagement);

  if (!initialized) return <SkeletonPanel />;

  if (!engagement && !graphSummary) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="text-4xl mb-4 opacity-40">⊘</div>
          <h3 className="text-sm font-medium text-foreground mb-1">No engagement loaded</h3>
          <p className="text-xs text-muted-foreground max-w-xs">
            Start the Overwatch MCP server with an engagement config to see live data here.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Overview" />

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricTile
          label="Nodes"
          value={graphSummary?.total_nodes ?? 0}
          sub={`${graphSummary?.confirmed_edges ?? 0} confirmed · ${graphSummary?.inferred_edges ?? 0} inferred`}
          onClick={() => navigateToGraph()}
        />
        <MetricTile
          label="Objectives"
          value={`${achievedCount}/${objectives.length}`}
          sub={achievedCount === objectives.length && objectives.length > 0 ? 'All achieved' : 'In progress'}
          accent={achievedCount === objectives.length && objectives.length > 0}
        />
        <MetricTile
          label="Frontier"
          value={frontier.length}
          sub="actionable items"
          onClick={() => navigateToPanel('frontier')}
        />
        <MetricTile
          label="Agents"
          value={agents.filter((a) => a.status === 'running').length}
          sub={`${agents.length} total`}
          onClick={() => navigateToPanel('agents')}
        />
        <MetricTile
          label="Access"
          value={accessSummary.current_access_level}
          sub={`${accessSummary.compromised_hosts.length} hosts · ${accessSummary.valid_credentials.length} creds`}
          accent={accessSummary.current_access_level === 'domain_admin'}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <PanelSection title="Needs Attention">
          <div className="space-y-2 text-xs">
            {attentionItems.map((item) => (
              <DecisionRow
                key={item.id}
                label={item.label}
                meta={item.meta}
                tone={item.tone === 'warning' ? 'warning' : undefined}
                onClick={() => navigateAttention(item, navigateToPanel, navigateToGraph)}
              />
            ))}
            {attentionItems.length === 0 && (
              <p className="text-muted-foreground">No immediate operator action queued.</p>
            )}
          </div>
        </PanelSection>

        <PanelSection title="Needs Verification" meta={trustSignals.length > 0 ? `(${trustSignals.length})` : undefined}>
          <div className="space-y-2 text-xs">
            {verificationItems.map(item => (
              <DecisionRow
                key={item.id}
                label={item.label}
                meta={item.meta}
                tone={item.severity === 'info' ? undefined : 'warning'}
                onClick={() => navigateVerification(item, navigateToPanel, navigateToGraph)}
              />
            ))}
            {verificationItems.length === 0 && (
              <p className="text-muted-foreground">No parser, path, IAM, or scoring caveats queued.</p>
            )}
          </div>
        </PanelSection>

        <PanelSection title="Current Access">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <AccessFact label="Level" value={accessFacts.level} onClick={() => navigateToGraph()} />
            <AccessFact label="Sessions" value={accessFacts.liveSessions} onClick={() => navigateToPanel('sessions')} />
            <AccessFact label="Hosts" value={accessFacts.hosts} onClick={() => navigateToGraphFilter('host')} />
            <AccessFact label="Valid creds" value={accessFacts.validCredentials} onClick={() => navigateToPanel('credentials')} />
          </div>
        </PanelSection>

        <PanelSection title="Recent Change">
          {recentChanges.length === 0 ? (
            <p className="text-xs text-muted-foreground">No recent activity yet.</p>
          ) : (
            <div className="space-y-1.5">
              {recentChanges.map((entry, index) => (
                <FindingEntry
                  key={activityKey(entry, index)}
                  entry={entry}
                  onClick={() => {
                    const nodeId = entry.target_node_ids?.[0];
                    nodeId ? navigateToGraph(nodeId, 2) : navigateToPanel('activity');
                  }}
                />
              ))}
            </div>
          )}
        </PanelSection>
      </div>

      {opsecBudget && <OpsecGauge budget={opsecBudget} />}

      {phases.length > 0 && (
        <PanelSection title="Engagement Phases">
          <div className="flex gap-2">
            {phases.map((phase, i) => (
              <div
                key={i}
                className={cn(
                  'flex-1 text-center text-xs py-2 px-3 rounded border',
                  phase.status === 'active' && 'border-accent bg-accent-dim text-accent',
                  phase.status === 'completed' && 'border-success/30 bg-success/5 text-success',
                  phase.status === 'pending' && 'border-border bg-elevated text-muted-foreground',
                )}
              >
                {phase.name}
              </div>
            ))}
          </div>
        </PanelSection>
      )}

      {activeCampaigns.length > 0 && (
        <PanelSection title="Active Campaigns" meta={`(${activeCampaigns.length})`}>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeCampaigns.slice(0, 6).map(c => (
              <CampaignCard key={c.id} campaign={c} onClick={() => navigateToPanel('campaigns', c.id)} />
            ))}
          </div>
        </PanelSection>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <PanelSection title="Graph Summary">
          {graphSummary?.nodes_by_type && (
            <div className="space-y-1.5">
              {Object.entries(graphSummary.nodes_by_type)
                .sort(([, a], [, b]) => b - a)
                .map(([type, count]) => (
                  <button
                    key={type}
                    onClick={() => navigateToGraphFilter(type)}
                    className="w-full flex items-center justify-between text-xs hover:bg-hover rounded px-1.5 py-0.5 -mx-1.5 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ backgroundColor: NODE_COLORS[type] || '#888' }}
                      />
                      <span className="text-muted-foreground">{type}</span>
                    </div>
                    <span className="font-mono text-foreground">{count}</span>
                  </button>
                ))}
            </div>
          )}
        </PanelSection>

        <PanelSection title="Objectives">
          {objectives.length === 0 ? (
            <p className="text-xs text-muted-foreground">No objectives defined</p>
          ) : (
            <div className="space-y-2">
              {objectives.map((obj) => (
                <button
                  key={obj.id}
                  onClick={() => navigateToEvidence(obj.id)}
                  className="w-full flex items-start gap-2 text-xs text-left hover:bg-hover rounded px-1 py-0.5 -mx-1 transition-colors"
                >
                  <span className={cn(
                    'mt-0.5 flex-shrink-0',
                    obj.achieved ? 'text-success' : 'text-muted',
                  )}>
                    {obj.achieved ? '✓' : '○'}
                  </span>
                  <span className={cn(
                    obj.achieved ? 'text-foreground' : 'text-muted-foreground',
                  )}>
                    {obj.description}
                  </span>
                </button>
              ))}
            </div>
          )}
        </PanelSection>
      </div>

      {recentFindings.length > 0 && (
        <PanelSection title="Recent Findings" meta={`(${recentFindings.length})`}>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {recentFindings.map((entry, index) => (
              <FindingEntry
                key={activityKey(entry, index)}
                entry={entry}
                onClick={() => {
                  const nodeId = entry.target_node_ids?.[0];
                  nodeId ? navigateToGraph(nodeId, 2) : navigateToPanel('findings');
                }}
              />
            ))}
          </div>
        </PanelSection>
      )}

      {readiness && readiness.issues.length > 0 && (
        <PanelSection>
          <h3 className="text-sm font-medium mb-2 flex items-center gap-2">
            Lab Readiness
            <span className={cn(
              'text-xs px-1.5 py-0.5 rounded',
              readiness.status === 'ready' ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning',
            )}>
              {readiness.status}
            </span>
          </h3>
          <ul className="text-xs text-muted-foreground space-y-1">
            {readiness.issues.map((issue, i) => (
              <li key={i} className="flex items-start gap-1.5">
                <span className="text-warning mt-0.5">⚠</span>
                {issue}
              </li>
            ))}
          </ul>
        </PanelSection>
      )}

      <TelemetrySection />

      <PanelSection title="Top Frontier Items" meta={`(${frontier.length})`}>
        {frontier.length === 0 ? (
          <p className="text-xs text-muted-foreground">No frontier items</p>
        ) : (
          <div className="space-y-1.5">
            {frontier.slice(0, 15).map((item, i) => {
              const targetNode = item.target_node || item.node_id || item.edge_target;
              return (
                <button
                  key={item.frontier_item_id || item.id || i}
                  onClick={() => targetNode && navigateToGraph(targetNode, 2)}
                  className="w-full flex items-center gap-3 text-xs hover:bg-hover rounded px-1 py-0.5 -mx-1 transition-colors text-left"
                >
                  <span className="text-muted font-mono w-5 text-right">{i + 1}</span>
                  <span className={cn(
                    'px-1.5 py-0.5 rounded text-[10px] font-medium',
                    item.type === 'inferred_edge' ? 'bg-purple-dim text-purple' :
                    item.type === 'untested_edge' ? 'bg-warning/10 text-warning' :
                    item.type === 'network_discovery' ? 'bg-accent-dim text-accent' :
                    'bg-elevated text-muted-foreground',
                  )}>
                    {item.type.replace(/_/g, ' ')}
                  </span>
                  <span className="text-muted-foreground flex-1 truncate">{item.description}</span>
                  <span className="font-mono text-foreground">{(item.priority ?? 0).toFixed(1)}</span>
                </button>
              );
            })}
          </div>
        )}
      </PanelSection>
    </div>
  );
}

function OpsecGauge({ budget }: { budget: OpsecBudget }) {
  const pct = budget.max_noise > 0
    ? Math.round((budget.global_noise_spent / budget.max_noise) * 100)
    : 0;
  const remainingPct = 100 - pct;

  const barColor = remainingPct > 60 ? 'bg-success' : remainingPct > 30 ? 'bg-warning' : 'bg-destructive';
  const approachBadge: Record<string, string> = {
    loud: 'bg-success/10 text-success',
    normal: 'bg-warning/10 text-warning',
    quiet: 'bg-destructive/10 text-destructive',
  };

  return (
    <section className="bg-surface border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium flex items-center gap-2">
          OPSEC Budget
          <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', approachBadge[budget.recommended_approach] || '')}>
            {budget.recommended_approach}
          </span>
        </h3>
        <span className="text-xs text-muted-foreground font-mono">
          {budget.global_noise_spent.toFixed(2)} / {budget.max_noise}
        </span>
      </div>
      <div className="h-2 bg-elevated rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', barColor)} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex items-center justify-between mt-1.5 text-[10px] text-muted-foreground">
        <span>{pct}% spent</span>
        {budget.time_window_remaining_hours !== undefined && (
          <span>{budget.time_window_remaining_hours.toFixed(1)}h remaining in window</span>
        )}
      </div>
      {budget.warning && (
        <div className="mt-2 text-xs text-warning bg-warning/5 border border-warning/20 rounded px-2 py-1">
          ⚠ {budget.warning}
        </div>
      )}
      {budget.defensive_signals.length > 0 && (
        <div className="mt-2 text-xs text-destructive">
          {budget.defensive_signals.length} defensive signal{budget.defensive_signals.length > 1 ? 's' : ''} detected
        </div>
      )}
    </section>
  );
}

const STRATEGY_ICONS: Record<string, string> = {
  credential_spray: '🔑',
  enumeration: '🔍',
  post_exploitation: '⚡',
  network_discovery: '🌐',
  custom: '⚙',
};

function CampaignCard({ campaign, onClick }: { campaign: Campaign; onClick?: () => void }) {
  const pct = campaign.completion_pct ?? 0;
  const icon = STRATEGY_ICONS[campaign.strategy] || '⚙';

  return (
    <button onClick={onClick} className="bg-elevated border border-border rounded-md p-3 text-left hover:border-accent/40 transition-colors w-full">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-sm">{icon}</span>
        <span className="text-xs font-medium text-foreground truncate flex-1">{campaign.name}</span>
        {campaign.status === 'paused' && (
          <span className="text-[10px] px-1 py-0.5 rounded bg-warning/10 text-warning">PAUSED</span>
        )}
      </div>
      <div className="h-1.5 bg-surface rounded-full overflow-hidden mb-1.5">
        <div className="h-full bg-accent rounded-full transition-all" style={{ width: `${pct}%` }} />
      </div>
      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span>{pct}%</span>
        <span>{campaign.agents_active ?? 0} agents · {campaign.findings_count ?? 0} findings</span>
      </div>
    </button>
  );
}

function FindingEntry({ entry, onClick }: { entry: ActivityEntry; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left flex items-center gap-3 text-xs hover:bg-hover rounded px-1 py-0.5 -mx-1 transition-colors"
    >
      <span className="text-muted-foreground font-mono flex-shrink-0 w-14">{formatTimestamp(entry.timestamp)}</span>
      <span className="w-1.5 h-1.5 rounded-full bg-warning flex-shrink-0" />
      <span className="text-muted-foreground flex-1 truncate">{entry.description}</span>
    </button>
  );
}

function activityKey(entry: ActivityEntry, index: number): string {
  return entry.event_id || entry.id || `${entry.timestamp}-${entry.event_type}-${index}`;
}

function navigateAttention(
  item: AttentionItem,
  navigateToPanel: ReturnType<typeof useNavigation>['navigateToPanel'],
  navigateToGraph: ReturnType<typeof useNavigation>['navigateToGraph'],
) {
  if (item.nodeId) {
    navigateToGraph(item.nodeId, 2);
    return;
  }
  navigateToPanel(item.route);
}

function navigateVerification(
  item: ReturnType<typeof deriveVerificationItems>[number],
  navigateToPanel: ReturnType<typeof useNavigation>['navigateToPanel'],
  navigateToGraph: ReturnType<typeof useNavigation>['navigateToGraph'],
) {
  if (item.nodeId) {
    navigateToGraph(item.nodeId, 2);
    return;
  }
  navigateToPanel(item.route);
}

function DecisionRow({
  label,
  meta,
  tone,
  onClick,
}: {
  label: string;
  meta?: string;
  tone?: 'warning';
  onClick?: () => void;
}) {
  const Wrapper = onClick ? 'button' : 'div';
  return (
    <Wrapper
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-2 text-left rounded px-2 py-1.5',
        onClick && 'hover:bg-hover transition-colors',
      )}
    >
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', tone === 'warning' ? 'bg-warning' : 'bg-accent')} />
      <span className="text-muted-foreground truncate flex-1">{label}</span>
      {meta && <span className="font-mono text-foreground">{meta}</span>}
    </Wrapper>
  );
}

function AccessFact({ label, value, onClick }: { label: string; value: number | string; onClick?: () => void }) {
  const Wrapper = onClick ? 'button' : 'div';
  return (
    <Wrapper
      onClick={onClick}
      className={cn(
        'w-full rounded border border-border bg-elevated px-2 py-1.5 text-left',
        onClick && 'hover:border-accent/40 hover:bg-hover transition-colors',
      )}
    >
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="text-sm font-semibold text-foreground truncate">{value}</div>
    </Wrapper>
  );
}
