import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronRight, CircleDot, Play, Plus } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useEngagementStore } from '../../stores/engagement-store';
import { useDashboardUiStore } from '../../stores/dashboard-ui-store';
import { useToastStore } from '../../stores/toast-store';
import * as api from '../../lib/api';
import type { AgentInfo, FrontierItem, PlaybookRun } from '../../lib/types';
import { buildAttentionQueue, type AttentionItem } from '../../lib/attention-queue';
import { agentDisplayLabel, canonicalAgentTaskId } from '../../lib/agent-reference';
import { getFrontierKey, getFrontierNodeIds, formatFrontierScore } from '../../lib/frontier-workspace';
import { sessionsForAgent } from '../../lib/session-workspace';
import { cn, formatRelativeTime } from '../../lib/utils';
import {
  agentLiveWorkState,
  displayWorkState,
  isTerminalAgent,
  playbookLiveWorkState,
  selectActiveWork,
  type LiveWorkState,
} from '../../lib/work-state';
import { buildWorkspacePath, type OperateView, OPERATE_VIEWS, setDrawerParams, setSelectionParams } from '../../lib/workspace-navigation';
import { AttentionDecisionActions, AttentionQueue } from '../panels/AttentionQueue';
import { ContextualCommandBar } from '../panels/ContextualCommandBar';
import { CampaignDetail, CampaignsPanel } from '../panels/CampaignsPanel';
import { AgentDetailPanel, type AgentContext } from '../agents/AgentDetailPanel';
import { StartWorkLauncher } from './StartWorkLauncher';
import { useWorkspaceInspectorAdapters, type WorkspaceInspectorAdapter } from '../layout/WorkspaceInspectorRegistry';
import {
  ActionButton,
  StatusPill,
  WorkspaceEmpty,
  WorkspaceHeader,
  WorkspaceInspector,
  WorkspaceRow,
  WorkspaceTabs,
} from '../shared/primitives';

function isOperateView(value: string | null): value is OperateView {
  return !!value && (OPERATE_VIEWS as readonly string[]).includes(value);
}

export function OperateWorkspace() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialized = useEngagementStore(state => state.initialized);
  const connected = useEngagementStore(state => state.connected);
  const agents = useEngagementStore(state => state.agents);
  const campaigns = useEngagementStore(state => state.campaigns);
  const frontier = useEngagementStore(state => state.frontier);
  const pendingActions = useEngagementStore(state => state.pendingActions);
  const playbookRuns = useEngagementStore(state => state.playbookRuns);
  const sessions = useEngagementStore(state => state.sessions);
  const setStoreAgents = useEngagementStore(state => state.setAgents);
  const [agentQueries, setAgentQueries] = useState<api.AgentQuery[]>([]);
  const [proposedPlans, setProposedPlans] = useState<api.ProposedPlan[]>([]);
  const [readiness, setReadiness] = useState<api.FindingReadinessReport | null>(null);
  const [supplementalReady, setSupplementalReady] = useState(false);
  const [historyStatus, setHistoryStatus] = useState('all');
  const [historyType, setHistoryType] = useState('all');
  const [historyCampaign, setHistoryCampaign] = useState('all');
  const [historySince, setHistorySince] = useState('');
  const launcherOpen = useDashboardUiStore(state => state.startWorkOpen);
  const setLauncherOpen = useDashboardUiStore(state => state.setStartWorkOpen);
  const addToast = useToastStore(state => state.addToast);

  const refreshSupplemental = useCallback(async () => {
    const [queries, plans, proof] = await Promise.allSettled([
      api.getAgentQueries(),
      api.getProposedPlans(),
      api.getFindingReadiness(),
    ]);
    if (queries.status === 'fulfilled') setAgentQueries(queries.value.queries || []);
    if (plans.status === 'fulfilled') setProposedPlans(plans.value.plans || []);
    if (proof.status === 'fulfilled') setReadiness(proof.value);
    setSupplementalReady(true);
  }, []);

  useEffect(() => {
    void refreshSupplemental();
    const onQuery = () => void refreshSupplemental();
    window.addEventListener('overwatch-agent-query-update', onQuery);
    const timer = window.setInterval(() => { if (connected) void refreshSupplemental(); }, 10_000);
    return () => {
      window.removeEventListener('overwatch-agent-query-update', onQuery);
      window.clearInterval(timer);
    };
  }, [connected, refreshSupplemental]);

  const proofGap = readiness
    ? { draft: readiness.summary.draft, needs_validation: readiness.summary.needs_validation }
    : undefined;
  const attention = useMemo(() => buildAttentionQueue({
    pendingActions,
    agentQueries,
    proposedPlans,
    agents,
    proofGap,
  }), [agentQueries, agents, pendingActions, proofGap, proposedPlans]);
  const activeWork = useMemo(() => selectActiveWork({ agents, campaigns, playbooks: playbookRuns }), [agents, campaigns, playbookRuns]);
  const { agents: activeAgents, campaigns: activeCampaigns, playbooks: activePlaybooks } = activeWork;
  const historyAgents = useMemo(() => agents.filter(isTerminalAgent), [agents]);
  const visibleHistoryAgents = useMemo(() => historyAgents.filter(agent => {
    if (historyStatus !== 'all' && agent.status !== historyStatus) return false;
    if (historyType !== 'all' && (agent.archetype || agent.role || 'default') !== historyType) return false;
    if (historyCampaign !== 'all' && agent.campaign_id !== historyCampaign) return false;
    if (historySince) {
      const stamp = new Date(agent.completed_at || agent.assigned_at).getTime();
      const since = new Date(`${historySince}T00:00:00`).getTime();
      if (!Number.isFinite(stamp) || stamp < since) return false;
    }
    return true;
  }), [historyAgents, historyCampaign, historySince, historyStatus, historyType]);
  const requested = searchParams.get('view');
  const view: OperateView | null = isOperateView(requested) ? requested : null;

  // Choose the initial view once the store and the small attention supplements
  // have hydrated. Once written to the URL, subsequent count changes never move it.
  useEffect(() => {
    if (!initialized || !supplementalReady || view) return;
    const initial: OperateView = attention.total > 0
      ? 'attention'
      : activeWork.total > 0
        ? 'active'
        : 'ready';
    const next = new URLSearchParams(searchParams);
    next.set('view', initial);
    setSearchParams(next, { replace: true });
  }, [activeWork.total, attention.total, initialized, searchParams, setSearchParams, supplementalReady, view]);

  const effectiveView = view ?? 'attention';
  const selectedKind = searchParams.get('kind');
  const selectedId = searchParams.get('item');
  const selectedAgent = selectedKind === 'agent' && selectedId
    ? agents.find(agent => canonicalAgentTaskId(agent) === selectedId || agent.id === selectedId) ?? null
    : null;
  const selectedFrontier = selectedKind === 'frontier' && selectedId
    ? frontier.find(item => getFrontierKey(item) === selectedId) ?? null
    : null;
  const selectedPlaybook = selectedKind === 'playbook' && selectedId
    ? playbookRuns.find(run => run.run_id === selectedId) ?? null
    : null;
  const selectedCampaign = selectedKind === 'campaign' && selectedId
    ? campaigns.find(campaign => campaign.id === selectedId) ?? null
    : null;
  const selectedAttention = selectedId && ['approval', 'question', 'plan', 'proof_gap'].includes(selectedKind || '')
    ? attention.items.find(item => {
      if (item.kind !== selectedKind) return false;
      const stableId = item.actionId || item.queryId || item.planId || (item.kind === 'proof_gap' ? 'findings' : item.id);
      return stableId === selectedId;
    }) ?? null
    : null;
  const inspectorOpen = !!(selectedAgent || selectedFrontier || selectedPlaybook || selectedCampaign || selectedAttention);

  const setView = (nextView: OperateView) => {
    const next = setSelectionParams(searchParams, null);
    next.set('view', nextView);
    setSearchParams(next);
  };
  const select = (kind: 'agent' | 'frontier' | 'playbook' | 'campaign' | 'approval' | 'question' | 'plan' | 'proof_gap', id: string) => {
    setSearchParams(setSelectionParams(searchParams, { kind, id }));
  };

  const refreshAgents = useCallback(async () => {
    try {
      const result = await api.getAgents();
      setStoreAgents(result.agents || []);
    } catch { /* preserve last-good fleet */ }
  }, [setStoreAgents]);

  const refreshCampaigns = useCallback(async () => {
    try {
      const result = await api.getCampaigns();
      useEngagementStore.setState({ campaigns: result.campaigns || [] });
    } catch { /* preserve last-good campaign list */ }
  }, []);

  const forceRemoveAgent = useCallback(async (taskId: string) => {
    try {
      await api.dismissAgent(taskId, { force: true });
      await refreshAgents();
    } catch (error) {
      addToast({ type: 'error', title: 'Force remove failed', message: error instanceof Error ? error.message : String(error) });
    }
  }, [addToast, refreshAgents]);

  const cancelAgent = useCallback(async (taskId: string) => {
    try {
      await api.cancelAgent(taskId);
      await refreshAgents();
    } catch (error) {
      addToast({ type: 'error', title: 'Cancel failed', message: error instanceof Error ? error.message : String(error) });
    }
  }, [addToast, refreshAgents]);

  const issueDirective = useCallback(async (taskId: string, kind: api.DirectiveKind) => {
    try {
      await api.issueDirective(taskId, kind);
      addToast({ type: 'success', title: `${kind[0].toUpperCase()}${kind.slice(1)} sent` });
    } catch (error) {
      addToast({ type: 'error', title: 'Directive failed', message: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }, [addToast]);

  const tabOptions: Array<{ value: OperateView; label: string; count?: number }> = [
    { value: 'attention', label: 'Needs you', count: attention.total },
    { value: 'active', label: 'Active', count: activeWork.total },
    { value: 'ready', label: 'Ready', count: frontier.length },
    { value: 'campaigns', label: 'Campaigns', count: campaigns.length },
    { value: 'history', label: 'History', count: historyAgents.length },
  ];

  const operateInspectorAdapter = useMemo<WorkspaceInspectorAdapter>(() => ({
    resolved: initialized && supplementalReady,
    available: inspectorOpen,
    render: ({ close }) => (
      <OperateInspector
        agent={selectedAgent}
        frontier={selectedFrontier}
        playbook={selectedPlaybook}
        campaign={selectedCampaign}
        attention={selectedAttention}
        frontierItems={frontier}
        sessions={sessions}
        onClose={close}
        onCancel={cancelAgent}
        onForceRemove={forceRemoveAgent}
        onIssueDirective={issueDirective}
        onNavigate={navigate}
        onOpenDrawer={(kind, item) => setSearchParams(setDrawerParams(searchParams, { kind, item }))}
        onStartFrontier={() => setLauncherOpen(true)}
        onRefreshCampaigns={refreshCampaigns}
        onAttentionAnswered={refreshSupplemental}
        onAttentionPlanResolved={refreshSupplemental}
        onReviewProof={() => navigate(buildWorkspacePath({ workspace: 'review', view: 'readiness', readiness: 'draft' }))}
      />
    ),
  }), [
    activeWork.total,
    cancelAgent,
    forceRemoveAgent,
    frontier,
    initialized,
    inspectorOpen,
    issueDirective,
    navigate,
    refreshCampaigns,
    refreshSupplemental,
    searchParams,
    selectedAgent,
    selectedAttention,
    selectedCampaign,
    selectedFrontier,
    selectedPlaybook,
    sessions,
    setLauncherOpen,
    setSearchParams,
    supplementalReady,
  ]);
  const operateInspectorAdapters = useMemo(() => ({
    agent: operateInspectorAdapter,
    frontier: operateInspectorAdapter,
    playbook: operateInspectorAdapter,
    campaign: operateInspectorAdapter,
    approval: operateInspectorAdapter,
    question: operateInspectorAdapter,
    plan: operateInspectorAdapter,
    proof_gap: operateInspectorAdapter,
  }), [operateInspectorAdapter]);
  useWorkspaceInspectorAdapters(operateInspectorAdapters);

  return (
    <div className="flex min-h-0 min-w-0 w-full flex-1 flex-col overflow-hidden bg-background">
      <WorkspaceHeader
        eyebrow="Mission control"
        title="Operate"
        description="Handle decisions, keep live work moving, and start the next highest-value action."
        actions={(
          <ActionButton variant="primary" className="h-8" onClick={() => setLauncherOpen(true)}>
            <Plus className="h-3.5 w-3.5" /> Start work
          </ActionButton>
        )}
      >
        <WorkspaceTabs value={effectiveView} options={tabOptions} onChange={setView} ariaLabel="Operate views" />
      </WorkspaceHeader>

      <div className="border-b border-border-subtle bg-surface/25 px-5 py-3 lg:px-6">
        <ContextualCommandBar focusedAgent={selectedAgent} agents={agents} onAgentCommandSent={() => void refreshAgents()} />
      </div>

      <div className="relative flex min-h-0 flex-1">
        <section className="min-w-0 flex-1 overflow-y-auto">
          {effectiveView === 'attention' && (
            <div className="p-4 lg:p-5">
              {attention.total > 0 ? (
                <AttentionQueue
                  full
                  agentQueries={agentQueries}
                  proposedPlans={proposedPlans}
                  proofGap={proofGap}
                  onAnswered={() => void refreshSupplemental()}
                  onPlanResolved={() => void refreshSupplemental()}
                  onSelectAgent={taskId => select('agent', taskId)}
                  onForceRemove={forceRemoveAgent}
                  onTriageAll={() => undefined}
                  onReviewProof={() => navigate(buildWorkspacePath({ workspace: 'review', view: 'readiness', readiness: 'draft' }))}
                  onSelectItem={item => {
                    if ((item.kind === 'failed' || item.kind === 'stuck') && item.taskId) select('agent', item.taskId);
                    else if (item.kind === 'approval' && item.actionId) select('approval', item.actionId);
                    else if (item.kind === 'question' && item.queryId) select('question', item.queryId);
                    else if (item.kind === 'plan' && item.planId) select('plan', item.planId);
                    else if (item.kind === 'proof_gap') select('proof_gap', 'findings');
                  }}
                />
              ) : (
                <WorkspaceEmpty
                  title="Nothing needs intervention"
                  detail="No approvals, questions, stalled agents, proposed plans, or proof gaps are waiting."
                  action={<ActionButton onClick={() => setView(activeAgents.length ? 'active' : 'ready')}>View {activeAgents.length ? 'active work' : 'ready work'}</ActionButton>}
                />
              )}
            </div>
          )}

          {effectiveView === 'active' && (
            <div>
              {activeAgents.length === 0 && activePlaybooks.length === 0 && activeCampaigns.length === 0 ? (
                <WorkspaceEmpty title="No work is running" detail="Start from a target, graph node, or ready frontier item." action={<ActionButton variant="primary" onClick={() => setLauncherOpen(true)}>Start work</ActionButton>} />
              ) : (
                <>
                  {(['running', 'queued'] as const).map(workState => {
                    const matching = activeAgents.filter(agent => agentLiveWorkState(agent) === workState);
                    return matching.length > 0 && <div key={workState}>
                      <SectionLabel label={`${displayWorkState(workState)} agents`} count={matching.length} />
                      {matching.map(agent => (
                        <AgentRow
                          key={canonicalAgentTaskId(agent)}
                          agent={agent}
                          selected={selectedAgent ? canonicalAgentTaskId(selectedAgent) === canonicalAgentTaskId(agent) : false}
                          onClick={() => select('agent', canonicalAgentTaskId(agent))}
                        />
                      ))}
                    </div>;
                  })}
                  {(['running', 'queued', 'waiting'] as const).map(workState => {
                    const matching = activePlaybooks.filter(run => playbookLiveWorkState(run) === workState);
                    return matching.length > 0 && <div key={workState}>
                      <SectionLabel label={`${displayWorkState(workState)} playbooks`} count={matching.length} />
                      {matching.map(run => (
                        <PlaybookRow key={run.run_id} run={run} state={workState} selected={selectedPlaybook?.run_id === run.run_id} onClick={() => select('playbook', run.run_id)} />
                      ))}
                    </div>;
                  })}
                  {activeCampaigns.length > 0 && <SectionLabel label="Campaigns" count={activeCampaigns.length} />}
                  {activeCampaigns.map(campaign => (
                    <WorkspaceRow key={campaign.id} selected={selectedCampaign?.id === campaign.id} onClick={() => select('campaign', campaign.id)}>
                      <CircleDot className="h-3.5 w-3.5 flex-shrink-0 text-accent" />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs font-medium text-foreground">{campaign.name || campaign.id}</div>
                        <div className="mt-0.5 text-[10px] text-muted-foreground">{campaign.status || 'active'} · {campaign.agents_active ?? campaign.running_agents ?? 0} agents active</div>
                      </div>
                      <ChevronRight className="h-3.5 w-3.5 text-muted" />
                    </WorkspaceRow>
                  ))}
                </>
              )}
            </div>
          )}

          {effectiveView === 'ready' && (
            <div>
              {frontier.length === 0 ? (
                <WorkspaceEmpty title="No actionable frontier items" detail="The current graph and scope do not expose unleased work. Add a target or investigate the graph." action={<ActionButton variant="primary" onClick={() => setLauncherOpen(true)}>Add a target</ActionButton>} />
              ) : frontier.map((item, index) => (
                <FrontierRow
                  key={getFrontierKey(item)}
                  item={item}
                  rank={index + 1}
                  selected={selectedFrontier ? getFrontierKey(selectedFrontier) === getFrontierKey(item) : false}
                  onInspect={() => select('frontier', getFrontierKey(item))}
                  onStart={() => {
                    select('frontier', getFrontierKey(item));
                    setLauncherOpen(true);
                  }}
                />
              ))}
            </div>
          )}

          {effectiveView === 'campaigns' && <div className="h-full p-4 lg:p-5"><CampaignsPanel embedded /></div>}

          {effectiveView === 'history' && (
            <div>
              <div className="flex flex-wrap items-center gap-2 border-b border-border-subtle px-3 py-2">
                <select aria-label="History status" value={historyStatus} onChange={event => setHistoryStatus(event.target.value)} className="settings-input h-8 w-auto text-xs"><option value="all">All outcomes</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="interrupted">Interrupted</option></select>
                <select aria-label="History agent type" value={historyType} onChange={event => setHistoryType(event.target.value)} className="settings-input h-8 w-auto text-xs"><option value="all">All agent types</option>{[...new Set(historyAgents.map(agent => agent.archetype || agent.role || 'default'))].sort().map(value => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select>
                <select aria-label="History campaign" value={historyCampaign} onChange={event => setHistoryCampaign(event.target.value)} className="settings-input h-8 w-auto text-xs"><option value="all">All campaigns</option>{campaigns.map(campaign => <option key={campaign.id} value={campaign.id}>{campaign.name}</option>)}</select>
                <label className="flex items-center gap-2 text-[10px] text-muted-foreground">Since <input aria-label="History since date" type="date" value={historySince} onChange={event => setHistorySince(event.target.value)} className="settings-input h-8 w-auto text-xs" /></label>
                <span className="ml-auto text-[10px] text-muted-foreground">{visibleHistoryAgents.length} outcomes</span>
              </div>
              {historyAgents.length === 0 ? (
                <WorkspaceEmpty title="No completed work yet" detail="Finished, failed, interrupted, and merged agents will collect here." />
              ) : visibleHistoryAgents.length === 0 ? (
                <WorkspaceEmpty title="No outcomes match these filters" detail="Broaden the outcome, agent type, campaign, or date filters." />
              ) : visibleHistoryAgents.map(agent => (
                <AgentRow
                  key={canonicalAgentTaskId(agent)}
                  agent={agent}
                  selected={selectedAgent ? canonicalAgentTaskId(selectedAgent) === canonicalAgentTaskId(agent) : false}
                  onClick={() => select('agent', canonicalAgentTaskId(agent))}
                />
              ))}
            </div>
          )}
        </section>

      </div>

      {launcherOpen && <StartWorkLauncher onClose={() => setLauncherOpen(false)} />}
    </div>
  );
}

function SectionLabel({ label, count }: { label: string; count: number }) {
  return (
    <div className="sticky top-0 z-10 flex h-8 items-center gap-2 border-b border-border-subtle bg-background/95 px-3 text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground backdrop-blur">
      {label}<span className="font-mono text-muted">{count}</span>
    </div>
  );
}

function AgentRow({ agent, selected, onClick }: { agent: AgentInfo; selected: boolean; onClick: () => void }) {
  const label = agentDisplayLabel(agent);
  const statusTone = agent.status === 'running' ? 'success' : agent.status === 'failed' ? 'danger' : agent.status === 'completed' ? 'accent' : agent.status === 'pending' ? 'warning' : 'muted';
  return (
    <WorkspaceRow selected={selected} onClick={onClick}>
      <span className={cn('h-2 w-2 flex-shrink-0 rounded-full', agent.status === 'running' ? 'bg-success' : agent.status === 'failed' ? 'bg-destructive' : agent.status === 'pending' ? 'bg-warning' : 'bg-accent')} />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-xs font-medium text-foreground">{label}</span>
          <StatusPill tone={statusTone}>{agent.status}</StatusPill>
        </div>
        <div className="mt-0.5 flex min-w-0 items-center gap-2 text-[10px] text-muted-foreground">
          <span className="truncate">{agent.current_action || agent.result_summary || agent.objective || agent.archetype || agent.role || 'Agent task'}</span>
          {agent.findings_count > 0 && <span className="flex-shrink-0 text-success">{agent.findings_count} findings</span>}
        </div>
      </div>
      <span className="hidden max-w-44 truncate font-mono text-[9px] text-muted lg:block">{canonicalAgentTaskId(agent)}</span>
      <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-muted" />
    </WorkspaceRow>
  );
}

function FrontierRow({
  item,
  rank,
  selected,
  onInspect,
  onStart,
}: {
  item: FrontierItem;
  rank: number;
  selected: boolean;
  onInspect: () => void;
  onStart: () => void;
}) {
  const nodes = getFrontierNodeIds(item);
  return (
    <WorkspaceRow selected={selected} onClick={onInspect}>
      <span className="w-5 flex-shrink-0 text-right font-mono text-[10px] text-muted">{rank}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-xs font-medium text-foreground">{item.description || item.type.replaceAll('_', ' ')}</span>
          <StatusPill tone="muted">{item.type.replaceAll('_', ' ')}</StatusPill>
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-muted-foreground">
          <span>{nodes.length > 0 ? `${nodes.length} linked asset${nodes.length === 1 ? '' : 's'}` : 'Discovery task'}</span>
          <span>noise {(item.opsec_noise ?? 0).toFixed(1)}</span>
          <span>confidence {Math.round((item.graph_metrics?.confidence ?? 0) * 100)}%</span>
        </div>
      </div>
      <span className="font-mono text-[10px] text-foreground">{formatFrontierScore(item)}</span>
      <ActionButton
        size="xs"
        variant="purple"
        onClick={event => { event.stopPropagation(); onStart(); }}
      >
        <Play className="h-3 w-3" /> Start
      </ActionButton>
    </WorkspaceRow>
  );
}

function PlaybookRow({ run, state, selected, onClick }: { run: PlaybookRun; state: LiveWorkState; selected: boolean; onClick: () => void }) {
  return (
    <WorkspaceRow selected={selected} onClick={onClick}>
      <span className="h-2 w-2 flex-shrink-0 rounded-full bg-purple" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-xs font-medium text-foreground">{String(run.provider).toUpperCase()} credential playbook</div>
        <div className="mt-0.5 text-[10px] text-muted-foreground">{displayWorkState(state)} · updated {formatRelativeTime(run.updated_at)}</div>
      </div>
      <ChevronRight className="h-3.5 w-3.5 text-muted" />
    </WorkspaceRow>
  );
}

function OperateInspector({
  agent,
  frontier,
  playbook,
  campaign,
  attention,
  frontierItems,
  sessions,
  onClose,
  onCancel,
  onForceRemove,
  onIssueDirective,
  onNavigate,
  onOpenDrawer,
  onStartFrontier,
  onRefreshCampaigns,
  onAttentionAnswered,
  onAttentionPlanResolved,
  onReviewProof,
}: {
  agent: AgentInfo | null;
  frontier: FrontierItem | null;
  playbook: PlaybookRun | null;
  campaign: ReturnType<typeof useEngagementStore.getState>['campaigns'][number] | null;
  attention: AttentionItem | null;
  frontierItems: FrontierItem[];
  sessions: ReturnType<typeof useEngagementStore.getState>['sessions'];
  onClose: () => void;
  onCancel: (taskId: string) => Promise<void>;
  onForceRemove: (taskId: string) => Promise<void>;
  onIssueDirective: (taskId: string, kind: api.DirectiveKind) => Promise<void>;
  onNavigate: ReturnType<typeof useNavigate>;
  onOpenDrawer: (kind: 'activity' | 'sessions' | 'run', item?: string) => void;
  onStartFrontier: () => void;
  onRefreshCampaigns: () => Promise<void>;
  onAttentionAnswered: () => Promise<void>;
  onAttentionPlanResolved: () => Promise<void>;
  onReviewProof: () => void;
}) {
  const [context, setContext] = useState<AgentContext | null>(null);
  useEffect(() => {
    if (!agent) { setContext(null); return; }
    let cancelled = false;
    void api.getAgentContext(canonicalAgentTaskId(agent))
      .then(result => { if (!cancelled) setContext(result as AgentContext); })
      .catch(() => { if (!cancelled) setContext(null); });
    return () => { cancelled = true; };
  }, [agent]);

  const inspectorLabel = agent ? 'Agent inspector'
    : frontier ? 'Frontier inspector'
      : playbook ? 'Playbook inspector'
        : campaign ? 'Campaign inspector'
          : attention ? `${attention.kind.replaceAll('_', ' ')} inspector`
            : 'Selection inspector';
  const inspectorTitle = agent ? agentDisplayLabel(agent)
    : frontier ? frontier.description || frontier.type.replaceAll('_', ' ')
      : playbook ? `${String(playbook.provider).toUpperCase()} credential playbook`
        : campaign ? campaign.name || campaign.id
          : attention?.title;
  const inspectorIdentifier = agent ? canonicalAgentTaskId(agent)
    : frontier ? getFrontierKey(frontier)
      : playbook ? playbook.run_id
        : campaign ? campaign.id
          : attention ? attention.actionId || attention.queryId || attention.planId || attention.id
            : undefined;

  return (
    <WorkspaceInspector label={inspectorLabel} title={inspectorTitle} identifier={inspectorIdentifier} onClose={onClose}>
          {agent && (
            <AgentDetailPanel
              agent={agent}
              context={context}
              ownedSessions={sessionsForAgent(sessions, agent)}
              onCancel={agent.status === 'running' || agent.status === 'pending' ? () => void onCancel(canonicalAgentTaskId(agent)) : undefined}
              onForceRemove={agent.status !== 'completed' ? () => void onForceRemove(canonicalAgentTaskId(agent)) : undefined}
              onNavigateGraph={nodeId => onNavigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id: nodeId }, context: { node: nodeId } }))}
              onNavigateCampaign={campaignId => onNavigate(buildWorkspacePath({ workspace: 'operate', view: 'campaigns', selection: { kind: 'campaign', id: campaignId } }))}
              onNavigateSession={sessionId => onOpenDrawer('sessions', sessionId)}
              onIssueDirective={onIssueDirective}
            />
          )}
          {frontier && <FrontierInspector item={frontier} onStart={onStartFrontier} onNavigate={onNavigate} />}
          {playbook && <PlaybookInspector run={playbook} />}
          {campaign && <CampaignDetail campaign={campaign} frontier={frontierItems} onRefresh={() => void onRefreshCampaigns()} />}
          {attention && (
            <div>
              <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">{attention.kind.replaceAll('_', ' ')}</div>
              <h2 className="mt-2 text-sm font-semibold text-foreground">{attention.title}</h2>
              {attention.agentLabel && <div className="mt-1 font-mono text-[9px] text-muted-foreground">{attention.agentLabel}</div>}
              <p className="mt-4 whitespace-pre-wrap text-[11px] leading-5 text-muted-foreground">{attention.detail}</p>
              <div className="mt-4 border-t border-border-subtle pt-3">
                <AttentionDecisionActions item={attention} onAnswered={() => void onAttentionAnswered()} onPlanResolved={() => void onAttentionPlanResolved()} onReviewProof={onReviewProof} />
              </div>
            </div>
          )}
    </WorkspaceInspector>
  );
}


function FrontierInspector({ item, onStart, onNavigate }: { item: FrontierItem; onStart: () => void; onNavigate: ReturnType<typeof useNavigate> }) {
  const nodes = getFrontierNodeIds(item);
  return (
    <div>
      <div className="text-sm font-semibold text-foreground">{item.description || item.type.replaceAll('_', ' ')}</div>
      <div className="mt-1 font-mono text-[9px] text-muted-foreground">{getFrontierKey(item)}</div>
      <div className="mt-4 grid grid-cols-[7rem_1fr] gap-y-2 text-[11px]">
        <span className="text-muted-foreground">Type</span><span>{item.type.replaceAll('_', ' ')}</span>
        <span className="text-muted-foreground">Score</span><span className="font-mono">{formatFrontierScore(item)}</span>
        <span className="text-muted-foreground">Noise</span><span>{(item.opsec_noise ?? 0).toFixed(1)}</span>
        <span className="text-muted-foreground">Staleness</span><span>{Math.round(item.staleness_seconds)}s</span>
      </div>
      <div className="mt-4 flex flex-wrap gap-1.5">
        <ActionButton variant="purple" onClick={onStart}>Start work</ActionButton>
        {nodes[0] && <ActionButton onClick={() => onNavigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', context: { context: 'frontier', node: nodes[0] } }))}>Show in topology</ActionButton>}
      </div>
      {nodes.length > 0 && (
        <div className="mt-5 border-t border-border-subtle pt-3">
          <div className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Linked assets</div>
          <div className="mt-2 space-y-1">
            {nodes.map(node => <button key={node} className="block w-full truncate text-left font-mono text-[10px] text-accent hover:underline" onClick={() => onNavigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id: node }, context: { node } }))}>{node}</button>)}
          </div>
        </div>
      )}
    </div>
  );
}

function PlaybookInspector({ run }: { run: PlaybookRun }) {
  return (
    <div>
      <div className="text-sm font-semibold text-foreground">{String(run.provider).toUpperCase()} credential playbook</div>
      <div className="mt-1 font-mono text-[9px] text-muted-foreground">{run.run_id}</div>
      <div className="mt-4 grid grid-cols-[7rem_1fr] gap-y-2 text-[11px]">
        <span className="text-muted-foreground">Status</span><span>{run.status}</span>
        <span className="text-muted-foreground">Credential</span><span className="truncate font-mono">{run.credential_id}</span>
        <span className="text-muted-foreground">Updated</span><span>{formatRelativeTime(run.updated_at)}</span>
      </div>
      <p className="mt-4 border-t border-border-subtle pt-3 text-[11px] leading-5 text-muted-foreground">Playbook execution remains dependency-aware. Resume, retry, and interruption controls are available from the credential context.</p>
    </div>
  );
}
