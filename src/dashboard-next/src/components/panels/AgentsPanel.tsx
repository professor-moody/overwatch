import { useState, useEffect, useMemo, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import * as api from '../../lib/api';
import type { AgentInfo, Campaign, ActivityEntry } from '../../lib/types';
import { cn, formatElapsed, formatTimestamp } from '../../lib/utils';
import { EmptyState } from '../shared';

const STRATEGY_ICONS: Record<string, string> = {
  credential_spray: '🔑',
  enumeration: '🔍',
  post_exploitation: '⚡',
  network_discovery: '🌐',
  custom: '⚙',
};

const STATUS_ORDER: Record<string, number> = {
  running: 0, pending: 1, failed: 2, interrupted: 3, completed: 4,
};

function sortAgents(list: AgentInfo[]): AgentInfo[] {
  return [...list].sort((a, b) => (STATUS_ORDER[a.status] ?? 5) - (STATUS_ORDER[b.status] ?? 5));
}

export function AgentsPanel() {
  const agents = useEngagementStore((s) => s.agents);
  const initialized = useEngagementStore((s) => s.initialized);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailAgent, setDetailAgent] = useState<AgentInfo | null>(null);
  const [detailContext, setDetailContext] = useState<{ subgraph?: { nodes?: { id: string; properties?: Record<string, unknown> }[]; edges?: unknown[] } } | null>(null);
  const [showDispatch, setShowDispatch] = useState(false);
  const [showBulkDispatch, setShowBulkDispatch] = useState(false);
  const { navigateToGraph, navigateToCampaign } = useNavigation();
  const setStoreAgents = useEngagementStore((s) => s.setAgents);

  const refreshAgents = useCallback(async () => {
    try {
      const data = await api.getAgents();
      setStoreAgents(data.agents || []);
      setSelectedIds(prev => {
        const validIds = new Set((data.agents || []).map((a: AgentInfo) => a.id));
        const next = new Set([...prev].filter(id => validIds.has(id)));
        return next.size !== prev.size ? next : prev;
      });
    } catch { /* silent */ }
  }, [setStoreAgents]);

  // Safety net: pull fresh agent state on mount in case the WS full_state
  // arrived before this panel mounted (or before the backend was patched
  // to include `agents` in EngagementState). Cheap — single GET.
  useEffect(() => { refreshAgents(); }, [refreshAgents]);

  // Campaign groups
  const { groups, ungrouped } = useMemo(() => {
    const g = new Map<string, { name: string; strategy: string; agents: AgentInfo[] }>();
    const ug: AgentInfo[] = [];
    for (const a of agents) {
      const cid = a.campaign_id || a.campaign?.id;
      if (cid) {
        if (!g.has(cid)) g.set(cid, { name: a.campaign?.name || cid, strategy: a.campaign?.strategy || '', agents: [] });
        g.get(cid)!.agents.push(a);
      } else { ug.push(a); }
    }
    return { groups: g, ungrouped: ug };
  }, [agents]);

  const running = agents.filter(a => a.status === 'running');
  const completed = agents.filter(a => a.status === 'completed');
  const failed = agents.filter(a => a.status === 'failed' || a.status === 'interrupted');

  const toggleGroup = (gid: string) => {
    setCollapsedGroups(prev => { const n = new Set(prev); n.has(gid) ? n.delete(gid) : n.add(gid); return n; });
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };

  const selectAll = () => {
    if (selectedIds.size === agents.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(agents.map(a => a.id)));
  };

  const cancelAgent = async (id: string) => {
    try { await api.cancelAgent(id); await refreshAgents(); } catch { /* silent */ }
  };

  const batchCancel = async () => {
    const cancellable = agents.filter(a => selectedIds.has(a.id) && (a.status === 'running' || a.status === 'pending'));
    await Promise.allSettled(cancellable.map(a => api.cancelAgent(a.id)));
    setSelectedIds(new Set());
    await refreshAgents();
  };

  const cancelGroup = async (gid: string) => {
    const group = gid === '__ungrouped__'
      ? agents.filter(a => !a.campaign_id && !a.campaign?.id)
      : agents.filter(a => (a.campaign_id || a.campaign?.id) === gid);
    const cancellable = group.filter(a => a.status === 'running' || a.status === 'pending');
    await Promise.allSettled(cancellable.map(a => api.cancelAgent(a.id)));
    await refreshAgents();
  };

  const showDetail = async (agent: AgentInfo) => {
    setDetailAgent(agent);
    try {
      const ctx = await api.getAgentContext(agent.id);
      setDetailContext(ctx as typeof detailContext);
    } catch { setDetailContext(null); }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Agents <span className="text-muted-foreground font-normal text-sm">({agents.length})</span>
        </h2>
        <div className="flex items-center gap-3">
          <div className="flex gap-2 text-xs">
            <span className="text-success">{running.length} running</span>
            <span className="text-muted-foreground">{completed.length} done</span>
            {failed.length > 0 && <span className="text-destructive">{failed.length} failed</span>}
          </div>
          <button
            onClick={() => setShowDispatch(true)}
            className="text-xs px-2.5 py-1 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
          >
            Deploy Agent
          </button>
          <button
            onClick={() => setShowBulkDispatch(true)}
            className="text-xs px-2.5 py-1 rounded bg-purple-dim text-purple hover:bg-purple/20 transition-colors"
          >
            Bulk from Frontier
          </button>
        </div>
      </div>

      {/* Batch bar */}
      {selectedIds.size > 0 && (
        <div className="bg-accent-dim border border-accent/30 rounded-md px-3 py-2 flex items-center gap-3 text-xs">
          <span className="text-accent font-medium">{selectedIds.size} selected</span>
          <button onClick={batchCancel} className="px-2 py-0.5 rounded bg-destructive/10 text-destructive hover:bg-destructive/20">
            Cancel Selected
          </button>
          <button onClick={() => setSelectedIds(new Set())} className="px-2 py-0.5 rounded text-muted-foreground hover:text-foreground">
            Deselect
          </button>
        </div>
      )}

      {!initialized ? (
        <div className="text-sm text-muted-foreground animate-pulse">Loading…</div>
      ) : agents.length === 0 ? (
        <EmptyState message="No agents dispatched yet." />
      ) : (
        <div className="space-y-2">
          {/* Select all */}
          <label className="flex items-center gap-2 text-xs text-muted-foreground px-1 cursor-pointer">
            <input
              type="checkbox"
              checked={selectedIds.size === agents.length && agents.length > 0}
              onChange={selectAll}
              className="accent-accent"
            />
            Select all
          </label>

          {/* Campaign groups */}
          {[...groups.entries()].map(([cid, group]) => {
            const isCollapsed = collapsedGroups.has(cid);
            const runningCount = group.agents.filter(a => a.status === 'running').length;
            const hasRunning = group.agents.some(a => a.status === 'running' || a.status === 'pending');
            const icon = STRATEGY_ICONS[group.strategy] || '⚙';

            return (
              <div key={cid} className="bg-surface border border-border rounded-lg overflow-hidden">
                <button
                  onClick={() => toggleGroup(cid)}
                  className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-hover transition-colors"
                >
                  <span className="text-muted-foreground">{isCollapsed ? '▸' : '▾'}</span>
                  <span>{icon}</span>
                  <span className="font-medium text-foreground flex-1 text-left truncate">{group.name}</span>
                  <span className="text-muted-foreground">{runningCount}/{group.agents.length} running</span>
                  {hasRunning && (
                    <span
                      onClick={e => { e.stopPropagation(); cancelGroup(cid); }}
                      className="px-1.5 py-0.5 rounded text-destructive hover:bg-destructive/10 cursor-pointer"
                    >
                      Cancel All
                    </span>
                  )}
                </button>
                {!isCollapsed && (
                  <div className="border-t border-border">
                    {sortAgents(group.agents).map(a => (
                      <AgentCard
                        key={a.id}
                        agent={a}
                        selected={selectedIds.has(a.id)}
                        onToggleSelect={() => toggleSelect(a.id)}
                        onCancel={() => cancelAgent(a.id)}
                        onClick={() => showDetail(a)}
                      />
                    ))}
                  </div>
                )}
              </div>
            );
          })}

          {/* Ungrouped */}
          {ungrouped.length > 0 && (
            <div className="bg-surface border border-border rounded-lg overflow-hidden">
              <button
                onClick={() => toggleGroup('__ungrouped__')}
                className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-hover transition-colors"
              >
                <span className="text-muted-foreground">{collapsedGroups.has('__ungrouped__') ? '▸' : '▾'}</span>
                <span className="font-medium text-foreground flex-1 text-left">Ungrouped</span>
                <span className="text-muted-foreground">{ungrouped.length}</span>
              </button>
              {!collapsedGroups.has('__ungrouped__') && (
                <div className="border-t border-border">
                  {sortAgents(ungrouped).map(a => (
                    <AgentCard
                      key={a.id}
                      agent={a}
                      selected={selectedIds.has(a.id)}
                      onToggleSelect={() => toggleSelect(a.id)}
                      onCancel={() => cancelAgent(a.id)}
                      onClick={() => showDetail(a)}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Detail Drawer */}
      {detailAgent && (
        <AgentDetailDrawer
          agent={detailAgent}
          context={detailContext}
          onClose={() => { setDetailAgent(null); setDetailContext(null); }}
          onCancel={() => { cancelAgent(detailAgent.id); setDetailAgent(null); }}
          onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
          onNavigateCampaign={(cid) => navigateToCampaign(cid)}
        />
      )}

      {/* Dispatch Modal */}
      {showDispatch && (
        <DispatchModal
          onClose={() => setShowDispatch(false)}
          onDispatched={() => { setShowDispatch(false); refreshAgents(); }}
        />
      )}

      {/* Bulk Frontier Dispatch Modal */}
      {showBulkDispatch && (
        <BulkFrontierDispatchModal
          onClose={() => setShowBulkDispatch(false)}
          onDispatched={() => { setShowBulkDispatch(false); refreshAgents(); }}
        />
      )}
    </div>
  );
}

// ---- Agent Card ----

function AgentCard({
  agent,
  selected,
  onToggleSelect,
  onCancel,
  onClick,
}: {
  agent: AgentInfo;
  selected: boolean;
  onToggleSelect: () => void;
  onCancel: () => void;
  onClick: () => void;
}) {
  const cancellable = agent.status === 'running' || agent.status === 'pending';
  const elapsed = agent.elapsed_ms ? formatElapsed(agent.elapsed_ms) : '';
  const summary = agent.result_summary
    ? (agent.result_summary.length > 80 ? agent.result_summary.slice(0, 77) + '…' : agent.result_summary)
    : '';

  // Compute findings/min rate for running agents
  const rate = agent.status === 'running' && agent.elapsed_ms && agent.elapsed_ms > 60_000 && agent.findings_count
    ? ((agent.findings_count / agent.elapsed_ms) * 60_000).toFixed(1)
    : null;

  return (
    <div
      onClick={onClick}
      className="px-3 py-2 border-b border-border last:border-b-0 hover:bg-hover/50 transition-colors cursor-pointer"
    >
      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={selected}
          onChange={e => { e.stopPropagation(); onToggleSelect(); }}
          onClick={e => e.stopPropagation()}
          className="accent-accent"
        />
        <span className={cn(
          'w-2 h-2 rounded-full flex-shrink-0',
          agent.status === 'running' && 'bg-success animate-pulse',
          agent.status === 'completed' && 'bg-accent',
          agent.status === 'failed' && 'bg-destructive',
          agent.status === 'interrupted' && 'bg-warning',
          agent.status === 'pending' && 'bg-muted',
        )} />
        <span className="text-xs font-mono text-muted-foreground truncate" title={agent.agent_id || agent.id}>{agent.agent_id || agent.id}</span>
        {cancellable && (
          <button
            onClick={e => { e.stopPropagation(); onCancel(); }}
            className="text-muted-foreground hover:text-destructive text-xs ml-auto"
            title="Cancel"
          >
            ✕
          </button>
        )}
      </div>
      <div className="flex items-center gap-2 mt-0.5 ml-6 text-xs">
        <span className={cn(
          'font-medium',
          agent.status === 'running' && 'text-success',
          agent.status === 'completed' && 'text-accent',
          agent.status === 'failed' && 'text-destructive',
          agent.status === 'interrupted' && 'text-warning',
          agent.status === 'pending' && 'text-muted-foreground',
        )}>
          {agent.status}
        </span>
        {agent.skill && <span className="text-muted-foreground bg-elevated px-1 py-0.5 rounded text-[10px]">{agent.skill}</span>}
        {elapsed && <span className="text-muted-foreground">{elapsed}</span>}
        {agent.findings_count != null && agent.findings_count > 0 && (
          <span className="text-success text-[10px]">{agent.findings_count} findings</span>
        )}
        {rate && <span className="text-accent text-[10px]">{rate}/min</span>}
      </div>
      {summary && <div className="text-[10px] text-muted-foreground mt-1 ml-6 truncate">{summary}</div>}
    </div>
  );
}

// ---- Agent Detail Drawer ----

function AgentDetailDrawer({
  agent,
  context,
  onClose,
  onCancel,
  onNavigateGraph,
  onNavigateCampaign,
}: {
  agent: AgentInfo;
  context: { subgraph?: { nodes?: { id: string; properties?: Record<string, unknown> }[]; edges?: unknown[] } } | null;
  onClose: () => void;
  onCancel: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigateCampaign?: (campaignId: string) => void;
}) {
  const cancellable = agent.status === 'running' || agent.status === 'pending';
  const elapsed = agent.elapsed_ms
    ? formatElapsed(agent.elapsed_ms)
    : agent.completed_at && agent.assigned_at
      ? formatElapsed(new Date(agent.completed_at).getTime() - new Date(agent.assigned_at).getTime())
      : '—';

  const subgraphNodes = context?.subgraph?.nodes || [];

  // Fetch task history
  const [history, setHistory] = useState<ActivityEntry[]>([]);
  const [historyExpanded, setHistoryExpanded] = useState(false);

  useEffect(() => {
    api.getAgentHistory(agent.id).then(d => setHistory(d.entries || [])).catch(() => {});
  }, [agent.id]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/30" />
      <div
        className="relative w-80 bg-surface border-l border-border h-full overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={cn(
              'w-2 h-2 rounded-full',
              agent.status === 'running' && 'bg-success',
              agent.status === 'completed' && 'bg-accent',
              agent.status === 'failed' && 'bg-destructive',
            )} />
            <span className="text-sm font-semibold font-mono">{agent.agent_id || agent.id}</span>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1">✕</button>
        </div>

        <div className="px-4 py-3 space-y-3">
          <DetailRow label="Status" value={agent.status} />
          <DetailRow label="Task ID" value={agent.id} mono />
          {agent.assigned_at && <DetailRow label="Assigned" value={new Date(agent.assigned_at).toLocaleString()} />}
          <DetailRow label="Elapsed" value={elapsed} />
          {agent.skill && <DetailRow label="Skill" value={agent.skill} />}
          {agent.frontier_item_id && <DetailRow label="Frontier Item" value={agent.frontier_item_id} mono />}
          {agent.campaign_id && (
            <div className="flex items-center gap-2">
              <DetailRow label="Campaign" value={agent.campaign_id} mono />
              <button onClick={() => onNavigateCampaign?.(agent.campaign_id!)} className="text-[10px] text-accent hover:underline">view</button>
            </div>
          )}
          {agent.result_summary && <DetailRow label="Result" value={agent.result_summary} />}
          <DetailRow label="Scope Nodes" value={String((agent.subgraph_node_ids || agent.scope_node_ids || []).length)} />

          {subgraphNodes.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Scoped Subgraph</div>
              <div className="text-xs text-muted-foreground mb-1">
                {subgraphNodes.length} nodes, {context?.subgraph?.edges?.length || 0} edges
              </div>
              <div className="space-y-0.5">
                {subgraphNodes.slice(0, 10).map(n => (
                  <button
                    key={n.id}
                    onClick={() => onNavigateGraph(n.id)}
                    className="block text-xs text-accent hover:underline truncate"
                  >
                    {String(n.properties?.label || n.id)}
                  </button>
                ))}
                {subgraphNodes.length > 10 && (
                  <span className="text-[10px] text-muted-foreground">… and {subgraphNodes.length - 10} more</span>
                )}
              </div>
            </div>
          )}

          {/* Task History */}
          {history.length > 0 && (
            <div>
              <button
                onClick={() => setHistoryExpanded(!historyExpanded)}
                className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1 flex items-center gap-1 hover:text-foreground"
              >
                <span>{historyExpanded ? '▾' : '▸'}</span>
                Task History ({history.length})
              </button>
              {historyExpanded && (
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {history.map((e, i) => (
                    <div key={e.id || i} className="flex items-start gap-2 text-[10px]">
                      <span className="text-muted-foreground font-mono flex-shrink-0 w-12">{formatTimestamp(e.timestamp)}</span>
                      <span className={cn(
                        'flex-shrink-0 w-1.5 h-1.5 rounded-full mt-1',
                        e.event_type?.includes('completed') ? 'bg-success' :
                        e.event_type?.includes('failed') ? 'bg-destructive' :
                        e.event_type?.includes('started') ? 'bg-accent' : 'bg-muted',
                      )} />
                      <span className="text-muted-foreground">{e.description}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {cancellable && (
          <div className="px-4 py-3 border-t border-border">
            <button
              onClick={onCancel}
              className="w-full text-xs py-1.5 rounded bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors"
            >
              Cancel Agent
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2 text-xs">
      <span className="text-muted-foreground w-24 flex-shrink-0">{label}</span>
      <span className={cn('text-foreground break-all', mono && 'font-mono text-[10px]')}>{value}</span>
    </div>
  );
}

// ---- Dispatch Modal ----

function DispatchModal({ onClose, onDispatched }: { onClose: () => void; onDispatched: () => void }) {
  const [nodeIds, setNodeIds] = useState<string[]>([]);
  const [nodeInput, setNodeInput] = useState('');
  const [skill, setSkill] = useState('');
  const [campaignId, setCampaignId] = useState('');
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [dispatching, setDispatching] = useState(false);

  useEffect(() => {
    api.getCampaigns().then(d => setCampaigns(d.campaigns || [])).catch(() => {});
  }, []);

  const addNodeId = () => {
    const id = nodeInput.trim();
    if (id && !nodeIds.includes(id)) { setNodeIds([...nodeIds, id]); setNodeInput(''); }
  };

  const dispatch = async () => {
    if (nodeIds.length === 0) return;
    setDispatching(true);
    try {
      await api.dispatchAgent({
        node_ids: nodeIds,
        skill: skill || undefined,
        campaign_id: campaignId || undefined,
      });
      onDispatched();
    } catch { /* silent */ } finally { setDispatching(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative bg-surface border border-border rounded-lg p-5 w-96 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold mb-3">Dispatch Agent</h3>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Target Nodes</label>
            <div className="flex gap-1 flex-wrap mb-1">
              {nodeIds.map(id => (
                <span key={id} className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-foreground flex items-center gap-1">
                  {id.slice(0, 16)}
                  <button onClick={() => setNodeIds(nodeIds.filter(x => x !== id))} className="text-muted-foreground hover:text-foreground">✕</button>
                </span>
              ))}
            </div>
            <div className="flex gap-1">
              <input
                value={nodeInput}
                onChange={e => setNodeInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addNodeId(); } }}
                placeholder="Node ID…"
                className="flex-1 text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground"
              />
              <button onClick={addNodeId} className="text-xs px-2 py-1 rounded bg-accent/10 text-accent">Add</button>
            </div>
          </div>

          <div>
            <label className="text-xs text-muted-foreground block mb-1">Skill (optional)</label>
            <input
              value={skill}
              onChange={e => setSkill(e.target.value)}
              placeholder="e.g. credential_spray"
              className="w-full text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground block mb-1">Campaign (optional)</label>
            <select
              value={campaignId}
              onChange={e => setCampaignId(e.target.value)}
              className="w-full text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground"
            >
              <option value="">None</option>
              {campaigns.map(c => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
            </select>
          </div>
        </div>

        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onClose} className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground">Cancel</button>
          <button
            onClick={dispatch}
            disabled={nodeIds.length === 0 || dispatching}
            className="text-xs px-3 py-1.5 rounded bg-accent text-background hover:bg-accent/90 disabled:opacity-50"
          >
            {dispatching ? 'Dispatching…' : 'Dispatch'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---- Bulk Frontier Dispatch Modal ----

function BulkFrontierDispatchModal({ onClose, onDispatched }: { onClose: () => void; onDispatched: () => void }) {
  const frontier = useEngagementStore((s) => s.frontier);
  const [selectedItemIds, setSelectedItemIds] = useState<Set<string>>(new Set());
  const [skill, setSkill] = useState('');
  const [dispatching, setDispatching] = useState(false);

  const topItems = frontier.slice(0, 20);

  const toggleItem = (id: string) => {
    setSelectedItemIds(prev => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const selectAll = () => {
    if (selectedItemIds.size === topItems.length) {
      setSelectedItemIds(new Set());
    } else {
      setSelectedItemIds(new Set(topItems.map(i => i.frontier_item_id || i.id)));
    }
  };

  const dispatchAll = async () => {
    if (selectedItemIds.size === 0) return;
    setDispatching(true);
    const selected = topItems.filter(i => selectedItemIds.has(i.frontier_item_id || i.id));
    try {
      await Promise.allSettled(
        selected.map(item => {
          const nodeIds = [item.target_node, item.source_node, item.node_id, item.edge_source, item.edge_target]
            .filter((n): n is string => !!n);
          const uniqueNodes = [...new Set(nodeIds)];
          if (uniqueNodes.length === 0) return Promise.resolve();
          return api.dispatchAgent({
            node_ids: uniqueNodes,
            skill: skill || undefined,
          });
        })
      );
      onDispatched();
    } catch { /* silent */ } finally { setDispatching(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative bg-surface border border-border rounded-lg p-5 w-[28rem] max-h-[80vh] flex flex-col shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold mb-1">Bulk Dispatch from Frontier</h3>
        <p className="text-[10px] text-muted-foreground mb-3">Select frontier items to dispatch as parallel agents.</p>

        <div className="flex items-center gap-2 mb-2">
          <label className="flex items-center gap-1 text-xs text-muted-foreground cursor-pointer">
            <input
              type="checkbox"
              checked={selectedItemIds.size === topItems.length && topItems.length > 0}
              onChange={selectAll}
              className="accent-accent"
            />
            Select all ({topItems.length})
          </label>
          <span className="flex-1" />
          <span className="text-xs text-accent font-medium">{selectedItemIds.size} selected</span>
        </div>

        <div className="flex-1 overflow-y-auto space-y-1 mb-3 max-h-64">
          {topItems.map((item) => {
            const itemId = item.frontier_item_id || item.id;
            return (
              <label
                key={itemId}
                className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-hover transition-colors cursor-pointer text-xs"
              >
                <input
                  type="checkbox"
                  checked={selectedItemIds.has(itemId)}
                  onChange={() => toggleItem(itemId)}
                  className="accent-accent"
                />
                <span className={cn(
                  'px-1 py-0.5 rounded text-[10px] font-medium flex-shrink-0',
                  item.type === 'inferred_edge' ? 'bg-purple-dim text-purple' :
                  item.type === 'untested_edge' ? 'bg-warning/10 text-warning' :
                  item.type === 'network_discovery' ? 'bg-accent-dim text-accent' :
                  'bg-elevated text-muted-foreground',
                )}>
                  {item.type.replace(/_/g, ' ')}
                </span>
                <span className="text-muted-foreground truncate flex-1">{item.description}</span>
                <span className="font-mono text-foreground flex-shrink-0">{(item.priority ?? 0).toFixed(1)}</span>
              </label>
            );
          })}
          {topItems.length === 0 && <p className="text-xs text-muted-foreground text-center py-4">No frontier items available.</p>}
        </div>

        <div>
          <label className="text-xs text-muted-foreground block mb-1">Skill (optional)</label>
          <input
            value={skill}
            onChange={e => setSkill(e.target.value)}
            placeholder="e.g. enumeration"
            className="w-full text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground mb-3"
          />
        </div>

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground">Cancel</button>
          <button
            onClick={dispatchAll}
            disabled={selectedItemIds.size === 0 || dispatching}
            className="text-xs px-3 py-1.5 rounded bg-purple text-background hover:bg-purple/90 disabled:opacity-50"
          >
            {dispatching ? 'Dispatching…' : `Dispatch ${selectedItemIds.size} Agent${selectedItemIds.size !== 1 ? 's' : ''}`}
          </button>
        </div>
      </div>
    </div>
  );
}
