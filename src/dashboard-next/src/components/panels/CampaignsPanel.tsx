import { useState, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { StatusBadge, EmptyState } from '../shared';
import {
  getCampaigns,
  createCampaign,
  campaignAction,
  dispatchCampaign,
  cloneCampaign,
} from '../../lib/api';
import type { Campaign, FrontierItem } from '../../lib/types';

const STRATEGY_ICONS: Record<string, string> = {
  credential_spray: '\ud83d\udd11',
  enumeration: '\ud83d\udd0d',
  post_exploitation: '\u26a1',
  network_discovery: '\ud83c\udf10',
  custom: '\u2699',
};

const STATUS_ORDER: Record<string, number> = { active: 0, paused: 1, draft: 2, completed: 3, aborted: 4 };

export function CampaignsPanel() {
  const campaigns = useEngagementStore((s) => s.campaigns);
  const frontier = useEngagementStore((s) => s.frontier);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailId, setDetailId] = useState<string | null>(null);
  const [showBuilder, setShowBuilder] = useState(false);
  const [dispatchTarget, setDispatchTarget] = useState<string | null>(null);

  const sorted = [...campaigns].sort((a, b) => (STATUS_ORDER[a.status] ?? 5) - (STATUS_ORDER[b.status] ?? 5));

  const refresh = useCallback(async () => {
    try {
      const data = await getCampaigns();
      useEngagementStore.setState({ campaigns: data.campaigns || [] });
    } catch {}
  }, []);

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const selectAll = (checked: boolean) => {
    setSelectedIds(checked ? new Set(sorted.map(c => c.id)) : new Set());
  };

  const batchAction = async (action: string) => {
    await Promise.allSettled([...selectedIds].map(id =>
      campaignAction(id, action as 'activate' | 'pause' | 'resume' | 'abort')
    ));
    setSelectedIds(new Set());
    refresh();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Campaigns <span className="text-muted-foreground font-normal text-sm">({campaigns.length})</span>
        </h2>
        <button onClick={() => setShowBuilder(true)} className="settings-save-btn">+ New Campaign</button>
      </div>

      {/* Builder */}
      {showBuilder && (
        <CampaignBuilder frontier={frontier} onClose={() => setShowBuilder(false)} onCreated={() => { setShowBuilder(false); refresh(); }} />
      )}

      {/* Batch bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-2 p-2 rounded bg-elevated border border-border text-xs">
          <span className="text-muted-foreground">{selectedIds.size} selected</span>
          <button onClick={() => batchAction('activate')} className="px-2 py-0.5 rounded bg-success/10 text-success border border-success/20">Activate</button>
          <button onClick={() => batchAction('pause')} className="px-2 py-0.5 rounded bg-warning/10 text-warning border border-warning/20">Pause</button>
          <button onClick={() => batchAction('abort')} className="px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20">Abort</button>
          <button onClick={() => setSelectedIds(new Set())} className="text-muted-foreground hover:text-foreground ml-auto">Deselect</button>
        </div>
      )}

      {/* Dispatch modal */}
      {dispatchTarget && (
        <DispatchModal campaignId={dispatchTarget} onClose={() => setDispatchTarget(null)} onDone={() => { setDispatchTarget(null); refresh(); }} />
      )}

      {sorted.length === 0 ? (
        <EmptyState message="No campaigns yet. Create one to get started." />
      ) : (
        <div className="space-y-2">
          {sorted.length > 1 && (
            <label className="flex items-center gap-2 text-xs text-muted-foreground pl-1">
              <input type="checkbox" checked={sorted.every(c => selectedIds.has(c.id))} onChange={e => selectAll(e.target.checked)} />
              Select all
            </label>
          )}
          {sorted.map((c) => (
            <CampaignCard key={c.id} campaign={c}
              selected={selectedIds.has(c.id)}
              onToggleSelect={() => toggleSelect(c.id)}
              onClickDetail={() => setDetailId(detailId === c.id ? null : c.id)}
              onAction={async (action) => { await campaignAction(c.id, action); refresh(); }}
              onDispatch={() => setDispatchTarget(c.id)}
              onClone={async () => { await cloneCampaign(c.id); refresh(); }}
              expanded={detailId === c.id}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/* ============ Campaign Card ============ */

function CampaignCard({ campaign: c, selected, onToggleSelect, onClickDetail, onAction, onDispatch, onClone, expanded }: {
  campaign: Campaign;
  selected: boolean;
  onToggleSelect: () => void;
  onClickDetail: () => void;
  onAction: (action: 'activate' | 'pause' | 'resume' | 'abort' | 'complete') => Promise<void>;
  onDispatch: () => void;
  onClone: () => Promise<void>;
  expanded: boolean;
}) {
  const icon = STRATEGY_ICONS[c.strategy] || '\u2699';
  const pct = c.completion_pct ?? 0;

  const actions: { action: 'activate' | 'pause' | 'resume' | 'abort'; label: string; cls: string }[] = [];
  if (c.status === 'draft') actions.push({ action: 'activate', label: 'Activate', cls: 'bg-success/10 text-success border-success/20' });
  if (c.status === 'active') {
    actions.push({ action: 'pause', label: 'Pause', cls: 'bg-warning/10 text-warning border-warning/20' });
    actions.push({ action: 'abort', label: 'Abort', cls: 'bg-destructive/10 text-destructive border-destructive/20' });
  }
  if (c.status === 'paused') {
    actions.push({ action: 'resume', label: 'Resume', cls: 'bg-success/10 text-success border-success/20' });
    actions.push({ action: 'abort', label: 'Abort', cls: 'bg-destructive/10 text-destructive border-destructive/20' });
  }

  const canDispatch = c.status === 'draft' || c.status === 'active';

  return (
    <div className={cn('bg-surface border rounded-lg p-4 transition-colors', c.parent_id && 'ml-4 border-border/50', !c.parent_id && 'border-border')}>
      <div className="flex items-center gap-2 mb-2 cursor-pointer" onClick={onClickDetail}>
        <input type="checkbox" checked={selected} onChange={onToggleSelect} onClick={e => e.stopPropagation()} className="accent-accent" />
        <span title={c.strategy}>{icon}</span>
        <h3 className="text-sm font-medium flex-1">{c.name || c.id}</h3>
        {c.parent_id && <span className="text-[10px] text-muted-foreground bg-elevated px-1 rounded">{'\u21b3'} child</span>}
        <StatusBadge status={c.status} />
      </div>

      {/* Progress */}
      <div className="flex items-center gap-2 mb-2">
        <div className="flex-1 h-1 bg-elevated rounded-full overflow-hidden">
          <div className="h-full bg-accent rounded-full transition-all" style={{ width: `${Math.min(100, pct)}%` }} />
        </div>
        <span className="text-[10px] text-muted-foreground font-mono">{pct}%</span>
      </div>

      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span>{c.items?.length ?? 0} items</span>
        <span>{c.agents_active ?? 0}/{c.agents_total ?? 0} agents</span>
        <span>{c.findings_count ?? 0} findings</span>
        {c.started_at && <span>{formatRelativeTime(c.started_at)}</span>}
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="mt-3 pt-3 border-t border-border space-y-2">
          <div className="flex gap-1.5 flex-wrap">
            {actions.map(a => (
              <button key={a.action} onClick={() => onAction(a.action)}
                className={cn('text-xs px-2 py-0.5 rounded border transition-colors', a.cls)}>
                {a.label}
              </button>
            ))}
            {canDispatch && (
              <button onClick={onDispatch} className="text-xs px-2 py-0.5 rounded bg-accent-dim text-accent border border-accent/20">
                Dispatch Agents
              </button>
            )}
            <button onClick={onClone} className="text-xs px-2 py-0.5 rounded bg-elevated text-muted-foreground border border-border hover:text-foreground">
              Clone
            </button>
          </div>

          {/* Abort conditions */}
          {c.abort_conditions && c.abort_conditions.length > 0 && (
            <div className="text-xs space-y-0.5">
              <span className="text-muted-foreground">Abort conditions:</span>
              {c.abort_conditions.map((ac, i) => (
                <div key={i} className="flex gap-2 text-muted-foreground">
                  <span className="font-mono">{ac.type}</span>
                  <span>{ac.description || String(ac.value)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Items preview */}
          {c.items && c.items.length > 0 && (
            <div className="text-xs space-y-0.5">
              <span className="text-muted-foreground">Items ({c.items.length}):</span>
              {c.items.slice(0, 5).map((item, i) => (
                <div key={item.id || i} className="text-muted-foreground truncate pl-2">{item.description}</div>
              ))}
              {c.items.length > 5 && <div className="text-muted pl-2">\u2026 {c.items.length - 5} more</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ============ Campaign Builder ============ */

function CampaignBuilder({ frontier, onClose, onCreated }: {
  frontier: FrontierItem[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState('');
  const [strategy, setStrategy] = useState<Campaign['strategy']>('custom');
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);

  const toggleItem = (id: string) => {
    setSelectedItems(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const submit = async () => {
    if (!name.trim()) return;
    setCreating(true);
    try {
      const items = frontier.filter(f => selectedItems.has(f.frontier_item_id || f.id));
      await createCampaign({ name: name.trim(), strategy, items: items.length > 0 ? items : undefined });
      onCreated();
    } catch { /* silent */ }
    finally { setCreating(false); }
  };

  return (
    <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">New Campaign</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-xs">&times;</button>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[11px] text-muted-foreground block mb-1">Name</label>
          <input value={name} onChange={e => setName(e.target.value)} className="settings-input" placeholder="Campaign name" />
        </div>
        <div>
          <label className="text-[11px] text-muted-foreground block mb-1">Strategy</label>
          <select value={strategy} onChange={e => setStrategy(e.target.value as Campaign['strategy'])} className="settings-input">
            <option value="custom">Custom</option>
            <option value="credential_spray">Credential Spray</option>
            <option value="enumeration">Enumeration</option>
            <option value="post_exploitation">Post Exploitation</option>
            <option value="network_discovery">Network Discovery</option>
          </select>
        </div>
      </div>
      {frontier.length > 0 && (
        <div>
          <label className="text-[11px] text-muted-foreground block mb-1">Frontier Items ({selectedItems.size}/{frontier.length})</label>
          <div className="max-h-32 overflow-y-auto space-y-0.5">
            {frontier.slice(0, 30).map(item => {
              const id = item.frontier_item_id || item.id;
              return (
                <label key={id} className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground cursor-pointer">
                  <input type="checkbox" checked={selectedItems.has(id)} onChange={() => toggleItem(id)} className="accent-accent" />
                  <span className="truncate">{item.description}</span>
                </label>
              );
            })}
          </div>
        </div>
      )}
      <div className="flex gap-2">
        <button onClick={submit} disabled={creating} className="settings-save-btn">{creating ? 'Creating\u2026' : 'Create'}</button>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
      </div>
    </div>
  );
}

/* ============ Dispatch Modal ============ */

function DispatchModal({ campaignId, onClose, onDone }: {
  campaignId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [maxAgents, setMaxAgents] = useState(3);
  const [scopeHops, setScopeHops] = useState(1);
  const [throttle, setThrottle] = useState(0);
  const [dispatching, setDispatching] = useState(false);

  const submit = async () => {
    setDispatching(true);
    try {
      await dispatchCampaign(campaignId, { max_agents: maxAgents, scope_hops: scopeHops, throttle_seconds: throttle || undefined });
      onDone();
    } catch {}
    finally { setDispatching(false); }
  };

  return (
    <div className="bg-surface border border-accent/20 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-accent">Dispatch Agents</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-xs">&times;</button>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-[11px] text-muted-foreground block mb-1">Max Agents</label>
          <input type="number" min={1} max={20} value={maxAgents} onChange={e => setMaxAgents(parseInt(e.target.value) || 1)} className="settings-input" />
        </div>
        <div>
          <label className="text-[11px] text-muted-foreground block mb-1">Scope Hops</label>
          <input type="number" min={0} max={5} value={scopeHops} onChange={e => setScopeHops(parseInt(e.target.value) || 0)} className="settings-input" />
        </div>
        <div>
          <label className="text-[11px] text-muted-foreground block mb-1">Throttle (s)</label>
          <input type="number" min={0} value={throttle} onChange={e => setThrottle(parseInt(e.target.value) || 0)} className="settings-input" />
        </div>
      </div>
      <div className="flex gap-2">
        <button onClick={submit} disabled={dispatching} className="settings-save-btn">{dispatching ? 'Dispatching\u2026' : 'Dispatch'}</button>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
      </div>
    </div>
  );
}
