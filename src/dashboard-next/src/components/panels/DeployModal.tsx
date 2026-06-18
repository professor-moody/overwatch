import { useEffect, useMemo, useState } from 'react';
import * as api from '../../lib/api';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import { classifyDeployInput, recommendArchetypeFor } from '../../lib/agent-archetypes';
import { ActionButton } from '../shared/primitives';

// Phase 5c — the Deploy experience. Type a target (a raw IP/CIDR/domain → ad-hoc
// real-time scan, or existing graph node ids → dispatch), see the recommended
// agent type, optionally override it from the catalog, and Deploy in one step.
// Raw targets route to /api/agents/quick-deploy (auto-scope + dispatch); node
// targets route to /api/agents/dispatch. Supersedes the old skill-only modal.

export function DeployModal({ onClose, onDeployed }: { onClose: () => void; onDeployed: () => void }) {
  const graphNodes = useEngagementStore(s => s.graph.nodes);
  const addToast = useToastStore(s => s.addToast);
  const [text, setText] = useState('');
  const [override, setOverride] = useState('');
  const [archetypes, setArchetypes] = useState<api.AgentArchetypeSummary[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getArchetypes().then(d => setArchetypes(d.archetypes || [])).catch(() => {});
  }, []);

  const parsed = useMemo(() => classifyDeployInput(text), [text]);

  // First node's type drives the node-mode recommendation; raw → recon.
  const firstNodeType = parsed.kind === 'nodes'
    ? graphNodes.find(n => n.id === parsed.nodeIds[0])?.type
    : undefined;
  const recommendedId = parsed.kind === 'raw'
    ? recommendArchetypeFor({ rawTarget: true })
    : parsed.kind === 'nodes'
      ? recommendArchetypeFor({ nodeType: firstNodeType })
      : 'default';
  const effectiveId = override || recommendedId;
  const effective = archetypes.find(a => a.id === effectiveId);
  const canDeploy = (parsed.kind === 'raw' || parsed.kind === 'nodes') && !busy;

  const deploy = async () => {
    if (parsed.kind === 'empty' || busy) return;
    setBusy(true);
    try {
      if (parsed.kind === 'raw') {
        const res = await api.quickDeploy({ target: parsed.target, archetype: effectiveId });
        if (res.dispatched) {
          const added = (res.scope?.added_cidrs.length || 0) + (res.scope?.added_domains.length || 0);
          addToast({ type: 'success', title: `Deployed ${res.archetype || effectiveId}`, message: `${added} target(s) added to scope · ${res.scope?.affected_node_count ?? 0} node(s) in scope` });
          onDeployed();
        } else {
          addToast({ type: 'warning', title: 'Not deployed', message: res.reason || 'dispatch refused' });
        }
      } else if (parsed.kind === 'nodes') {
        const res = await api.dispatchAgent({ target_node_ids: parsed.nodeIds, archetype: effectiveId });
        if (res.dispatched) {
          addToast({ type: 'success', title: `Deployed ${effectiveId}`, message: res.task?.agent_id });
          onDeployed();
        } else {
          addToast({ type: 'warning', title: 'Not deployed', message: res.reason === 'frontier_lease_conflict' ? 'target already being worked' : (res.reason || 'dispatch refused') });
        }
      }
    } catch (err) {
      addToast({ type: 'error', title: 'Deploy failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={busy ? undefined : onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative w-[32rem] max-h-[85vh] overflow-y-auto rounded-lg border border-border bg-surface p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold">Deploy agent</h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          Type a target and deploy. An <span className="font-mono">IP / CIDR / domain</span> scopes + scans it in real time; graph node IDs dispatch against existing nodes.
        </p>

        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder={'10.20.0.20    or    10.30.0.0/24    or    shop.example.com    or    node IDs (h-app …)'}
          rows={3}
          className="mt-3 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent placeholder:text-muted-foreground"
          disabled={busy}
        />

        {/* What we detected */}
        {parsed.kind === 'raw' && (
          <div className="mt-1.5 text-[11px] text-muted-foreground">
            Real-time scan target{parsed.cidrs.length + parsed.domains.length > 1 ? 's' : ''}: <span className="font-mono text-accent">{[...parsed.cidrs, ...parsed.domains].join(', ')}</span>
          </div>
        )}
        {parsed.kind === 'nodes' && (
          <div className="mt-1.5 text-[11px] text-muted-foreground">Dispatch against {parsed.nodeIds.length} node(s){firstNodeType ? ` (${firstNodeType})` : ''}.</div>
        )}
        {parsed.kind === 'mixed' && (
          <div className="mt-1.5 text-[11px] text-warning">
            Mix of targets (<span className="font-mono">{[...parsed.cidrs, ...parsed.domains].join(', ')}</span>) and unrecognized tokens (<span className="font-mono">{parsed.invalid.join(', ')}</span>). Deploy raw targets and graph node IDs separately.
          </div>
        )}

        {/* Agent type: recommended + override */}
        <div className="mt-3">
          <label className="mb-1 block text-[10px] uppercase tracking-wider text-muted-foreground">Agent type</label>
          <div className="flex items-center gap-2">
            <select
              value={override}
              onChange={e => setOverride(e.target.value)}
              className="flex-1 rounded border border-border bg-elevated px-2 py-1 text-xs text-foreground"
              disabled={busy}
            >
              <option value="">Recommended: {recommendedId}</option>
              {archetypes.map(a => <option key={a.id} value={a.id}>{a.label} ({a.id})</option>)}
            </select>
          </div>
          {effective && <div className="mt-1 text-[11px] text-muted-foreground">{effective.description}</div>}
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <ActionButton onClick={onClose} variant="ghost" size="xs" disabled={busy}>Cancel</ActionButton>
          <ActionButton onClick={() => void deploy()} variant="purple" size="xs" disabled={!canDeploy}>
            {busy ? 'Deploying…' : 'Deploy'}
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
