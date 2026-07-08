import { useEffect, useMemo, useState } from 'react';
import * as api from '../../lib/api';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import { recommendArchetypeFor } from '../../lib/agent-archetypes';
import { ActionButton } from '../shared/primitives';

// Fan-out deploy — dispatch N agents across a multi-selection of graph nodes in
// one step, WITHOUT overlap (the server skips any node already being worked).
// `per-node` gives one agent per node (distinct lanes); `per-batch` groups up to
// `batch_size` nodes per agent. Routes to /api/agents/dispatch-batch.

type Mode = 'per-node' | 'per-batch';

export function DeploySelectedModal({
  nodeIds,
  onClose,
  onDeployed,
}: {
  nodeIds: string[];
  onClose: () => void;
  onDeployed: () => void;
}) {
  const graphNodes = useEngagementStore(s => s.graph.nodes);
  const addToast = useToastStore(s => s.addToast);
  const [archetypes, setArchetypes] = useState<api.AgentArchetypeSummary[]>([]);
  const [models, setModels] = useState<{ available: string[]; default?: string }>({ available: [] });
  const [override, setOverride] = useState('');
  const [model, setModel] = useState('');
  const [mode, setMode] = useState<Mode>('per-node');
  const [batchSize, setBatchSize] = useState(5);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getArchetypes().then(d => {
      setArchetypes(d.archetypes || []);
      setModels(d.models || { available: [] });
    }).catch(() => {});
  }, []);

  // Recommend an agent type from the first selected node's type (operator can
  // override). Mixed selections still get a sensible default + one override.
  const firstNodeType = useMemo(
    () => graphNodes.find(n => n.id === nodeIds[0])?.type,
    [graphNodes, nodeIds],
  );
  const recommendedId = recommendArchetypeFor({ nodeType: firstNodeType });
  const effectiveId = override || recommendedId;
  const effective = archetypes.find(a => a.id === effectiveId);
  const agentCount = mode === 'per-node' ? nodeIds.length : Math.ceil(nodeIds.length / Math.max(1, batchSize));

  const deploy = async () => {
    if (nodeIds.length === 0 || busy) return;
    setBusy(true);
    try {
      // Don't send an explicit `default` from the recommendation — that would take
      // the server's explicit-archetype path and dispatch the full-surface default
      // agent, bypassing its explore-safe recon_scanner floor. Omitting it lets the
      // server auto-pick per node type. An operator who deliberately picks `default`
      // from the dropdown (override) still gets it.
      const archetype = override || (recommendedId === 'default' ? undefined : recommendedId);
      const res = await api.dispatchBatch({
        target_node_ids: nodeIds,
        mode,
        batch_size: mode === 'per-batch' ? batchSize : undefined,
        archetype,
        model: model || undefined,
      });
      const { dispatched, skipped, deferred } = res.summary;
      const parts = [`${dispatched} agent(s) dispatched`];
      if (skipped > 0) parts.push(`${skipped} already being worked`);
      if (deferred > 0) parts.push(`${deferred} deferred (cap)`);
      // Report the archetype the server actually launched (we may have sent none).
      const launched = res.dispatched[0]?.archetype ?? archetype ?? recommendedId;
      addToast({
        type: dispatched > 0 ? 'success' : 'warning',
        title: dispatched > 0 ? `Deployed ${launched}` : 'Nothing dispatched',
        message: parts.join(' · '),
      });
      onDeployed();
    } catch (err) {
      addToast({ type: 'error', title: 'Fan-out failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={busy ? undefined : onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative w-[32rem] max-h-[85vh] overflow-y-auto rounded-lg border border-border bg-surface p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold">Fan out agents</h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          Deploy across <span className="text-accent">{nodeIds.length} selected node(s)</span> without overlap — any node already being worked is skipped.
        </p>

        {/* Mode */}
        <div className="mt-3">
          <label className="mb-1 block text-[10px] uppercase tracking-wider text-muted-foreground">Distribution</label>
          <div className="flex items-center gap-2">
            <select
              value={mode}
              onChange={e => setMode(e.target.value as Mode)}
              className="flex-1 rounded border border-border bg-elevated px-2 py-1 text-xs text-foreground"
              disabled={busy}
            >
              <option value="per-node">One agent per node ({nodeIds.length} agents)</option>
              <option value="per-batch">Batches of N nodes per agent</option>
            </select>
            {mode === 'per-batch' && (
              <input
                type="number"
                min={1}
                max={nodeIds.length}
                value={batchSize}
                onChange={e => setBatchSize(Math.max(1, Math.min(nodeIds.length, Number(e.target.value) || 1)))}
                className="w-20 rounded border border-border bg-elevated px-2 py-1 text-xs text-foreground"
                disabled={busy}
              />
            )}
          </div>
          <div className="mt-1 text-[11px] text-muted-foreground">Will launch up to {agentCount} agent(s).</div>
        </div>

        {/* Agent type */}
        <div className="mt-3">
          <label className="mb-1 block text-[10px] uppercase tracking-wider text-muted-foreground">Agent type</label>
          <select
            value={override}
            onChange={e => setOverride(e.target.value)}
            className="w-full rounded border border-border bg-elevated px-2 py-1 text-xs text-foreground"
            disabled={busy}
          >
            <option value="">Recommended: {recommendedId}</option>
            {archetypes.map(a => <option key={a.id} value={a.id}>{a.label} ({a.id})</option>)}
          </select>
          {effective && <div className="mt-1 text-[11px] text-muted-foreground">{effective.description}</div>}
        </div>

        {/* Model */}
        {models.available.length > 0 && (
          <div className="mt-3">
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-muted-foreground">Model</label>
            <select
              value={model}
              onChange={e => setModel(e.target.value)}
              className="w-full rounded border border-border bg-elevated px-2 py-1 text-xs text-foreground"
              disabled={busy}
            >
              <option value="">Default{models.default ? `: ${models.default}` : ''}</option>
              {models.available.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <ActionButton onClick={onClose} variant="ghost" size="xs" disabled={busy}>Cancel</ActionButton>
          <ActionButton onClick={() => void deploy()} variant="purple" size="xs" disabled={busy || nodeIds.length === 0}>
            {busy ? 'Deploying…' : `Deploy ${agentCount} agent(s)`}
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
