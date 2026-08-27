import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, Check, ChevronRight, Play, X } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import * as api from '../../lib/api';
import { classifyDeployInput, recommendArchetypeFor, type DeployInput } from '../../lib/agent-archetypes';
import { mergeScopeWithTargets, parseTargetBlob } from '../../lib/target-input';
import { getFrontierKey, getFrontierNodeIds } from '../../lib/frontier-workspace';
import { cn } from '../../lib/utils';
import { ActionButton } from '../shared/primitives';

type Step = 'target' | 'method' | 'review' | 'result';
type Distribution = 'per-node' | 'per-batch';

type ResultState = {
  tone: 'success' | 'warning';
  title: string;
  detail: string;
};

function previewFingerprint(preview: api.ScopeChangePreview): string {
  return JSON.stringify({
    after: preview.after,
    added: preview.added,
    removed: preview.removed,
    entering: preview.nodes_entering_scope,
    leaving: preview.nodes_leaving_scope,
  });
}

export function StartWorkLauncher({ onClose }: { onClose: () => void }) {
  const [searchParams] = useSearchParams();
  const graph = useEngagementStore(state => state.graph);
  const frontier = useEngagementStore(state => state.frontier);
  const addToast = useToastStore(state => state.addToast);
  const selectionKind = searchParams.get('kind') || searchParams.get('entity');
  const selectionId = searchParams.get('item');
  const selectedFrontier = selectionKind === 'frontier' && selectionId
    ? frontier.find(item => getFrontierKey(item) === selectionId) ?? null
    : null;
  const selectedNodeIds = selectionId && (selectionKind === 'node' || selectionKind === 'credential')
    ? [selectionId]
    : [];

  const [step, setStep] = useState<Step>(selectedFrontier || selectedNodeIds.length ? 'method' : 'target');
  const [text, setText] = useState(selectedNodeIds.join('\n'));
  const [archetypes, setArchetypes] = useState<api.AgentArchetypeSummary[]>([]);
  const [models, setModels] = useState<{ available: string[]; default?: string }>({ available: [] });
  const [archetype, setArchetype] = useState('');
  const [model, setModel] = useState('');
  const [objective, setObjective] = useState('');
  const [distribution, setDistribution] = useState<Distribution>('per-node');
  const [batchSize, setBatchSize] = useState(5);
  const [preview, setPreview] = useState<api.ScopeChangePreview | null>(null);
  const [previewNotice, setPreviewNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ResultState | null>(null);

  useEffect(() => {
    void api.getArchetypes().then(data => {
      setArchetypes(data.archetypes || []);
      setModels(data.models || { available: [] });
    }).catch(() => { /* server remains authoritative if catalog is unavailable */ });
  }, []);

  const parsed: DeployInput = useMemo(() => {
    if (selectedFrontier) return { kind: 'nodes', nodeIds: getFrontierNodeIds(selectedFrontier) };
    return classifyDeployInput(text);
  }, [selectedFrontier, text]);
  const nodeIds = parsed.kind === 'nodes' ? parsed.nodeIds : [];
  const firstNode = nodeIds.length > 0 ? graph.nodes.find(node => node.id === nodeIds[0]) : undefined;
  const recommended = selectedFrontier
    ? 'default'
    : parsed.kind === 'raw'
      ? recommendArchetypeFor({ rawTarget: true })
      : recommendArchetypeFor({ nodeType: firstNode?.type });
  const effectiveArchetype = archetype || recommended;
  const selectedArchetype = archetypes.find(item => item.id === effectiveArchetype);
  const fanout = nodeIds.length > 1;
  const agentCount = fanout
    ? distribution === 'per-node' ? nodeIds.length : Math.ceil(nodeIds.length / Math.max(1, batchSize))
    : 1;

  const canContinueFromTarget = parsed.kind === 'raw' || parsed.kind === 'nodes';

  const goToReview = async () => {
    setError(null);
    setPreviewNotice(null);
    if (selectedFrontier || parsed.kind === 'nodes') {
      setStep('review');
      return;
    }
    if (parsed.kind !== 'raw') return;
    setBusy(true);
    try {
      const config = await api.getConfig();
      const merged = mergeScopeWithTargets(config.scope, parseTargetBlob(parsed.target));
      setPreview(await api.previewScope(merged));
      setStep('review');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const execute = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    setPreviewNotice(null);
    try {
      if (selectedFrontier) {
        const response = await api.dispatchAgent({
          frontier_item_id: getFrontierKey(selectedFrontier),
          archetype: archetype || undefined,
          model: model || undefined,
        });
        setResult({
          tone: response.dispatched ? 'success' : 'warning',
          title: response.dispatched ? 'Work started' : 'Dispatch was not started',
          detail: response.dispatched ? api.dispatchedAgentLabel(response.task) : response.reason || 'The server refused the dispatch.',
        });
      } else if (parsed.kind === 'raw') {
        // Re-preview against live scope. A changed review requires a fresh operator
        // confirmation instead of executing on a stale impact summary.
        const config = await api.getConfig();
        const merged = mergeScopeWithTargets(config.scope, parseTargetBlob(parsed.target));
        const livePreview = await api.previewScope(merged);
        if (!preview || previewFingerprint(livePreview) !== previewFingerprint(preview)) {
          setPreview(livePreview);
          setPreviewNotice('Scope changed since the first preview. Review the updated impact before confirming again.');
          return;
        }
        const response = await api.quickDeploy({
          target: parsed.target,
          archetype: effectiveArchetype,
          model: model || undefined,
        });
        const added = (response.scope?.added_cidrs.length || 0) + (response.scope?.added_domains.length || 0);
        setResult({
          tone: response.dispatched ? 'success' : 'warning',
          title: response.dispatched ? 'Target scoped and work started' : 'Work was not started',
          detail: response.dispatched
            ? `${api.dispatchedAgentLabel(response.task)} · ${added} scope entr${added === 1 ? 'y' : 'ies'} added`
            : response.reason || 'The server refused the dispatch.',
        });
      } else if (parsed.kind === 'nodes' && parsed.nodeIds.length > 1) {
        const response = await api.dispatchBatch({
          target_node_ids: parsed.nodeIds,
          mode: distribution,
          batch_size: distribution === 'per-batch' ? batchSize : undefined,
          archetype: archetype || (recommended === 'default' ? undefined : recommended),
          model: model || undefined,
          objective: objective.trim() || undefined,
        });
        const { dispatched, skipped, deferred } = response.summary;
        setResult({
          tone: dispatched > 0 ? 'success' : 'warning',
          title: dispatched > 0 ? `${dispatched} agent${dispatched === 1 ? '' : 's'} started` : 'No agents were started',
          detail: `${skipped} already being worked · ${deferred} deferred by concurrency limits`,
        });
      } else if (parsed.kind === 'nodes') {
        const response = await api.dispatchAgent({
          target_node_ids: parsed.nodeIds,
          archetype: effectiveArchetype,
          model: model || undefined,
        });
        setResult({
          tone: response.dispatched ? 'success' : 'warning',
          title: response.dispatched ? 'Work started' : 'Dispatch was not started',
          detail: response.dispatched ? api.dispatchedAgentLabel(response.task) : response.reason || 'The server refused the dispatch.',
        });
      }
      setStep('result');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 p-4 backdrop-blur-[2px]" role="dialog" aria-modal="true" aria-label="Start work" onMouseDown={busy ? undefined : event => { if (event.target === event.currentTarget) onClose(); }}>
      <div className="flex max-h-[88vh] w-full max-w-[620px] flex-col overflow-hidden rounded-xl border border-border-strong bg-surface shadow-2xl">
        <header className="flex flex-shrink-0 items-center gap-3 border-b border-border-subtle px-5 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-accent/10 text-accent"><Play className="h-4 w-4" /></div>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-foreground">Start work</h2>
            <p className="mt-0.5 text-[10px] text-muted-foreground">Target → method → review → execute</p>
          </div>
          <button type="button" onClick={onClose} disabled={busy} className="rounded p-1.5 text-muted-foreground hover:bg-hover hover:text-foreground disabled:opacity-50" aria-label="Close launcher"><X className="h-4 w-4" /></button>
        </header>

        <div className="flex flex-shrink-0 border-b border-border-subtle px-5">
          {(['target', 'method', 'review', 'result'] as Step[]).map((id, index) => (
            <div key={id} className={cn('flex h-9 items-center gap-1.5 border-b-2 px-2 text-[10px] uppercase tracking-[0.12em]', step === id ? 'border-accent text-accent' : 'border-transparent text-muted')}>
              <span className="font-mono">0{index + 1}</span>{id}
            </div>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
          {step === 'target' && (
            <div>
              <label className="text-xs font-medium text-foreground" htmlFor="start-work-targets">Targets or graph node IDs</label>
              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">Enter IPs, CIDRs, or domains to scope and scan, or enter existing graph node IDs to dispatch against known context.</p>
              <textarea
                id="start-work-targets"
                autoFocus
                rows={5}
                value={text}
                onChange={event => { setText(event.target.value); setError(null); }}
                placeholder={'10.20.0.20\n10.30.0.0/24\nshop.example.com\n\nor existing node IDs'}
                className="mt-4 w-full resize-none rounded-md border border-border bg-background px-3 py-2.5 font-mono text-xs leading-5 text-foreground outline-none transition-colors placeholder:text-muted focus:border-accent"
              />
              <TargetClassification parsed={parsed} />
            </div>
          )}

          {step === 'method' && (
            <div className="space-y-5">
              <TargetSummary parsed={parsed} frontierLabel={selectedFrontier?.description} />
              <div>
                <label className="text-xs font-medium text-foreground">Agent type</label>
                <p className="mt-1 text-[11px] text-muted-foreground">The recommendation reflects the target type. Override only when the mission needs a narrower tool surface.</p>
                <select value={archetype} onChange={event => setArchetype(event.target.value)} className="settings-input mt-2 h-8 w-full">
                  <option value="">Recommended · {recommended}</option>
                  {archetypes.map(item => <option key={item.id} value={item.id}>{item.label} · {item.id}</option>)}
                </select>
                {selectedArchetype && <p className="mt-2 text-[10px] leading-4 text-muted-foreground">{selectedArchetype.description}</p>}
              </div>
              {models.available.length > 0 && (
                <div>
                  <label className="text-xs font-medium text-foreground">Model</label>
                  <select value={model} onChange={event => setModel(event.target.value)} className="settings-input mt-2 h-8 w-full">
                    <option value="">Engagement default{models.default ? ` · ${models.default}` : ''}</option>
                    {models.available.map(item => <option key={item} value={item}>{item}</option>)}
                  </select>
                </div>
              )}
              {fanout && (
                <div>
                  <label className="text-xs font-medium text-foreground">Distribution</label>
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    <Choice active={distribution === 'per-node'} title="One per node" detail={`${nodeIds.length} agents`} onClick={() => setDistribution('per-node')} />
                    <Choice active={distribution === 'per-batch'} title="Grouped batches" detail={`${Math.ceil(nodeIds.length / Math.max(1, batchSize))} agents`} onClick={() => setDistribution('per-batch')} />
                  </div>
                  {distribution === 'per-batch' && (
                    <label className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground">Nodes per agent<input type="number" min={1} max={nodeIds.length} value={batchSize} onChange={event => setBatchSize(Math.max(1, Math.min(nodeIds.length, Number(event.target.value) || 1)))} className="settings-input h-7 w-20" /></label>
                  )}
                  <input value={objective} onChange={event => setObjective(event.target.value)} placeholder="Optional shared objective" className="settings-input mt-3 h-8 w-full" />
                </div>
              )}
            </div>
          )}

          {step === 'review' && (
            <div className="space-y-5">
              <div>
                <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Review</div>
                <h3 className="mt-1 text-base font-semibold text-foreground">{selectedFrontier ? 'Dispatch the selected frontier item' : parsed.kind === 'raw' ? 'Add scope and deploy reconnaissance' : fanout ? `Dispatch ${agentCount} agents` : 'Dispatch one agent'}</h3>
                <p className="mt-1 text-[11px] leading-5 text-muted-foreground">Overwatch’s server-side scope, lease, concurrency, and OPSEC checks remain authoritative at execution time.</p>
              </div>
              <ReviewFacts
                parsed={parsed}
                selectedFrontier={selectedFrontier}
                preview={preview}
                archetype={effectiveArchetype}
                model={model || models.default || 'engagement default'}
                distribution={distribution}
                agentCount={agentCount}
              />
              {previewNotice && <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] text-warning">{previewNotice}</div>}
              {fanout && <div className="rounded-md border border-warning/20 bg-warning/5 px-3 py-2 text-[11px] leading-5 text-muted-foreground"><strong className="font-medium text-warning">Confirmation required.</strong> This creates up to {agentCount} independent work lanes. Targets already leased are skipped and concurrency-limited work is deferred.</div>}
            </div>
          )}

          {step === 'result' && result && (
            <div className="flex min-h-48 flex-col items-center justify-center text-center">
              <div className={cn('flex h-11 w-11 items-center justify-center rounded-full', result.tone === 'success' ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning')}><Check className="h-5 w-5" /></div>
              <h3 className="mt-4 text-base font-semibold text-foreground">{result.title}</h3>
              <p className="mt-1 max-w-md text-[11px] leading-5 text-muted-foreground">{result.detail}</p>
            </div>
          )}

          {error && <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-[11px] text-destructive">{error}</div>}
        </div>

        <footer className="flex flex-shrink-0 items-center justify-between border-t border-border-subtle px-5 py-3">
          {step !== 'target' && step !== 'result' ? (
            <ActionButton variant="ghost" onClick={() => setStep(step === 'review' ? 'method' : 'target')} disabled={busy}><ArrowLeft className="h-3 w-3" /> Back</ActionButton>
          ) : <span />}
          {step === 'target' && <ActionButton variant="primary" onClick={() => setStep('method')} disabled={!canContinueFromTarget}>Choose method <ChevronRight className="h-3 w-3" /></ActionButton>}
          {step === 'method' && <ActionButton variant="primary" onClick={() => void goToReview()} disabled={busy}>{busy ? 'Preparing…' : 'Review'} <ChevronRight className="h-3 w-3" /></ActionButton>}
          {step === 'review' && <ActionButton variant={fanout || parsed.kind === 'raw' ? 'warning' : 'primary'} onClick={() => void execute()} disabled={busy}>{busy ? 'Checking…' : fanout ? `Confirm & dispatch ${agentCount}` : parsed.kind === 'raw' ? 'Confirm scope & start' : 'Start work'}</ActionButton>}
          {step === 'result' && <ActionButton variant="primary" onClick={() => { addToast({ type: result?.tone === 'success' ? 'success' : 'warning', title: result?.title || 'Start work complete', message: result?.detail }); onClose(); }}>Done</ActionButton>}
        </footer>
      </div>
    </div>
  );
}

function TargetClassification({ parsed }: { parsed: DeployInput }) {
  if (parsed.kind === 'empty') return <p className="mt-2 text-[10px] text-muted">No target detected yet.</p>;
  if (parsed.kind === 'mixed') return <p className="mt-2 text-[10px] text-warning">Separate raw targets from graph node IDs. Unrecognized: {parsed.invalid.join(', ')}</p>;
  if (parsed.kind === 'raw') return <p className="mt-2 text-[10px] text-muted-foreground">Detected {parsed.cidrs.length} network target{parsed.cidrs.length === 1 ? '' : 's'} and {parsed.domains.length} domain{parsed.domains.length === 1 ? '' : 's'}.</p>;
  return <p className="mt-2 text-[10px] text-muted-foreground">Detected {parsed.nodeIds.length} graph node ID{parsed.nodeIds.length === 1 ? '' : 's'}.</p>;
}

function TargetSummary({ parsed, frontierLabel }: { parsed: DeployInput; frontierLabel?: string }) {
  return (
    <div className="border-b border-border-subtle pb-4">
      <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Target</div>
      <div className="mt-1 text-sm font-medium text-foreground">{frontierLabel || (parsed.kind === 'raw' ? parsed.target : parsed.kind === 'nodes' ? `${parsed.nodeIds.length} graph node${parsed.nodeIds.length === 1 ? '' : 's'}` : 'Unresolved')}</div>
    </div>
  );
}

function Choice({ active, title, detail, onClick }: { active: boolean; title: string; detail: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className={cn('rounded-md border px-3 py-2 text-left transition-colors', active ? 'border-accent/50 bg-accent/10' : 'border-border bg-background hover:border-border-strong')}>
      <div className="text-xs font-medium text-foreground">{title}</div>
      <div className="mt-0.5 text-[10px] text-muted-foreground">{detail}</div>
    </button>
  );
}

function ReviewFacts({
  parsed,
  selectedFrontier,
  preview,
  archetype,
  model,
  distribution,
  agentCount,
}: {
  parsed: DeployInput;
  selectedFrontier: ReturnType<typeof useEngagementStore.getState>['frontier'][number] | null;
  preview: api.ScopeChangePreview | null;
  archetype: string;
  model: string;
  distribution: Distribution;
  agentCount: number;
}) {
  const rows: Array<[string, React.ReactNode]> = [
    ['Agent type', <span key="archetype">{archetype}</span>],
    ['Model', <span key="model">{model}</span>],
  ];
  if (selectedFrontier) rows.unshift(['Frontier item', <span key="frontier" className="font-mono text-[10px]">{getFrontierKey(selectedFrontier)}</span>]);
  else if (parsed.kind === 'raw') rows.unshift(['Targets', <span key="target" className="font-mono text-[10px]">{[...parsed.cidrs, ...parsed.domains].join(', ')}</span>]);
  else if (parsed.kind === 'nodes') rows.unshift(['Nodes', <span key="nodes" className="font-mono text-[10px]">{parsed.nodeIds.join(', ')}</span>]);
  if (parsed.kind === 'nodes' && parsed.nodeIds.length > 1) rows.push(['Distribution', <span key="distribution">{distribution === 'per-node' ? 'one per node' : 'grouped batches'} · {agentCount} agents</span>]);
  return (
    <div className="divide-y divide-border-subtle border-y border-border-subtle">
      {rows.map(([label, value]) => <div key={label} className="grid grid-cols-[8rem_1fr] gap-3 py-2 text-[11px]"><span className="text-muted-foreground">{label}</span><span className="min-w-0 break-words text-foreground">{value}</span></div>)}
      {preview && (
        <div className="grid grid-cols-3 gap-3 py-3 text-center">
          <div><div className="text-lg font-semibold tabular-nums text-foreground">{preview.added.cidrs.length + preview.added.domains.length}</div><div className="text-[9px] uppercase tracking-wide text-muted-foreground">scope additions</div></div>
          <div><div className="text-lg font-semibold tabular-nums text-success">{preview.nodes_entering_scope}</div><div className="text-[9px] uppercase tracking-wide text-muted-foreground">nodes entering</div></div>
          <div><div className="text-lg font-semibold tabular-nums text-warning">{preview.nodes_leaving_scope}</div><div className="text-[9px] uppercase tracking-wide text-muted-foreground">nodes leaving</div></div>
        </div>
      )}
    </div>
  );
}
