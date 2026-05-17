import { useState, useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { cn, formatTimestamp } from '../../lib/utils';
import { getEvidenceChains, getFindings, getPaths, type FindingDto } from '../../lib/api';
import type { EvidenceChainResponse, AttackPath, Objective } from '../../lib/types';
import { PageHeader, PanelSection } from '../shared/primitives';
import { deriveNodeRelationships } from '../../lib/relationships';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { EvidenceNarrative } from '../shared/EvidenceNarrative';
import { narrativeItemsFromChains, resolveEvidenceQuery } from '../../lib/evidence-narrative';

export function EvidencePanel() {
  const objectives = useEngagementStore((s) => s.objectives);
  const [searchParams] = useSearchParams();

  const initialQuery = searchParams.get('node') || '';
  const initialObjective = searchParams.get('objective') || '';

  return (
    <div className="space-y-6">
      <PageHeader title="Evidence" />
      <EvidenceChainSearch initialQuery={initialQuery} />
      <AttackPathViewer objectives={objectives} initialObjective={initialObjective} />
    </div>
  );
}

/* ============ Evidence Chain Search ============ */

function EvidenceChainSearch({ initialQuery }: { initialQuery?: string }) {
  const [query, setQuery] = useState(initialQuery || '');
  const [data, setData] = useState<EvidenceChainResponse | null>(null);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { navigateToPanel } = useNavigation();
  const graph = useEngagementStore(s => s.graph);
  const sessions = useEngagementStore(s => s.sessions);
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const frontier = useEngagementStore(s => s.frontier);

  const search = useCallback(async () => {
    const q = query.trim();
    if (!q) return;
    setLoading(true); setError(''); setData(null);
    try {
      const resolved = resolveEvidenceQuery(q, graph, findings) || q;
      const resp = await getEvidenceChains(resolved);
      setData(resp);
    } catch {
      setError('No evidence found');
    } finally { setLoading(false); }
  }, [query, graph, findings]);

  // Auto-search if initialQuery provided
  useEffect(() => {
    if (initialQuery) {
      setQuery(initialQuery);
      getEvidenceChains(initialQuery).then(setData).catch(() => setError('No evidence found'));
    }
  }, [initialQuery]);

  useEffect(() => {
    let cancelled = false;
    getFindings()
      .then(resp => { if (!cancelled) setFindings(resp.findings || []); })
      .catch(() => { if (!cancelled) setFindings([]); });
    return () => { cancelled = true; };
  }, []);

  const relationships = data ? deriveNodeRelationships(data.node_id, {
    graph,
    sessions,
    pendingActions,
    frontier,
    findings,
  }) : null;

  return (
    <PanelSection title="Evidence Chain" className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Search a graph node ID (e.g. <span className="font-mono">cred-aws-power</span>, <span className="font-mono">host-jumpbox</span>) to see the actions that produced or touched it — the tool name, command, output preview, and timestamp for each step. Useful for "how did we end up with this credential?" or "what did we run against this host?".
      </p>
      <div className="flex gap-2">
        <input value={query} onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Node ID or label…" className="settings-input flex-1" />
        <button onClick={search} className="settings-save-btn">Search</button>
      </div>

      {loading && <p className="text-xs text-muted-foreground">Searching…</p>}
      {error && <p className="text-xs text-muted-foreground">{error}</p>}

      {data && (
        <div className="space-y-3">
          {/* Node header */}
          <div className="flex items-center gap-2 flex-wrap">
            <GraphNodeLinks nodeId={data.node_id} />
            <span className="text-xs text-muted-foreground">{data.count} entries</span>
          </div>

          {/* Node properties */}
          {data.node_props && (
            <div className="flex gap-1.5 flex-wrap">
              {data.node_props.type && <PropTag className="bg-accent-dim text-accent">{data.node_props.type}</PropTag>}
              {data.node_props.label && data.node_props.label !== data.node_id && <PropTag>{data.node_props.label}</PropTag>}
              {data.node_props.os && <PropTag>{data.node_props.os}</PropTag>}
              {data.node_props.confidence != null && <PropTag>conf: {Math.round(data.node_props.confidence * 100)}%</PropTag>}
              {data.node_props.chain_template && <PropTag className="bg-purple-dim text-purple">{data.node_props.chain_template}</PropTag>}
            </div>
          )}

          {/* Findings */}
          {data.findings && data.findings.length > 0 && (
            <div className="space-y-1.5">
              <h4 className="text-xs font-medium text-muted-foreground">Findings ({data.findings.length})</h4>
              {data.findings.map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-xs p-2 rounded bg-elevated border border-border">
                  <span className="text-muted-foreground">{f.finding_type || 'finding'}</span>
                  {f.severity && (
                    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium',
                      f.severity === 'critical' ? 'bg-destructive/10 text-destructive' :
                      f.severity === 'high' ? 'bg-warning/10 text-warning' :
                      f.severity === 'medium' ? 'bg-accent-dim text-accent' :
                      'bg-elevated text-muted-foreground',
                    )}>{f.severity}</span>
                  )}
                  {f.technique_id && <span className="font-mono text-accent">{f.technique_id}</span>}
                  {f.description && <span className="text-muted-foreground truncate flex-1">{f.description}</span>}
                </div>
              ))}
            </div>
          )}

          {relationships && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              <RelatedCard title="Sessions" count={relationships.sessions.length} onClick={() => navigateToPanel('sessions')} />
              <RelatedCard title="Actions" count={relationships.pendingActions.length} onClick={() => navigateToPanel('actions')} />
              <RelatedCard title="Frontier" count={relationships.frontier.length} onClick={() => navigateToPanel('frontier', data.node_id)} />
              {relationships.findings.length > 0 && (
                <div className="md:col-span-3 rounded border border-border bg-elevated p-2">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-medium">Related Findings</span>
                    <button onClick={() => navigateToPanel('findings')} className="text-accent hover:underline">Open findings</button>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {relationships.findings.slice(0, 6).map(finding => (
                      <span key={finding.id} className="text-[10px] px-1.5 py-0.5 rounded bg-background text-muted-foreground">
                        {finding.severity} · {finding.title}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="rounded border border-border bg-background/40 p-2">
            <div className="mb-2 text-xs font-medium text-muted-foreground">Narrative</div>
            <EvidenceNarrative items={narrativeItemsFromChains([data])} />
          </div>

          {/* Timeline */}
          {data.chains.length > 0 && (
            <div className="space-y-0 ml-3 border-l border-border pl-4">
              {data.chains.map((entry, i) => (
                <div key={entry.activity_id || i} className="relative pb-3">
                  <div className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-accent border border-surface" />
                  <div className="flex items-center gap-2 text-xs mb-0.5">
                    <span className="text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
                    {entry.tool && <span className="px-1.5 py-0.5 rounded bg-elevated text-accent text-[10px]">{entry.tool}</span>}
                    {entry.action_id && <span className="font-mono text-muted-foreground">{entry.action_id.slice(0, 8)}</span>}
                  </div>
                  {entry.command && <div className="text-xs font-mono text-foreground bg-background rounded p-1.5 mt-1 border border-border">{entry.command}</div>}
                  {entry.snippet && <div className="text-xs font-mono text-muted-foreground bg-background rounded p-1.5 mt-1">{entry.snippet}</div>}
                </div>
              ))}
            </div>
          )}

          {data.chains.length === 0 && <p className="text-xs text-muted-foreground">No evidence chain entries</p>}
        </div>
      )}
    </PanelSection>
  );
}

function RelatedCard({ title, count, onClick }: { title: string; count: number; onClick: () => void }) {
  return (
    <button onClick={onClick} className="rounded border border-border bg-elevated p-2 text-left hover:bg-hover transition-colors">
      <div className="text-[10px] text-muted-foreground">{title}</div>
      <div className="text-lg font-semibold text-foreground">{count}</div>
    </button>
  );
}

function PropTag({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('text-[10px] px-1.5 py-0.5 rounded bg-elevated text-foreground', className)}>{children}</span>;
}

/* ============ Attack Path Viewer ============ */

function AttackPathViewer({ objectives, initialObjective }: { objectives: Objective[]; initialObjective?: string }) {
  const [selectedObjective, setSelectedObjective] = useState(initialObjective || '');
  const [optimize, setOptimize] = useState<'confidence' | 'stealth' | 'balanced'>('confidence');
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(false);
  const { navigateToGraph } = useNavigation();

  // Auto-search if initialObjective provided
  useEffect(() => {
    if (initialObjective) {
      setSelectedObjective(initialObjective);
      getPaths(initialObjective, { limit: 5, optimize }).then(r => setPaths(r.paths || [])).catch(() => {});
    }
  }, [initialObjective, optimize]);

  const search = useCallback(async () => {
    if (!selectedObjective) return;
    setLoading(true); setPaths([]);
    try {
      const resp = await getPaths(selectedObjective, { limit: 5, optimize });
      setPaths(resp.paths || []);
    } catch { /* silent */ }
    finally { setLoading(false); }
  }, [selectedObjective, optimize]);

  return (
    <section className="bg-surface border border-border rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-medium">Attack Paths</h3>
      <div className="flex gap-2">
        <select value={selectedObjective} onChange={e => setSelectedObjective(e.target.value)} className="settings-input flex-1">
          <option value="">Select objective…</option>
          {objectives.map(obj => (
            <option key={obj.id} value={obj.id}>{obj.description}{obj.achieved ? ' ✓' : ''}</option>
          ))}
        </select>
        <select value={optimize} onChange={e => setOptimize(e.target.value as typeof optimize)} className="settings-input w-auto">
          <option value="confidence">Confidence</option>
          <option value="stealth">Stealth</option>
          <option value="balanced">Balanced</option>
        </select>
        <button onClick={search} className="settings-save-btn">Find Paths</button>
      </div>

      {loading && <p className="text-xs text-muted-foreground">Finding paths…</p>}

      {paths.length > 0 && (
        <div className="space-y-3">
          {paths.map((path, i) => {
            const conf = path.confidence != null ? Math.round(path.confidence * 100) : null;
            const noise = path.opsec_noise != null ? Math.round(path.opsec_noise * 100) : null;

            return (
              <div key={i} className="p-3 rounded border border-border bg-elevated space-y-2">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground font-medium">#{i + 1}</span>
                  {conf !== null && <span className="text-success">{conf}% conf</span>}
                  {noise !== null && <span className="text-warning">{noise}% noise</span>}
                </div>
                <div className="flex items-center gap-1 flex-wrap text-xs">
                  {path.nodes.map((n, j) => (
                    <span key={j} className="contents">
                      {j > 0 && typeof n === 'object' && n.edge_type && (
                        <span className="text-[10px] text-muted-foreground">{n.edge_type}</span>
                      )}
                      {j > 0 && <span className="text-muted">{'\u2192'}</span>}
                      <span
                        onClick={() => {
                          const nodeId = typeof n === 'object' ? n.id : String(n);
                          navigateToGraph(nodeId, 2);
                        }}
                        className="px-1.5 py-0.5 rounded bg-background text-foreground font-mono cursor-pointer hover:text-accent transition-colors"
                        title={typeof n === 'object' ? n.id : String(n)}>
                        {typeof n === 'object' ? (n.label || n.id) : String(n)}
                      </span>
                    </span>
                  ))}
                </div>
                {/* Metric bars */}
                <div className="space-y-1">
                  {conf !== null && <MetricBar label="confidence" value={conf} color="bg-success" />}
                  {noise !== null && <MetricBar label="noise" value={noise} color="bg-warning" />}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {!loading && paths.length === 0 && selectedObjective && (
        <p className="text-xs text-muted-foreground">No attack paths found. Select an objective and search.</p>
      )}
    </section>
  );
}

function MetricBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-2 text-[10px]">
      <span className="text-muted-foreground w-16">{label}</span>
      <div className="flex-1 h-1 bg-background rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${value}%` }} />
      </div>
      <span className="text-muted-foreground font-mono w-8 text-right">{value}%</span>
    </div>
  );
}
