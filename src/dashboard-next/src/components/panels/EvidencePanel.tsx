import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { cn, formatTimestamp } from '../../lib/utils';
import { getEvidenceChains, getFindings, type FindingDto } from '../../lib/api';
import type { EvidenceChainResponse } from '../../lib/types';
import { ActionButton, EmptyPanelState, PageHeader, PanelSection } from '../shared/primitives';
import { deriveNodeRelationships } from '../../lib/relationships';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { EvidenceNarrative } from '../shared/EvidenceNarrative';
import { narrativeItemsFromChains, resolveEvidenceQuery } from '../../lib/evidence-narrative';
import { findingTitle, severityDiverseEntryFindings } from '../../lib/finding-display';

export function EvidencePanel() {
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('node') || '';

  // Node-centric provenance (a node's evidence chain). The run-centric lens lives
  // in the Analysis workspace; Attack Paths is its own nav item (the redundant
  // copy that used to live here was removed — see multi-agent-roadmap consolidation).
  return (
    <div className="space-y-6">
      <PageHeader title="Evidence" />
      <EvidenceChainSearch initialQuery={initialQuery} />
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
  const requestGeneration = useRef(0);
  // Entry-point shortcuts spread across severities — /api/findings is risk-sorted, so a
  // plain top-N only surfaced critical/high (see severityDiverseEntryFindings).
  const entryFindings = useMemo(() => severityDiverseEntryFindings(findings), [findings]);
  const { navigateToPanel, navigateToAction } = useNavigation();
  const graph = useEngagementStore(s => s.graph);
  const sessions = useEngagementStore(s => s.sessions);
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const frontier = useEngagementStore(s => s.frontier);

  const runSearch = useCallback(async (raw?: string) => {
    const q = (raw ?? query).trim();
    if (!q) return;
    const generation = ++requestGeneration.current;
    setLoading(true); setError(''); setData(null);
    try {
      const resolved = resolveEvidenceQuery(q, graph, findings) || q;
      const resp = await getEvidenceChains(resolved);
      if (requestGeneration.current === generation) setData(resp);
    } catch {
      if (requestGeneration.current === generation) setError('No evidence found');
    } finally {
      if (requestGeneration.current === generation) setLoading(false);
    }
  }, [query, graph, findings]);

  // Auto-search if initialQuery provided. Set loading (like runSearch) so the
  // guided empty state doesn't flash on top of the in-flight deep-link fetch.
  useEffect(() => {
    if (!initialQuery) return;
    const generation = ++requestGeneration.current;
    setQuery(initialQuery);
    setLoading(true); setError(''); setData(null);
    getEvidenceChains(initialQuery)
      .then(resp => {
        if (requestGeneration.current === generation) setData(resp);
      })
      .catch(() => {
        if (requestGeneration.current === generation) setError('No evidence found');
      })
      .finally(() => {
        if (requestGeneration.current === generation) setLoading(false);
      });
    return () => {
      if (requestGeneration.current === generation) requestGeneration.current += 1;
    };
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
      <div className="flex gap-2">
        <input value={query} onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && runSearch()}
          placeholder="Node ID or label…" className="settings-input flex-1 min-w-0" />
        <ActionButton onClick={() => runSearch()} variant="primary">Search</ActionButton>
      </div>

      {loading && <p className="text-xs text-muted-foreground">Searching…</p>}
      {error && <p className="text-xs text-muted-foreground">{error}</p>}

      {/* Guided empty state: landing here without a node param (e.g. the sidebar
          nav) used to show a blank search box. Explain the node-centric model and
          offer recent findings as one-click entry points. Suppressed while an
          error is showing so it can't stack under "No evidence found". */}
      {!data && !loading && !error && (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Evidence is node-centric. Search a node ID or label above, or open a node in the graph and click
            “View evidence”.{entryFindings.length > 0 ? ' Or start from a finding:' : ''}
          </p>
          {entryFindings.length > 0 && (
            <div className="space-y-1.5">
              {entryFindings.map(f => {
                const asset = f.affected_assets?.[0];
                return (
                  <button
                    key={f.id}
                    onClick={() => { if (asset) { setQuery(asset); void runSearch(asset); } }}
                    disabled={!asset}
                    className="flex w-full items-center gap-2 rounded border border-border bg-elevated p-2 text-left text-xs hover:bg-hover disabled:cursor-default disabled:opacity-50"
                  >
                    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium',
                      f.severity === 'critical' ? 'bg-destructive/10 text-destructive' :
                      f.severity === 'high' ? 'bg-warning/10 text-warning' :
                      f.severity === 'medium' ? 'bg-accent-dim text-accent' :
                      'bg-elevated text-muted-foreground',
                    )}>{f.severity}</span>
                    <span className="truncate flex-1">{findingTitle(f)}</span>
                    {asset && <span className="font-mono text-muted-foreground truncate max-w-[40%]">{asset}</span>}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}

      {data && (
        <div className="space-y-3">
          {/* Node header */}
          <div className="flex items-center gap-2 flex-wrap">
            <GraphNodeLinks
              nodeId={data.node_id}
              graphTarget={{ kind: 'evidence', nodeId: data.node_id, label: `Evidence for ${data.node_props?.label || data.node_id}` }}
            />
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
                        {finding.severity} · {findingTitle(finding)}
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
                    {entry.action_id && (
                      <button
                        onClick={() => navigateToAction(entry.action_id!)}
                        title="Open the run that produced this in Analysis"
                        className="font-mono text-muted-foreground hover:text-accent hover:underline"
                      >{entry.action_id.slice(0, 8)}</button>
                    )}
                  </div>
                  {entry.command && <div className="text-xs font-mono text-foreground bg-background rounded p-1.5 mt-1 border border-border">{entry.command}</div>}
                  {entry.snippet && <div className="text-xs font-mono text-muted-foreground bg-background rounded p-1.5 mt-1">{entry.snippet}</div>}
                </div>
              ))}
            </div>
          )}

          {data.chains.length === 0 && <EmptyPanelState message="No evidence chain entries." />}
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
