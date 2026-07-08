// ============================================================
// FindingsPanel (B.3)
//
// Lists structured findings — same shape generate_report uses, just
// scoped to the dashboard. Severity-grouped with classification badges
// (CWE / OWASP / NIST / PCI / ATT&CK). Header has a "Generate Report"
// button that opens RenderReportModal, plus an inline ReportsList for
// past renders.
// ============================================================

import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import * as api from '../../lib/api';
import type { FindingDto, ReportRecord } from '../../lib/api';
import type { FindingContextResponse } from '../../lib/types';
import { cn, formatTimestamp } from '../../lib/utils';
import { RenderReportModal } from './RenderReportModal';
import { ReportsList } from './ReportsList';
import { useEngagementStore } from '../../stores/engagement-store';
import { resolveAssetToNodeId } from '../../lib/relationships';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { EvidenceNarrative } from '../shared/EvidenceNarrative';
import { narrativeItemsFromFindingContext } from '../../lib/evidence-narrative';
import { ActionButton, EmptyPanelState, PageHeader } from '../shared/primitives';
import { extractFindingTrustSignals } from '../../lib/trust-signals';
import { TrustSignalList, TrustSignalPills } from '../shared/TrustSignals';
import {
  findingCategoryLabel,
  findingImpact,
  findingRemediation,
  findingSummary,
  findingTitle,
  findingVulnLabel,
} from '../../lib/finding-display';

const SEVERITY_ORDER: Array<FindingDto['severity']> = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_BADGE: Record<FindingDto['severity'], string> = {
  critical: 'bg-destructive/15 text-destructive border-destructive/30',
  high: 'bg-warning/15 text-warning border-warning/30',
  medium: 'bg-accent/15 text-accent border-accent/30',
  low: 'bg-muted text-muted-foreground border-border',
  info: 'bg-elevated text-muted-foreground border-border',
};

export function FindingsPanel() {
  const graph = useEngagementStore(s => s.graph);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [summary, setSummary] = useState<{ critical: number; high: number; medium: number; low: number; info: number }>({
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  });
  const [loading, setLoading] = useState(true);
  const [showRender, setShowRender] = useState(false);
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [expandedSeverity, setExpandedSeverity] = useState<Set<FindingDto['severity']>>(new Set(['critical', 'high']));
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
  const [findingContext, setFindingContext] = useState<FindingContextResponse | null>(null);
  const [contextLoading, setContextLoading] = useState(false);

  const refreshFindings = useCallback(async () => {
    try {
      const data = await api.getFindings();
      setFindings(data.findings);
      setSummary(data.severity_summary);
    } catch { /* silent */ } finally { setLoading(false); }
  }, []);

  const refreshReports = useCallback(async () => {
    try {
      const data = await api.listReports();
      setReports(data.reports);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    refreshFindings();
    refreshReports();
    // Light poll — findings move when agents finish; reports move when
    // operator renders.
    const id = setInterval(() => { refreshFindings(); refreshReports(); }, 8000);
    return () => clearInterval(id);
  }, [refreshFindings, refreshReports]);

  useEffect(() => {
    const item = searchParams.get('item');
    if (!item || findings.length === 0) return;
    setSelectedFindingId(item);
    const match = findings.find(f => f.id === item);
    if (match) setExpandedSeverity(prev => new Set([...prev, match.severity]));
  }, [searchParams, findings]);

  const toggleSeverity = (s: FindingDto['severity']) => {
    setExpandedSeverity(prev => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s); else next.add(s);
      return next;
    });
  };

  const grouped: Record<FindingDto['severity'], FindingDto[]> = { critical: [], high: [], medium: [], low: [], info: [] };
  for (const f of findings) grouped[f.severity].push(f);

  useEffect(() => {
    if (!selectedFindingId) {
      setFindingContext(null);
      return;
    }
    let cancelled = false;
    setContextLoading(true);
    api.getFindingContext(selectedFindingId)
      .then(context => { if (!cancelled) setFindingContext(context); })
      .catch(() => { if (!cancelled) setFindingContext(null); })
      .finally(() => { if (!cancelled) setContextLoading(false); });
    return () => { cancelled = true; };
  }, [selectedFindingId]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Findings"
        meta={`(${findings.length})`}
        actions={(
        <>
          <div className="flex gap-2 text-xs">
            {summary.critical > 0 && <span className="text-destructive">{summary.critical} critical</span>}
            {summary.high > 0 && <span className="text-warning">{summary.high} high</span>}
            {summary.medium > 0 && <span className="text-accent">{summary.medium} medium</span>}
            {(summary.low > 0 || summary.info > 0) && (
              <span className="text-muted-foreground">{summary.low + summary.info} info/low</span>
            )}
          </div>
          <ActionButton
            onClick={() => {
              const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `findings-${new Date().toISOString().slice(0, 10)}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
            variant="secondary"
            title="Export findings as JSON"
          >
            Export JSON
          </ActionButton>
          <ActionButton
            onClick={() => setShowRender(true)}
            variant="primary"
          >
            Generate Report
          </ActionButton>
        </>
        )}
      />

      {/* Reports archive (past renders) */}
      {reports.length > 0 && (
        <ReportsList reports={reports} onRefresh={refreshReports} />
      )}

      {(selectedFindingId || findingContext) && (
        <FindingInspector
          context={findingContext}
          loading={contextLoading}
          onClose={() => setSelectedFindingId(null)}
        />
      )}

      {/* Findings list */}
      {loading ? (
        <div className="text-sm text-muted-foreground animate-pulse">Loading…</div>
      ) : findings.length === 0 ? (
        <EmptyPanelState message="No findings yet." />
      ) : (
        <div className="space-y-2">
          {SEVERITY_ORDER.map(sev => {
            const group = grouped[sev];
            if (group.length === 0) return null;
            const isExpanded = expandedSeverity.has(sev);
            return (
              <div key={sev} className="bg-surface border border-border rounded-lg overflow-hidden">
                <button
                  onClick={() => toggleSeverity(sev)}
                  className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-hover transition-colors"
                >
                  <span className="text-muted-foreground">{isExpanded ? '▾' : '▸'}</span>
                  <span className={cn('px-1.5 py-0.5 rounded border text-[10px] uppercase font-semibold', SEVERITY_BADGE[sev])}>
                    {sev}
                  </span>
                  <span className="text-muted-foreground">{group.length} finding{group.length === 1 ? '' : 's'}</span>
                </button>
                {isExpanded && (
                  <div className="border-t border-border divide-y divide-border">
                    {group.map(f => (
                      <FindingRow
                        key={f.id}
                        finding={f}
                        resolveAsset={(asset) => resolveAssetToNodeId(asset, graph)}
                        selected={selectedFindingId === f.id}
                        onInspect={() => setSelectedFindingId(f.id)}
                      />
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {showRender && (
        <RenderReportModal
          onClose={() => setShowRender(false)}
          onRendered={() => { refreshReports(); }}
        />
      )}
    </div>
  );
}

function FindingRow({
  finding: f,
  resolveAsset,
  selected,
  onInspect,
}: {
  finding: FindingDto;
  resolveAsset: (asset: string) => string | null;
  selected: boolean;
  onInspect: () => void;
}) {
  const cls = f.classification;
  const trustSignals = extractFindingTrustSignals(f);
  return (
    <div className={cn('px-3 py-2 hover:bg-hover transition-colors', selected && 'bg-accent/5')}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-foreground">{findingTitle(f)}</div>
          <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{findingSummary(f)}</div>
          <TrustSignalPills signals={trustSignals} className="mt-1.5" />
          {f.affected_assets.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {f.affected_assets.slice(0, 6).map(asset => {
                const nodeId = resolveAsset(asset);
                return nodeId ? (
                  <GraphNodeLinks
                    key={asset}
                    nodeId={nodeId}
                    label={asset}
                    className="rounded bg-accent/10 px-1 py-0.5 text-accent"
                    graphTarget={{ kind: 'finding', findingId: f.id, nodeIds: [nodeId], label: `Finding ${findingTitle(f)}` }}
                  />
                ) : (
                  <span key={asset} className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-muted-foreground font-mono">{asset}</span>
                );
              })}
              {f.affected_assets.length > 6 && <span className="text-[10px] text-muted-foreground">+{f.affected_assets.length - 6} more</span>}
            </div>
          )}
          {cls && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {cls.cwe && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated border border-border">CWE-{cls.cwe.id} {cls.cwe.name}</span>
              )}
              {cls.owasp_top_10 && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated border border-border">OWASP {cls.owasp_top_10.id}</span>
              )}
              {cls.attack_techniques?.slice(0, 2).map(t => (
                <span key={t.id} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-dim text-purple border border-purple/30">ATT&CK {t.id}</span>
              ))}
            </div>
          )}
        </div>
        <div className="text-right flex-shrink-0">
          <div className="text-xs text-muted-foreground">risk {f.risk_score.toFixed(1)}</div>
          {f.cvss_score !== undefined && (
            <div className={cn('text-[10px]', f.cvss_estimated ? 'text-accent' : 'text-muted-foreground')} title={f.cvss_vector}>
              CVSS {f.cvss_score.toFixed(1)}{f.cvss_estimated ? ' est.' : ''}
            </div>
          )}
          <button onClick={onInspect} className="mt-1 text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent hover:bg-accent/20">
            Inspect
          </button>
        </div>
      </div>
    </div>
  );
}

function FindingInspector({
  context,
  loading,
  onClose,
}: {
  context: FindingContextResponse | null;
  loading: boolean;
  onClose: () => void;
}) {
  if (loading) {
    return (
      <div className="rounded-lg border border-border bg-surface p-3 text-sm text-muted-foreground">
        Loading finding context…
      </div>
    );
  }
  if (!context) {
    return (
      <div className="rounded-lg border border-border bg-surface p-3 flex items-center justify-between">
        <span className="text-sm text-muted-foreground">Finding context unavailable.</span>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Close</button>
      </div>
    );
  }

  const f = context.finding;
  const trustSignals = extractFindingTrustSignals(f);
  const impact = findingImpact(f);
  return (
    <div className="rounded-lg border border-border bg-surface p-3 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold">{findingTitle(f)}</div>
          <div className="text-xs text-muted-foreground">{findingCategoryLabel(f.category)} · {f.severity} · risk {f.risk_score.toFixed(1)}</div>
        </div>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Close</button>
      </div>

      <div className="rounded border border-border bg-elevated p-2 text-xs space-y-1.5">
        <div className="text-foreground">{findingSummary(f)}</div>
        {impact && (
          <div>
            <span className="font-medium text-muted-foreground">Impact: </span>
            <span className="text-foreground">{impact}</span>
          </div>
        )}
      </div>

      {(f.cvss_score !== undefined || trustSignals.length > 0) && (
        <div className="rounded border border-border bg-elevated p-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            {f.cvss_score !== undefined && (
              <span className="text-muted-foreground">
                CVSS <span className="font-mono text-foreground">{f.cvss_score.toFixed(1)}</span>{f.cvss_estimated ? ' estimated' : ''}
              </span>
            )}
          </div>
          {f.cvss_vector && (
            <details className="mt-1">
              <summary className="cursor-pointer text-[10px] text-accent">CVSS vector</summary>
              <div className="mt-1 font-mono text-[10px] text-muted-foreground break-all">{f.cvss_vector}</div>
            </details>
          )}
          <TrustSignalList signals={trustSignals} className="mt-2" />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-3">
        <div className="space-y-2">
          <div className="text-xs font-medium text-muted-foreground">Supporting Evidence</div>
          <FindingEvidence context={context} />
          <div>
            <div className="mb-1 text-xs font-medium text-muted-foreground">Recommended Remediation</div>
            <div className="rounded border border-border bg-elevated p-2 text-xs text-foreground whitespace-pre-wrap">
              {findingRemediation(f)}
            </div>
          </div>
        </div>
        <div className="space-y-2">
          <ContextMetric label="Affected nodes" value={context.affected_nodes.length} />
          <ContextMetric label="Sessions" value={context.sessions.length} />
          <ContextMetric label="Pending actions" value={context.pending_actions.length} />
          <ContextMetric label="Frontier" value={context.frontier.length} />
          <ContextMetric label="Path impacts" value={context.path_impacts.length} />
          <ContextMetric label="Report ready" value={context.report_ready ? 'yes' : 'no'} />
        </div>
      </div>

      {context.affected_nodes.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Affected Graph Nodes</div>
          <div className="flex flex-wrap gap-1">
            {context.affected_nodes.map(node => (
              <GraphNodeLinks
                key={`${node.asset || ''}-${node.id}`}
                nodeId={node.id}
                label={(node.label as string) || node.asset}
                graphTarget={{
                  kind: 'finding',
                  findingId: context.finding.id,
                  nodeIds: context.affected_nodes.map(affected => affected.id),
                  label: `Finding ${findingTitle(context.finding)}`,
                }}
              />
            ))}
          </div>
        </div>
      )}

      {context.path_impacts.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Path Impact</div>
          <div className="space-y-1">
            {context.path_impacts.slice(0, 3).map((path, index) => (
              <div key={`${path.objective_id}-${index}`} className="rounded border border-border bg-elevated p-2 text-xs">
                <div className="font-medium">{path.objective}</div>
                <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate">{path.nodes.join(' -> ')}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** Evidence for a finding — anchored to the vuln it proves, and honest when there's
 *  none (an inference/analysis-derived finding, not broken). */
function FindingEvidence({ context }: { context: FindingContextResponse }) {
  const items = narrativeItemsFromFindingContext(context);
  if (items.length === 0) {
    return (
      <div className="rounded border border-warning/30 bg-warning/5 p-2 text-xs">
        <div className="font-medium text-warning">No direct tool evidence</div>
        <div className="mt-0.5 text-muted-foreground">
          Derived from the graph (inference / analysis of {context.affected_nodes.length} affected node{context.affected_nodes.length === 1 ? '' : 's'}) rather than captured tool output — open the affected nodes to see what it's based on.
        </div>
      </div>
    );
  }
  return <EvidenceNarrative items={items} subject={findingVulnLabel(context.finding)} />;
}

function ContextMetric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="flex items-center justify-between rounded border border-border bg-elevated px-2 py-1 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground">{value}</span>
    </div>
  );
}

// formatTimestamp is imported from utils for any timestamp rendering;
// kept here to avoid dead-code lint when this file gets edited.
void formatTimestamp;
