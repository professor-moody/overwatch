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
import * as api from '../../lib/api';
import type { FindingDto, ReportRecord } from '../../lib/api';
import type { FindingContextResponse } from '../../lib/types';
import { EmptyState } from '../shared';
import { cn, formatTimestamp } from '../../lib/utils';
import { RenderReportModal } from './RenderReportModal';
import { ReportsList } from './ReportsList';
import { useEngagementStore } from '../../stores/engagement-store';
import { resolveAssetToNodeId } from '../../lib/relationships';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { EvidenceNarrative } from '../shared/EvidenceNarrative';
import { narrativeItemsFromFindingContext } from '../../lib/evidence-narrative';

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
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Findings <span className="text-muted-foreground font-normal text-sm">({findings.length})</span>
        </h2>
        <div className="flex items-center gap-3">
          <div className="flex gap-2 text-xs">
            {summary.critical > 0 && <span className="text-destructive">{summary.critical} critical</span>}
            {summary.high > 0 && <span className="text-warning">{summary.high} high</span>}
            {summary.medium > 0 && <span className="text-accent">{summary.medium} medium</span>}
            {(summary.low > 0 || summary.info > 0) && (
              <span className="text-muted-foreground">{summary.low + summary.info} info/low</span>
            )}
          </div>
          <button
            onClick={() => {
              const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `findings-${new Date().toISOString().slice(0, 10)}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
            className="text-xs px-2.5 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors"
            title="Export findings as JSON"
          >
            Export JSON
          </button>
          <button
            onClick={() => setShowRender(true)}
            className="text-xs px-2.5 py-1 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
          >
            Generate Report
          </button>
        </div>
      </div>

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
        <EmptyState
          title="No findings yet"
          description="Findings populate as agents discover compromised hosts, credentials, vulnerabilities, and access paths."
        />
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
          onRendered={() => { setShowRender(false); refreshReports(); }}
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
  return (
    <div className={cn('px-3 py-2 hover:bg-hover transition-colors', selected && 'bg-accent/5')}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-foreground">{f.title}</div>
          <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{f.description}</div>
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
                    graphTarget={{ kind: 'finding', findingId: f.id, nodeIds: [nodeId], label: `Finding ${f.title}` }}
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
            <div className="text-[10px] text-muted-foreground">CVSS {f.cvss_score.toFixed(1)}</div>
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
  return (
    <div className="rounded-lg border border-border bg-surface p-3 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold">{f.title}</div>
          <div className="text-xs text-muted-foreground">{f.category} · {f.severity} · risk {f.risk_score.toFixed(1)}</div>
        </div>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Close</button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-3">
        <div className="space-y-2">
          <div className="text-xs font-medium text-muted-foreground">Supporting Evidence</div>
          <EvidenceNarrative items={narrativeItemsFromFindingContext(context)} />
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
                  label: `Finding ${context.finding.title}`,
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
