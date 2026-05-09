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
import { EmptyState } from '../shared';
import { cn, formatTimestamp } from '../../lib/utils';
import { RenderReportModal } from './RenderReportModal';
import { ReportsList } from './ReportsList';

const SEVERITY_ORDER: Array<FindingDto['severity']> = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_BADGE: Record<FindingDto['severity'], string> = {
  critical: 'bg-destructive/15 text-destructive border-destructive/30',
  high: 'bg-warning/15 text-warning border-warning/30',
  medium: 'bg-accent/15 text-accent border-accent/30',
  low: 'bg-muted text-muted-foreground border-border',
  info: 'bg-elevated text-muted-foreground border-border',
};

export function FindingsPanel() {
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [summary, setSummary] = useState<{ critical: number; high: number; medium: number; low: number; info: number }>({
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  });
  const [loading, setLoading] = useState(true);
  const [showRender, setShowRender] = useState(false);
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [expandedSeverity, setExpandedSeverity] = useState<Set<FindingDto['severity']>>(new Set(['critical', 'high']));

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
                      <FindingRow key={f.id} finding={f} />
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

function FindingRow({ finding: f }: { finding: FindingDto }) {
  const cls = f.classification;
  return (
    <div className="px-3 py-2 hover:bg-hover transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-foreground">{f.title}</div>
          <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{f.description}</div>
          {f.affected_assets.length > 0 && (
            <div className="text-[10px] text-muted-foreground mt-1 font-mono truncate">
              affects: {f.affected_assets.slice(0, 3).join(', ')}{f.affected_assets.length > 3 ? ` +${f.affected_assets.length - 3} more` : ''}
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
        </div>
      </div>
    </div>
  );
}

// formatTimestamp is imported from utils for any timestamp rendering;
// kept here to avoid dead-code lint when this file gets edited.
void formatTimestamp;
