// ============================================================
// ReportsList (B.3)
//
// Embedded inside FindingsPanel. Lists past report renders from the
// per-engagement archive, with download + delete actions.
// ============================================================

import * as api from '../../lib/api';
import type { ReportRecord } from '../../lib/api';
import { formatReportBytes, reportEvidenceLabel, reportPrimaryActionLabel, reportProfileLabel } from '../../lib/report-display';
import { cn, formatTimestamp } from '../../lib/utils';

interface Props {
  reports: ReportRecord[];
  onRefresh: () => void;
}

const FORMAT_BADGE: Record<ReportRecord['format'], string> = {
  markdown: 'bg-blue-dim text-blue border-blue/30',
  html: 'bg-purple-dim text-purple border-purple/30',
  json: 'bg-accent/15 text-accent border-accent/30',
  pdf: 'bg-warning/15 text-warning border-warning/30',
};

export function ReportsList({ reports, onRefresh }: Props) {
  if (reports.length === 0) return null;

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this report from the archive?')) return;
    try {
      await api.deleteReport(id);
      onRefresh();
    } catch { /* silent */ }
  };

  return (
    <section className="bg-surface border border-border rounded-lg p-3">
      <h3 className="text-sm font-medium mb-2">Reports archive ({reports.length})</h3>
      <div className="divide-y divide-border">
        {reports.map(r => (
          <div key={r.id} className="py-2 flex items-center gap-3 text-xs">
            <span className={cn('px-1.5 py-0.5 rounded border text-[10px] uppercase font-semibold', FORMAT_BADGE[r.format])}>
              {r.format}
            </span>
            {r.redaction_mode === 'client_safe' && (
              <span className="px-1.5 py-0.5 rounded border border-success/30 bg-success/10 text-success text-[10px] uppercase font-semibold">
                client-safe
              </span>
            )}
            <span className="px-1.5 py-0.5 rounded border border-border bg-elevated text-muted-foreground text-[10px] uppercase font-semibold">
              {reportProfileLabel(r)}
            </span>
            <span className="text-muted-foreground flex-1">
              {formatTimestamp(r.generated_at)} — {formatReportBytes(r.size_bytes)}
              {(r.findings_count !== undefined || r.evidence_count !== undefined) && (
                <span className="ml-2">
                  {r.findings_count ?? '—'} findings · {r.evidence_count ?? '—'} evidence · {reportEvidenceLabel(r.evidence_style)}
                </span>
              )}
            </span>
            <a
              href={reportPrimaryActionLabel(r.format) === 'Open' ? api.reportOpenUrl(r.id) : api.reportDownloadUrl(r.id)}
              target="_blank"
              rel="noopener noreferrer"
              className="px-2 py-0.5 rounded bg-accent/10 text-accent hover:bg-accent/20"
            >
              {reportPrimaryActionLabel(r.format)}
            </a>
            <button
              onClick={() => handleDelete(r.id)}
              className="px-2 py-0.5 rounded text-muted-foreground hover:text-destructive"
            >
              Delete
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}
