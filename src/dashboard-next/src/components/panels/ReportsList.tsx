// ============================================================
// ReportsList (B.3)
//
// Embedded inside FindingsPanel. Lists past report renders from the
// per-engagement archive, with download + delete actions.
// ============================================================

import * as api from '../../lib/api';
import type { ReportRecord } from '../../lib/api';
import { useState } from 'react';
import { formatReportBytes, reportEvidenceLabel, reportPrimaryActionLabel, reportProfileLabel } from '../../lib/report-display';
import { cn, formatTimestamp } from '../../lib/utils';
import { downloadDashboardResource, openDashboardResource } from '../../lib/dashboard-transport';

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
  const [deleteNotice, setDeleteNotice] = useState<{
    tone: 'warning' | 'error';
    message: string;
  } | null>(null);

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this report from the archive?')) return;
    try {
      const result = await api.deleteReport(id);
      if (!result.deleted) {
        setDeleteNotice({ tone: 'error', message: 'The report was not found and was not deleted.' });
        return;
      }
      const pending: string[] = [];
      if (result.commit_durability !== 'confirmed') {
        pending.push('filesystem durability was not confirmed');
      }
      if (result.reference_persisted === false) {
        pending.push('the durable state reference was not checkpointed');
      }
      if (result.cleanup_complete === false) {
        pending.push('archive cleanup remains pending');
      }
      if (pending.length > 0 || result.warning) {
        setDeleteNotice({
          tone: 'warning',
          message: [
            `The report deletion is visible, but ${pending.join(', ') || 'recovery work remains pending'}.`,
            result.warning,
          ].filter(Boolean).join(' '),
        });
      } else {
        setDeleteNotice(null);
      }
      onRefresh();
    } catch (error) {
      setDeleteNotice({
        tone: 'error',
        message: `Report deletion failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  };

  const handleReport = async (report: ReportRecord) => {
    const open = reportPrimaryActionLabel(report.format) === 'Open';
    const path = open ? api.reportOpenUrl(report.id) : api.reportDownloadUrl(report.id);
    try {
      if (open) await openDashboardResource(path);
      else await downloadDashboardResource(path);
    } catch {
      // Keep the archive row available for retry.
    }
  };

  if (reports.length === 0 && !deleteNotice) return null;

  return (
    <section className="bg-surface border border-border rounded-lg p-3">
      {deleteNotice && (
        <div
          role="alert"
          className={cn(
            'mb-2 rounded border px-3 py-2 text-xs',
            deleteNotice.tone === 'error'
              ? 'border-destructive/30 bg-destructive/10 text-destructive'
              : 'border-warning/30 bg-warning/10 text-warning',
          )}
        >
          {deleteNotice.message}
        </div>
      )}
      {reports.length > 0 && <h3 className="text-sm font-medium mb-2">Reports archive ({reports.length})</h3>}
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
            <button
              onClick={() => void handleReport(r)}
              className="px-2 py-0.5 rounded bg-accent/10 text-accent hover:bg-accent/20"
            >
              {reportPrimaryActionLabel(r.format)}
            </button>
            <button
              onClick={() => void handleDelete(r.id)}
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
