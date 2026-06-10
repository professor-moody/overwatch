import type { ReportRecord } from './api';

export function reportProfileLabel(report: Pick<ReportRecord, 'profile' | 'redaction_mode'>): string {
  if (report.profile === 'client' || report.redaction_mode === 'client_safe') return 'client';
  return 'operator';
}

export function reportEvidenceLabel(style?: ReportRecord['evidence_style']): string {
  if (style === 'appendix') return 'appendix';
  if (style === 'full_inline') return 'full inline';
  return 'proof cards';
}

export function reportPrimaryActionLabel(format: ReportRecord['format']): string {
  return format === 'html' || format === 'pdf' ? 'Open' : 'Download';
}

export function formatReportBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
