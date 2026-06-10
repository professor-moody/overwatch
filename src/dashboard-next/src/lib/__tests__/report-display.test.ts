import { describe, expect, it } from 'vitest';
import { formatReportBytes, reportEvidenceLabel, reportPrimaryActionLabel, reportProfileLabel } from '../report-display';
import type { ReportRecord } from '../api';

function record(overrides: Partial<ReportRecord>): ReportRecord {
  return {
    id: 'report-1',
    generated_at: '2026-06-10T12:00:00.000Z',
    format: 'html',
    redaction_mode: 'operator',
    filename: 'report.html',
    size_bytes: 1536,
    content_sha256: 'abc',
    options: {},
    ...overrides,
  };
}

describe('dashboard report display helpers', () => {
  it('labels client-safe reports as client deliverables even without profile metadata', () => {
    expect(reportProfileLabel(record({ profile: 'operator' }))).toBe('operator');
    expect(reportProfileLabel(record({ profile: 'client' }))).toBe('client');
    expect(reportProfileLabel(record({ redaction_mode: 'client_safe' }))).toBe('client');
  });

  it('uses open for browser-readable reports and download for raw artifacts', () => {
    expect(reportPrimaryActionLabel('html')).toBe('Open');
    expect(reportPrimaryActionLabel('pdf')).toBe('Open');
    expect(reportPrimaryActionLabel('markdown')).toBe('Download');
    expect(reportPrimaryActionLabel('json')).toBe('Download');
  });

  it('formats report evidence style and byte counts for compact archive rows', () => {
    expect(reportEvidenceLabel('proof_cards')).toBe('proof cards');
    expect(reportEvidenceLabel('appendix')).toBe('appendix');
    expect(reportEvidenceLabel('full_inline')).toBe('full inline');
    expect(reportEvidenceLabel(undefined)).toBe('proof cards');
    expect(formatReportBytes(512)).toBe('512 B');
    expect(formatReportBytes(1536)).toBe('1.5 KB');
    expect(formatReportBytes(2 * 1024 * 1024)).toBe('2.0 MB');
  });
});
