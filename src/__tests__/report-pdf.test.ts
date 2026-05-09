// ============================================================
// B.4 — PDF rendering smoke test.
//
// Renders a tiny self-contained HTML through puppeteer-core if a
// chromium binary is discoverable on this machine. Skipped on CI
// runners that don't have chromium installed (the ci_skip flag prints
// a clear reason so it's not silently green).
// ============================================================

import { describe, it, expect } from 'vitest';
import { isPdfRenderingAvailable } from '../services/report-pdf.js';

const HTML = `<!doctype html>
<html><head><title>smoke</title></head>
<body style="font-family: sans-serif; padding: 2em;">
  <h1>Overwatch PDF Smoke Test</h1>
  <p>If you're reading this in a PDF, B.4 works.</p>
</body></html>`;

describe('report-pdf', () => {
  const status = isPdfRenderingAvailable();

  it('isPdfRenderingAvailable reports a discoverable executable when one exists', () => {
    if (!status.available) {
      // Not a failure — just no chromium installed. Surface the reason.
      console.info('[B.4 smoke] PDF rendering not available:', status.error);
      return;
    }
    expect(status.executable).toBeDefined();
  });

  it.skipIf(!status.available)('renders a minimal HTML through puppeteer-core into a PDF buffer', async () => {
    const { renderReportPdf } = await import('../services/report-pdf.js');
    const buf = await renderReportPdf(HTML, { format: 'A4', printBackground: true });
    expect(Buffer.isBuffer(buf)).toBe(true);
    // PDF magic header is `%PDF-`. Anything smaller than ~1KB is
    // suspicious; valid PDFs of a one-paragraph page are typically
    // 5–20 KB.
    expect(buf.byteLength).toBeGreaterThan(1024);
    expect(buf.subarray(0, 5).toString('ascii')).toBe('%PDF-');
  }, 30_000);
});
