// ============================================================
// B.4 — PDF rendering smoke test.
//
// Renders a tiny self-contained HTML through puppeteer-core if a
// chromium binary is discoverable on this machine. CI runners can expose
// incidental system Chromium builds that puppeteer-core does not manage,
// so the render smoke is opt-in there unless a browser path is explicit.
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
  const hasExplicitCiBrowser =
    Boolean(process.env.PUPPETEER_EXECUTABLE_PATH) || Boolean(process.env.CHROME_BIN);
  const shouldRunRenderSmoke =
    status.available &&
    (process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.OVERWATCH_PDF_SMOKE === '1' ||
      hasExplicitCiBrowser);

  it('isPdfRenderingAvailable reports a discoverable executable when one exists', () => {
    if (!status.available) {
      // Not a failure — just no chromium installed. Surface the reason.
      console.info('[B.4 smoke] PDF rendering not available:', status.error);
      return;
    }
    if (!shouldRunRenderSmoke) {
      console.info(
        '[B.4 smoke] PDF render smoke skipped on CI without explicit Chromium configuration',
      );
    }
    expect(status.executable).toBeDefined();
  });

  // Cold Chromium launch + render can exceed 30s under CI load; 60s + one
  // retry absorbs a transient slow render without masking a real hang.
  it.skipIf(!shouldRunRenderSmoke)('renders a minimal HTML through puppeteer-core into a PDF buffer', { timeout: 60_000, retry: 1 }, async () => {
    const { renderReportPdf } = await import('../services/report-pdf.js');
    const buf = await renderReportPdf(HTML, { format: 'A4', printBackground: true });
    expect(Buffer.isBuffer(buf)).toBe(true);
    // PDF magic header is `%PDF-`. Anything smaller than ~1KB is
    // suspicious; valid PDFs of a one-paragraph page are typically
    // 5–20 KB.
    expect(buf.byteLength).toBeGreaterThan(1024);
    expect(buf.subarray(0, 5).toString('ascii')).toBe('%PDF-');
  });
});
