// ============================================================
// Report → PDF rendering (B.4)
//
// Pipes a self-contained HTML report (the output of
// renderReportHtml()) through a headless Chromium binary via
// puppeteer-core and returns a Buffer of the resulting PDF.
//
// We use `puppeteer-core` (not `puppeteer`) so the install footprint
// stays small — operators bring their own Chrome / Chromium binary.
// On Kali this is `chromium` (or `google-chrome` for the labs that
// install the official package). Discovery order:
//   1. PUPPETEER_EXECUTABLE_PATH env var (explicit override)
//   2. CHROME_BIN env var (Playwright/CI convention)
//   3. Common system paths probed via fs.existsSync
//
// If no binary is found, we throw a clear actionable error rather
// than silently returning an empty buffer.
// ============================================================

import { existsSync } from 'fs';

const COMMON_CHROMIUM_PATHS = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/snap/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
];

function discoverExecutable(): string {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) return process.env.PUPPETEER_EXECUTABLE_PATH;
  if (process.env.CHROME_BIN) return process.env.CHROME_BIN;
  for (const p of COMMON_CHROMIUM_PATHS) {
    if (existsSync(p)) return p;
  }
  throw new Error(
    'No Chromium / Chrome binary found. Set PUPPETEER_EXECUTABLE_PATH ' +
    '(or CHROME_BIN) to a chromium executable, or install one of: ' +
    'chromium, chromium-browser, google-chrome. On Kali: ' +
    '`apt-get install chromium`. Falling back to a different format ' +
    '(markdown / html / json) is the simplest workaround.',
  );
}

export interface PdfRenderOptions {
  format?: 'A4' | 'Letter' | 'Legal';
  /** Render backgrounds (CSS bg colors / images). Default true so the
   *  styled HTML report still looks like a report. */
  printBackground?: boolean;
  /** Margins in CSS units (default `1cm`). */
  margin?: { top?: string; right?: string; bottom?: string; left?: string };
}

export async function renderReportPdf(html: string, opts: PdfRenderOptions = {}): Promise<Buffer> {
  // Lazy import — keeps puppeteer-core off the cold-start path for
  // engagements that never render PDFs.
  const puppeteer = await import('puppeteer-core');
  const executablePath = discoverExecutable();
  const browser = await puppeteer.default.launch({
    executablePath,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  try {
    const page = await browser.newPage();
    // setContent + waitUntil networkidle0 lets any inlined fonts /
    // images settle before the snapshot. Reports are self-contained,
    // so this typically resolves immediately.
    await page.setContent(html, { waitUntil: 'networkidle0', timeout: 30_000 });
    const pdfData = await page.pdf({
      format: opts.format ?? 'A4',
      printBackground: opts.printBackground ?? true,
      margin: {
        top: opts.margin?.top ?? '1cm',
        right: opts.margin?.right ?? '1cm',
        bottom: opts.margin?.bottom ?? '1cm',
        left: opts.margin?.left ?? '1cm',
      },
    });
    return Buffer.from(pdfData);
  } finally {
    await browser.close();
  }
}

export function isPdfRenderingAvailable(): { available: boolean; executable?: string; error?: string } {
  try {
    const exe = discoverExecutable();
    return { available: true, executable: exe };
  } catch (e) {
    return { available: false, error: e instanceof Error ? e.message : String(e) };
  }
}
