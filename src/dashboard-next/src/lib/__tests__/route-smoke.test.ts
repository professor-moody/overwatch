import { describe, expect, it } from 'vitest';
import puppeteer from 'puppeteer-core';

const smokeUrl = process.env.OVERWATCH_DASHBOARD_SMOKE_URL || '';
const chromePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const ROUTES = ['/actions', '/activity', '/sessions', '/frontier', '/graph', '/evidence', '/findings'];

describe.skipIf(!smokeUrl)('dashboard route smoke', () => {
  it('loads core operator routes without blanking', async () => {
    const browser = await puppeteer.launch({
      executablePath: chromePath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      const errors: string[] = [];
      page.on('pageerror', err => {
        errors.push(err instanceof Error ? err.message : String(err));
      });
      page.on('console', msg => {
        if (msg.type() === 'error') errors.push(msg.text());
      });

      for (const route of ROUTES) {
        await page.goto(`${smokeUrl}${route}`, { waitUntil: 'domcontentloaded', timeout: 20_000 });
        await page.waitForSelector('body', { timeout: 5_000 });
        const text = await page.evaluate(() => document.body.innerText);
        expect(text.length, route).toBeGreaterThan(20);
        expect(text, route).not.toContain('Graph renderer is not mounted.');
      }

      expect(errors.filter(error =>
        !error.includes('favicon') &&
        !error.includes('status of 503'),
      )).toEqual([]);
    } finally {
      await browser.close();
    }
  }, 60_000);
});
