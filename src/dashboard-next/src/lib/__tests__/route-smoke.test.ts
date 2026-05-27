import { describe, expect, it } from 'vitest';
import puppeteer from 'puppeteer-core';

const smokeUrl = process.env.OVERWATCH_DASHBOARD_SMOKE_URL || '';
const chromePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const ROUTES: Array<{ path: string; expects: string[]; expectsAny?: string[] }> = [
  { path: '/overview', expects: ['Overview', 'Needs Verification'], expectsAny: ['No parser data', 'Dropped records', 'Path analysis failed', 'Estimated CVSS'] },
  { path: '/actions', expects: ['Actions', 'terminal'] },
  { path: '/activity', expects: ['Activity'], expectsAny: ['No parser data', 'Dropped records', 'Path analysis failed'] },
  { path: '/campaigns', expects: ['Campaigns'] },
  { path: '/sessions', expects: ['Sessions'], expectsAny: ['Attach', 'open_session'] },
  { path: '/frontier', expects: ['Frontier'] },
  { path: '/graph', expects: ['Graph'] },
  { path: '/graph?node=cred-jdoe-ntlm&hops=2', expects: ['Focused on', 'Show All'] },
  { path: '/graph?context=evidence&node=cred-jdoe-ntlm', expects: ['Evidence for', 'Show All'] },
  { path: '/graph?context=frontier&node=cred-jdoe-ntlm', expects: ['Frontier', 'Show All'] },
  { path: '/identity', expects: ['Identity Providers', 'Okta', 'GitHub Actions', 'Benefits Portal', 'MFA'] },
  { path: '/paths', expects: ['Attack Paths'], expectsAny: ['WS01', 'Benefits Portal', 'AWS BackupRole', 'corp-payroll-archive'] },
  { path: '/evidence', expects: ['Evidence'] },
  { path: '/findings', expects: ['Findings'], expectsAny: ['Estimated CVSS', 'CVSS'] },
  { path: '/smoke', expects: ['Smoke', '/api/trust-signals'] },
  { path: '/engagements', expects: ['Engagements'] },
];

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
        await page.goto(`${smokeUrl}${route.path}`, { waitUntil: 'domcontentloaded', timeout: 20_000 });
        await page.waitForSelector('body', { timeout: 5_000 });
        if (route.path.startsWith('/graph?')) {
          await page.waitForFunction(() => document.body.innerText.includes('Show All'), { timeout: 15_000 });
        }
        const text = await page.evaluate(() => document.body.innerText);
        expect(text.length, route.path).toBeGreaterThan(20);
        for (const expected of route.expects) {
          expect(text, route.path).toContain(expected);
        }
        if (route.expectsAny) {
          expect(route.expectsAny.some(expected => text.includes(expected)), route.path).toBe(true);
        }
        expect(text, route.path).not.toContain('Graph renderer is not mounted.');
        const pageTitle = route.path.split('?')[0].slice(1);
        const expectedTitle = pageTitle === 'paths'
          ? 'Attack Paths'
          : pageTitle.charAt(0).toUpperCase() + pageTitle.slice(1);
        if (!route.path.startsWith('/graph') && expectedTitle) {
          const titleCount = await page.evaluate((title) => (
            [...document.querySelectorAll('main h2')]
              .filter(heading => heading.textContent?.trim().startsWith(title)).length
          ), expectedTitle);
          expect(titleCount, `${route.path} duplicate page title`).toBeLessThanOrEqual(1);
        }
      }

      expect(errors.filter(error =>
        !error.includes('favicon') &&
        !error.includes('status of 503'),
      )).toEqual([]);
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('carries contextual graph links through evidence click-through', async () => {
    const browser = await puppeteer.launch({
      executablePath: chromePath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.goto(`${smokeUrl}/evidence?node=cred-jdoe-ntlm`, { waitUntil: 'domcontentloaded', timeout: 20_000 });
      await page.waitForFunction(() => document.body.innerText.includes('cred-jdoe-ntlm'), { timeout: 10_000 });
      await page.evaluate(() => {
        const button = [...document.querySelectorAll('button')]
          .find(candidate => candidate.title?.includes('Open cred-jdoe-ntlm in graph'));
        if (!(button instanceof HTMLButtonElement)) throw new Error('credential graph button missing');
        button.click();
      });
      await page.waitForFunction(() => location.pathname.endsWith('/graph') && document.body.innerText.includes('Evidence for'), { timeout: 15_000 });
      const text = await page.evaluate(() => document.body.innerText);
      expect(text).toContain('Show All');
      expect(text).not.toContain('Graph renderer is not mounted.');
    } finally {
      await browser.close();
    }
  }, 40_000);
});
