import { describe, expect, it } from 'vitest';
import puppeteer from 'puppeteer-core';

const smokeUrl = process.env.OVERWATCH_DASHBOARD_SMOKE_URL || '';
const chromePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const ROUTES: Array<{ path: string; expects: string[]; expectsAny?: string[] }> = [
  { path: '/overview', expects: ['Overview', 'Now', 'Next', 'Changed', 'Current Access'] },
  { path: '/actions', expects: ['Actions', 'terminal'] },
  { path: '/agents', expects: ['Operator Console', 'Primary Operator'], expectsAny: ['may be stuck', 'stuck'] },
  { path: '/activity', expects: ['Activity'], expectsAny: ['No parser data', 'Dropped records', 'Path analysis failed'] },
  { path: '/campaigns', expects: ['Campaigns'] },
  { path: '/sessions', expects: ['Sessions', 'Terminal', 'Error'], expectsAny: ['Attach', 'Detach', 'open_session'] },
  { path: '/frontier', expects: ['Frontier'] },
  { path: '/graph', expects: ['Graph'] },
  { path: '/graph?node=cred-jdoe-ntlm&hops=2', expects: ['Focused on', 'Fit', 'Show All'] },
  { path: '/graph?context=evidence&node=cred-jdoe-ntlm', expects: ['Evidence for', 'Fit', 'Show All'] },
  { path: '/graph?context=frontier&node=cred-jdoe-ntlm', expects: ['Frontier', 'Fit', 'Show All'] },
  { path: '/graph?filter=host', expects: ['host nodes', 'Fit', 'Show All'] },
  { path: '/identity', expects: ['Identity Providers', 'Okta', 'GitHub Actions', 'Benefits Portal', 'MFA'] },
  { path: '/credentials', expects: ['Credentials', 'Expansion candidates', 'Expiring soon', 'Expired tokens'] },
  { path: '/paths', expects: ['Attack Paths', 'Inspect Path'], expectsAny: ['Fast wins', 'Cloud reach', 'Identity pivots', 'Higher risk'] },
  { path: '/evidence', expects: ['Evidence'] },
  { path: '/findings', expects: ['Findings'], expectsAny: ['Estimated CVSS', 'CVSS'] },
  { path: '/findings?item=nonexistent-id', expects: ['Findings'] },
  { path: '/sessions?item=nonexistent-id', expects: ['Sessions'] },
  { path: '/smoke', expects: ['Smoke', '/api/trust-signals'] },
  { path: '/settings', expects: ['Settings'] },
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
        if (msg.type() === 'error') {
          const location = msg.location();
          errors.push(location.url ? `${msg.text()} ${location.url}` : msg.text());
        }
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
        !error.includes('/api/findings/nonexistent-id/context') &&
        !error.includes('status of 503'),
      )).toEqual([]);
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('keeps desktop navigation expanded with visible labels by default', async () => {
    const browser = await puppeteer.launch({
      executablePath: chromePath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.evaluateOnNewDocument(() => {
        window.localStorage.setItem('overwatch-sidebar-expanded', 'true');
      });
      await page.goto(`${smokeUrl}/overview`, { waitUntil: 'domcontentloaded', timeout: 20_000 });
      await page.waitForFunction(() => document.body.innerText.includes('Current Access'), { timeout: 10_000 });
      const nav = await page.evaluate(() => {
        const el = document.querySelector('nav');
        const rect = el?.getBoundingClientRect();
        return {
          width: rect?.width || 0,
          text: el?.textContent || '',
        };
      });
      expect(nav.width).toBeGreaterThanOrEqual(200);
      expect(nav.text).toContain('Overview');
      expect(nav.text).toContain('Frontier');
      expect(nav.text).toContain('Settings');
    } finally {
      await browser.close();
    }
  }, 30_000);

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

  it('presents attack paths as decision rows and inspects them in graph context', async () => {
    const browser = await puppeteer.launch({
      executablePath: chromePath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.goto(`${smokeUrl}/paths`, { waitUntil: 'domcontentloaded', timeout: 20_000 });
      await page.waitForFunction(() => document.body.innerText.includes('Inspect Path'), { timeout: 10_000 });
      let text = await page.evaluate(() => document.body.innerText);
      expect(text).toContain('can reach');
      expect(text).not.toContain('HAS_SESSION -> OWNS_CRED');
      expect(text).not.toContain('network\napp\ncloud\nidentity');
      expect(text).toContain('All');

      await page.evaluate(() => {
        const summary = [...document.querySelectorAll('summary')]
          .find(candidate => candidate.textContent?.includes('Raw graph details'));
        if (!(summary instanceof HTMLElement)) throw new Error('raw path details missing');
        summary.click();
      });
      text = await page.evaluate(() => document.body.innerText);
      expect(['CAN_REACH', 'HAS_SESSION', 'OWNS_CRED'].some(raw => text.includes(raw))).toBe(true);

      await page.evaluate(() => {
        const button = [...document.querySelectorAll('button')]
          .find(candidate => candidate.textContent?.includes('Inspect Path'));
        if (!(button instanceof HTMLButtonElement)) throw new Error('inspect path button missing');
        button.click();
      });
      await page.waitForFunction(() => location.pathname.endsWith('/graph') && document.body.innerText.includes('Show All'), { timeout: 15_000 });
      text = await page.evaluate(() => document.body.innerText);
      expect(text).toContain('Fit');
      expect(text).not.toContain('Graph renderer is not mounted.');
    } finally {
      await browser.close();
    }
  }, 40_000);
});
