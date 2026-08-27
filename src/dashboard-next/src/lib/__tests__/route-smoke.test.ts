import { describe, expect, it } from 'vitest';
import puppeteer from 'puppeteer-core';

const smokeUrl = process.env.OVERWATCH_DASHBOARD_SMOKE_URL || '';
const chromePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const ROUTES: Array<{ path: string; canonical: string; expects: string[]; expectsAny?: string[] }> = [
  { path: '/operate', canonical: '/operate', expects: ['Operate', 'Start work', 'Needs you', 'Active', 'Ready'] },
  { path: '/investigate', canonical: '/investigate', expects: ['Investigate', 'Topology', 'Topology controls'] },
  { path: '/review', canonical: '/review', expects: ['Review', 'Readiness', 'Proof library', 'Reports'] },
  { path: '/manage', canonical: '/manage', expects: ['Manage', 'Engagement', 'Settings', 'Diagnostics'] },
  { path: '/overview', canonical: '/operate', expects: ['Operate', 'Start work'] },
  { path: '/actions', canonical: '/operate', expects: ['Operate', 'Needs you'] },
  { path: '/agents', canonical: '/operate', expects: ['Operate', 'Active'] },
  { path: '/activity', canonical: '/operate', expects: ['Operate', 'Activity'], expectsAny: ['No parser data', 'Dropped records', 'Path analysis failed'] },
  { path: '/campaigns', canonical: '/operate', expects: ['Operate', 'Campaigns'] },
  { path: '/sessions', canonical: '/operate', expects: ['Operate', 'Sessions'], expectsAny: ['Attach', 'Detach', 'open_session'] },
  { path: '/frontier', canonical: '/operate', expects: ['Operate', 'Ready'] },
  { path: '/graph', canonical: '/investigate', expects: ['Investigate', 'Topology controls'] },
  { path: '/graph?node=cred-jdoe-ntlm&hops=2', canonical: '/investigate', expects: ['Focused on', 'Fit', 'Show All'] },
  { path: '/graph?context=evidence&node=cred-jdoe-ntlm', canonical: '/investigate', expects: ['Evidence for', 'Fit', 'Show All'] },
  { path: '/graph?context=frontier&node=cred-jdoe-ntlm', canonical: '/investigate', expects: ['Frontier', 'Fit', 'Show All'] },
  { path: '/graph?filter=host', canonical: '/investigate', expects: ['host nodes', 'Fit', 'Show All'] },
  { path: '/identity', canonical: '/investigate', expects: ['Investigate', 'Identity Providers', 'Okta', 'GitHub Actions', 'Benefits Portal', 'MFA'] },
  { path: '/credentials', canonical: '/investigate', expects: ['Investigate', 'Credentials', 'Expansion candidates', 'Expiring soon', 'Expired tokens'] },
  { path: '/paths', canonical: '/investigate', expects: ['Investigate', 'Attack Paths', 'Inspect Path'], expectsAny: ['Fast wins', 'Cloud reach', 'Identity pivots', 'Higher risk'] },
  { path: '/evidence', canonical: '/review', expects: ['Review', 'Proof library', 'Evidence'] },
  { path: '/findings', canonical: '/review', expects: ['Review', 'Readiness', 'Proof ready'] },
  { path: '/findings?item=nonexistent-id', canonical: '/review', expects: ['Review', 'Readiness'] },
  { path: '/sessions?item=nonexistent-id', canonical: '/operate', expects: ['Operate', 'Sessions'] },
  { path: '/smoke', canonical: '/manage', expects: ['Manage', 'Diagnostics', '/api/trust-signals'] },
  { path: '/settings', canonical: '/manage', expects: ['Manage', 'Settings'] },
  { path: '/engagements', canonical: '/manage', expects: ['Manage', 'Engagements'] },
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
        await page.waitForFunction((canonical) => location.pathname.endsWith(canonical), { timeout: 10_000 }, route.canonical);
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
      await page.waitForFunction(() => document.body.innerText.includes('Start work'), { timeout: 10_000 });
      const nav = await page.evaluate(() => {
        const el = document.querySelector('nav');
        const rect = el?.getBoundingClientRect();
        return {
          width: rect?.width || 0,
          text: el?.textContent || '',
        };
      });
      expect(nav.width).toBeGreaterThanOrEqual(200);
      expect(nav.text).toContain('Operate');
      expect(nav.text).toContain('Investigate');
      expect(nav.text).toContain('Review');
      expect(nav.text).toContain('Manage');
      expect(nav.text).not.toContain('Overview');
    } finally {
      await browser.close();
    }
  }, 30_000);

  it('translates scoped evidence links into persistent topology context', async () => {
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
      await page.waitForFunction(() => location.pathname.endsWith('/investigate') && document.body.innerText.includes('Evidence for'), { timeout: 15_000 });
      const text = await page.evaluate(() => document.body.innerText);
      expect(text).toContain('Show All');
      expect(text).not.toContain('Graph renderer is not mounted.');
      const params = await page.evaluate(() => Object.fromEntries(new URLSearchParams(location.search)));
      expect(params).toMatchObject({ lens: 'topology', context: 'evidence', node: 'cred-jdoe-ntlm' });
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
      await page.waitForFunction(() => location.pathname.endsWith('/investigate') && document.body.innerText.includes('Show All'), { timeout: 15_000 });
      text = await page.evaluate(() => document.body.innerText);
      expect(text).toContain('Fit');
      expect(text).not.toContain('Graph renderer is not mounted.');
    } finally {
      await browser.close();
    }
  }, 40_000);
});
