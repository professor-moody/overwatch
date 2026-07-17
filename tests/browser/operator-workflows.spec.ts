import { expect, test, type Page } from '@playwright/test';

const dashboardPort = Number.parseInt(process.env.OVERWATCH_BROWSER_PORT ?? '18484', 10);
const recoveryPort = Number.parseInt(process.env.OVERWATCH_BROWSER_RECOVERY_PORT ?? '18485', 10);
const controlPort = Number.parseInt(process.env.OVERWATCH_BROWSER_CONTROL_PORT ?? '18486', 10);
const dashboardBase = `http://127.0.0.1:${dashboardPort}`;
const recoveryBase = `http://127.0.0.1:${recoveryPort}`;
const controlBase = `http://127.0.0.1:${controlPort}`;
const token = 'browser-ci-token / encoded';
const browserSessionId = '00000000-0000-4000-8000-000000000014';
const browserActionId = 'browser-live-action';
const browserErrors = new WeakMap<Page, string[]>();

function withToken(path: string): string {
  const url = new URL(path, dashboardBase);
  url.searchParams.append('token', token);
  return url.toString();
}

async function land(page: Page, path: string, base = dashboardBase): Promise<void> {
  const url = new URL(path, base);
  url.searchParams.append('token', token);
  await page.goto(url.toString(), { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Live', { exact: true })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  browserErrors.set(page, errors);
  page.on('pageerror', error => errors.push(`pageerror: ${error.message}`));
  page.on('console', message => {
    // Chromium reports every 5xx as this URL-free generic console message.
    // The response listener below records the actionable method/path/status.
    if (
      message.type() === 'error'
      && !message.text().startsWith('Failed to load resource:')
    ) {
      errors.push(`console: ${message.text()}`);
    }
  });
  page.on('response', response => {
    if (response.status() < 500) return;
    const url = new URL(response.url());
    // Tape capture is an optional runtime attachment. This fixture deliberately
    // has no tape service, and the dashboard represents that state as 503.
    if (url.pathname === '/api/tape' && response.status() === 503) return;
    errors.push(`http: ${response.request().method()} ${url.pathname} -> ${response.status()}`);
  });
});

test.afterEach(async ({ page }, testInfo) => {
  const errors = browserErrors.get(page) ?? [];
  if (errors.length > 0) {
    await testInfo.attach('browser-errors.txt', {
      body: Buffer.from(errors.join('\n'), 'utf8'),
      contentType: 'text/plain',
    });
  }
  expect.soft(errors, 'unexpected browser runtime errors').toEqual([]);
});

test.describe('dashboard operator journeys', () => {
  test('captures and scrubs remote tokens while authenticating HTTP and WebSockets', async ({ page }) => {
    const authorizationHeaders: string[] = [];
    const websocketUrls: string[] = [];
    page.on('request', request => {
      if (new URL(request.url()).pathname.startsWith('/api/')) {
        authorizationHeaders.push(request.headers().authorization ?? '');
      }
    });
    page.on('websocket', socket => websocketUrls.push(socket.url()));

    const landing = new URL('/overview?keep=1#retained', dashboardBase);
    landing.searchParams.append('token', 'stale-token');
    landing.searchParams.append('token', token);
    await page.goto(landing.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Live', { exact: true })).toBeVisible();

    const visible = new URL(page.url());
    expect(visible.pathname).toBe('/overview');
    expect(visible.searchParams.get('keep')).toBe('1');
    expect(visible.searchParams.has('token')).toBe(false);
    expect(visible.hash).toBe('#retained');
    expect(await page.evaluate(() => sessionStorage.getItem('overwatch.dashboard.token'))).toBe(token);
    await expect.poll(() => authorizationHeaders).toContain(`Bearer ${token}`);

    // Exercise the actual component-owned session and action-output channels;
    // this protects browser transport wiring as well as the server handshake.
    await page.goto(`${dashboardBase}/sessions?item=${encodeURIComponent(browserSessionId)}`, {
      waitUntil: 'domcontentloaded',
    });
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible();
    await expect.poll(() => websocketUrls.some(url => (
      new URL(url).pathname === `/ws/session/${browserSessionId}`
    ))).toBe(true);

    await page.goto(`${dashboardBase}/analysis?item=${encodeURIComponent(browserActionId)}`, {
      waitUntil: 'domcontentloaded',
    });
    await expect(page.getByRole('heading', { name: 'Analysis' })).toBeVisible();
    await expect.poll(() => websocketUrls.some(url => (
      new URL(url).pathname === `/ws/actions/${browserActionId}/output`
    ))).toBe(true);

    for (const expectedPath of [
      '/ws',
      `/ws/session/${browserSessionId}`,
      `/ws/actions/${browserActionId}/output`,
    ]) {
      const socketUrl = websocketUrls.find(url => new URL(url).pathname === expectedPath);
      expect(socketUrl, `${expectedPath} socket opened`).toBeTruthy();
      expect(new URL(socketUrl!).searchParams.get('token')).toBe(token);
    }
  });

  test('edits, clones, deep-links, and splits campaigns through real responses', async ({ page, request }) => {
    const response = await request.get(`${dashboardBase}/api/campaigns`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.ok()).toBe(true);
    const body = await response.json() as { campaigns: Array<{ id: string; name: string }> };
    const draft = body.campaigns.find(campaign => campaign.name === 'Browser draft campaign');
    const parent = body.campaigns.find(campaign => campaign.name === 'Browser split parent');
    expect(draft).toBeTruthy();
    expect(parent).toBeTruthy();

    await land(page, `/campaigns?item=${encodeURIComponent(draft!.id)}`);
    await expect(page.getByRole('heading', { name: 'Browser draft campaign' })).toBeVisible();
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByRole('textbox', { name: 'Campaign name' }).fill('Browser draft edited');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('heading', { name: 'Browser draft edited' })).toBeVisible();
    await page.getByRole('button', { name: 'Clone' }).click();
    await expect(page.getByText('Browser draft edited (copy)', { exact: true }).first()).toBeVisible();

    await page.goto(withToken(`/campaigns?item=${encodeURIComponent(parent!.id)}`), { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Live', { exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Browser split parent' })).toBeVisible();
    await page.getByRole('spinbutton', { name: 'Campaign child count' }).fill('2');
    await page.getByRole('button', { name: 'Split', exact: true }).click();
    await expect(page.getByRole('heading', { name: /Child Campaigns/ })).toBeVisible();
    await expect(page.getByText(/Browser split parent \(1\/2\)/).first()).toBeVisible();
    await expect(page.getByText(/Browser split parent \(2\/2\)/).first()).toBeVisible();
  });

  test('round-trips objectives and resolves graph deep links', async ({ page }) => {
    await land(page, '/settings');
    await expect(page.getByText('Reach the browser journey objective', { exact: true })).toBeVisible();
    await page.getByRole('checkbox', {
      name: 'Mark objective Reach the browser journey objective achieved',
    }).click();
    await expect(page.getByRole('checkbox', {
      name: 'Mark objective Reach the browser journey objective incomplete',
    })).toBeChecked();

    await page.goto(withToken('/graph?node=browser-objective-host&hops=2'), {
      waitUntil: 'domcontentloaded',
    });
    await expect(page.getByText('Focused on', { exact: false })).toBeVisible();
    await expect(page.getByText('Browser Objective Host', { exact: false }).first()).toBeVisible();
    const visible = new URL(page.url());
    // Graph target parameters are one-shot commands: a successful focus consumes
    // them, while the selected node remains visible in the inspector/banner.
    expect(visible.pathname).toBe('/graph');
    expect(visible.searchParams.get('node')).toBeNull();
    expect(visible.searchParams.get('hops')).toBeNull();
    expect(visible.searchParams.has('token')).toBe(false);
  });

  test('prepares a durable playbook retry without executing it in the browser', async ({ page }) => {
    await land(page, '/credentials?item=browser-credential');
    await expect(page.getByRole('button', { name: 'Collapse credential Browser CI credential' })).toBeVisible();
    await expect(page.getByText('Browser credential validation', { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Prepare retry' }).click();
    await expect(page.getByText('Execution descriptor prepared', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Release claim' })).toBeVisible();
    await page.getByRole('button', { name: 'Release claim' }).click();
    await expect(page.getByRole('button', { name: 'Release claim' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Prepare retry' })).toBeVisible();
    await expect(page.getByText(/Attempts:.*interrupted/)).toBeVisible();
  });

  test('reconnects through a fresh full state after a socket loss', async ({ page, request }) => {
    const websocketUrls: string[] = [];
    page.on('websocket', socket => websocketUrls.push(socket.url()));
    await land(page, '/overview');
    const nodesValue = page.getByText('Nodes', { exact: true }).locator('..').locator('span').first();
    const initialNodes = Number.parseInt((await nodesValue.textContent()) ?? '0', 10);

    const changed = await request.post(`${controlBase}/drop-main-ws`);
    expect(changed.ok()).toBe(true);
    const mutation = await changed.json() as { total_nodes: number };
    expect(mutation.total_nodes).toBe(initialNodes + 1);

    await expect.poll(() => websocketUrls.filter(url => new URL(url).pathname === '/ws').length)
      .toBeGreaterThanOrEqual(2);
    await expect(page.getByText('Live', { exact: true })).toBeVisible();
    await expect(nodesValue).toHaveText(String(mutation.total_nodes));
    expect(websocketUrls.every(url => new URL(url).searchParams.get('token') === token)).toBe(true);
  });

  test('shows config divergence and reconciles with durable state', async ({ page }) => {
    page.on('dialog', dialog => void dialog.accept());
    await land(page, '/settings', recoveryBase);
    await expect(page.getByRole('heading', { name: /Recovery and configuration ownership/ })).toBeVisible();
    await expect(page.getByText('Configuration reconciliation required', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('Writable', { exact: true }).locator('..')).toContainText('no');
    await page.getByRole('button', { name: 'Use durable state' }).click();
    await expect(page.getByText('Writable', { exact: true }).locator('..')).toContainText('yes');
    await expect(page.getByRole('button', { name: 'Use durable state' })).toHaveCount(0);
    await expect(page.locator('input[value="Browser Recovery Engagement"]')).toBeVisible();
  });
});
