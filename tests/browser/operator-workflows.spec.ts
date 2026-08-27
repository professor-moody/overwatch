import { expect, test, type Page } from '@playwright/test';

const dashboardPort = Number.parseInt(process.env.OVERWATCH_BROWSER_PORT ?? '18484', 10);
const recoveryPort = Number.parseInt(process.env.OVERWATCH_BROWSER_RECOVERY_PORT ?? '18485', 10);
const controlPort = Number.parseInt(process.env.OVERWATCH_BROWSER_CONTROL_PORT ?? '18486', 10);
const dashboardBase = `http://127.0.0.1:${dashboardPort}`;
const recoveryBase = `http://127.0.0.1:${recoveryPort}`;
const controlBase = `http://127.0.0.1:${controlPort}`;
const token = process.env.OVERWATCH_BROWSER_TOKEN ?? 'browser-ci-token / encoded';
const browserSessionId = '00000000-0000-4000-8000-000000000014';
const browserActionId = 'browser-live-action';
const browserSuccessActionId = 'act_browser-success-action';
const browserFailureActionId = 'act_browser-failure-action';
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

test.beforeEach(async ({ page, request }) => {
  const reset = await request.post(`${controlBase}/reset`);
  expect(reset.ok()).toBe(true);
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
  test('stays usable when browser storage property access is denied', async ({ page }) => {
    await page.addInitScript(() => {
      for (const key of ['localStorage', 'sessionStorage'] as const) {
        Object.defineProperty(window, key, {
          configurable: true,
          get() { throw new DOMException(`${key} denied`, 'SecurityError'); },
        });
      }
    });

    await page.goto(withToken('/agents'), { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Live', { exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.has('token')).toBe(false);
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('dialog', { name: 'Command palette' })).toBeVisible();
    await page.getByRole('textbox', { name: 'Search workspaces and engagement entities' }).fill('Investigate');
    await page.getByRole('option', { name: /Investigate/ }).click();
    await expect(page).toHaveURL(/\/investigate$/);
    await expect(page.getByText('Nodes', { exact: true }).locator('..')).toContainText('12');
    await page.getByTitle('More graph controls').click();
    await page.getByText('Reset positions', { exact: true }).click();
    await expect(page.getByText('Positions reset', { exact: true })).toBeVisible();
    await page.keyboard.press('Control+k');
    await page.getByRole('textbox', { name: 'Search workspaces and engagement entities' }).fill('Operate');
    await page.getByRole('option', { name: /Operate/ }).click();
    await page.keyboard.press('Control+k');
    await page.getByRole('textbox', { name: 'Search workspaces and engagement entities' }).fill('Investigate');
    await page.getByRole('option', { name: /Investigate/ }).click();
    await expect(page.getByText('Nodes', { exact: true }).locator('..')).toContainText('12');
  });

  test('stays usable when browser storage methods throw', async ({ page }) => {
    await page.addInitScript(() => {
      for (const method of ['getItem', 'setItem', 'removeItem'] as const) {
        Object.defineProperty(Storage.prototype, method, {
          configurable: true,
          value() { throw new DOMException(`${method} denied`, 'SecurityError'); },
        });
      }
    });

    await page.goto(withToken('/agents'), { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Live', { exact: true })).toBeVisible();
    await page.keyboard.press('Control+k');
    await page.getByRole('textbox', { name: 'Search workspaces and engagement entities' }).fill('Investigate');
    await page.getByRole('option', { name: /Investigate/ }).click();
    await expect(page).toHaveURL(/\/investigate$/);
    await expect(page.getByText('Nodes', { exact: true }).locator('..')).toContainText('12');
  });

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
    expect(visible.pathname).toBe('/operate');
    expect(visible.searchParams.get('keep')).toBe('1');
    expect(visible.searchParams.has('token')).toBe(false);
    expect(visible.hash).toBe('#retained');
    expect(await page.evaluate(() => sessionStorage.getItem('overwatch.dashboard.token'))).toBe(token);
    await expect.poll(() => authorizationHeaders).toContain(`Bearer ${token}`);

    // Exercise the actual component-owned session and action-output channels;
    // this protects browser transport wiring as well as the server handshake.
    await page.goto(`${dashboardBase}/operate?drawer=sessions&drawerItem=${encodeURIComponent(browserSessionId)}`, {
      waitUntil: 'domcontentloaded',
    });
    await expect(page.getByText('Browser journey terminal', { exact: true }).first()).toBeVisible();
    await page.getByRole('button', { name: 'Attach terminal' }).click();
    await expect.poll(() => websocketUrls.some(url => (
      new URL(url).pathname === `/ws/session/${browserSessionId}`
    ))).toBe(true);

    await page.goto(`${dashboardBase}/operate?drawer=run&drawerItem=${encodeURIComponent(browserActionId)}`, {
      waitUntil: 'domcontentloaded',
    });
    await expect(page.getByText('Browser journey live output.', { exact: false })).toBeVisible();
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
    await land(page, '/manage?section=engagement');
    await expect(page.getByText('Reach the browser journey objective', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Mark achieved' }).click();
    await expect(page.getByRole('button', { name: 'Reopen' })).toBeVisible();

    await page.goto(withToken('/graph?node=browser-objective-host&hops=2'), {
      waitUntil: 'domcontentloaded',
    });
    await expect(page.getByText('Focused on', { exact: false })).toBeVisible();
    const inspector = page.getByRole('complementary', { name: 'Host inspector' });
    await expect(inspector).toBeVisible();
    await expect(inspector.getByText('10.44.0.10', { exact: true }).first()).toBeVisible();
    const visible = new URL(page.url());
    // Canonical route state remains shareable after legacy graph translation.
    expect(visible.pathname).toBe('/investigate');
    expect(visible.searchParams.get('lens')).toBe('topology');
    expect(visible.searchParams.get('node')).toBe('browser-objective-host');
    expect(visible.searchParams.get('hops')).toBe('2');
    expect(visible.searchParams.has('token')).toBe(false);
  });

  test('prepares a durable playbook retry without executing it in the browser', async ({ page }) => {
    await land(page, '/investigate?lens=credentials&kind=credential&item=browser-credential&tab=actions');
    const inspector = page.getByRole('complementary', { name: 'Credential inspector' });
    await expect(inspector).toBeVisible();
    await expect(inspector.getByText('Browser credential validation', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Prepare retry' }).click();
    await expect(page.getByText('Execution descriptor prepared', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Release claim' })).toBeVisible();
    await page.getByRole('button', { name: 'Release claim' }).click();
    await expect(page.getByRole('button', { name: 'Release claim' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Prepare retry' })).toBeVisible();
    await expect(inspector.getByText('interrupted', { exact: true }).first()).toBeVisible();
  });

  test('reconnects through a fresh full state after a socket loss', async ({ page, request }) => {
    const websocketUrls: string[] = [];
    page.on('websocket', socket => websocketUrls.push(socket.url()));
    await land(page, '/overview');
    const nodesValue = page.getByTestId('asset-count');
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
    await land(page, '/manage?section=diagnostics', recoveryBase);
    await expect(page.getByRole('heading', { name: 'Recovery and configuration convergence' })).toBeVisible();
    await expect(page.getByText('Configuration reconciliation required', { exact: true }).first()).toBeVisible();
    await page.getByRole('button', { name: 'Use durable state' }).click();
    await expect(page.getByRole('button', { name: 'Use durable state' })).toHaveCount(0);
    await expect(page.getByText('No recovery action required.', { exact: true }).first()).toBeVisible();
  });

  test('renders the four-workspace shell and the consolidated review queue', async ({ page }) => {
    await land(page, '/overview');
    await expect(page).toHaveURL(/\/operate/);
    await expect(page.getByRole('heading', { name: 'Operate' })).toBeVisible();
    const primary = page.getByRole('navigation', { name: 'Primary workspaces' });
    await expect(primary.getByRole('button')).toHaveCount(4);
    for (const name of ['Operate', 'Investigate', 'Review', 'Manage']) {
      await expect(primary.getByRole('button', { name: new RegExp(`^${name}`) })).toBeVisible();
    }
    await expect(page.getByRole('tab', { name: /Needs you/ })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Active/ })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Ready/ })).toBeVisible();

    await land(page, '/review?view=proof');
    await expect(page.getByRole('textbox', { name: 'Search proof' })).toBeVisible();
    await expect(page.getByText('4 proof records', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: /Browser fixture successful command started/ })).toBeVisible();
  });

  test('keeps command output beside Activity and preserves action context in Runs', async ({ page }) => {
    await land(page, `/operate?view=attention&drawer=activity&drawerItem=${browserSuccessActionId}`);
    await expect(page.getByText('nmap -sV 10.44.0.10', { exact: true })).toBeVisible();
    await expect(page.getByText('Browser fixture command completed.', { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.getByText('Browser fixture durable tail reached.', { exact: false })).toBeAttached();

    await page.getByRole('button', { name: 'Runs', exact: true }).click();
    expect(new URL(page.url()).searchParams.get('drawerItem')).toBe(browserSuccessActionId);
    await expect(page.getByText('Browser fixture command completed.', { exact: false })).toBeVisible();

    await page.goto(withToken(`/operate?view=history&drawer=run&drawerItem=${browserFailureActionId}`), { waitUntil: 'domcontentloaded' });
    await page.getByRole('tab', { name: 'stderr', exact: true }).click();
    await expect(page.getByText('target rejected the test connection', { exact: false })).toBeVisible();

    await page.getByRole('button', { name: 'Focus drawer' }).click();
    await expect(page.locator('[data-drawer-mode="focus"]')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('[data-drawer-mode="compact"]')).toBeVisible();
    expect(new URL(page.url()).searchParams.get('drawer')).toBe('run');
  });

  test('keeps labeled navigation, avoids horizontal overflow, and switches inspector mode at 1280px', async ({ page, request }) => {
    const findingsResponse = await request.get(`${dashboardBase}/api/findings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(findingsResponse.ok()).toBe(true);
    const findingBody = await findingsResponse.json() as { findings: Array<{ id: string }> };
    expect(findingBody.findings.length).toBeGreaterThan(0);
    const target = findingBody.findings[0].id;

    for (const viewport of [
      { width: 1440, height: 900, inspectorPosition: 'static' },
      { width: 1280, height: 800, inspectorPosition: 'static' },
      { width: 1024, height: 768, inspectorPosition: 'fixed' },
    ] as const) {
      await page.setViewportSize(viewport);
      await land(page, `/review?view=readiness&kind=finding&item=${encodeURIComponent(target)}&drawer=activity`);

      const primary = page.getByRole('navigation', { name: 'Primary workspaces' });
      for (const label of ['Operate', 'Investigate', 'Review', 'Manage']) {
        await expect(primary.getByRole('button', { name: new RegExp(`^${label}`) })).toBeVisible();
      }
      await expect(page.locator('.workspace-inspector')).toBeVisible();
      expect(await page.locator('.workspace-inspector').evaluate(element => getComputedStyle(element).position))
        .toBe(viewport.inspectorPosition);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(viewport.width);
      expect(await page.evaluate(() => document.body.scrollWidth)).toBe(viewport.width);
    }

    // At overlay widths Escape closes the transient inspector first, preserving
    // the independently-targeted drawer, then closes the drawer on the next press.
    await page.keyboard.press('Escape');
    await expect(page.locator('.workspace-inspector')).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get('drawer')).toBe('activity');
    await page.keyboard.press('Escape');
    expect(new URL(page.url()).searchParams.has('drawer')).toBe(false);
  });

  test('never indexes or persists credential material in workspace navigation', async ({ page }) => {
    const credentialId = 'browser-credential';
    const credentialValue = 'browser-ci-redacted';
    await land(page, `/investigate?lens=credentials&kind=credential&item=${encodeURIComponent(credentialId)}`);
    expect(decodeURIComponent(page.url())).not.toContain(credentialValue);
    await page.keyboard.press('Control+k');
    await page.getByRole('textbox', { name: 'Search workspaces and engagement entities' }).fill(credentialValue);
    await expect(page.getByText('No matches', { exact: true })).toBeVisible();

    const stored = await page.evaluate(() => {
      const values: string[] = [];
      for (const storage of [localStorage, sessionStorage]) {
        for (let index = 0; index < storage.length; index += 1) {
          const key = storage.key(index);
          if (key) values.push(`${key}=${storage.getItem(key)}`);
        }
      }
      return values.join('\n');
    });
    expect(stored).not.toContain(credentialValue);
    expect((browserErrors.get(page) ?? []).join('\n')).not.toContain(credentialValue);
  });

  test('corrects a claim from the node drawer and surfaces it as evidence debt', async ({ page }) => {
    // The deep-link opens the graph with the objective host selected → its inspector drawer.
    await page.goto(withToken('/graph?node=browser-objective-host&hops=2'), { waitUntil: 'domcontentloaded' });
    // Wait on the drawer's Claim-standing section directly (the graph page's connection banner
    // renders differently than the panel views after a direct deep-link goto).
    await expect(page.getByRole('heading', { name: 'Claim standing' })).toBeVisible();

    // Refute a confidence-1.0 (evidence-positive) node → a promotion-vs-evidence contradiction,
    // committed through the real POST /api/claims/promote command path: select the state, give a
    // reason, then a single Apply.
    await page.getByRole('button', { name: 'Refuted' }).click();
    await page.getByLabel('Claim judgment reason').fill('browser journey: disputing this host');
    await page.getByRole('button', { name: 'Apply refuted' }).click();
    await expect(page.getByText(/Promoted to refuted/)).toBeVisible();

    // The contradiction now appears in Review's proof workspace.
    await land(page, '/review?view=proof');
    await expect(page.getByText(/promoted refuted, but its evidence is positive/)).toBeVisible();
  });
});
