import { expect, test, type Page } from '@playwright/test';

const dashboardPort = Number.parseInt(process.env.OVERWATCH_BROWSER_PORT ?? '18484', 10);
const recoveryPort = Number.parseInt(process.env.OVERWATCH_BROWSER_RECOVERY_PORT ?? '18485', 10);
const controlPort = Number.parseInt(process.env.OVERWATCH_BROWSER_CONTROL_PORT ?? '18486', 10);
const dashboardBase = `http://127.0.0.1:${dashboardPort}`;
const recoveryBase = `http://127.0.0.1:${recoveryPort}`;
const controlBase = `http://127.0.0.1:${controlPort}`;
const token = process.env.OVERWATCH_BROWSER_TOKEN ?? 'browser-ci-token / encoded';

async function land(page: Page, path: string, base = dashboardBase): Promise<void> {
  const url = new URL(path, base);
  url.searchParams.set('token', token);
  await page.goto(url.toString(), { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Live', { exact: true })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
}

async function expectWorkspaceScreenshot(page: Page, name: string, mask = false): Promise<void> {
  await expect(page).toHaveScreenshot(name, {
    animations: 'disabled',
    caret: 'hide',
    maxDiffPixelRatio: 0.015,
    mask: mask ? [page.locator('canvas')] : [],
    maskColor: '#0a0a0d',
  });
}

test.beforeEach(async ({ request }) => {
  const reset = await request.post(`${controlBase}/reset`);
  expect(reset.ok()).toBe(true);
});

test.describe('workspace visual baselines', () => {
  test('Operate campaign inspector at 1440×900', async ({ page, request }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    const response = await request.get(`${dashboardBase}/api/campaigns`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.ok()).toBe(true);
    const body = await response.json() as { campaigns: Array<{ id: string; name: string }> };
    const campaign = body.campaigns.find(item => item.name === 'Browser draft campaign');
    expect(campaign).toBeTruthy();

    await land(page, `/operate?view=campaigns&kind=campaign&item=${encodeURIComponent(campaign!.id)}`);
    await expect(page.getByLabel('Campaign inspector')).toBeVisible();
    await expectWorkspaceScreenshot(page, 'operate-campaign-1440.png');
  });

  test('Investigate node inspector at 1280×800', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await land(page, '/investigate?lens=topology&entity=node&item=browser-objective-host&node=browser-objective-host&hops=2');
    await expect(page.getByLabel('Host inspector')).toBeVisible();
    await expectWorkspaceScreenshot(page, 'investigate-node-1280.png', true);
  });

  test('Review finding inspector at 1024×768', async ({ page, request }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    const response = await request.get(`${dashboardBase}/api/findings/readiness`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.ok()).toBe(true);
    const body = await response.json() as { findings: Array<{ id: string; readiness: string }> };
    const finding = body.findings[0];
    expect(finding).toBeTruthy();
    await land(page, `/review?view=readiness&readiness=${encodeURIComponent(finding.readiness)}&kind=finding&item=${encodeURIComponent(finding.id)}`);
    await expect(page.getByRole('complementary', { name: 'Finding inspector' })).toBeVisible();
    await expectWorkspaceScreenshot(page, 'review-finding-1024.png');
  });

  test('Manage recovery divergence at 1440×900', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await land(page, '/manage?section=diagnostics', recoveryBase);
    await expect(page.getByText('Configuration reconciliation required', { exact: true }).first()).toBeVisible();
    await expectWorkspaceScreenshot(page, 'manage-recovery-1440.png');
  });
});
