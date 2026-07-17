import { defineConfig } from '@playwright/test';

const dashboardPort = Number.parseInt(process.env.OVERWATCH_BROWSER_PORT ?? '18484', 10);
const recoveryPort = Number.parseInt(process.env.OVERWATCH_BROWSER_RECOVERY_PORT ?? '18485', 10);
const controlPort = Number.parseInt(process.env.OVERWATCH_BROWSER_CONTROL_PORT ?? '18486', 10);
const externallyManagedServer = process.env.OVERWATCH_BROWSER_EXTERNAL_SERVER === '1';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  // The fixture intentionally exercises durable mutations. A retry against an
  // already-reconciled or already-split engagement would conceal state bugs.
  retries: 0,
  timeout: 45_000,
  expect: { timeout: 12_000 },
  reporter: process.env.CI ? [['line']] : [['list']],
  use: {
    baseURL: `http://127.0.0.1:${dashboardPort}`,
    browserName: 'chromium',
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: externallyManagedServer ? undefined : {
    command: 'npm run build && npm run test:browser:server',
    url: `http://127.0.0.1:${controlPort}/health`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      ...process.env,
      OVERWATCH_BROWSER_PORT: String(dashboardPort),
      OVERWATCH_BROWSER_RECOVERY_PORT: String(recoveryPort),
      OVERWATCH_BROWSER_CONTROL_PORT: String(controlPort),
      OVERWATCH_BROWSER_TOKEN: process.env.OVERWATCH_BROWSER_TOKEN ?? 'browser-ci-token / encoded',
    },
  },
  metadata: {
    recoveryBaseURL: `http://127.0.0.1:${recoveryPort}`,
    controlBaseURL: `http://127.0.0.1:${controlPort}`,
  },
});
