import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createOverwatchApp, shutdownOverwatchApp } from '../app.js';
import { createTestSandbox } from '../test-support/test-sandbox.js';
import type { EngagementConfig } from '../types.js';

const skillDir = resolve('skills');

function config(): EngagementConfig {
  return {
    id: 'in-memory-app',
    name: 'In-memory app',
    created_at: '2026-07-17T00:00:00.000Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 1 },
  };
}

describe('in-memory app artifact ownership', () => {
  it('does not create checkout-relative engagement storage without a config path', async () => {
    const sandbox = createTestSandbox('in-memory-app');
    const originalDirectory = process.cwd();
    process.chdir(sandbox.root);
    const app = createOverwatchApp({
      config: config(),
      stateFilePath: sandbox.path('state.json'),
      skillDir,
      // Construct the dashboard adapter too; it must not infer ./engagement.json.
      dashboardPort: 65_534,
    });
    try {
      expect(existsSync(sandbox.path('engagements'))).toBe(false);
    } finally {
      await shutdownOverwatchApp(app);
      process.chdir(originalDirectory);
    }
  });
});
