import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { createOverwatchApp, registerAllTools } from '../app.js';

describe('app bootstrap', () => {
  it('creates the core app without binding a transport', () => {
    const app = createOverwatchApp({
      configPath: resolve('./engagement.json'),
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });

    expect(app.server).toBeDefined();
    expect(app.engine).toBeDefined();
    expect(app.sessionManager).toBeDefined();
    expect(app.dashboard).toBeNull();
  });

  it('registers all tools without requiring stdio startup', () => {
    const app = createOverwatchApp({
      configPath: resolve('./engagement.json'),
      skillDir: resolve('./skills'),
      dashboardPort: 0,
    });

    const toolNames: string[] = [];
    const fakeServer = {
      registerTool(name: string) {
        toolNames.push(name);
      },
    } as any;

    registerAllTools(fakeServer, {
      engine: app.engine,
      skills: app.skills,
      processTracker: app.processTracker,
      sessionManager: app.sessionManager,
      getDashboardStatus: () => ({ enabled: false, running: false }),
    });

    expect(toolNames).toHaveLength(34);
    expect(toolNames).toContain('get_state');
    expect(toolNames).toContain('run_retrospective');
    expect(toolNames).toContain('open_session');
    expect(toolNames).toContain('close_session');
  });
});
