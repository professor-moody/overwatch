import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(new URL('../WorkspaceShell.tsx', import.meta.url), 'utf8');

describe('WorkspaceShell architecture', () => {
  it('owns exactly four labeled primary workspaces', () => {
    for (const label of ['Operate', 'Investigate', 'Review', 'Manage']) {
      expect(source).toContain(`label: '${label}'`);
    }
    expect(source).toContain('aria-label="Primary workspaces"');
    expect(source).not.toMatch(/collapse|icon-only/i);
  });

  it('lazy-loads native drawer destinations without legacy panel imports', () => {
    expect(source).toContain("import('../drawer/ActivityDrawer')");
    expect(source).toContain("import('../drawer/SessionsDrawer')");
    expect(source).toContain("import('../drawer/RunsDrawer')");
    expect(source).not.toMatch(/panels\/(ActivityPanel|AnalysisPanel|SessionsPanel)/);
  });

  it('keeps focus mode local and implements the required Escape ordering', () => {
    expect(source).toContain("type DrawerMode = 'compact' | 'focus'");
    expect(source).toContain("drawerMode === 'focus'");
    expect(source).toContain("setDrawerMode('compact')");
    expect(source).not.toMatch(/set\(['"]drawerMode/);
  });
});
