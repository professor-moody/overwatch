import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const source = readFileSync(new URL('../WorkspaceShell.tsx', import.meta.url), 'utf8');
const runtimeRoot = fileURLToPath(new URL('../../../', import.meta.url));

function runtimeFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (entry.name === '__tests__') return [];
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return runtimeFiles(path);
    return /\.(?:ts|tsx|css)$/.test(entry.name) ? [path] : [];
  });
}

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

  it('keeps the execution console visibly labeled and searchable', () => {
    expect(source).toContain('data-testid="execution-console-rail"');
    expect(source).toContain('aria-label="Execution console"');
    expect(source).toContain("label: 'Activity'");
    expect(source).toContain("label: 'Sessions'");
    expect(source).toContain("label: 'Runs'");
    expect(source).toContain("paletteHint: 'Command history and output'");
  });

  it('keeps em dashes out of dashboard runtime copy', () => {
    const files = [
      ...runtimeFiles(runtimeRoot),
      fileURLToPath(new URL('../../../../index.html', import.meta.url)),
      fileURLToPath(new URL('../../../../../../scripts/demo-dashboard.ts', import.meta.url)),
    ];
    const offenders = files.filter(file => readFileSync(file, 'utf8').includes('\u2014'));
    expect(offenders).toEqual([]);
  });

  it('keeps focus mode local and implements the required Escape ordering', () => {
    expect(source).toContain("type DrawerMode = 'compact' | 'focus'");
    expect(source).toContain("drawerMode === 'focus'");
    expect(source).toContain("setDrawerMode('compact')");
    expect(source).not.toMatch(/set\(['"]drawerMode/);
  });
});
