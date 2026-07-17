import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(
  new URL('../OperatorLayout.tsx', import.meta.url),
  'utf8',
);

const PANEL_IDS = [
  'overview',
  'campaigns',
  'agents',
  'sessions',
  'actions',
  'frontier',
  'activity',
  'analysis',
  'evidence',
  'identity',
  'credentials',
  'recon',
  'paths',
  'findings',
  'engagements',
  'smoke',
  'settings',
] as const;

describe('OperatorLayout panel boundaries', () => {
  it('lazy-loads every top-level panel without static panel imports', () => {
    expect(source).not.toMatch(/import\s+\{[^}]+Panel[^}]*\}\s+from\s+['"]\.\.\/panels\//);
    expect(source.match(/lazy\(\(\) => import\(['"]\.\.\/panels\//g)).toHaveLength(PANEL_IDS.length);
    for (const panelId of PANEL_IDS) {
      expect(source).toMatch(new RegExp(`\\b${panelId}:\\s*lazy\\(`));
    }
  });

  it('renders lazy panels inside loading and error boundaries', () => {
    expect(source).toContain('<ErrorBoundary fallbackLabel={activePanel}>');
    expect(source).toContain('<Suspense fallback={<PanelLoading panel={activePanel} />}>');
  });
});
