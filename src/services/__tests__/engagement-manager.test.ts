import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { EngagementManager } from '../engagement-manager.js';

describe('EngagementManager — engagement ID containment', () => {
  let dir: string;
  let activePath: string;
  let mgr: EngagementManager;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-eng-mgr-'));
    activePath = join(dir, 'engagement.json');
    mgr = new EngagementManager(activePath);
    // Seed one valid engagement so positive lookups still work.
    writeFileSync(
      join(mgr.engagementsDir, 'real-eng.json'),
      JSON.stringify({ id: 'real-eng', name: 'Real', scope: { cidrs: [], domains: [], exclusions: [] } }, null, 2),
    );
    // Seed a tempting target outside engagements/ to prove traversal can't reach it.
    writeFileSync(join(dir, 'secret.json'), JSON.stringify({ id: '../secret', name: 'leak' }));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('getEngagement reads a normal id', () => {
    const got = mgr.getEngagement('real-eng');
    expect(got?.id).toBe('real-eng');
  });

  it.each([
    '../secret',
    '..',
    '.',
    '.hidden',
    'has/slash',
    'has\\backslash',
    'with space',
    'null\u0000byte',
    '',
  ])('getEngagement refuses traversal/invalid id: %j', (id) => {
    expect(mgr.getEngagement(id)).toBeNull();
  });

  it.each(['../secret', 'has/slash', '.', '..'])('updateEngagement refuses traversal/invalid id: %j', (id) => {
    const before = readFileSync(join(dir, 'secret.json'), 'utf-8');
    expect(mgr.updateEngagement(id, { name: 'pwned' })).toBeNull();
    // sibling file untouched
    expect(readFileSync(join(dir, 'secret.json'), 'utf-8')).toBe(before);
  });

  it('does not create an engagements/ file for a rejected id', () => {
    mgr.updateEngagement('../escape', { name: 'x' });
    expect(existsSync(join(mgr.engagementsDir, '../escape.json'))).toBe(false);
  });
});
