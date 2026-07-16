// ============================================================
// OPSEC visibility (Phase B). OPSEC enforcement is intentionally
// opt-in via `opsec.enabled` — this suite verifies that the engine
// loudly surfaces the configured-but-disabled state so operators
// don't get a false sense of security from a 0.4 noise ceiling
// that isn't actually being checked.
// ============================================================

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, rmSync, unlinkSync } from 'fs';
import { GraphEngine } from '../services/graph-engine.js';
import type { EngagementConfig } from '../types.js';
import { cleanupTestPersistence } from './helpers/cleanup-test-persistence.js';

const TEST_STATE_FILE = './state-test-opsec-visibility.json';
const liveEngines = new Set<GraphEngine>();

function openEngine(opsec: EngagementConfig['opsec']): GraphEngine {
  const engine = new GraphEngine(makeConfig(opsec), TEST_STATE_FILE);
  liveEngines.add(engine);
  return engine;
}

function makeConfig(opsec: EngagementConfig['opsec']): EngagementConfig {
  return {
    id: 'test-opsec-visibility',
    name: 'opsec-visibility test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec,
  };
}

function cleanup(): void {
  for (const engine of liveEngines) engine.dispose();
  liveEngines.clear();
  cleanupTestPersistence(TEST_STATE_FILE);
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-opsec-visibility', { recursive: true, force: true }); } catch {}
}

describe('OPSEC visibility (Phase B)', () => {
  beforeEach(() => { cleanup(); });
  afterEach(() => { cleanup(); });

  it('flags inert OPSEC when max_noise is set but enabled is omitted', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const engine = openEngine({ name: 'pentest', max_noise: 0.4 });
      const status = engine.getOpsecStatus();
      expect(status.enabled).toBe(false);
      expect(status.inert).toBe(true);
      expect(status.configured_fields).toContain('max_noise');

      const warns = warn.mock.calls.flat().map(String).join('\n');
      expect(warns).toMatch(/OPSEC.*inert/);
      expect(warns).toMatch(/max_noise=0\.4/);
      expect(warns).toMatch(/enabled=false/);
    } finally {
      warn.mockRestore();
    }
  });

  it('does not warn when OPSEC is enabled', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const engine = openEngine({
        name: 'pentest',
        enabled: true,
        max_noise: 0.4,
        blacklisted_techniques: ['nmap_aggressive'],
      });
      const status = engine.getOpsecStatus();
      expect(status.enabled).toBe(true);
      expect(status.inert).toBe(false);

      const inertWarns = warn.mock.calls.flat().map(String).filter(s => /OPSEC.*inert/.test(s));
      expect(inertWarns).toHaveLength(0);
    } finally {
      warn.mockRestore();
    }
  });

  it('does not warn when OPSEC has no enforcement fields configured (nothing to be inert about)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      // max_noise: 1 means no ceiling; this is not a "configured but disabled" trap.
      const engine = openEngine({ name: 'ctf', max_noise: 1 });
      const status = engine.getOpsecStatus();
      expect(status.inert).toBe(false);
      expect(status.configured_fields).not.toContain('max_noise');

      const inertWarns = warn.mock.calls.flat().map(String).filter(s => /OPSEC.*inert/.test(s));
      expect(inertWarns).toHaveLength(0);
    } finally {
      warn.mockRestore();
    }
  });

  it('reports opsec_skipped on validateAction when enforcement is inert', () => {
    const engine = openEngine({ name: 'pentest', max_noise: 0.4 });
    const r = engine.validateAction({ technique: 'recon' });
    expect(r.opsec_skipped).toBe(true);
  });

  it('omits opsec_skipped when enforcement is enabled', () => {
    const engine = openEngine({ name: 'pentest', enabled: true, max_noise: 0.4 });
    const r = engine.validateAction({ technique: 'recon' });
    expect(r.opsec_skipped).toBeUndefined();
  });
});
