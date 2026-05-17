import { describe, expect, it, afterEach } from 'vitest';
import { existsSync } from 'fs';
import { resolve } from 'path';
import { spawnSync } from 'child_process';
import { formatConfigError, parseEngagementConfig, listTemplates, loadTemplate, mergeTemplateWithConfig } from '../config.js';
import { loadConfig } from '../app.js';

const VALID_CONFIG = JSON.stringify({
  id: 'eng-1',
  name: 'Test Engagement',
  created_at: '2026-03-21T00:00:00Z',
  scope: {
    cidrs: ['10.10.10.0/24'],
    domains: ['test.local'],
    exclusions: [],
  },
  objectives: [{
    id: 'obj-1',
    description: 'Get DA',
    achieved: false,
  }],
  opsec: {
    name: 'pentest',
    max_noise: 0.7,
  },
});

describe('engagement config validation', () => {
  it('parses a valid engagement config', () => {
    const config = parseEngagementConfig(VALID_CONFIG);
    expect(config.id).toBe('eng-1');
    expect(config.scope.domains).toEqual(['test.local']);
  });

  it('preserves redacted session-scoped postgres DSN metadata', () => {
    const raw = {
      ...JSON.parse(VALID_CONFIG),
      postgres_dsn: 'postgresql://operator:[redacted]@localhost:5432/msf',
    };
    const config = parseEngagementConfig(JSON.stringify(raw));
    expect(config.postgres_dsn).toBe('postgresql://operator:[redacted]@localhost:5432/msf');
  });

  it('fails fast on invalid config shape with actionable paths', () => {
    let thrown: unknown;

    try {
      parseEngagementConfig(JSON.stringify({
        id: 'eng-1',
        name: 'Broken Engagement',
        created_at: '2026-03-21T00:00:00Z',
        scope: {
          cidrs: '10.10.10.0/24',
          domains: ['test.local'],
          exclusions: [],
        },
        objectives: [],
        opsec: {
          name: 'pentest',
          max_noise: 1.5,
        },
      }));
    } catch (error) {
      thrown = error;
    }

    const message = formatConfigError(thrown, 'inline-config');
    expect(message).toContain('scope.cidrs');
    expect(message).toContain('opsec.max_noise');
  });

  it('reports malformed JSON cleanly', () => {
    let thrown: unknown;

    try {
      parseEngagementConfig('{ invalid json');
    } catch (error) {
      thrown = error;
    }

    expect(formatConfigError(thrown, 'inline-config')).toContain('Invalid JSON');
  });
});

describe('loadConfig', () => {
  const originalBootstrap = process.env.OVERWATCH_BOOTSTRAP;

  afterEach(() => {
    if (originalBootstrap === undefined) {
      delete process.env.OVERWATCH_BOOTSTRAP;
    } else {
      process.env.OVERWATCH_BOOTSTRAP = originalBootstrap;
    }
  });

  it('throws when config file is missing and OVERWATCH_BOOTSTRAP is not set', () => {
    delete process.env.OVERWATCH_BOOTSTRAP;
    expect(() => loadConfig('/tmp/nonexistent-overwatch-config.json')).toThrow('Engagement config not found');
  });

  it('creates default config when OVERWATCH_BOOTSTRAP=1', () => {
    process.env.OVERWATCH_BOOTSTRAP = '1';
    const config = loadConfig('/tmp/nonexistent-overwatch-config.json');
    expect(config.name).toBe('default-engagement');
    expect(config.scope.cidrs).toEqual([]);
  });
});

describe('engagement templates', () => {
  it('lists all available templates', () => {
    const templates = listTemplates();
    expect(templates.length).toBeGreaterThanOrEqual(6);
    const ids = templates.map(t => t.id);
    expect(ids).toContain('internal-pentest');
    expect(ids).toContain('external-assessment');
    expect(ids).toContain('red-team');
    expect(ids).toContain('cloud-assessment');
    expect(ids).toContain('assumed-breach');
    expect(ids).toContain('ctf');
  });

  it('loads a specific template by id', () => {
    const template = loadTemplate('internal-pentest');
    expect(template).not.toBeNull();
    expect(template!.name).toBe('Internal Penetration Test');
    expect(template!.profile).toBe('goad_ad');
    expect(template!.recommended_skills.length).toBeGreaterThan(0);
  });

  it('returns null for unknown template', () => {
    expect(loadTemplate('nonexistent-template')).toBeNull();
  });

  it('merges template with overrides into valid config', () => {
    const template = loadTemplate('internal-pentest')!;
    const config = mergeTemplateWithConfig(template, {
      id: 'eng-test-1',
      name: 'My Internal Test',
      created_at: '2026-03-21T00:00:00Z',
      scope: { cidrs: ['10.0.0.0/8'], domains: ['corp.local'], exclusions: [] },
    });
    expect(config.id).toBe('eng-test-1');
    expect(config.name).toBe('My Internal Test');
    expect(config.template).toBe('internal-pentest');
    expect(config.scope.cidrs).toEqual(['10.0.0.0/8']);
    expect(config.opsec.max_noise).toBe(0.7);
  });

  it('override opsec takes precedence over template', () => {
    const template = loadTemplate('ctf')!;
    const config = mergeTemplateWithConfig(template, {
      id: 'eng-test-2',
      name: 'Custom CTF',
      created_at: '2026-03-21T00:00:00Z',
      opsec: { name: 'lab', max_noise: 0.5 },
    });
    expect(config.opsec.max_noise).toBe(0.5);
  });
});

// =============================================
// Built-dist smoke test (Phase G regression)
// =============================================
//
// vitest runs TS sources through its own transformer, so a CommonJS
// `__dirname` reference in src/config.ts can pass tests but blow up the
// real ESM build with `ReferenceError: __dirname is not defined`. This
// test loads the actual compiled output and calls listTemplates() to
// confirm dist/config.js works end-to-end.
describe('built dist smoke (config.js)', () => {
  const distConfig = resolve('./dist/config.js');
  const hasDist = existsSync(distConfig);
  const t = hasDist ? it : it.skip;

  t('compiled config.js loads templates without ReferenceError', () => {
    const r = spawnSync(process.execPath, [
      '--input-type=module',
      '-e',
      `import('${distConfig}').then(m => { const ts = m.listTemplates(); console.log(JSON.stringify({ count: ts.length, ids: ts.map(t => t.id) })); }).catch(e => { console.error(e && e.message ? e.message : String(e)); process.exit(1); });`,
    ], { encoding: 'utf-8' });
    expect(r.status, `stderr: ${r.stderr}`).toBe(0);
    const out = JSON.parse(r.stdout.trim());
    expect(out.count).toBeGreaterThanOrEqual(6);
    expect(out.ids).toContain('internal-pentest');
  });
});
