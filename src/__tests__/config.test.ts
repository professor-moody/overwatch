import { describe, expect, it } from 'vitest';
import { formatConfigError, parseEngagementConfig } from '../config.js';

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
