import { describe, expect, it } from 'vitest';
import { parseRetrospectiveArgs } from '../retrospective.js';

describe('retrospective CLI arg parsing', () => {
  it('parses --state with a custom path', () => {
    const result = parseRetrospectiveArgs(['--state', '/custom/path/state.json']);
    expect(result.statePath).toBe('/custom/path/state.json');
  });

  it('returns undefined statePath when --state is omitted', () => {
    const result = parseRetrospectiveArgs(['--config', './my-config.json']);
    expect(result.statePath).toBeUndefined();
  });

  it('parses all flags together', () => {
    const result = parseRetrospectiveArgs([
      '--config', '/etc/overwatch/eng.json',
      '--skills', '/opt/skills',
      '--output', '/tmp/retro-out',
      '--state', '/data/state-eng-1.json',
    ]);
    expect(result.configPath).toBe('/etc/overwatch/eng.json');
    expect(result.skillDir).toBe('/opt/skills');
    expect(result.outputDir).toBe('/tmp/retro-out');
    expect(result.statePath).toBe('/data/state-eng-1.json');
  });

  it('uses defaults when no flags are provided', () => {
    const result = parseRetrospectiveArgs([]);
    expect(result.configPath).toBe(process.env.OVERWATCH_CONFIG || './engagement.json');
    expect(result.skillDir).toBe(process.env.OVERWATCH_SKILLS || './skills');
    expect(result.outputDir).toBe('./retrospective');
    expect(result.statePath).toBeUndefined();
  });

  it('ignores --state when no value follows', () => {
    const result = parseRetrospectiveArgs(['--state']);
    expect(result.statePath).toBeUndefined();
  });
});
