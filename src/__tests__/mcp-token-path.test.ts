import { resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { resolveMcpTokenPath } from '../app.js';

const originalConfig = process.env.OVERWATCH_CONFIG;
const originalState = process.env.OVERWATCH_STATE_FILE;
const originalTokenFile = process.env.OVERWATCH_MCP_TOKEN_FILE;

afterEach(() => {
  if (originalConfig === undefined) delete process.env.OVERWATCH_CONFIG;
  else process.env.OVERWATCH_CONFIG = originalConfig;
  if (originalState === undefined) delete process.env.OVERWATCH_STATE_FILE;
  else process.env.OVERWATCH_STATE_FILE = originalState;
  if (originalTokenFile === undefined) delete process.env.OVERWATCH_MCP_TOKEN_FILE;
  else process.env.OVERWATCH_MCP_TOKEN_FILE = originalTokenFile;
});

describe('MCP token path', () => {
  it('stays beside the engagement config when state is stored elsewhere', () => {
    process.env.OVERWATCH_CONFIG = '/tmp/overwatch-config/engagement.json';
    process.env.OVERWATCH_STATE_FILE = '/mnt/large-state/state.json';
    delete process.env.OVERWATCH_MCP_TOKEN_FILE;

    expect(resolveMcpTokenPath()).toBe(
      '/tmp/overwatch-config/.overwatch-mcp-token',
    );
  });

  it('honors an explicit token-file override', () => {
    process.env.OVERWATCH_MCP_TOKEN_FILE = './secrets/mcp-token';
    expect(resolveMcpTokenPath()).toBe(resolve('./secrets/mcp-token'));
  });
});
