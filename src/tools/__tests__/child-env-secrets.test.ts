import { describe, it, expect, afterEach } from 'vitest';
import { buildChildEnv } from '../_process-runner.js';

describe('buildChildEnv secret isolation', () => {
  const saved: Record<string, string | undefined> = {};
  function setEnv(k: string, v: string) { saved[k] = process.env[k]; process.env[k] = v; }
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  });

  it('strips OVERWATCH server secrets from tool/child env', () => {
    setEnv('OVERWATCH_MCP_TOKEN', 'master-token');
    setEnv('OVERWATCH_DASHBOARD_TOKEN', 'dash-token');
    setEnv('OVERWATCH_CHECKPOINT_SIGNING_KEY', 'signing-key');
    const env = buildChildEnv(undefined);
    expect(env.OVERWATCH_MCP_TOKEN).toBeUndefined();
    expect(env.OVERWATCH_DASHBOARD_TOKEN).toBeUndefined();
    expect(env.OVERWATCH_CHECKPOINT_SIGNING_KEY).toBeUndefined();
  });

  it('strips a future OVERWATCH_*-prefixed secret-looking var (defensive pattern)', () => {
    setEnv('OVERWATCH_FUTURE_API_TOKEN', 'x');
    setEnv('OVERWATCH_SOMETHING_SECRET', 'y');
    const env = buildChildEnv(undefined);
    expect(env.OVERWATCH_FUTURE_API_TOKEN).toBeUndefined();
    expect(env.OVERWATCH_SOMETHING_SECRET).toBeUndefined();
  });

  it('still passes through genuine tool credentials (not OVERWATCH-prefixed)', () => {
    setEnv('AWS_SECRET_ACCESS_KEY', 'aws-secret');
    setEnv('AWS_ACCESS_KEY_ID', 'aws-id');
    const env = buildChildEnv(undefined);
    expect(env.AWS_SECRET_ACCESS_KEY).toBe('aws-secret');
    expect(env.AWS_ACCESS_KEY_ID).toBe('aws-id');
  });

  it('caller-supplied extra env still overrides/passes through', () => {
    const env = buildChildEnv({ MY_TOOL_FLAG: '1' });
    expect(env.MY_TOOL_FLAG).toBe('1');
  });
});
