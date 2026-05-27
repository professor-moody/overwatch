import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../_process-runner.js', () => ({
  MAX_TIMEOUT_MS: 4 * 60 * 60 * 1000,
  runInstrumentedProcess: vi.fn(async (_engine, opts) => ({
    content: [{ type: 'text', text: JSON.stringify(opts, null, 2) }],
  })),
}));

import { registerTokenReplayTool } from '../token-replay.js';
import { runInstrumentedProcess } from '../_process-runner.js';

function buildHandlers(credential: Record<string, unknown>) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const engine = {
    getNode: vi.fn((id: string) => id === credential.id ? credential : null),
  };

  registerTokenReplayTool(fakeServer, engine as any);
  return { handlers, engine };
}

describe('validate_token_credential', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses Bearer auth for Okta OIDC/JWT credentials', async () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIn0.signature';
    const { handlers } = buildHandlers({
      id: 'cred-okta-oidc',
      type: 'credential',
      label: 'Okta OIDC token',
      cred_material_kind: 'oidc_access_token',
      cred_type: 'oidc_token',
      cred_value: jwt,
      cred_usable_for_auth: true,
      cred_audience: 'https://example.okta.com',
    });

    await handlers.validate_token_credential({
      credential_id: 'cred-okta-oidc',
      provider: 'okta',
      endpoint: 'https://example.okta.com/api/v1/users/me',
    });

    expect(runInstrumentedProcess).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      binary: 'curl',
      args: expect.arrayContaining([`Authorization: Bearer ${jwt}`]),
      command_repr: expect.not.stringContaining(jwt),
      parse_with: 'token_replay_okta',
    }));
  });

  it('keeps SSWS auth for Okta API tokens', async () => {
    const apiToken = '00exampleoktaapitoken';
    const { handlers } = buildHandlers({
      id: 'cred-okta-ssws',
      type: 'credential',
      label: 'Okta API token',
      cred_material_kind: 'token',
      cred_type: 'token',
      cred_value: apiToken,
      cred_usable_for_auth: true,
      cred_audience: 'https://example.okta.com',
    });

    await handlers.validate_token_credential({
      credential_id: 'cred-okta-ssws',
      provider: 'okta',
      endpoint: 'https://example.okta.com/api/v1/users/me',
    });

    expect(runInstrumentedProcess).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      binary: 'curl',
      args: expect.arrayContaining([`Authorization: SSWS ${apiToken}`]),
      command_repr: expect.not.stringContaining(apiToken),
      parse_with: 'token_replay_okta',
    }));
  });
});
