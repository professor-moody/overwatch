import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerParseOutputTools } from '../parse-output.js';
import { registerRunToolTool } from '../run-tool.js';
import { registerRunBashTool } from '../run-bash.js';
import type { EngagementConfig } from '../../types.js';

function config(): EngagementConfig {
  return {
    id: 'parser-context-public', name: 'Parser context public paths', created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
  };
}

describe('public parser context schemas', () => {
  let dir: string;
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let schemas: Record<string, Record<string, z.ZodTypeAny>>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-parser-context-public-'));
    engine = new GraphEngine(config(), join(dir, 'state.json'));
    handlers = {};
    schemas = {};
    const server = {
      registerTool(name: string, meta: any, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
        schemas[name] = meta.inputSchema;
      },
    } as unknown as McpServer;
    registerParseOutputTools(server, engine);
    registerRunToolTool(server, engine);
    registerRunBashTool(server, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  it.each([
    ['run_tool', 'parser_context'],
    ['run_bash', 'parser_context'],
    ['parse_output', 'context'],
  ] as const)('%s preserves known and extension context at its MCP boundary', (tool, field) => {
    const input = field === 'context'
      ? { tool_name: 'nmap', output: '<nmaprun/>', [field]: {
          source_credential_id: 'cred-1', tenant_id: 'tenant-1', repo_full_name: 'acme/repo',
          branch_name: 'main', cloud_account: '111122223333', target_host: 'host-1',
          provider_extension: { nested: { retained: true } },
        } }
      : tool === 'run_tool'
        ? { binary: 'true', [field]: {
            source_credential_id: 'cred-1', tenant_id: 'tenant-1', repo_full_name: 'acme/repo',
            branch_name: 'main', cloud_account: '111122223333', target_host: 'host-1',
            provider_extension: { nested: { retained: true } },
          } }
        : { command: 'true', [field]: {
            source_credential_id: 'cred-1', tenant_id: 'tenant-1', repo_full_name: 'acme/repo',
            branch_name: 'main', cloud_account: '111122223333', target_host: 'host-1',
            provider_extension: { nested: { retained: true } },
          } };
    const parsed = z.object(schemas[tool]).parse(input) as Record<string, any>;
    expect(parsed[field]).toEqual(input[field]);
  });

  it('parse_output lands Entra identities under the supplied tenant through the public schema', async () => {
    const params = z.object(schemas.parse_output).parse({
      tool_name: 'msgraph-users',
      output: JSON.stringify({ value: [{
        id: 'object-1', displayName: 'Alice', userPrincipalName: 'alice@acme.onmicrosoft.com',
      }] }),
      context: { tenant_id: 'acme.onmicrosoft.com', extension: { retained: true } },
      action_id: 'act-public-parse',
      ingest: true,
    });
    const response = await handlers.parse_output(params);
    const payload = JSON.parse(response.content[0].text);
    expect(response.isError).toBeFalsy();
    expect(payload.parse_outcome).toBe('ok');
    expect(engine.getNodesByType('idp_principal')[0]).toMatchObject({ tenant_id: 'acme.onmicrosoft.com' });
  });
});
