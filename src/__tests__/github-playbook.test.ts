// ============================================================
// A.2 — GitHub playbook + 5 new gh-api parsers.
// ============================================================

import { describe, it, expect } from 'vitest';
import { parseGhApiOrgs } from '../services/parsers/gh-api-orgs.js';
import { parseGhApiRepos } from '../services/parsers/gh-api-repos.js';
import { parseGhApiSecrets } from '../services/parsers/gh-api-secrets.js';
import { parseGhApiBranchProtection } from '../services/parsers/gh-api-branch-protection.js';
import { parseGhApiDeployKeys } from '../services/parsers/gh-api-deploy-keys.js';

describe('parseGhApiOrgs', () => {
  it('emits one idp per org and stamps cred_orgs on the source credential', () => {
    const output = JSON.stringify([
      { login: 'acme-corp', id: 1, url: 'https://api.github.com/orgs/acme-corp' },
      { login: 'acme-tools', id: 2 },
    ]);
    const finding = parseGhApiOrgs(output, 'test', { source_credential_id: 'cred-pat-1' } as any);
    const idps = finding.nodes.filter(n => n.type === 'idp');
    expect(idps).toHaveLength(2);
    expect(idps[0].idp_kind).toBe('github_org');
    expect(idps[0].tenant_id).toBe('acme-corp');

    const credUpdate = finding.nodes.find(n => n.id === 'cred-pat-1');
    expect(credUpdate?.cred_orgs).toEqual(['acme-corp', 'acme-tools']);

    const edges = finding.edges.filter(e => e.properties.type === 'AUTHENTICATES_VIA');
    expect(edges).toHaveLength(2);
  });

  it('handles empty array', () => {
    expect(parseGhApiOrgs('[]', 'test').nodes).toHaveLength(0);
  });
});

describe('parseGhApiRepos', () => {
  it('emits idp_application per repo with full metadata + VALID_FOR_APP edges', () => {
    const output = JSON.stringify([
      { full_name: 'acme-corp/webapp', private: true, default_branch: 'main', language: 'TypeScript', archived: false, fork: false, owner: { login: 'acme-corp' } },
    ]);
    const finding = parseGhApiRepos(output, 'test', { source_credential_id: 'cred-pat-1' } as any);
    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps).toHaveLength(1);
    expect(apps[0].repo_full_name).toBe('acme-corp/webapp');
    expect(apps[0].private).toBe(true);
    expect(apps[0].default_branch).toBe('main');
    expect(apps[0].app_kind).toBe('github_repo');

    const edges = finding.edges.filter(e => e.properties.type === 'VALID_FOR_APP');
    expect(edges).toHaveLength(1);
  });
});

describe('parseGhApiSecrets', () => {
  it('emits credential nodes for each secret with fingerprint-only cred_value', () => {
    const output = JSON.stringify({
      total_count: 2,
      secrets: [
        { name: 'DEPLOY_TOKEN', created_at: '2025-01-01T00:00:00Z' },
        { name: 'AWS_ACCESS_KEY_ID', updated_at: '2025-05-01T00:00:00Z' },
      ],
    });
    const finding = parseGhApiSecrets(output, 'test', { repo_full_name: 'acme/webapp' } as any);
    const creds = finding.nodes.filter(n => n.type === 'credential');
    expect(creds).toHaveLength(2);
    expect(creds[0].cred_value).toMatch(/<gh-actions-secret/);
    expect(creds[0].cred_usable_for_auth).toBe(false);
    expect(creds[0].cred_audience).toBe('acme/webapp');

    expect(finding.edges).toHaveLength(2);
    expect(finding.edges[0].properties.type).toBe('OWNS_CRED');
  });
});

describe('parseGhApiBranchProtection', () => {
  it('flags fully unprotected branches as high severity', () => {
    const output = JSON.stringify({ message: 'Branch not protected' });
    const finding = parseGhApiBranchProtection(output, 'test', { repo_full_name: 'acme/webapp', branch_name: 'main' } as any);
    const node = finding.nodes[0];
    expect(node.branch_protection.status).toBe('unprotected');
    expect(node.finding_severity).toBe('high');
    expect(node.branch_protection_gaps.length).toBeGreaterThan(0);
  });

  it('flags partial protection (missing reviews, signatures, admin enforcement) as medium/high', () => {
    const output = JSON.stringify({
      required_status_checks: { strict: false },
      // No required_pull_request_reviews
      enforce_admins: { enabled: false },
      required_signatures: { enabled: false },
    });
    const finding = parseGhApiBranchProtection(output, 'test', { repo_full_name: 'acme/webapp' } as any);
    const node = finding.nodes[0];
    expect(node.branch_protection.status).toBe('weak');
    expect(node.branch_protection_gaps).toContain('admins can bypass protection');
    expect(node.finding_severity).toBe('high');
  });

  it('omits severity stamp when fully protected', () => {
    const output = JSON.stringify({
      required_status_checks: { strict: true, contexts: ['ci'] },
      required_pull_request_reviews: { required_approving_review_count: 2, require_code_owner_reviews: true },
      enforce_admins: { enabled: true },
      required_signatures: { enabled: true },
    });
    const finding = parseGhApiBranchProtection(output, 'test', { repo_full_name: 'acme/webapp' } as any);
    const node = finding.nodes[0];
    expect(node.branch_protection.status).toBe('strong');
    expect(node.finding_severity).toBeUndefined();
  });
});

describe('parseGhApiDeployKeys', () => {
  it('flags read-write deploy keys as high severity, read-only as low', () => {
    const output = JSON.stringify([
      { id: 1, key: 'ssh-rsa AAAA...write', title: 'ci-deploy', read_only: false, created_at: '2025-01-01T00:00:00Z' },
      { id: 2, key: 'ssh-rsa BBBB...readonly', title: 'metrics-readonly', read_only: true },
    ]);
    const finding = parseGhApiDeployKeys(output, 'test', { repo_full_name: 'acme/webapp' } as any);
    const creds = finding.nodes.filter(n => n.type === 'credential');
    expect(creds).toHaveLength(2);
    const writeKey = creds.find(c => (c.label as string).includes('ci-deploy'))!;
    expect(writeKey.finding_severity).toBe('high');
    expect(writeKey.deploy_key_write_access).toBe(true);
    const readKey = creds.find(c => (c.label as string).includes('metrics-readonly'))!;
    expect(readKey.finding_severity).toBe('low');
    expect(readKey.deploy_key_write_access).toBe(false);
  });
});

describe('expand_github_credential plan shape', () => {
  it('produces plan steps with proper parser hints and stamps the credential', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'test', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-gh-playbook.json');
    engine.addNode({
      id: 'cred-pat-1',
      type: 'credential',
      label: 'github-pat-test',
      cred_type: 'token',
      cred_material_kind: 'pat',
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerGithubPlaybookTool } = await import('../tools/github-playbook.js');
    let captured: { content: Array<{ text: string }> } | undefined;
    const fakeServer = {
      registerTool: (_name: string, _meta: unknown, handler: any) => {
        Promise.resolve(handler({ credential_id: 'cred-pat-1', max_repos: 200, include_orgs: true })).then(r => { captured = r; });
      },
    };
    registerGithubPlaybookTool(fakeServer as any, engine);
    await new Promise(r => setTimeout(r, 10));

    expect(captured).toBeDefined();
    const payload = JSON.parse(captured!.content[0].text);
    if (!payload.steps) throw new Error(`unexpected payload: ${JSON.stringify(payload)}`);
    expect(payload.steps[0].command).toContain('/user');
    expect(payload.steps[1].parse_with).toBe('gh-api-orgs');
    expect(payload.steps[2].parse_with).toBe('gh-api-repos');

    expect(engine.getNode('cred-pat-1')?.recon_playbook_invoked_at).toBeDefined();
  });

  it('expands per-repo steps when candidate_repos is provided', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'test2', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-gh-playbook-2.json');
    engine.addNode({
      id: 'cred-pat-2',
      type: 'credential',
      label: 'github-pat-test-2',
      cred_type: 'token',
      cred_material_kind: 'pat',
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerGithubPlaybookTool } = await import('../tools/github-playbook.js');
    let captured: { content: Array<{ text: string }> } | undefined;
    const fakeServer = {
      registerTool: (_name: string, _meta: unknown, handler: any) => {
        Promise.resolve(handler({
          credential_id: 'cred-pat-2',
          max_repos: 200,
          include_orgs: true,
          candidate_repos: ['acme/webapp'],
        })).then(r => { captured = r; });
      },
    };
    registerGithubPlaybookTool(fakeServer as any, engine);
    await new Promise(r => setTimeout(r, 10));

    const payload = JSON.parse(captured!.content[0].text);
    // One pre-expanded repo should yield 4 per-repo steps (secrets,
    // branch-protection, deploy-keys, oidc-customization).
    const perRepo = payload.steps.filter((s: any) => /repos\/acme\/webapp/.test(s.command));
    expect(perRepo).toHaveLength(4);
  });
});
