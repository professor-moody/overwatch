// ============================================================
// A.3 — CI/CD OIDC playbook (expand_oidc_capture).
// ============================================================

import { describe, it, expect } from 'vitest';
import { cloudIdentityId } from '../services/parser-utils.js';

describe('expand_oidc_capture plan shape', () => {
  it('emits one step per inferred-federation cloud_identity target', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'oidc-test', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-oidc-playbook.json');

    // Captured OIDC token from a CI workflow.
    engine.addNode({
      id: 'cred-oidc-1',
      type: 'credential',
      label: 'gha-oidc-prod',
      cred_type: 'token',
      cred_material_kind: 'oidc_access_token',
      cred_audience: 'sts.amazonaws.com',
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);
    engine.addNode({
      id: 'idp-app-gha',
      type: 'idp_application',
      label: 'gha-prod-deploy',
      idp_kind: 'ci_github_actions',
      audience: 'sts.amazonaws.com',
      sub_claim_pattern: 'repo:acme/webapp:ref:refs/heads/main',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);
    const roleArn = 'arn:aws:iam::111122223333:role/PowerUser';
    const roleId = cloudIdentityId(roleArn);
    engine.addNode({
      id: roleId,
      type: 'cloud_identity',
      label: roleArn,
      arn: roleArn,
      principal_type: 'role',
      provider: 'aws',
      cloud_account: '111122223333',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);
    engine.addEdge('idp-app-gha', roleId, {
      type: 'ISSUES_TOKENS_FOR',
      confidence: 0.9,
      discovered_at: '2026-01-01T00:00:00Z',
    } as any);
    engine.addNode({
      id: 'legacy-role', type: 'cloud_identity', label: 'legacy', provider: 'aws',
      arn: 'arn:aws:iam::111:role/Legacy', principal_type: 'role',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    } as any);
    engine.addEdge('idp-app-gha', 'legacy-role', {
      type: 'ISSUES_TOKENS_FOR', confidence: 0.8, discovered_at: '2026-01-01T00:00:00Z',
    } as any);

    const { registerCicdOidcPlaybookTool } = await import('../tools/cicd-oidc-playbook.js');
    let captured: { content: Array<{ text: string }> } | undefined;
    const fakeServer = {
      registerTool: (_name: string, _meta: unknown, handler: any) => {
        Promise.resolve(handler({ credential_id: 'cred-oidc-1', max_targets: 10 })).then(r => { captured = r; });
      },
    };
    registerCicdOidcPlaybookTool(fakeServer as any, engine);
    await new Promise(r => setTimeout(r, 10));

    expect(captured).toBeDefined();
    const payload = JSON.parse(captured!.content[0].text);
    if (!payload.steps) throw new Error(`unexpected payload: ${JSON.stringify(payload)}`);
    expect(payload.candidates_considered).toBe(2);
    expect(payload.eligible_candidates).toBe(1);
    expect(payload.step_count).toBe(1);
    expect(payload.steps[0].tool).toBe('validate_token_credential');
    expect(payload.steps[0].args.target_role_arn).toBe(roleArn);
    expect(payload.steps[0].args.target_cloud_identity_id).toBe(roleId);
    expect(payload.blocked_candidates).toEqual([
      expect.objectContaining({ cloud_identity_id: 'legacy-role' }),
    ]);
  });

  it('returns no_targets hint when no idp_application matches the credential audience', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'oidc-test-2', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-oidc-playbook-2.json');
    engine.addNode({
      id: 'cred-oidc-x',
      type: 'credential',
      label: 'orphan-oidc',
      cred_type: 'token',
      cred_material_kind: 'oidc_access_token',
      cred_audience: 'sts.amazonaws.com',
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerCicdOidcPlaybookTool } = await import('../tools/cicd-oidc-playbook.js');
    let captured: { content: Array<{ text: string }> } | undefined;
    const fakeServer = {
      registerTool: (_name: string, _meta: unknown, handler: any) => {
        Promise.resolve(handler({ credential_id: 'cred-oidc-x', max_targets: 10 })).then(r => { captured = r; });
      },
    };
    registerCicdOidcPlaybookTool(fakeServer as any, engine);
    await new Promise(r => setTimeout(r, 10));

    const payload = JSON.parse(captured!.content[0].text);
    expect(payload.candidates_considered).toBe(0);
    expect(payload.step_count).toBe(0);
    expect(payload.no_targets).toBeDefined();
  });
});
