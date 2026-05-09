// ============================================================
// A.1 — AWS playbook + parsers.
//
// `expand_aws_credential` returns a structured recon plan; its
// per-step parsers ingest cli output into the graph. Together they let
// an operator run "given AWS creds, enumerate the account" end-to-end
// without re-deriving the canonical chain each engagement.
// ============================================================

import { describe, it, expect } from 'vitest';
import { parseAwsStsIdentity } from '../services/parsers/aws-sts-identity.js';
import { parseAwsIamSummary } from '../services/parsers/aws-iam-summary.js';

describe('parseAwsStsIdentity', () => {
  it('emits cloud_identity + OWNS_CRED edge for an IAM user caller', () => {
    const output = JSON.stringify({
      UserId: 'AIDAEXAMPLE123',
      Account: '111122223333',
      Arn: 'arn:aws:iam::111122223333:user/svc-deploy',
    });
    const finding = parseAwsStsIdentity(output, 'test', { source_credential_id: 'cred-aws-1' } as any);
    expect(finding.nodes).toHaveLength(1);
    const cloudId = finding.nodes[0];
    expect(cloudId.type).toBe('cloud_identity');
    expect(cloudId.principal_type).toBe('user');
    expect(cloudId.caller_kind).toBe('user');
    expect(cloudId.cloud_account).toBe('111122223333');
    expect(cloudId.arn).toBe('arn:aws:iam::111122223333:user/svc-deploy');

    const edge = finding.edges[0];
    expect(edge.properties.type).toBe('OWNS_CRED');
    expect(edge.target).toBe('cred-aws-1');
  });

  it('classifies assumed-role sessions as federated principals', () => {
    const output = JSON.stringify({
      UserId: 'AROA1234:overwatch-replay-xyz',
      Account: '111122223333',
      Arn: 'arn:aws:sts::111122223333:assumed-role/PowerUser/overwatch-replay-xyz',
    });
    const finding = parseAwsStsIdentity(output, 'test');
    expect(finding.nodes[0].principal_type).toBe('federated');
    expect(finding.nodes[0].caller_kind).toBe('role_session');
  });

  it('returns empty finding for malformed JSON', () => {
    const finding = parseAwsStsIdentity('not json', 'test');
    expect(finding.nodes).toHaveLength(0);
    expect(finding.edges).toHaveLength(0);
  });

  it('returns empty finding when Arn or Account are missing', () => {
    const finding = parseAwsStsIdentity(JSON.stringify({ UserId: 'AIDA' }), 'test');
    expect(finding.nodes).toHaveLength(0);
  });
});

describe('parseAwsIamSummary', () => {
  it('stamps SummaryMap on the synthesized account-root cloud_identity when only aws_account context is provided', () => {
    const output = JSON.stringify({
      SummaryMap: { Users: 12, Groups: 4, Roles: 30, Policies: 17, AccountMFAEnabled: 1 },
    });
    const finding = parseAwsIamSummary(output, 'test', { aws_account: '111122223333' } as any);
    expect(finding.nodes).toHaveLength(1);
    const node = finding.nodes[0];
    expect(node.type).toBe('cloud_identity');
    expect(node.cloud_account).toBe('111122223333');
    expect((node.account_summary as Record<string, number>).Users).toBe(12);
  });

  it('stamps the summary on an explicit target_cloud_identity_id when provided', () => {
    const output = JSON.stringify({ SummaryMap: { Users: 1 } });
    const finding = parseAwsIamSummary(output, 'test', { target_cloud_identity_id: 'cloud-identity-arn-aws-iam-111-user-svc' } as any);
    expect(finding.nodes[0].id).toBe('cloud-identity-arn-aws-iam-111-user-svc');
  });

  it('returns empty finding for malformed payload', () => {
    expect(parseAwsIamSummary('garbage', 'test').nodes).toHaveLength(0);
    expect(parseAwsIamSummary('{}', 'test').nodes).toHaveLength(0);
  });
});

describe('expand_aws_credential plan shape', () => {
  // The full tool wiring is exercised through MCP; here we just confirm
  // the plan-building path picks up the credential and synthesizes a
  // reasonable step list. Lightweight smoke test.
  it('builds a plan starting with sts get-caller-identity', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'test', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-aws-playbook.json');
    engine.addNode({
      id: 'cred-aws-1',
      type: 'credential',
      label: 'aws-test',
      cred_type: 'token',
      cred_material_kind: 'oidc_access_token',
      cred_user: 'svc-deploy',
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerAwsPlaybookTool } = await import('../tools/aws-playbook.js');
    let captured: { content: Array<{ text: string }> } | undefined;
    const fakeServer = {
      registerTool: (_name: string, _meta: unknown, handler: any) => {
        // Invoke the handler with our test inputs and capture the response.
        Promise.resolve(handler({ credential_id: 'cred-aws-1', skip_inventory: false, include_destructive: false })).then(r => { captured = r; });
      },
    };
    registerAwsPlaybookTool(fakeServer as any, engine);
    // Allow microtask queue to drain.
    await new Promise(r => setTimeout(r, 10));

    expect(captured).toBeDefined();
    const payload = JSON.parse(captured!.content[0].text);
    if (!payload.steps) throw new Error(`unexpected payload: ${JSON.stringify(payload)}`);
    expect(payload.steps[0].command).toContain('sts get-caller-identity');
    expect(payload.steps[0].parse_with).toBe('aws-sts-identity');
    expect(payload.step_count).toBeGreaterThanOrEqual(4);
    // No destructive steps when include_destructive: false.
    expect(payload.steps.find((s: any) => s.destructive)).toBeUndefined();

    const updatedCred = engine.getNode('cred-aws-1');
    expect(updatedCred?.recon_playbook_invoked_at).toBeDefined();
    expect(updatedCred?.recon_playbook_step_count).toBe(payload.step_count);
  });
});
