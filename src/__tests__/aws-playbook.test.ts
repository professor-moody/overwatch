import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawnSync } from 'child_process';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../services/graph-engine.js';
import { parseAndMaybeIngest } from '../services/parse-ingest.js';
import { getSupportedParsers } from '../services/parsers/index.js';
import { parseAwsStsIdentity } from '../services/parsers/aws-sts-identity.js';
import { parseAwsIamSummary } from '../services/parsers/aws-iam-summary.js';
import { parseAwsIamAttachedPolicies } from '../services/parsers/aws-iam-attached-policies.js';
import { parseCloudFox } from '../services/parsers/cloudfox.js';
import { registerAwsPlaybookTool } from '../tools/aws-playbook.js';
import { cloudIdentityId } from '../services/parser-utils.js';
import type { EngagementConfig } from '../types.js';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/aws/${name}`, import.meta.url), 'utf8');
const AMBIENT_STS_CONTEXT = {
  source_credential_id: 'cred-aws-1',
  credential_execution_binding: 'ambient:explicit',
  credential_execution_binding_identity: 'ambient:explicit',
};

function config(): EngagementConfig {
  return {
    id: 'aws-test', name: 'AWS test', created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
  };
}

function seedCredential(engine: GraphEngine): void {
  engine.addNode({
    id: 'cred-aws-1', type: 'credential', label: 'aws-test',
    cred_type: 'token', cred_material_kind: 'oidc_access_token',
    provider: 'aws', cred_audience: 'sts.amazonaws.com',
    cred_value: 'fixture-token', credential_status: 'active',
    cred_token_expires_at: '2099-01-01T00:00:00Z',
    discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0,
  });
}

async function expand(engine: GraphEngine, overrides: Record<string, unknown> = {}): Promise<any> {
  let handler: ((params: any) => Promise<any>) | undefined;
  const server = {
    registerTool(_name: string, _meta: unknown, registered: (params: any) => Promise<any>) {
      handler = registered;
    },
  } as unknown as McpServer;
  registerAwsPlaybookTool(server, engine);
  const response = await handler!({
    credential_id: 'cred-aws-1', regions: ['us-east-1'],
    skip_inventory: false, include_destructive: false, use_ambient_credentials: true, ...overrides,
  });
  return JSON.parse(response.content[0].text);
}

describe('AWS credential playbook and parsers', () => {
  let dir: string;
  let engine: GraphEngine;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-aws-playbook-'));
    engine = new GraphEngine(config(), join(dir, 'state.json'));
    seedCredential(engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  it('binds an IAM user caller to its source credential and ingests the promised shape', () => {
    const parsed = parseAwsStsIdentity(fixture('caller-user.json'), 'test', AMBIENT_STS_CONTEXT);
    expect(parsed.nodes[0]).toMatchObject({
      type: 'cloud_identity', provider: 'aws', cloud_account: '111122223333',
      caller_kind: 'user', enumeration_principal_kind: 'user', principal_name: 'svc-deploy',
    });
    expect(parsed.edges[0]).toMatchObject({ target: 'cred-aws-1', properties: { type: 'OWNS_CRED' } });
    expect(parsed.edges[0].properties.binding_source).toBe('aws_sts_get_caller_identity');

    const result = parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-sts-user', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    expect(result.parse_outcome).toBe('ok');
    expect(engine.queryGraph({ edge_type: 'OWNS_CRED' }).edges).toHaveLength(1);
  });

  it('normalizes an assumed-role session for role-policy enumeration', () => {
    const parsed = parseAwsStsIdentity(fixture('caller-assumed-role.json'), 'test');
    expect(parsed.nodes[0]).toMatchObject({
      principal_type: 'federated', caller_kind: 'role_session',
      enumeration_principal_kind: 'role', principal_name: 'PowerUser',
    });
  });

  it('uses the final IAM path component for user and direct-role enumeration', () => {
    const user = parseAwsStsIdentity(JSON.stringify({
      UserId: 'AIDA', Account: '111122223333', Arn: 'arn:aws:iam::111122223333:user/team/platform/alice',
    }), 'test');
    const role = parseAwsStsIdentity(JSON.stringify({
      UserId: 'AROA', Account: '111122223333', Arn: 'arn:aws:iam::111122223333:role/team/platform/Deployer',
    }), 'test');
    expect(user.nodes[0].principal_name).toBe('alice');
    expect(role.nodes[0].principal_name).toBe('Deployer');
  });

  it('classifies root and federated callers without pretending they are IAM users', () => {
    const root = parseAwsStsIdentity(JSON.stringify({
      UserId: '111122223333', Account: '111122223333', Arn: 'arn:aws:iam::111122223333:root',
    }), 'test');
    expect(root.nodes[0]).toMatchObject({ caller_kind: 'root', enumeration_principal_kind: 'root' });
    const federated = parseAwsStsIdentity(JSON.stringify({
      UserId: 'AROAFED:user', Account: '111122223333', Arn: 'arn:aws:sts::111122223333:federated-user/alice',
    }), 'test');
    expect(federated.nodes[0]).toMatchObject({ caller_kind: 'federated', enumeration_principal_kind: 'federated' });
  });

  it('never fabricates an account-summary target when context is absent', () => {
    expect(parseAwsIamSummary(fixture('account-summary.json'), 'test').nodes).toEqual([]);
    const callerArn = 'arn:aws:iam::111122223333:user/svc-deploy';
    const callerId = cloudIdentityId(callerArn);
    const explicit = parseAwsIamSummary(fixture('account-summary.json'), 'test', {
      target_cloud_identity_id: callerId,
      caller_arn: callerArn,
      aws_account: '111122223333', principal_kind: 'user',
    });
    expect(explicit.nodes[0]).toMatchObject({
      id: callerId, arn: callerArn,
      account_summary: expect.objectContaining({ Users: 12 }),
    });
    expect(parseAwsIamSummary(fixture('account-summary.json'), 'test', {
      target_cloud_identity_id: cloudIdentityId('arn:aws:iam::444455556666:user/other'),
      caller_arn: callerArn, aws_account: '111122223333', principal_kind: 'user',
    }).nodes).toEqual([]);
  });

  it('ingests dedicated policy, S3, and Lambda fixtures with their promised graph shapes', () => {
    const sts = parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-sts', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    expect(sts.isError).toBe(false);
    const callerId = engine.queryGraph({ node_type: 'cloud_identity' }).nodes[0].id;
    const context = {
      source_credential_id: 'cred-aws-1', target_cloud_identity_id: callerId,
      cloud_account: '111122223333', caller_arn: 'arn:aws:iam::111122223333:user/svc-deploy',
      principal_kind: 'user',
    };

    const policies = parseAndMaybeIngest(engine, {
      tool_name: 'aws-iam-attached-policies', outputText: fixture('attached-policies.json'),
      action_id: 'act-policies', context, ingest: true,
    });
    const buckets = parseAndMaybeIngest(engine, {
      tool_name: 'aws-s3-list-buckets', outputText: fixture('list-buckets.json'),
      action_id: 'act-buckets', context, ingest: true,
    });
    const lambdas = parseAndMaybeIngest(engine, {
      tool_name: 'aws-lambda-list-functions', outputText: fixture('list-functions.json'),
      action_id: 'act-lambdas', context: { ...context, cloud_region: 'us-east-1' }, ingest: true,
    });

    expect([policies, buckets, lambdas].map(result => result.parse_outcome)).toEqual(['ok', 'ok', 'ok']);
    expect(engine.getNodesByType('cloud_policy').every(node => node.permission_expansion === 'unevaluable')).toBe(true);
    expect(engine.queryGraph({ edge_type: 'HAS_POLICY' }).edges).toHaveLength(2);
    expect(engine.queryGraph({ node_type: 'cloud_resource', node_filter: { resource_type: 's3_bucket' } }).nodes).toHaveLength(2);
    expect(engine.queryGraph({ edge_type: 'MANAGED_BY' }).edges).toHaveLength(1);
    expect(engine.queryGraph({ edge_type: 'ASSUMES_ROLE' }).edges.some(edge => {
      const source = engine.getNode(edge.source);
      return source?.resource_type === 'lambda'
        && edge.properties.inferred_by_rule === 'rule-lambda-iam-escalation';
    })).toBe(true);
  });

  it('keys and ingests same-name customer policies by ARN across accounts', () => {
    const callerA = cloudIdentityId('arn:aws:iam::111122223333:user/a');
    const callerB = cloudIdentityId('arn:aws:iam::444455556666:user/b');
    engine.addNode({ id: callerA, type: 'cloud_identity', label: 'a', provider: 'aws',
      arn: 'arn:aws:iam::111122223333:user/a', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
    engine.addNode({ id: callerB, type: 'cloud_identity', label: 'b', provider: 'aws',
      arn: 'arn:aws:iam::444455556666:user/b', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
    const firstOutput = JSON.stringify({
      AttachedPolicies: [{ PolicyName: 'DeployPolicy', PolicyArn: 'arn:aws:iam::111122223333:policy/DeployPolicy' }],
    });
    const secondOutput = JSON.stringify({
      AttachedPolicies: [{ PolicyName: 'DeployPolicy', PolicyArn: 'arn:aws:iam::444455556666:policy/DeployPolicy' }],
    });
    const first = parseAwsIamAttachedPolicies(firstOutput, 'test', { target_cloud_identity_id: callerA });
    const second = parseAwsIamAttachedPolicies(secondOutput, 'test', { target_cloud_identity_id: callerB });
    expect(first.nodes[0].id).not.toBe(second.nodes[0].id);
    expect(parseAndMaybeIngest(engine, { tool_name: 'aws-iam-attached-policies', outputText: firstOutput,
      action_id: 'act-policy-a', context: { target_cloud_identity_id: callerA }, ingest: true }).parse_outcome).toBe('ok');
    expect(parseAndMaybeIngest(engine, { tool_name: 'aws-iam-attached-policies', outputText: secondOutput,
      action_id: 'act-policy-b', context: { target_cloud_identity_id: callerB }, ingest: true }).parse_outcome).toBe('ok');
    expect(engine.getNodesByType('cloud_policy').filter(node => node.policy_name === 'DeployPolicy')).toHaveLength(2);
  });

  it('marks paginated AWS artifacts partial without discarding them', () => {
    const callerId = 'cloud-identity-caller';
    engine.addNode({
      id: callerId, type: 'cloud_identity', label: 'caller', provider: 'aws',
      arn: 'arn:aws:iam::111122223333:user/svc', principal_type: 'user',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    });
    const payload = JSON.parse(fixture('attached-policies.json'));
    payload.IsTruncated = true;
    payload.Marker = 'next-page';
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'aws-iam-attached-policies', outputText: JSON.stringify(payload),
      action_id: 'act-partial', context: { target_cloud_identity_id: callerId }, ingest: true,
    });
    expect(result).toMatchObject({ parse_status: 'ok', parse_outcome: 'partial', partial: true });
    expect(engine.getNodesByType('cloud_policy').every(node => node.partial === undefined)).toBe(true);
  });

  it('parses the CloudFox v2 JSON-file envelope instead of console output', () => {
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'cloudfox', outputText: fixture('cloudfox-v2-envelope.json'),
      action_id: 'act-cloudfox', context: { cloud_account: '111122223333' }, ingest: true,
    });
    expect(result.parse_outcome).toBe('ok');
    expect(engine.getNodesByType('cloud_resource').some(node => node.resource_type === 'lambda')).toBe(true);
    expect(engine.getNodesByType('cloud_resource').some(node => node.resource_type === 's3_bucket' && node.public === true)).toBe(true);
    expect(engine.queryGraph({ edge_type: 'ASSUMES_ROLE' }).edges.length).toBeGreaterThan(0);
    expect(engine.queryGraph({ edge_type: 'POLICY_ALLOWS' }).edges.length).toBeGreaterThan(0);
    const resources = engine.getNodesByType('cloud_resource');
    expect(resources.find(node => node.label === 'private-assets')?.public).toBe(false);
    expect(resources.find(node => node.arn === 'arn:aws:ec2:us-west-2:111122223333:instance/i-0123456789abcdef0')).toBeTruthy();
    const identities = engine.getNodesByType('cloud_identity');
    expect(identities.find(node => node.arn === 'arn:aws:iam::444455556666:root')).toMatchObject({
      principal_type: 'canonical', principal_display_suffix: 'Vendor Corp',
    });
    expect(identities.find(node => node.principal_value === 'lambda.amazonaws.com')?.principal_type).toBe('service');
    expect(identities.find(node => node.arn === 'arn:aws:iam::111122223333:role/AppRole')).toMatchObject({
      is_admin: false, can_priv_esc_to_admin: true,
    });
    const federatedTrust = engine.queryGraph({ edge_type: 'ASSUMES_ROLE' }).edges.find(edge => {
      const source = engine.getNode(edge.source);
      return source?.principal_type === 'federated';
    });
    expect(federatedTrust?.properties).toMatchObject({ condition_present: true });
    expect(federatedTrust?.properties.trusted_subjects).toEqual(expect.arrayContaining([
      'repo:acme/app:ref:refs/heads/main', 'repo:acme/app:environment:prod',
    ]));
    const policies = engine.getNodesByType('cloud_policy');
    const guardrail = policies.find(node => node.policy_name === 'Guardrail');
    expect(guardrail).toMatchObject({ not_actions: ['iam:GetRole'], condition_present: false, policy_arn: undefined });
    expect(engine.queryGraph({ edge_type: 'POLICY_ALLOWS' }).edges
      .some(edge => edge.source === guardrail?.id)).toBe(false);
    const dataRead = policies.filter(node => node.policy_name === 'DataRead' && node.policy_statement === true);
    expect(dataRead.map(node => node.condition_present).sort()).toEqual([false, true]);
    const conditionalDataRead = dataRead.find(node => node.condition_present === true)!;
    expect(engine.queryGraph({ edge_type: 'POLICY_ALLOWS' }).edges
      .some(edge => edge.source === conditionalDataRead.id)).toBe(false);
    expect(policies.find(node => node.policy_name === 'DataRead' && node.policy_statement !== true))
      .toMatchObject({ permission_expansion: 'expanded', policy_expanded_by: 'cloudfox' });
  });

  it('hashes exact CloudFox statement identities so legacy slug collisions cannot merge permissions', () => {
    const policyArn = 'arn:aws:iam::111122223333:policy/Collision';
    const principalArn = 'arn:aws:iam::111122223333:user/operator';
    const finding = parseCloudFox(JSON.stringify([
      { Type: 'Permission', PrincipalArn: principalArn, PolicyArn: policyArn,
        PolicyName: 'Collision', Action: 's3:Get*', Resource: 'arn:aws:s3:::bucket/a.b' },
      { Type: 'Permission', PrincipalArn: principalArn, PolicyArn: policyArn,
        PolicyName: 'Collision', Action: 's3:Get', Resource: 'arn:aws:s3:::bucket/a/b' },
    ]), 'test', { cloud_account: '111122223333' });
    const statements = finding.nodes.filter(node => node.type === 'cloud_policy' && node.policy_statement === true);
    expect(statements).toHaveLength(2);
    expect(new Set(statements.map(node => node.id)).size).toBe(2);
    expect(statements.map(node => node.actions)).toEqual([['s3:Get*'], ['s3:Get']]);
    expect(statements.map(node => node.resources)).toEqual([
      ['arn:aws:s3:::bucket/a.b'], ['arn:aws:s3:::bucket/a/b'],
    ]);

    const ingested = parseAndMaybeIngest(engine, {
      tool_name: 'cloudfox', outputText: JSON.stringify([
        { Type: 'Permission', PrincipalArn: principalArn, PolicyArn: policyArn,
          PolicyName: 'Collision', Action: 's3:Get*', Resource: 'arn:aws:s3:::bucket/a.b' },
        { Type: 'Permission', PrincipalArn: principalArn, PolicyArn: policyArn,
          PolicyName: 'Collision', Action: 's3:Get', Resource: 'arn:aws:s3:::bucket/a/b' },
      ]),
      action_id: 'act-cloudfox-collision', context: { cloud_account: '111122223333' }, ingest: true,
    });
    expect(ingested.parse_outcome).toBe('ok');
    expect(engine.getNodesByType('cloud_policy').filter(node => node.policy_statement === true)).toHaveLength(2);
  });

  it('merges duplicate CloudFox trust alternatives and inventory deterministically', () => {
    const roleArn = 'arn:aws-us-gov:iam::111122223333:role/Target';
    const sourceArn = 'arn:aws-us-gov:iam::222233334444:role/Source';
    const records = [
      { Type: 'RoleTrust', RoleArn: roleArn, TrustedPrincipal: sourceArn, Condition: 'Yes' },
      { Type: 'RoleTrust', RoleArn: roleArn, TrustedPrincipal: sourceArn },
      { _cloudfox_module: 'instances', Account: '111122223333', Zone: 'us-gov-west-1-lax-1a', 'Instance ID': 'i-local', Name: 'local', confidence: 0.2 },
    ];
    const finding = parseCloudFox(JSON.stringify(records), 'test', {
      caller_arn: 'arn:aws-us-gov:iam::111122223333:user/operator', cloud_account: '111122223333',
    });
    expect(finding.edges.find(edge => edge.properties.type === 'ASSUMES_ROLE')?.properties).toMatchObject({
      condition_present: false, confidence: 0.9,
    });
    expect(finding.nodes.find(node => node.label === 'local')).toMatchObject({
      arn: 'arn:aws-us-gov:ec2:us-gov-west-1:111122223333:instance/i-local',
      region: 'us-gov-west-1',
    });

    const reversed = parseCloudFox(JSON.stringify([...records].reverse()), 'test', {
      caller_arn: 'arn:aws-us-gov:iam::111122223333:user/operator', cloud_account: '111122223333',
    });
    expect(reversed.edges.find(edge => edge.properties.type === 'ASSUMES_ROLE')?.properties).toMatchObject({
      condition_present: false, confidence: 0.9,
    });
  });

  it('normalizes the real CloudFox lambda.json wrapper output', async () => {
    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-bind-wrapper', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    const payload = await expand(engine);
    const command = payload.steps.find((step: any) => step.step_id === 'cloudfox-inventory').command as string;
    const fakeBin = join(dir, 'bin');
    mkdirSync(fakeBin);
    const fakeCloudfox = join(fakeBin, 'cloudfox');
    writeFileSync(fakeCloudfox, `#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--outdir" ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out/cloudfox-output/aws"
printf '%s' '[{"Account":"111122223333","Region":"us-east-1","Name":"wrapped","Arn":"arn:aws:lambda:us-east-1:111122223333:function:wrapped","Role":"arn:aws:iam::111122223333:role/Wrapped"}]' > "$out/cloudfox-output/aws/lambda.json"
`, 'utf8');
    chmodSync(fakeCloudfox, 0o755);
    const run = spawnSync('bash', ['-c', command], {
      encoding: 'utf8', env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}` },
    });
    expect(run.status).toBe(0);
    const envelope = JSON.parse(run.stdout);
    expect(envelope.records).toEqual(expect.arrayContaining([
      expect.objectContaining({ module: 'lambda', record: expect.objectContaining({ Name: 'wrapped' }) }),
    ]));
  });

  it('emits only STS as ready until its bindings have landed', async () => {
    const payload = await expand(engine);
    expect(payload.binding_status).toBe('unresolved');
    expect(payload.ready_step_count).toBe(1);
    expect(payload.steps[0]).toMatchObject({
      step_id: 'caller-identity', ready: true, parse_with: 'aws-sts-identity',
      parser_context: {
        source_credential_id: 'cred-aws-1',
        credential_execution_binding_identity: 'ambient:explicit',
      },
    });
    expect(payload.steps.slice(1).every((step: any) => step.ready === false && !step.command)).toBe(true);
    expect(payload.steps.slice(1).every((step: any) => step.status === 'blocked' && step.command === null)).toBe(true);
    expect(payload.plan_version).toBe(2);
    expect(engine.getNode('cred-aws-1')).toMatchObject({
      recon_playbook_invoked_at: expect.any(String),
      recon_playbook_step_count: payload.step_count,
    });
    const canonical = (engine as unknown as {
      ctx: { graph: { getNodeAttributes(id: string): Record<string, unknown> } };
    }).ctx.graph.getNodeAttributes('cred-aws-1');
    expect(canonical.recon_playbook_invoked_at).toBeUndefined();
    expect(canonical.recon_playbook_step_count).toBeUndefined();
  });

  it('blocks every command until an execution credential is explicitly bound', async () => {
    const payload = await expand(engine, { use_ambient_credentials: false });
    expect(payload.credential_binding).toBeNull();
    expect(payload.ready_step_count).toBe(0);
    expect(payload.steps.every((step: any) => step.status === 'blocked' && step.command === null)).toBe(true);
  });

  it('accepts an explicit profile binding and rejects unmarked ambient tokens', async () => {
    const profile = await expand(engine, { use_ambient_credentials: false, aws_profile: 'selected-prod' });
    expect(profile.credential_binding).toBe('profile:selected-prod');
    expect(profile.steps[0]).toMatchObject({ status: 'ready', ready: true });
    expect(profile.steps[0].command).toContain("--profile 'selected-prod'");

    engine.addNode({ id: 'cred-unmarked', type: 'credential', label: 'generic', cred_type: 'token',
      cred_material_kind: 'token', cred_value: 'x', credential_status: 'active',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1 });
    const rejected = await expand(engine, { credential_id: 'cred-unmarked', use_ambient_credentials: true });
    expect(rejected.error).toContain('no AWS provider/audience marker');
  });

  it('chains minted AWS session JSON into exact fail-closed CLI environment bindings', async () => {
    const targetId = cloudIdentityId('arn:aws:iam::111122223333:role/PowerUser');
    engine.addNode({
      id: targetId, type: 'cloud_identity', label: 'PowerUser', provider: 'aws',
      arn: 'arn:aws:iam::111122223333:role/PowerUser', principal_type: 'role',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    });
    const replayOutput = JSON.stringify({
      Credentials: {
        AccessKeyId: 'ASIASELECTED', SecretAccessKey: 'selected-secret',
        SessionToken: 'selected-session', Expiration: '2099-01-01T00:00:00Z',
      },
      AssumedRoleUser: { AssumedRoleId: 'AROA:session', Arn: 'arn:aws:sts::111122223333:assumed-role/PowerUser/session' },
    });
    const replay = parseAndMaybeIngest(engine, {
      tool_name: 'token_replay_awssts', outputText: replayOutput, action_id: 'act-session-mint', ingest: true,
      context: {
        source_credential_id: 'cred-aws-1', target_role_arn: 'arn:aws:iam::111122223333:role/PowerUser',
        target_cloud_identity_id: targetId,
      },
    });
    expect(replay.parse_outcome).toBe('ok');
    const sessionCred = engine.getNodesByType('credential').find(node => node.cred_material_kind === 'aws_session_credentials')!;
    expect(JSON.parse(String(sessionCred.cred_value))).toEqual({
      AccessKeyId: 'ASIASELECTED', SecretAccessKey: 'selected-secret', SessionToken: 'selected-session',
    });

    const payload = await expand(engine, {
      credential_id: sessionCred.id, use_ambient_credentials: false, session_credentials_env_var: 'OW_AWS_JSON',
    });
    expect(payload).toMatchObject({
      credential_binding: 'env:OW_AWS_JSON',
      env_from_credential: { OW_AWS_JSON: sessionCred.id },
      credential_source: 'AWS session JSON from run_bash.env.OW_AWS_JSON',
    });
    const command = payload.steps[0].command as string;
    const fakeBin = join(dir, 'session-bin');
    mkdirSync(fakeBin);
    const fakeAws = join(fakeBin, 'aws');
    writeFileSync(fakeAws, `#!/bin/sh
printf '%s|%s|%s' "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN" > "$CAPTURE_FILE"
printf '%s' '{"UserId":"AIDA","Account":"111122223333","Arn":"arn:aws:iam::111122223333:user/session"}'
`, 'utf8');
    chmodSync(fakeAws, 0o755);
    const capture = join(dir, 'session-env.txt');
    const run = spawnSync('bash', ['-c', command], {
      encoding: 'utf8',
      env: {
        ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, CAPTURE_FILE: capture,
        OW_AWS_JSON: String(sessionCred.cred_value),
      },
    });
    expect(run.status).toBe(0);
    expect(readFileSync(capture, 'utf8')).toBe('ASIASELECTED|selected-secret|selected-session');

    rmSync(capture, { force: true });
    const malformed = spawnSync('bash', ['-c', command], {
      encoding: 'utf8',
      env: {
        ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, CAPTURE_FILE: capture,
        OW_AWS_JSON: JSON.stringify({ AccessKeyId: 'ASIAONLY' }),
      },
    });
    expect(malformed.status).not.toBe(0);
    expect(() => readFileSync(capture, 'utf8')).toThrow();

    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-session-caller', ingest: true,
      context: {
        source_credential_id: sessionCred.id,
        credential_execution_binding: 'env:OW_AWS_JSON',
        credential_execution_binding_identity: `session_credential:${sessionCred.id}`,
      },
    });
    const aliasPayload = await expand(engine, {
      credential_id: sessionCred.id,
      session_credentials_env_var: 'DIFFERENT_ENV_ALIAS',
      use_ambient_credentials: false,
    });
    expect(aliasPayload.binding_status).toBe('resolved');
    expect(aliasPayload.credential_binding).toBe('env:DIFFERENT_ENV_ALIAS');
    expect(aliasPayload.credential_binding_identity).toBe(`session_credential:${sessionCred.id}`);
    expect(aliasPayload.confirmed_credential_binding).toBe(`session_credential:${sessionCred.id}`);
  });

  it('does not resolve dependencies from an ordinary ownership edge', async () => {
    engine.addNode({
      id: 'cloud-identity-imported', type: 'cloud_identity', label: 'imported', provider: 'aws',
      arn: 'arn:aws:iam::111122223333:user/imported', cloud_account: '111122223333',
      principal_type: 'user', discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    });
    engine.addEdge('cloud-identity-imported', 'cred-aws-1', {
      type: 'OWNS_CRED', confidence: 1, discovered_at: '2026-01-01T00:00:00Z', discovered_by: 'import',
    });
    const payload = await expand(engine);
    expect(payload.binding_status).toBe('unresolved');
    expect(payload.ready_step_count).toBe(1);
  });

  it('re-expands a bound IAM user with concrete contexts and dedicated parsers', async () => {
    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-bind-user', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    const payload = await expand(engine);
    expect(payload.binding_status).toBe('resolved');
    expect(payload.bindings).toMatchObject({
      account_id: '111122223333', principal_kind: 'user', principal_name: 'svc-deploy',
    });
    const policy = payload.steps.find((step: any) => step.step_id === 'attached-policies');
    expect(policy.command).toContain("list-attached-user-policies --user-name 'svc-deploy'");
    expect(policy.parse_with).toBe('aws-iam-attached-policies');
    expect(policy.parser_context).toMatchObject({
      source_credential_id: 'cred-aws-1', cloud_account: '111122223333',
      target_cloud_identity_id: payload.binding_source_identity_id,
    });
    const s3 = payload.steps.find((step: any) => step.step_id === 's3-buckets');
    const lambda = payload.steps.find((step: any) => step.step_id.startsWith('lambda-functions-'));
    expect(s3.parse_with).toBe('aws-s3-list-buckets');
    expect(lambda.parse_with).toBe('aws-lambda-list-functions');
    const cloudfox = payload.steps.find((step: any) => step.step_id === 'cloudfox-inventory');
    expect(cloudfox.command).not.toContain('--regions');
    expect(cloudfox.command).toContain('cloudfox-json-files-v1');
    expect(cloudfox.command).toContain('cloudfox-output/aws');
    expect(spawnSync('bash', ['-n'], { input: cloudfox.command, encoding: 'utf8' })).toMatchObject({ status: 0 });
    for (const step of payload.steps.filter((candidate: any) => candidate.ready && candidate.parse_with)) {
      expect(getSupportedParsers()).toContain(step.parse_with);
    }
  });

  it('does not reuse caller attribution across different execution bindings', async () => {
    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-profile-a', ingest: true,
      context: {
        source_credential_id: 'cred-aws-1',
        credential_execution_binding: 'profile:profile-a',
        credential_execution_binding_identity: 'profile:profile-a',
      },
    });
    const sameProfile = await expand(engine, { aws_profile: 'profile-a', use_ambient_credentials: false });
    expect(sameProfile.binding_status).toBe('resolved');
    expect(sameProfile.confirmed_credential_binding).toBe('profile:profile-a');

    const differentProfile = await expand(engine, { aws_profile: 'profile-b', use_ambient_credentials: false });
    expect(differentProfile.binding_status).toBe('incomplete');
    expect(differentProfile.ready_step_count).toBe(1);
    expect(differentProfile.steps[0]).toMatchObject({ step_id: 'caller-identity', ready: true });
    expect(differentProfile.steps.slice(1).every((step: any) => step.ready === false && step.command === null)).toBe(true);
    expect(differentProfile.binding_warning).toContain('not the current profile:profile-b');
  });

  it('selects the role-policy branch for an STS assumed-role caller', async () => {
    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-assumed-role.json'),
      action_id: 'act-bind-role', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    const payload = await expand(engine);
    expect(payload.bindings).toMatchObject({ principal_kind: 'role', principal_name: 'PowerUser' });
    expect(payload.steps.find((step: any) => step.step_id === 'attached-policies').command)
      .toContain("list-attached-role-policies --role-name 'PowerUser'");
  });

  it('blocks unsupported root policy branching and refuses ambiguous caller identities', async () => {
    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity',
      outputText: JSON.stringify({ UserId: 'root', Account: '111122223333', Arn: 'arn:aws:iam::111122223333:root' }),
      action_id: 'act-root', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    let payload = await expand(engine);
    expect(payload.steps.find((step: any) => step.step_id === 'attached-policies')).toMatchObject({ ready: false });
    expect(payload.steps.find((step: any) => step.step_id === 's3-buckets')).toMatchObject({ ready: true });

    parseAndMaybeIngest(engine, {
      tool_name: 'aws-sts-identity', outputText: fixture('caller-user.json'),
      action_id: 'act-second-caller', context: AMBIENT_STS_CONTEXT, ingest: true,
    });
    payload = await expand(engine);
    expect(payload.binding_status).toBe('ambiguous');
    expect(payload.ready_step_count).toBe(1);
    expect(payload.binding_warning).toContain('refusing to guess');
  });
});
