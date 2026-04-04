import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { parsePacu, parseProwler, parseOutput } from '../parsers/index.js';
import { parseAzureHoundFile } from '../azurehound-ingest.js';
import { cloudIdentityId, cloudResourceId, cloudPolicyId, cloudNetworkId } from '../parser-utils.js';
import { validateEdgeEndpoints } from '../graph-schema.js';
import { resolveNodeIdentity } from '../identity-resolution.js';
import type { EngagementConfig, Finding } from '../../types.js';
import { NODE_TYPES, EDGE_TYPES } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';

const TEST_STATE_FILE = './state-test-sprint11.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-s11',
    name: 'Sprint 11 Cloud Test',
    created_at: '2026-04-01T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
      aws_accounts: ['123456789012'],
      azure_subscriptions: ['sub-abc-123'],
    },
    objectives: [{
      id: 'obj-cloud',
      description: 'Compromise cloud admin',
      target_node_type: 'cloud_identity',
      target_criteria: { privileged: true },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

const now = new Date().toISOString();

function makeFinding(nodes: Finding['nodes'], edges: Finding['edges'] = []): Finding {
  return { id: `f-${Date.now()}`, agent_id: 'test', timestamp: now, nodes, edges };
}

// ============================================================
// 11.1: Node Types
// ============================================================
describe('11.1 — Cloud node types', () => {
  afterEach(cleanup);

  it('NODE_TYPES includes all 4 cloud types', () => {
    expect(NODE_TYPES).toContain('cloud_identity');
    expect(NODE_TYPES).toContain('cloud_resource');
    expect(NODE_TYPES).toContain('cloud_policy');
    expect(NODE_TYPES).toContain('cloud_network');
  });

  it('cloud_identity node can be ingested with typed properties', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'ci-test', type: 'cloud_identity', label: 'test-role',
      discovered_at: now, confidence: 1.0,
      provider: 'aws', arn: 'arn:aws:iam::123456789012:role/TestRole',
      principal_type: 'role', cloud_account: '123456789012',
    }]));
    const node = engine.getNode(cloudIdentityId('arn:aws:iam::123456789012:role/TestRole'));
    expect(node).toBeTruthy();
    expect(node!.type).toBe('cloud_identity');
    expect(node!.provider).toBe('aws');
    expect(node!.principal_type).toBe('role');
  });

  it('cloud_resource node can be ingested', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'cr-test', type: 'cloud_resource', label: 'my-bucket',
      discovered_at: now, confidence: 1.0,
      provider: 'aws', arn: 'arn:aws:s3:::my-bucket',
      resource_type: 's3_bucket', public: true,
    }]));
    const node = engine.getNode(cloudResourceId('arn:aws:s3:::my-bucket'));
    expect(node).toBeTruthy();
    expect(node!.resource_type).toBe('s3_bucket');
    expect(node!.public).toBe(true);
  });

  it('cloud_policy node can be ingested', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'cp-test', type: 'cloud_policy', label: 'AdminAccess',
      discovered_at: now, confidence: 1.0,
      provider: 'aws', policy_name: 'AdminAccess',
      actions: ['*:*'], resources: ['*'],
    }]));
    const node = engine.getNode(cloudPolicyId('aws', 'AdminAccess'));
    expect(node).toBeTruthy();
    expect(node!.actions).toEqual(['*:*']);
  });

  it('cloud_network node can be ingested', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'cn-test', type: 'cloud_network', label: 'vpc-abc123',
      discovered_at: now, confidence: 1.0,
      provider: 'aws', arn: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abc123',
      network_type: 'vpc',
    }]));
    const node = engine.getNode(cloudNetworkId('arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abc123'));
    expect(node).toBeTruthy();
    expect(node!.network_type).toBe('vpc');
  });
});

// ============================================================
// 11.1: Identity Resolution
// ============================================================
describe('11.1 — Cloud identity resolution', () => {
  it('cloud_identity resolves canonical ID from ARN', () => {
    const res = resolveNodeIdentity({ id: 'temp', type: 'cloud_identity', arn: 'arn:aws:iam::123:role/Foo' } as any);
    expect(res.status).toBe('canonical');
    expect(res.id).toBe(cloudIdentityId('arn:aws:iam::123:role/Foo'));
  });

  it('cloud_identity without ARN is unresolved', () => {
    const res = resolveNodeIdentity({ id: 'temp', type: 'cloud_identity' } as any);
    expect(res.status).toBe('unresolved');
  });

  it('cloud_resource resolves canonical ID from ARN', () => {
    const res = resolveNodeIdentity({ id: 'temp', type: 'cloud_resource', arn: 'arn:aws:s3:::bucket' } as any);
    expect(res.status).toBe('canonical');
    expect(res.id).toBe(cloudResourceId('arn:aws:s3:::bucket'));
  });

  it('cloud_policy resolves from provider + policy_name', () => {
    const res = resolveNodeIdentity({ id: 'temp', type: 'cloud_policy', provider: 'aws', policy_name: 'ReadOnly' } as any);
    expect(res.status).toBe('canonical');
    expect(res.id).toBe(cloudPolicyId('aws', 'ReadOnly'));
  });

  it('cloud_network resolves from ARN', () => {
    const res = resolveNodeIdentity({ id: 'temp', type: 'cloud_network', arn: 'arn:aws:ec2:us-east-1:123:vpc/vpc-1' } as any);
    expect(res.status).toBe('canonical');
    expect(res.id).toBe(cloudNetworkId('arn:aws:ec2:us-east-1:123:vpc/vpc-1'));
  });

  it('cloud_network falls back to label when no ARN', () => {
    const res = resolveNodeIdentity({ id: 'temp', type: 'cloud_network', label: 'my-vpc' } as any);
    expect(res.status).toBe('canonical');
    expect(res.id).toBe(cloudNetworkId('my-vpc'));
  });
});

// ============================================================
// 11.2: Edge Types + Constraints
// ============================================================
describe('11.2 — Cloud edge types and constraints', () => {
  it('EDGE_TYPES includes all 6 cloud edge types', () => {
    expect(EDGE_TYPES).toContain('ASSUMES_ROLE');
    expect(EDGE_TYPES).toContain('HAS_POLICY');
    expect(EDGE_TYPES).toContain('POLICY_ALLOWS');
    expect(EDGE_TYPES).toContain('EXPOSED_TO');
    expect(EDGE_TYPES).toContain('RUNS_ON');
    expect(EDGE_TYPES).toContain('MANAGED_BY');
  });

  it('ASSUMES_ROLE validates cloud_identity → cloud_identity', () => {
    const result = validateEdgeEndpoints('ASSUMES_ROLE', 'cloud_identity', 'cloud_identity', {
      source_id: 'a', target_id: 'b',
    });
    expect(result.valid).toBe(true);
  });

  it('ASSUMES_ROLE rejects user → cloud_identity', () => {
    const result = validateEdgeEndpoints('ASSUMES_ROLE', 'user', 'cloud_identity', {
      source_id: 'a', target_id: 'b',
    });
    expect(result.valid).toBe(false);
  });

  it('HAS_POLICY validates cloud_identity → cloud_policy', () => {
    const result = validateEdgeEndpoints('HAS_POLICY', 'cloud_identity', 'cloud_policy', {
      source_id: 'a', target_id: 'b',
    });
    expect(result.valid).toBe(true);
  });

  it('RUNS_ON validates host → cloud_resource', () => {
    const result = validateEdgeEndpoints('RUNS_ON', 'host', 'cloud_resource', {
      source_id: 'a', target_id: 'b',
    });
    expect(result.valid).toBe(true);
  });

  it('MANAGED_BY validates cloud_resource → cloud_identity', () => {
    const result = validateEdgeEndpoints('MANAGED_BY', 'cloud_resource', 'cloud_identity', {
      source_id: 'a', target_id: 'b',
    });
    expect(result.valid).toBe(true);
  });

  it('PATH_TO_OBJECTIVE allows cloud_identity as source', () => {
    const result = validateEdgeEndpoints('PATH_TO_OBJECTIVE', 'cloud_identity', 'objective', {
      source_id: 'a', target_id: 'b',
    });
    expect(result.valid).toBe(true);
  });

  afterEach(cleanup);

  it('cloud edges can be ingested into graph', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'ci-1', type: 'cloud_identity', label: 'role-a', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::123:role/A' },
        { id: 'ci-2', type: 'cloud_identity', label: 'role-b', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::123:role/B' },
      ],
      [
        { source: 'ci-1', target: 'ci-2', properties: { type: 'ASSUMES_ROLE', confidence: 0.9, discovered_at: now } },
      ]
    ));
    const edges = engine.queryGraph({ edge_type: 'ASSUMES_ROLE' });
    expect(edges.edges.length).toBe(1);
  });
});

// ============================================================
// 11.3: Inference Rules
// ============================================================
describe('11.3 — Cloud inference rules', () => {
  afterEach(cleanup);

  it('rule-overprivileged-policy fires for wildcard actions', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'cp-wild', type: 'cloud_policy', label: 'SuperAdmin', discovered_at: now, confidence: 1.0, provider: 'aws', policy_name: 'SuperAdmin', actions: ['*:*'], resources: ['*'] },
    ]));
    const edges = engine.queryGraph({ edge_type: 'PATH_TO_OBJECTIVE' });
    expect(edges.edges.length).toBeGreaterThanOrEqual(1);
    const ptoEdge = edges.edges.find(e => e.properties.inferred_by_rule === 'rule-overprivileged-policy');
    expect(ptoEdge).toBeTruthy();
  });

  it('rule-overprivileged-policy does NOT fire for non-wildcard actions', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'cp-safe', type: 'cloud_policy', label: 'ReadOnly', discovered_at: now, confidence: 1.0, provider: 'aws', policy_name: 'ReadOnly', actions: ['s3:GetObject'], resources: ['*'] },
    ]));
    const edges = engine.queryGraph({ edge_type: 'PATH_TO_OBJECTIVE' });
    const ptoEdge = edges.edges.find(e => e.properties.inferred_by_rule === 'rule-overprivileged-policy');
    expect(ptoEdge).toBeUndefined();
  });

  it('rule-public-bucket fires for public S3 bucket', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'cr-pub', type: 'cloud_resource', label: 'leaky-bucket', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:s3:::leaky', resource_type: 's3_bucket', public: true },
    ]));
    const edges = engine.queryGraph({ edge_type: 'PATH_TO_OBJECTIVE' });
    const ptoEdge = edges.edges.find(e => e.properties.inferred_by_rule === 'rule-public-bucket');
    expect(ptoEdge).toBeTruthy();
  });

  it('rule-cross-account-role fires when ASSUMES_ROLE crosses accounts', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'ci-src', type: 'cloud_identity', label: 'src-role', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::123456789012:role/Src', cloud_account: '123456789012' },
        { id: 'ci-tgt', type: 'cloud_identity', label: 'tgt-role', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::999999999999:role/Tgt', cloud_account: '999999999999' },
      ],
      [
        { source: 'ci-src', target: 'ci-tgt', properties: { type: 'ASSUMES_ROLE', confidence: 1.0, discovered_at: now } },
      ]
    ));
    // The rule triggers on the source identity which has an outbound ASSUMES_ROLE edge
    const edges = engine.queryGraph({ edge_type: 'REACHABLE' });
    const crossAcct = edges.edges.find(e => e.properties.inferred_by_rule === 'rule-cross-account-role');
    expect(crossAcct).toBeTruthy();
  });

  it('inferImdsv1Ssrf creates EXPLOITS edge for SSRF → EC2 without IMDSv2', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const hostArn = 'arn:aws:ec2:us-east-1:123456789012:instance/i-abc';
    const roleArn = 'arn:aws:iam::123456789012:role/EC2Role';
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-5', type: 'host', label: '10.10.10.5', discovered_at: now, confidence: 1.0, ip: '10.10.10.5', alive: true },
        { id: 'svc-http', type: 'service', label: 'http', discovered_at: now, confidence: 1.0, service_name: 'http', port: 80 },
        { id: 'webapp-app', type: 'webapp', label: 'http://10.10.10.5', discovered_at: now, confidence: 1.0, url: 'http://10.10.10.5' },
        { id: 'vuln-ssrf', type: 'vulnerability', label: 'SSRF', discovered_at: now, confidence: 1.0, vuln_type: 'ssrf' },
        { id: 'cr-ec2', type: 'cloud_resource', label: 'i-abc', discovered_at: now, confidence: 1.0, provider: 'aws', arn: hostArn, resource_type: 'ec2', imdsv2_required: false },
        { id: 'ci-role', type: 'cloud_identity', label: 'EC2Role', discovered_at: now, confidence: 1.0, provider: 'aws', arn: roleArn, principal_type: 'role' },
      ],
      [
        { source: 'host-10-10-10-5', target: 'svc-http', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } },
        { source: 'svc-http', target: 'webapp-app', properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now } },
        { source: 'webapp-app', target: 'vuln-ssrf', properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: now } },
        { source: 'host-10-10-10-5', target: 'cr-ec2', properties: { type: 'RUNS_ON', confidence: 1.0, discovered_at: now } },
        { source: 'cr-ec2', target: 'ci-role', properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now } },
      ]
    ));
    const edges = engine.queryGraph({ edge_type: 'EXPLOITS' });
    const ssrfEdge = edges.edges.find(e => e.properties.inferred_by_rule === 'imdsv1-ssrf');
    expect(ssrfEdge).toBeTruthy();
    expect(ssrfEdge!.properties.confidence).toBe(0.85);
  });

  it('inferImdsv1Ssrf does NOT fire when IMDSv2 is required', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-6', type: 'host', label: '10.10.10.6', discovered_at: now, confidence: 1.0, ip: '10.10.10.6', alive: true },
        { id: 'svc-http2', type: 'service', label: 'http', discovered_at: now, confidence: 1.0, service_name: 'http', port: 80 },
        { id: 'webapp-app2', type: 'webapp', label: 'http://10.10.10.6', discovered_at: now, confidence: 1.0, url: 'http://10.10.10.6' },
        { id: 'vuln-ssrf2', type: 'vulnerability', label: 'SSRF', discovered_at: now, confidence: 1.0, vuln_type: 'ssrf' },
        { id: 'cr-ec2v2', type: 'cloud_resource', label: 'i-def', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:ec2:us-east-1:123:instance/i-def', resource_type: 'ec2', imdsv2_required: true },
        { id: 'ci-role2', type: 'cloud_identity', label: 'EC2Role2', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::123:role/EC2Role2', principal_type: 'role' },
      ],
      [
        { source: 'host-10-10-10-6', target: 'svc-http2', properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } },
        { source: 'svc-http2', target: 'webapp-app2', properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now } },
        { source: 'webapp-app2', target: 'vuln-ssrf2', properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: now } },
        { source: 'host-10-10-10-6', target: 'cr-ec2v2', properties: { type: 'RUNS_ON', confidence: 1.0, discovered_at: now } },
        { source: 'cr-ec2v2', target: 'ci-role2', properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now } },
      ]
    ));
    const edges = engine.queryGraph({ edge_type: 'EXPLOITS' });
    const ssrfEdge = edges.edges.find(e => e.properties.inferred_by_rule === 'imdsv1-ssrf');
    expect(ssrfEdge).toBeUndefined();
  });

  it('inferManagedIdentityPivot creates POTENTIAL_AUTH from session holder to cloud identity', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'host-10-10-10-7', type: 'host', label: '10.10.10.7', discovered_at: now, confidence: 1.0, ip: '10.10.10.7', alive: true },
        { id: 'user-attacker', type: 'user', label: 'attacker', discovered_at: now, confidence: 1.0, username: 'attacker' },
        { id: 'cr-vm', type: 'cloud_resource', label: 'vm-1', discovered_at: now, confidence: 1.0, provider: 'azure', arn: 'azure:vm:vm-1', resource_type: 'azure_vm' },
        { id: 'ci-mi', type: 'cloud_identity', label: 'managed-identity', discovered_at: now, confidence: 1.0, provider: 'azure', arn: 'azure:mi:mi-1', principal_type: 'managed_identity' },
      ],
      [
        { source: 'user-attacker', target: 'host-10-10-10-7', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: now } },
        { source: 'host-10-10-10-7', target: 'cr-vm', properties: { type: 'RUNS_ON', confidence: 1.0, discovered_at: now } },
        { source: 'cr-vm', target: 'ci-mi', properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now } },
      ]
    ));
    const edges = engine.queryGraph({ edge_type: 'POTENTIAL_AUTH' });
    const pivotEdge = edges.edges.find(e => e.properties.inferred_by_rule === 'managed-identity-pivot');
    expect(pivotEdge).toBeTruthy();
    expect(pivotEdge!.properties.confidence).toBe(0.75);
  });
});

// ============================================================
// 11.7: Frontier
// ============================================================
describe('11.7 — Cloud frontier awareness', () => {
  afterEach(cleanup);

  it('cloud_identity missing policies_enumerated appears in frontier', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'ci-f', type: 'cloud_identity', label: 'test-user', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::123:user/Test' },
    ]));
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.node_id === cloudIdentityId('arn:aws:iam::123:user/Test'));
    expect(item).toBeTruthy();
    expect(item!.missing_properties).toContain('policies_enumerated');
    expect(item!.missing_properties).toContain('mfa_enabled');
  });

  it('cloud_resource missing public appears in frontier', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'cr-f', type: 'cloud_resource', label: 'bucket-x', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:s3:::bucket-x', resource_type: 's3_bucket' },
    ]));
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.node_id === cloudResourceId('arn:aws:s3:::bucket-x'));
    expect(item).toBeTruthy();
    expect(item!.missing_properties).toContain('public_access_checked');
    expect(item!.missing_properties).toContain('encryption_checked');
  });

  it('cloud_identity with all properties does NOT appear in frontier', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([
      { id: 'ci-complete', type: 'cloud_identity', label: 'complete-user', discovered_at: now, confidence: 1.0, provider: 'aws', arn: 'arn:aws:iam::123:user/Complete', policies_enumerated: true, mfa_enabled: false },
    ]));
    const frontier = engine.computeFrontier();
    const item = frontier.find(f => f.node_id === cloudIdentityId('arn:aws:iam::123:user/Complete') && f.type === 'incomplete_node');
    expect(item).toBeUndefined();
  });
});

// ============================================================
// 11.4: Pacu Parser
// ============================================================
describe('11.4 — Pacu parser', () => {
  afterEach(cleanup);

  it('parses IAM users', () => {
    const data = { IAMUsers: [{ Arn: 'arn:aws:iam::123456789012:user/admin', UserName: 'admin' }] };
    const finding = parsePacu(JSON.stringify(data));
    expect(finding.nodes.length).toBe(1);
    expect(finding.nodes[0].type).toBe('cloud_identity');
    expect(finding.nodes[0].principal_type).toBe('user');
  });

  it('parses IAM roles with trust policy → ASSUMES_ROLE edges', () => {
    const data = {
      IAMRoles: [{
        Arn: 'arn:aws:iam::123456789012:role/AppRole',
        RoleName: 'AppRole',
        AssumeRolePolicyDocument: {
          Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' } }]
        }
      }]
    };
    const finding = parsePacu(JSON.stringify(data));
    expect(finding.nodes.length).toBe(2); // role + trusted principal
    expect(finding.edges.length).toBe(1);
    expect(finding.edges[0].properties.type).toBe('ASSUMES_ROLE');
  });

  it('parses IAM policies with actions and attached entities', () => {
    const data = {
      IAMPolicies: [{
        PolicyName: 'AdminPolicy',
        Arn: 'arn:aws:iam::123:policy/AdminPolicy',
        PolicyDocument: { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] },
        AttachedEntities: [{ Arn: 'arn:aws:iam::123:user/admin' }],
      }]
    };
    const finding = parsePacu(JSON.stringify(data));
    const policyNode = finding.nodes.find(n => n.type === 'cloud_policy');
    expect(policyNode).toBeTruthy();
    expect(policyNode!.actions).toContain('*');
    expect(finding.edges.some(e => e.properties.type === 'HAS_POLICY')).toBe(true);
  });

  it('parses S3 buckets', () => {
    const data = { S3Buckets: [{ Name: 'my-data', Region: 'us-east-1' }] };
    const finding = parsePacu(JSON.stringify(data));
    expect(finding.nodes[0].type).toBe('cloud_resource');
    expect(finding.nodes[0].resource_type).toBe('s3_bucket');
  });

  it('parses EC2 instances with host linkage and MANAGED_BY', () => {
    const data = {
      EC2Instances: [{
        InstanceId: 'i-abc123',
        Region: 'us-east-1',
        PrivateIpAddress: '10.10.10.50',
        IamInstanceProfile: { Arn: 'arn:aws:iam::123:instance-profile/MyProfile' },
      }]
    };
    const finding = parsePacu(JSON.stringify(data), 'test', { cloud_account: '123456789012' });
    const ec2 = finding.nodes.find(n => n.resource_type === 'ec2');
    expect(ec2).toBeTruthy();
    const host = finding.nodes.find(n => n.type === 'host');
    expect(host).toBeTruthy();
    expect(finding.edges.some(e => e.properties.type === 'RUNS_ON')).toBe(true);
    expect(finding.edges.some(e => e.properties.type === 'MANAGED_BY')).toBe(true);
  });

  it('resolves IAM role ARN from instance profile Roles array', () => {
    const data = {
      EC2Instances: [{
        InstanceId: 'i-role-test',
        Region: 'us-east-1',
        PrivateIpAddress: '10.10.10.60',
        IamInstanceProfile: {
          Arn: 'arn:aws:iam::123456789012:instance-profile/MyProfile',
          Roles: [{ Arn: 'arn:aws:iam::123456789012:role/EC2ServiceRole', RoleName: 'EC2ServiceRole' }],
        },
      }]
    };
    const finding = parsePacu(JSON.stringify(data), 'test', { cloud_account: '123456789012' });
    const managedByEdge = finding.edges.find(e => e.properties.type === 'MANAGED_BY');
    expect(managedByEdge).toBeTruthy();
    const roleNode = finding.nodes.find(n => n.type === 'cloud_identity' && n.arn === 'arn:aws:iam::123456789012:role/EC2ServiceRole');
    expect(roleNode).toBeTruthy();
    expect(roleNode!.principal_type).toBe('role');
    // Should NOT create a node with the instance-profile ARN
    const profileNode = finding.nodes.find(n => n.arn === 'arn:aws:iam::123456789012:instance-profile/MyProfile');
    expect(profileNode).toBeUndefined();
  });

  it('falls back to instance profile ARN when Roles array is empty', () => {
    const data = {
      EC2Instances: [{
        InstanceId: 'i-fallback',
        Region: 'us-east-1',
        PrivateIpAddress: '10.10.10.70',
        IamInstanceProfile: { Arn: 'arn:aws:iam::123456789012:instance-profile/NoRoles' },
      }]
    };
    const finding = parsePacu(JSON.stringify(data), 'test', { cloud_account: '123456789012' });
    const managedByEdge = finding.edges.find(e => e.properties.type === 'MANAGED_BY');
    expect(managedByEdge).toBeTruthy();
    const profileNode = finding.nodes.find(n => n.type === 'cloud_identity' && n.arn === 'arn:aws:iam::123456789012:instance-profile/NoRoles');
    expect(profileNode).toBeTruthy();
    expect(profileNode!.principal_type).toBe('instance_profile');
  });

  it('survives malformed trust policy without aborting', () => {
    const data = {
      IAMRoles: [
        { Arn: 'arn:aws:iam::123456789012:role/GoodRole', RoleName: 'GoodRole' },
        { Arn: 'arn:aws:iam::123456789012:role/BadRole', RoleName: 'BadRole', AssumeRolePolicyDocument: 'not-json' },
        { Arn: 'arn:aws:iam::123456789012:role/AlsoGood', RoleName: 'AlsoGood' },
      ],
    };
    const finding = parsePacu(JSON.stringify(data));
    const roles = finding.nodes.filter(n => n.type === 'cloud_identity');
    expect(roles.length).toBe(3);
    expect(roles.some(r => r.label === 'GoodRole')).toBe(true);
    expect(roles.some(r => r.label === 'BadRole')).toBe(true);
    expect(roles.some(r => r.label === 'AlsoGood')).toBe(true);
  });

  it('is registered in PARSERS as pacu', () => {
    const result = parseOutput('pacu', JSON.stringify({ IAMUsers: [] }));
    expect(result).toBeTruthy();
  });

  it('handles invalid JSON gracefully', () => {
    const finding = parsePacu('not json');
    expect(finding.nodes).toHaveLength(0);
  });
});

// ============================================================
// 11.5: Prowler Parser
// ============================================================
describe('11.5 — Prowler parser', () => {
  afterEach(cleanup);

  it('parses OCSF JSON lines into cloud_resource nodes', () => {
    const line = JSON.stringify({
      ResourceArn: 'arn:aws:s3:::test-bucket',
      ResourceId: 'test-bucket',
      AccountId: '123456789012',
      Region: 'us-east-1',
      ServiceName: 's3',
      Status: 'PASS',
      Severity: 'LOW',
    });
    const finding = parseProwler(line);
    expect(finding.nodes.length).toBe(1);
    expect(finding.nodes[0].type).toBe('cloud_resource');
    expect(finding.nodes[0].provider).toBe('aws');
  });

  it('creates vulnerability nodes for FAIL + HIGH severity', () => {
    const line = JSON.stringify({
      ResourceArn: 'arn:aws:s3:::vuln-bucket',
      ResourceId: 'vuln-bucket',
      AccountId: '123',
      Region: 'us-east-1',
      ServiceName: 's3',
      Status: 'FAIL',
      Severity: 'HIGH',
      CheckID: 's3_bucket_public_access',
      StatusExtended: 'Bucket is publicly accessible',
    });
    const finding = parseProwler(line);
    const vulnNode = finding.nodes.find(n => n.type === 'vulnerability');
    expect(vulnNode).toBeTruthy();
    expect(vulnNode!.vuln_type).toBe('cloud_misconfiguration');
    expect(finding.edges.some(e => e.properties.type === 'VULNERABLE_TO')).toBe(true);
  });

  it('skips PASS findings for vulnerability creation', () => {
    const line = JSON.stringify({
      ResourceArn: 'arn:aws:s3:::safe-bucket',
      ResourceId: 'safe-bucket',
      Status: 'PASS',
      Severity: 'HIGH',
      CheckID: 's3_check',
    });
    const finding = parseProwler(line);
    expect(finding.nodes.filter(n => n.type === 'vulnerability')).toHaveLength(0);
  });

  it('is registered in PARSERS as prowler (scoutsuite alias removed)', () => {
    const line = JSON.stringify({ ResourceArn: 'arn:aws:s3:::x', ResourceId: 'x', Status: 'PASS', Severity: 'LOW' });
    expect(parseOutput('prowler', line)).toBeTruthy();
    expect(parseOutput('scoutsuite', line)).toBeNull();
  });

  it('handles multiple lines', () => {
    const lines = [
      JSON.stringify({ ResourceArn: 'arn:aws:s3:::b1', ResourceId: 'b1', Status: 'PASS', Severity: 'LOW', ServiceName: 's3' }),
      JSON.stringify({ ResourceArn: 'arn:aws:s3:::b2', ResourceId: 'b2', Status: 'FAIL', Severity: 'CRITICAL', CheckID: 'check1', ServiceName: 's3' }),
    ].join('\n');
    const finding = parseProwler(lines);
    expect(finding.nodes.filter(n => n.type === 'cloud_resource')).toHaveLength(2);
    expect(finding.nodes.filter(n => n.type === 'vulnerability')).toHaveLength(1);
  });
});

// ============================================================
// 11.6: AzureHound Ingest
// ============================================================
describe('11.6 — AzureHound ingest', () => {
  afterEach(cleanup);

  it('parses Azure users', () => {
    const data = { kind: 'azusers', data: [{ Properties: { id: 'user-obj-1', userPrincipalName: 'admin@test.onmicrosoft.com', displayName: 'Admin', accountEnabled: true, tenantId: 'tenant-1' } }] };
    const finding = parseAzureHoundFile(JSON.stringify(data), 'users.json');
    expect(finding.nodes.length).toBe(1);
    expect(finding.nodes[0].type).toBe('cloud_identity');
    expect(finding.nodes[0].provider).toBe('azure');
    expect(finding.nodes[0].principal_type).toBe('user');
  });

  it('parses Azure groups with members → MEMBER_OF edges', () => {
    const data = {
      kind: 'azgroups',
      data: [{
        Properties: { id: 'group-obj-1', displayName: 'Admins' },
        Members: [{ ObjectIdentifier: 'user-obj-1', ObjectType: 'User', displayName: 'Admin' }],
      }]
    };
    const finding = parseAzureHoundFile(JSON.stringify(data), 'groups.json');
    expect(finding.nodes.find(n => n.type === 'group')).toBeTruthy();
    expect(finding.edges.some(e => e.properties.type === 'MEMBER_OF')).toBe(true);
  });

  it('parses Azure apps', () => {
    const data = { kind: 'azapps', data: [{ Properties: { appId: 'app-123', displayName: 'MyApp', tenantId: 't-1' } }] };
    const finding = parseAzureHoundFile(JSON.stringify(data), 'apps.json');
    expect(finding.nodes[0].type).toBe('cloud_identity');
    expect(finding.nodes[0].principal_type).toBe('app');
  });

  it('parses Azure service principals', () => {
    const data = { kind: 'azserviceprincipals', data: [{ Properties: { id: 'sp-1', displayName: 'MySP', appId: 'app-123' } }] };
    const finding = parseAzureHoundFile(JSON.stringify(data), 'serviceprincipals.json');
    expect(finding.nodes[0].type).toBe('cloud_identity');
    expect(finding.nodes[0].principal_type).toBe('service_account');
    expect(finding.edges.some(e => e.properties.type === 'ASSUMES_ROLE')).toBe(true);
  });

  it('parses Azure role assignments → HAS_POLICY edges', () => {
    const data = {
      kind: 'azroleassignments',
      data: [{ Properties: { principalId: 'user-obj-1', roleDefinitionName: 'Contributor', roleDefinitionId: 'role-def-1' } }]
    };
    const finding = parseAzureHoundFile(JSON.stringify(data), 'roleassignments.json');
    const policyNode = finding.nodes.find(n => n.type === 'cloud_policy');
    expect(policyNode).toBeTruthy();
    expect(policyNode!.policy_name).toBe('Contributor');
    expect(finding.edges.some(e => e.properties.type === 'HAS_POLICY')).toBe(true);
  });

  it('parses Azure app role assignments → ASSUMES_ROLE edges', () => {
    const data = {
      kind: 'azapproleassignments',
      data: [{ Properties: { principalId: 'user-obj-1', resourceId: 'sp-1' } }]
    };
    const finding = parseAzureHoundFile(JSON.stringify(data), 'approleassignments.json');
    expect(finding.edges.some(e => e.properties.type === 'ASSUMES_ROLE')).toBe(true);
  });

  it('infers kind from filename when kind field is absent', () => {
    const data = [{ Properties: { id: 'user-1', displayName: 'Test', userPrincipalName: 'test@test.com' } }];
    const finding = parseAzureHoundFile(JSON.stringify({ data }), 'azusers.json');
    // Should infer 'azusers' from filename
    expect(finding.nodes[0]?.type).toBe('cloud_identity');
  });

  it('handles invalid JSON gracefully', () => {
    const finding = parseAzureHoundFile('not json', 'bad.json');
    expect(finding.nodes).toHaveLength(0);
  });
});
