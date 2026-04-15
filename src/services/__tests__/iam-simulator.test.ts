import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import { EngineContext } from '../engine-context.js';
import { evaluateIAM } from '../iam-simulator.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig() {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
  } as any;
}

function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: new Date().toISOString(), confidence: 1.0, ...props } as NodeProperties);
}

function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string) {
  graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: new Date().toISOString() } as EdgeProperties);
}

describe('IAM Simulator', () => {
  describe('AWS evaluation', () => {
    it('allows action when matching allow policy exists', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/admin' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'AdminPolicy', effect: 'allow', actions: ['s3:*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::my-bucket/file.txt', ctx);
      expect(result.allowed).toBe(true);
      expect(result.provider).toBe('aws');
      expect(result.matching_policies).toContain('AdminPolicy');
    });

    it('denies when explicit deny overrides allow', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/admin' });
      addNode(graph, 'allow-policy', { type: 'cloud_policy', policy_name: 'AllowAll', effect: 'allow', actions: ['s3:*'], resources: ['*'] });
      addNode(graph, 'deny-policy', { type: 'cloud_policy', policy_name: 'DenyS3', effect: 'deny', actions: ['s3:GetObject'], resources: ['arn:aws:s3:::restricted/*'] });
      addEdge(graph, 'user-1', 'allow-policy', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'deny-policy', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::restricted/secret.txt', ctx);
      expect(result.allowed).toBe(false);
      expect(result.deny_policies).toContain('DenyS3');
    });

    it('implicitly denies when no matching allow', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/viewer' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'ReadOnly', effect: 'allow', actions: ['s3:GetObject'], resources: ['*'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:PutObject', 'arn:aws:s3:::my-bucket/file.txt', ctx);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Implicitly denied');
    });

    it('traverses group membership for policies', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/dev' });
      addNode(graph, 'group-1', { type: 'group', label: 'Developers' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'DevPolicy', effect: 'allow', actions: ['ec2:*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'group-1', 'MEMBER_OF');
      addEdge(graph, 'group-1', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'ec2:RunInstances', 'arn:aws:ec2:us-east-1:123:instance/*', ctx);
      expect(result.allowed).toBe(true);
      expect(result.matching_policies).toContain('DevPolicy');
    });

    it('returns error for unknown principal', () => {
      const graph = makeGraph();
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('nonexistent', 's3:GetObject', '*', ctx);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Principal not found');
    });

    it('returns denied when no policies attached', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/orphan' });

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:GetObject', '*', ctx);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('No policies');
    });

    it('supports wildcard action matching', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/admin' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'FullAdmin', effect: 'allow', actions: ['*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'iam:CreateUser', 'arn:aws:iam::123:user/new', ctx);
      expect(result.allowed).toBe(true);
    });
  });

  describe('Azure evaluation', () => {
    it('allows action with matching RBAC role', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: '/subscriptions/123', principal_type: 'managed_identity' });
      addNode(graph, 'role-1', { type: 'cloud_policy', policy_name: 'Contributor', effect: 'allow', actions: ['Microsoft.Compute/*'], resources: ['/subscriptions/123'] });
      addEdge(graph, 'user-1', 'role-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'Microsoft.Compute/virtualMachines/start', '/subscriptions/123/resourceGroups/rg1/vm/1', ctx);
      expect(result.allowed).toBe(true);
      expect(result.provider).toBe('azure');
    });

    it('evaluates scope hierarchy (subscription → resource group)', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: '/subscriptions/abc.azure.com', principal_type: 'managed_identity' });
      addNode(graph, 'role-1', { type: 'cloud_policy', policy_name: 'SubReader', effect: 'allow', actions: ['Microsoft.Compute/*'], resources: ['/subscriptions/abc'] });
      addEdge(graph, 'user-1', 'role-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      // Resource is under the subscription scope
      const result = evaluateIAM('user-1', 'Microsoft.Compute/virtualMachines/read', '/subscriptions/abc/resourceGroups/rg1', ctx);
      expect(result.allowed).toBe(true);
      expect(result.provider).toBe('azure');
    });
  });

  describe('GCP evaluation', () => {
    it('allows action with matching IAM binding', () => {
      const graph = makeGraph();
      addNode(graph, 'sa-1', { type: 'user', arn: 'sa@project.iam.gserviceaccount.com', principal_type: 'service_account' });
      addNode(graph, 'binding-1', { type: 'cloud_policy', policy_name: 'StorageAdmin', effect: 'allow', actions: ['storage.objects.get', 'storage.objects.create'], resources: ['*'] });
      addEdge(graph, 'sa-1', 'binding-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('sa-1', 'storage.objects.get', 'projects/myproj/buckets/b1', ctx);
      expect(result.allowed).toBe(true);
      expect(result.provider).toBe('gcp');
    });

    it('deny policy overrides allow', () => {
      const graph = makeGraph();
      addNode(graph, 'sa-1', { type: 'user', principal_type: 'service_account' });
      addNode(graph, 'allow-1', { type: 'cloud_policy', policy_name: 'StorageAdmin', effect: 'allow', actions: ['storage.*'], resources: ['*'] });
      addNode(graph, 'deny-1', { type: 'cloud_policy', policy_name: 'DenyDelete', effect: 'deny', actions: ['storage.objects.delete'], resources: ['*'] });
      addEdge(graph, 'sa-1', 'allow-1', 'HAS_POLICY');
      addEdge(graph, 'sa-1', 'deny-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('sa-1', 'storage.objects.delete', 'projects/p/buckets/b', ctx);
      expect(result.allowed).toBe(false);
      expect(result.deny_policies).toContain('DenyDelete');
    });
  });
});
