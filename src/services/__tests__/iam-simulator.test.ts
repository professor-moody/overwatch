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

function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Partial<EdgeProperties> = {}) {
  graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: new Date().toISOString(), ...extra } as EdgeProperties);
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

    it('returns indeterminate when only a conditional allow could match', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/viewer' });
      addNode(graph, 'conditional-allow', {
        type: 'cloud_policy', policy_name: 'MfaOnlyRead', effect: 'allow',
        actions: ['s3:GetObject'], resources: ['arn:aws:s3:::private/*'], condition_present: true,
      });
      addEdge(graph, 'user-1', 'conditional-allow', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::private/key', ctx);
      expect(result).toMatchObject({ allowed: false, decision: 'indeterminate' });
      expect(result.reason).toContain('conditional allow');
    });

    it('does not claim an unconditional allow when a matching conditional deny may apply', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/viewer' });
      addNode(graph, 'allow', {
        type: 'cloud_policy', policy_name: 'Read', effect: 'allow', actions: ['s3:GetObject'], resources: ['*'],
      });
      addNode(graph, 'conditional-deny', {
        type: 'cloud_policy', policy_name: 'DenyOutsideNetwork', effect: 'deny',
        actions: ['s3:GetObject'], resources: ['*'], condition_present: true,
      });
      addEdge(graph, 'user-1', 'allow', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'conditional-deny', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::private/key', ctx);
      expect(result).toMatchObject({ allowed: false, decision: 'indeterminate' });
      expect(result.deny_policies).toContain('DenyOutsideNetwork');
    });

    it('returns indeterminate for an attached policy whose document was not expanded', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::123456789:user/viewer' });
      addNode(graph, 'attached', {
        type: 'cloud_policy', policy_name: 'AdministratorAccess',
        policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess',
        permission_expansion: 'unevaluable',
      });
      addEdge(graph, 'user-1', 'attached', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');

      const result = evaluateIAM('user-1', 'iam:CreateUser', '*', ctx);
      expect(result).toMatchObject({
        allowed: false, decision: 'indeterminate',
        enumerated_only_policies: ['AdministratorAccess'],
      });
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

    it('evaluates policies on assumable roles', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:user/dev' });
      addNode(graph, 'role-admin', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/Admin' });
      addNode(graph, 'assume-policy', { type: 'cloud_policy', policy_name: 'AllowAssumeAdmin', effect: 'allow', actions: ['sts:AssumeRole'], resources: ['arn:aws:iam::123:role/Admin'] });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'AdminPolicy', effect: 'allow', actions: ['*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'assume-policy', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'role-admin', 'ASSUMES_ROLE');
      addEdge(graph, 'role-admin', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'iam:CreateUser', 'arn:aws:iam::123:user/new', ctx);
      expect(result.allowed).toBe(true);
      expect(result.matching_policies).toContain('AdminPolicy');
      expect(result.evaluated_principals).toEqual(['user-1', 'role-admin']);
      expect(result.assumption_paths).toEqual([['user-1', 'role-admin']]);
    });

    it('does not evaluate trusted role policies without sts:AssumeRole permission', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:user/dev' });
      addNode(graph, 'role-admin', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/Admin' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'AdminPolicy', effect: 'allow', actions: ['*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'role-admin', 'ASSUMES_ROLE', { assumption_confirmed: false, assumption_basis: 'trust_policy' });
      addEdge(graph, 'role-admin', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'iam:CreateUser', 'arn:aws:iam::123:user/new', ctx);
      expect(result.allowed).toBe(false);
      expect(result.matching_policies).toEqual([]);
      expect(result.evaluated_principals).toEqual(['user-1']);
      expect(result.assumption_paths).toEqual([]);
    });

    it('evaluates a successfully tested assume-role edge without a local policy artifact', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:user/dev' });
      addNode(graph, 'role-admin', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/Admin' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'AdminPolicy', effect: 'allow', actions: ['*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'role-admin', 'ASSUMES_ROLE', { tested: true, test_result: 'success' });
      addEdge(graph, 'role-admin', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'iam:CreateUser', 'arn:aws:iam::123:user/new', ctx);
      expect(result.allowed).toBe(true);
      expect(result.matching_policies).toContain('AdminPolicy');
    });

    it('handles ASSUMES_ROLE cycles without looping', () => {
      const graph = makeGraph();
      addNode(graph, 'role-a', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/A' });
      addNode(graph, 'role-b', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/B' });
      addNode(graph, 'assume-b', { type: 'cloud_policy', policy_name: 'AssumeB', effect: 'allow', actions: ['sts:AssumeRole'], resources: ['arn:aws:iam::123:role/B'] });
      addNode(graph, 'assume-a', { type: 'cloud_policy', policy_name: 'AssumeA', effect: 'allow', actions: ['sts:AssumeRole'], resources: ['arn:aws:iam::123:role/A'] });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'ReadPolicy', effect: 'allow', actions: ['s3:GetObject'], resources: ['*'] });
      addEdge(graph, 'role-a', 'assume-b', 'HAS_POLICY');
      addEdge(graph, 'role-b', 'assume-a', 'HAS_POLICY');
      addEdge(graph, 'role-a', 'role-b', 'ASSUMES_ROLE');
      addEdge(graph, 'role-b', 'role-a', 'ASSUMES_ROLE');
      addEdge(graph, 'role-b', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('role-a', 's3:GetObject', 'arn:aws:s3:::bucket/key', ctx);
      expect(result.allowed).toBe(true);
      expect(result.evaluated_principals).toEqual(['role-a', 'role-b']);
    });

    it('returns indeterminate when assume-role traversal hits the configured depth cap', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:user/dev' });
      addNode(graph, 'role-admin', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/Admin' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'AdminPolicy', effect: 'allow', actions: ['*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'role-admin', 'ASSUMES_ROLE', { tested: true, test_result: 'success' });
      addEdge(graph, 'role-admin', 'policy-1', 'HAS_POLICY');

      const ctx = new EngineContext(graph, { ...makeConfig(), iam_assume_depth: 0 }, './test.json');
      const result = evaluateIAM('user-1', 'iam:CreateUser', 'arn:aws:iam::123:user/new', ctx);
      expect(result.allowed).toBe(false);
      expect(result.decision).toBe('indeterminate');
      expect(result.depth_capped).toBe(true);
      expect(result.warnings?.[0]).toContain('depth cap (0)');
      expect(result.evaluated_principals).toEqual(['user-1']);
    });

    it('explicit deny on an assumed role overrides allow', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:user/dev' });
      addNode(graph, 'role-1', { type: 'cloud_identity', provider: 'aws', arn: 'arn:aws:iam::123:role/Restricted' });
      addNode(graph, 'allow-policy', { type: 'cloud_policy', policy_name: 'AllowS3', effect: 'allow', actions: ['s3:*'], resources: ['*'] });
      addNode(graph, 'assume-policy', { type: 'cloud_policy', policy_name: 'AssumeRestricted', effect: 'allow', actions: ['sts:AssumeRole'], resources: ['arn:aws:iam::123:role/Restricted'] });
      addNode(graph, 'deny-policy', { type: 'cloud_policy', policy_name: 'DenySecret', effect: 'deny', actions: ['s3:GetObject'], resources: ['arn:aws:s3:::secret/*'] });
      addEdge(graph, 'user-1', 'allow-policy', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'assume-policy', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'role-1', 'ASSUMES_ROLE');
      addEdge(graph, 'role-1', 'deny-policy', 'HAS_POLICY');

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::secret/key', ctx);
      expect(result.allowed).toBe(false);
      expect(result.deny_policies).toContain('DenySecret');
    });

    it('matches an action with a MID-string wildcard (s3:*Object)', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'MidStar', effect: 'allow', actions: ['s3:*Object'], resources: ['*'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      // Suffix-only matching would have missed this — s3:GetObject ends in "Object".
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::b/f', ctx).allowed).toBe(true);
      expect(evaluateIAM('user-1', 's3:ListBucket', 'arn:aws:s3:::b', ctx).allowed).toBe(false);
    });

    it('applies NotAction: allows everything EXCEPT the excluded actions', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      // Allow all actions except iam:* (an "Allow NotAction: iam:*" statement).
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'NotIam', effect: 'allow', not_actions: ['iam:*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::b/f', ctx).allowed).toBe(true);
      expect(evaluateIAM('user-1', 'iam:CreateUser', '*', ctx).allowed).toBe(false);
    });

    it('applies NotResource: allows the action EXCEPT on the excluded resource', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'NotSecret', effect: 'allow', actions: ['s3:*'], not_resources: ['arn:aws:s3:::secret/*'], resources: [] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::public/f', ctx).allowed).toBe(true);
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::secret/key', ctx).allowed).toBe(false);
    });

    it('a Deny NotAction is no longer a no-op (denies everything except the listed actions)', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'allow', { type: 'cloud_policy', policy_name: 'AllowAll', effect: 'allow', actions: ['*'], resources: ['*'] });
      // Deny everything EXCEPT s3:* — so ec2:* must be denied.
      addNode(graph, 'deny', { type: 'cloud_policy', policy_name: 'DenyNotS3', effect: 'deny', not_actions: ['s3:*'], resources: ['*'] });
      addEdge(graph, 'user-1', 'allow', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'deny', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      expect(evaluateIAM('user-1', 'ec2:RunInstances', '*', ctx).allowed).toBe(false);
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::b/f', ctx).allowed).toBe(true);
    });

    it('an Allow NotResource statement does NOT answer a blanket "anywhere" (*) query with yes', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'NotSecret', effect: 'allow', actions: ['s3:*'], not_resources: ['arn:aws:s3:::secret/*'], resources: [] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      // "can P GetObject anywhere?" — must NOT be a blanket allow (secret/* is excluded).
      expect(evaluateIAM('user-1', 's3:GetObject', '*', ctx).allowed).toBe(false);
      // but a concrete non-excluded resource is still allowed.
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::public/f', ctx).allowed).toBe(true);
    });

    it('a Deny NotResource statement does NOT fire on a blanket "anywhere" (*) query', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'allow', { type: 'cloud_policy', policy_name: 'AllowAll', effect: 'allow', actions: ['*'], resources: ['*'] });
      // Deny everything except public/* — must not blanket-deny a '*' query.
      addNode(graph, 'deny', { type: 'cloud_policy', policy_name: 'DenyNotPublic', effect: 'deny', actions: ['*'], not_resources: ['arn:aws:s3:::public/*'], resources: [] });
      addEdge(graph, 'user-1', 'allow', 'HAS_POLICY');
      addEdge(graph, 'user-1', 'deny', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      // '*' query: the scoped deny doesn't fire, so the blanket allow governs.
      expect(evaluateIAM('user-1', 's3:GetObject', '*', ctx).allowed).toBe(true);
      // concrete excluded resource: deny still correctly skips (public/* excluded from deny).
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::public/f', ctx).allowed).toBe(true);
      // concrete non-excluded resource: deny fires.
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::other/f', ctx).allowed).toBe(false);
    });

    it('a *:* pattern matches actions but a resource *:* still requires the ARN shape', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      // actions '*:*' = all actions; resources '*:*' is non-idiomatic and must NOT
      // blanket-match a resource with no colon.
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'Weird', effect: 'allow', actions: ['*:*'], resources: ['*:*'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::b/f', ctx).allowed).toBe(true); // colon-bearing ARN
      expect(evaluateIAM('user-1', 's3:GetObject', 'plainname', ctx).allowed).toBe(false); // no colon → not matched
    });

    it('a one-char glob (?) resource does NOT answer an "anywhere" (*) query as a match-all', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'OneChar', effect: 'allow', actions: ['s3:*'], resources: ['?'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      // '?' glob-matches the literal 1-char string '*' but is NOT match-all.
      expect(evaluateIAM('user-1', 's3:GetObject', '*', ctx).allowed).toBe(false);
      expect(evaluateIAM('user-1', 's3:GetObject', 'arn:aws:s3:::b/f', ctx).allowed).toBe(false);
    });

    it('a many-wildcard resource pattern evaluates in linear time (no ReDoS)', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: 'arn:aws:iam::1:user/u' });
      addNode(graph, 'policy-1', { type: 'cloud_policy', policy_name: 'Globby', effect: 'allow', actions: ['s3:*'], resources: ['arn:*:*:*:*:*:*:*:*:*x'] });
      addEdge(graph, 'user-1', 'policy-1', 'HAS_POLICY');
      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      // A long resource that does NOT end in 'x' is the classic ReDoS trigger.
      const longResource = 'arn:aws:s3:::' + 'a'.repeat(5000);
      const start = Date.now();
      const result = evaluateIAM('user-1', 's3:GetObject', longResource, ctx);
      expect(Date.now() - start).toBeLessThan(1000);
      expect(result.allowed).toBe(false); // pattern requires a trailing 'x'
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

    it('returns indeterminate for assigned Azure roles that cannot be permission-expanded', () => {
      const graph = makeGraph();
      addNode(graph, 'user-1', { type: 'user', arn: '/subscriptions/123', principal_type: 'managed_identity' });
      addNode(graph, 'role-unknown', {
        type: 'cloud_policy',
        policy_name: 'Custom Mystery Operator',
        role_definition_name: 'Custom Mystery Operator',
        resources: ['/subscriptions/123'],
        permission_expansion: 'enumerated_only',
      });
      addEdge(graph, 'user-1', 'role-unknown', 'HAS_POLICY', {
        scope: '/subscriptions/123',
        role_definition_name: 'Custom Mystery Operator',
      });

      const ctx = new EngineContext(graph, makeConfig(), './test.json');
      const result = evaluateIAM('user-1', 'Microsoft.Compute/virtualMachines/start', '/subscriptions/123/resourceGroups/rg1/vm/1', ctx);
      expect(result.allowed).toBe(false);
      expect(result.decision).toBe('indeterminate');
      expect(result.enumerated_only_policies).toEqual(['Custom Mystery Operator']);
      expect(result.reason).toContain('not permission-expanded');
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
