// ============================================================
// CI / OIDC federation parsers + CI_TRUST_WILDCARD inference rule.
//
// Track B of the post-enterprise plan. Each parser emits the same
// identity-tier shape (idp + idp_application + ISSUES_TOKENS_FOR
// when the cloud side is also visible) and the wildcard rule flags
// overly-broad GitHub Actions trust patterns.
// ============================================================

import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { existsSync, rmSync, unlinkSync } from 'fs';
import Graph from 'graphology';
import {
  parseGitHubActionsOidc,
  parseGitlabCiOidc,
  parseCircleciOidc,
} from '../services/parsers/index.js';
import { runCrossTierInference } from '../services/cross-tier-inference.js';
import { EngineContext } from '../services/engine-context.js';
import type { OverwatchGraph } from '../services/engine-context.js';
import type { EdgeProperties, NodeProperties } from '../types.js';

const TEST_STATE_FILE = './state-test-ci-oidc.json';

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-ci-oidc', { recursive: true, force: true }); } catch {}
}

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, allowSelfLoops: true, type: 'directed' }) as OverwatchGraph;
}
function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  const now = new Date().toISOString();
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}
function makeConfig() {
  return {
    id: 'test-ci-oidc',
    name: 'ci-oidc test',
    created_at: '2026-05-07T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  } as any;
}
function buildHost(graph: OverwatchGraph, config: any) {
  const ctx = new EngineContext(graph, config, TEST_STATE_FILE);
  return {
    ctx,
    addEdge: (src: string, tgt: string, props: EdgeProperties) => {
      const existing = graph.edges(src, tgt).find(eid => graph.getEdgeAttributes(eid).type === props.type);
      if (existing) return { id: existing, isNew: false };
      const id = graph.addEdge(src, tgt, props);
      return { id, isNew: true };
    },
    log: () => {},
  };
}

beforeEach(cleanup);
afterEach(cleanup);

// =============================================
// GitHub Actions OIDC parser
// =============================================

describe('parseGitHubActionsOidc', () => {
  it('extracts idp + idp_application + cloud_identity + ISSUES_TOKENS_FOR from a GHA trust policy', () => {
    const trust = {
      Role: {
        RoleName: 'GhaDeployer',
        Arn: 'arn:aws:iam::111111111111:role/GhaDeployer',
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Federated: 'arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com' },
            Action: 'sts:AssumeRoleWithWebIdentity',
            Condition: {
              StringLike: {
                'token.actions.githubusercontent.com:sub': 'repo:acme/webapp:ref:refs/heads/main',
              },
            },
          }],
        },
      },
    };
    const finding = parseGitHubActionsOidc(JSON.stringify(trust));

    const idp = finding.nodes.find(n => n.type === 'idp');
    expect(idp).toBeDefined();
    expect(idp!.idp_kind).toBe('ci_github_actions');
    expect(idp!.issuer_url).toBe('https://token.actions.githubusercontent.com');

    const app = finding.nodes.find(n => n.type === 'idp_application');
    expect(app).toBeDefined();
    expect(app!.client_id).toBe('acme/webapp');
    expect(app!.sub_claim_pattern).toBe('repo:acme/webapp:ref:refs/heads/main');

    const cloud = finding.nodes.find(n => n.type === 'cloud_identity');
    expect(cloud).toBeDefined();
    expect(cloud!.arn).toBe('arn:aws:iam::111111111111:role/GhaDeployer');

    const issues = finding.edges.filter(e => e.properties.type === 'ISSUES_TOKENS_FOR');
    expect(issues).toHaveLength(1);
    expect(issues[0].properties.sub_claim_pattern).toBe('repo:acme/webapp:ref:refs/heads/main');
  });

  it('preserves sub_claim_pattern for an unbounded wildcard (`repo:*`)', () => {
    const trust = {
      Role: {
        RoleName: 'BadRole',
        Arn: 'arn:aws:iam::222:role/BadRole',
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Federated: 'arn:aws:iam::222:oidc-provider/token.actions.githubusercontent.com' },
            Condition: { StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:*' } },
          }],
        },
      },
    };
    const finding = parseGitHubActionsOidc(JSON.stringify(trust));
    const app = finding.nodes.find(n => n.type === 'idp_application')!;
    expect(app.sub_claim_pattern).toBe('repo:*');
  });

  it('emits a node + ISSUES_TOKENS_FOR edge for EVERY subject in a `:sub` array (wildcard not dropped)', () => {
    // A StringLike `:sub` condition is commonly an array; the old pickCondition
    // returned only v[0], hiding a wide-open `repo:*` alongside a narrow pattern.
    const trust = {
      Role: {
        RoleName: 'MultiSubRole',
        Arn: 'arn:aws:iam::444:role/MultiSubRole',
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Federated: 'arn:aws:iam::444:oidc-provider/token.actions.githubusercontent.com' },
            Condition: {
              StringLike: {
                'token.actions.githubusercontent.com:sub': [
                  'repo:acme/webapp:ref:refs/heads/main',
                  'repo:*',
                ],
              },
            },
          }],
        },
      },
    };
    const finding = parseGitHubActionsOidc(JSON.stringify(trust));

    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    const patterns = apps.map(a => a.sub_claim_pattern).sort();
    expect(patterns).toEqual(['repo:*', 'repo:acme/webapp:ref:refs/heads/main']);

    // The wildcard app must have its own ISSUES_TOKENS_FOR edge to the role so
    // the CI_TRUST_WILDCARD rule can see it.
    const issues = finding.edges.filter(e => e.properties.type === 'ISSUES_TOKENS_FOR');
    expect(issues.map(e => e.properties.sub_claim_pattern).sort())
      .toEqual(['repo:*', 'repo:acme/webapp:ref:refs/heads/main']);
    // Exactly one role node, regardless of subject count.
    expect(finding.nodes.filter(n => n.type === 'cloud_identity')).toHaveLength(1);
  });

  it('does not crash on a malformed Condition operator mapping to null', () => {
    const trust = {
      Role: {
        RoleName: 'MalformedRole',
        Arn: 'arn:aws:iam::555:role/MalformedRole',
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Federated: 'arn:aws:iam::555:oidc-provider/token.actions.githubusercontent.com' },
            Condition: { StringLike: null, StringEquals: { 'token.actions.githubusercontent.com:sub': 'repo:acme/app:ref:refs/heads/main' } },
          }],
        },
      },
    };
    // Must not throw (Object.keys(null) guard) and still parse the valid operator.
    const finding = parseGitHubActionsOidc(JSON.stringify(trust));
    const app = finding.nodes.find(n => n.type === 'idp_application');
    expect(app).toBeDefined();
    expect(app!.client_id).toBe('acme/app');
  });

  it('returns empty for non-GHA trust (Federated is not GitHub Actions)', () => {
    const trust = {
      Role: {
        RoleName: 'OtherRole',
        AssumeRolePolicyDocument: {
          Statement: [{ Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::333:oidc-provider/sts.amazonaws.com' } }],
        },
      },
    };
    const finding = parseGitHubActionsOidc(JSON.stringify(trust));
    expect(finding.nodes.find(n => n.type === 'idp_application')).toBeUndefined();
  });
});

// =============================================
// GitLab CI OIDC parser
// =============================================

describe('parseGitlabCiOidc', () => {
  it('extracts idp + idp_application from JSON id_tokens block', () => {
    const bundle = {
      project: 'acme/webapp',
      'deploy-prod': {
        id_tokens: { GITLAB_OIDC_TOKEN: { aud: 'https://vault.example.com' } },
      },
    };
    const finding = parseGitlabCiOidc(JSON.stringify(bundle));
    const idp = finding.nodes.find(n => n.type === 'idp')!;
    expect(idp.idp_kind).toBe('ci_gitlab');
    expect(idp.tenant_id).toBe('acme/webapp');
    const app = finding.nodes.find(n => n.type === 'idp_application')!;
    expect(app.audience).toBe('https://vault.example.com');
  });

  it('parses a YAML-shaped .gitlab-ci.yml subset', () => {
    const yaml = [
      'deploy:',
      '  id_tokens:',
      '    GITLAB_OIDC_TOKEN:',
      '      aud: https://aws-sts.example.com',
      '  script:',
      '    - echo deploy',
      '',
      'lint:',
      '  script:',
      '    - eslint',
    ].join('\n');
    const finding = parseGitlabCiOidc(yaml, 'test', { gitlab_project: 'acme/webapp' } as any);
    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps).toHaveLength(1);
    expect(apps[0].audience).toBe('https://aws-sts.example.com');
  });
});

// =============================================
// CircleCI OIDC parser
// =============================================

describe('parseCircleciOidc', () => {
  it('extracts idp + idp_application from JSON workflows', () => {
    const bundle = {
      org_id: 'acme-org',
      project_id: 'webapp',
      workflows: { build: { jobs: ['deploy', 'test'] } },
    };
    const finding = parseCircleciOidc(JSON.stringify(bundle));
    const idp = finding.nodes.find(n => n.type === 'idp')!;
    expect(idp.idp_kind).toBe('ci_circleci');
    expect(idp.tenant_id).toBe('acme-org/webapp');
    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps).toHaveLength(2);
  });

  it('emits a placeholder application when YAML references OIDC without explicit jobs', () => {
    const yaml = [
      'jobs:',
      '  deploy:',
      '    environment:',
      '      OIDC_TOKEN_FILE: /tmp/circle_token',
    ].join('\n');
    const finding = parseCircleciOidc(yaml, 'test', { circleci_org_id: 'acme-org', circleci_project_id: 'webapp' } as any);
    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps.length).toBeGreaterThanOrEqual(1);
  });
});

// =============================================
// CI_TRUST_WILDCARD inference rule
// =============================================

describe('CI_TRUST_WILDCARD inference rule', () => {
  it('flags `repo:*` as overly broad', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-gha', { type: 'idp', idp_kind: 'ci_github_actions', tenant_id: 'public' });
    addNode(graph, 'app-bad', { type: 'idp_application', client_id: 'bad', idp_id: 'idp-gha', sub_claim_pattern: 'repo:*' });

    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ci_trust_wildcard).toBe(1);
    const node = graph.getNodeAttributes('app-bad');
    expect(node.wildcard_trust).toBe(true);
    expect(node.wildcard_trust_reason).toMatch(/owner position/);
  });

  it('flags `repo:acme*` (wildcard inside owner segment) as overly broad', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-gha', { type: 'idp', idp_kind: 'ci_github_actions', tenant_id: 'public' });
    addNode(graph, 'app-shifty', { type: 'idp_application', client_id: 'shifty', idp_id: 'idp-gha', sub_claim_pattern: 'repo:acme*/webapp:ref:refs/heads/main' });

    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ci_trust_wildcard).toBe(1);
    expect(graph.getNodeAttributes('app-shifty').wildcard_trust).toBe(true);
  });

  it('does NOT flag `repo:acme/*` (org-bounded wildcard)', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-gha', { type: 'idp', idp_kind: 'ci_github_actions', tenant_id: 'public' });
    addNode(graph, 'app-ok', { type: 'idp_application', client_id: 'ok', idp_id: 'idp-gha', sub_claim_pattern: 'repo:acme/*' });

    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ci_trust_wildcard).toBe(0);
    expect(graph.getNodeAttributes('app-ok').wildcard_trust).toBeUndefined();
  });

  it('does NOT flag a fully-qualified pattern (`repo:acme/webapp:ref:refs/heads/main`)', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-gha', { type: 'idp', idp_kind: 'ci_github_actions', tenant_id: 'public' });
    addNode(graph, 'app-perfect', { type: 'idp_application', client_id: 'perfect', idp_id: 'idp-gha', sub_claim_pattern: 'repo:acme/webapp:ref:refs/heads/main' });

    const host = buildHost(graph, makeConfig());
    const r = runCrossTierInference(host);
    expect(r.ci_trust_wildcard).toBe(0);
  });

  it('is idempotent — second run adds no new findings', () => {
    const graph = makeGraph();
    addNode(graph, 'idp-gha', { type: 'idp', idp_kind: 'ci_github_actions', tenant_id: 'public' });
    addNode(graph, 'app-bad', { type: 'idp_application', client_id: 'bad', idp_id: 'idp-gha', sub_claim_pattern: 'repo:*' });

    const host = buildHost(graph, makeConfig());
    const r1 = runCrossTierInference(host);
    const r2 = runCrossTierInference(host);
    expect(r1.ci_trust_wildcard).toBe(1);
    expect(r2.ci_trust_wildcard).toBe(0);
  });
});
