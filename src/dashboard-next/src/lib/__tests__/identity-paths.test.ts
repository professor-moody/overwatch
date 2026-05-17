import { describe, expect, it } from 'vitest';
import { groupByIdp, tokenCredentials } from '../../components/panels/IdentityPanel';
import { computePaths } from '../../components/panels/AttackPathsPanel';
import type { ExportedEdge, ExportedGraph, ExportedNode } from '../types';

const now = '2026-05-15T18:23:34.963Z';

function node(id: string, type: ExportedNode['type'], label = id, extra: Record<string, unknown> = {}): ExportedNode {
  return { id, type, label, confidence: 1, discovered_at: now, ...extra };
}

function edge(source: string, target: string, type: string, extra: Record<string, unknown> = {}): ExportedEdge {
  return { source, target, type, confidence: 1, discovered_at: now, ...extra };
}

describe('identity and attack path demo helpers', () => {
  it('groups identity apps and principals by explicit IdP metadata', () => {
    const nodes: ExportedNode[] = [
      node('idp-okta', 'idp', 'Okta Corp', { idp_kind: 'okta', tenant_id: 'corp-okta', federation_mode: 'saml+oidc' }),
      node('idp-app-benefits', 'idp_application', 'Benefits Portal SSO', { idp_id: 'idp-okta', app_name: 'Benefits Portal', app_mfa_required: true }),
      node('idp-principal-jdoe', 'idp_principal', 'jdoe@corp.local', { idp_id: 'idp-okta', username: 'jdoe@corp.local', mfa_factors: ['webauthn'] }),
      node('cred-okta-cookie', 'credential', 'jdoe:Okta session', { cred_material_kind: 'session_cookie', cred_user: 'jdoe@corp.local' }),
      node('domain-corp-local', 'domain', 'corp.local', { domain_name: 'corp.local' }),
    ];
    const edges = [
      edge('idp-okta', 'domain-corp-local', 'FEDERATES_WITH'),
      edge('idp-principal-jdoe', 'idp-app-benefits', 'ASSIGNED_TO_APP'),
    ];

    const [okta] = groupByIdp(nodes, edges);

    expect(okta.idp.id).toBe('idp-okta');
    expect(okta.apps.map(app => app.id)).toEqual(['idp-app-benefits']);
    expect(okta.principals.map(principal => principal.id)).toEqual(['idp-principal-jdoe']);
    expect(okta.federatedDomains).toEqual(['corp.local']);
    expect(tokenCredentials(nodes).map(cred => cred.id)).toEqual(['cred-okta-cookie']);
  });

  it('computes AD, hybrid identity, and CI/OIDC cloud paths from live session sources', () => {
    const graph: ExportedGraph = {
      nodes: [
        node('ws01', 'host', 'WS01', { compromised: true }),
        node('jdoe', 'user', 'jdoe'),
        node('domain-admins', 'group', 'Domain Admins'),
        node('dc01', 'host', 'DC01', { hvt: true }),
        node('cred-okta', 'credential', 'jdoe:Okta session'),
        node('benefits-app', 'idp_application', 'Benefits Portal SSO'),
        node('backup-role', 'cloud_identity', 'AWS BackupRole', { hvt: true }),
        node('backup-policy', 'cloud_policy', 'BackupReadPolicy'),
        node('payroll', 'cloud_resource', 's3://corp-payroll-archive', { hvt: true }),
        node('cred-gha', 'credential', 'GitHub Actions OIDC token'),
        node('gha-app', 'idp_application', 'benefits-portal deploy'),
        node('deploy-role', 'cloud_identity', 'AWS DeployRole'),
        node('admin-role', 'cloud_identity', 'AWS AdminRole', { hvt: true }),
      ],
      edges: [
        edge('jdoe', 'ws01', 'HAS_SESSION', { session_live: true }),
        edge('jdoe', 'domain-admins', 'MEMBER_OF'),
        edge('domain-admins', 'dc01', 'ADMIN_TO'),
        edge('jdoe', 'cred-okta', 'OWNS_CRED'),
        edge('cred-okta', 'benefits-app', 'VALID_FOR_APP'),
        edge('benefits-app', 'backup-role', 'ISSUES_TOKENS_FOR'),
        edge('backup-role', 'backup-policy', 'HAS_POLICY'),
        edge('backup-policy', 'payroll', 'POLICY_ALLOWS'),
        edge('jdoe', 'cred-gha', 'OWNS_CRED'),
        edge('cred-gha', 'gha-app', 'VALID_FOR_APP'),
        edge('gha-app', 'deploy-role', 'ISSUES_TOKENS_FOR'),
        edge('deploy-role', 'admin-role', 'ASSUMES_ROLE'),
      ],
    };
    const byId = new Map(graph.nodes.map(n => [n.id, n]));
    const paths = computePaths(graph.nodes, graph.edges, 'confidence', 6, byId).map(path => path.nodes.join('>'));

    expect(paths).toContain('ws01>jdoe>domain-admins>dc01');
    expect(paths).toContain('ws01>jdoe>cred-okta>benefits-app>backup-role>backup-policy>payroll');
    expect(paths).toContain('ws01>jdoe>cred-gha>gha-app>deploy-role>admin-role');
  });
});
