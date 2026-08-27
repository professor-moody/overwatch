import type { ExportedEdge, ExportedNode } from './types';
import { credentialExpiry, type CredentialExpiry } from './credential-display';

export interface IdentityProviderGroup {
  idp: ExportedNode;
  applications: ExportedNode[];
  principals: ExportedNode[];
  federatedDomains: string[];
}

export interface IdentityTokenSummary {
  node: ExportedNode;
  kind: string;
  user?: string;
  audience?: string;
  scopes: string[];
  expires?: string;
  expiry: CredentialExpiry | null;
  status: 'usable' | 'MFA satisfied' | 'MFA blocked';
}

const TOKEN_KINDS = new Set([
  'oidc_id_token', 'oidc_access_token', 'oidc_refresh_token', 'saml_assertion',
  'oauth_client_secret', 'pat', 'app_password', 'session_cookie', 'aws_session_credentials',
]);

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length ? value : undefined;
}

export function buildIdentityProviderGroups(nodes: ExportedNode[], edges: ExportedEdge[]): IdentityProviderGroup[] {
  const providers = nodes.filter(node => node.type === 'idp');
  const applications = nodes.filter(node => node.type === 'idp_application');
  const principals = nodes.filter(node => node.type === 'idp_principal');
  const relationships = edges.filter(edge => edge.type === 'TRUSTS' || edge.type === 'ASSIGNED_TO_APP');
  return providers.map(idp => {
    const applicationIds = new Set(relationships.filter(edge => edge.target === idp.id).map(edge => edge.source));
    const groupedApplications = applications.filter(application => applicationIds.has(application.id) || stringValue(application.idp_id) === idp.id);
    const groupedApplicationIds = new Set(groupedApplications.map(application => application.id));
    const kind = stringValue(idp.idp_kind);
    const tenant = stringValue(idp.tenant_id);
    const groupedPrincipals = principals.filter(principal =>
      stringValue(principal.idp_id) === idp.id
      || relationships.some(edge => edge.source === principal.id && groupedApplicationIds.has(edge.target))
      || Boolean(kind && tenant && principal.id.includes(`${kind}-${tenant}`)));
    const federatedDomains = edges
      .filter(edge => edge.type === 'FEDERATES_WITH' && (edge.source === idp.id || edge.target === idp.id))
      .map(edge => nodes.find(node => node.id === (edge.source === idp.id ? edge.target : edge.source)))
      .map(peer => stringValue(peer?.domain_name) || peer?.label)
      .filter((value): value is string => Boolean(value));
    return { idp, applications: groupedApplications, principals: groupedPrincipals, federatedDomains };
  });
}

export function buildIdentityTokenSummaries(nodes: ExportedNode[], now = Date.now()): IdentityTokenSummary[] {
  return nodes.filter(node => node.type === 'credential' && TOKEN_KINDS.has(stringValue(node.cred_material_kind) || '')).map(node => {
    // Identity inventories and palette-adjacent models carry safe metadata only.
    // The full credential remains in the engagement store for the explicit reveal
    // flow, but its material must not leak through a derived/searchable summary.
    const { cred_value: _credentialValue, ...safeNode } = node;
    return {
      node: safeNode as ExportedNode,
      kind: stringValue(node.cred_material_kind) || 'token',
      user: stringValue(node.cred_user),
      audience: stringValue(node.cred_audience),
      scopes: Array.isArray(node.cred_scopes) ? node.cred_scopes.filter((scope): scope is string => typeof scope === 'string') : [],
      expires: stringValue(node.cred_token_expires_at),
      expiry: credentialExpiry(node, now),
      status: node.cred_mfa_satisfied === true ? 'MFA satisfied' : node.cred_mfa_required === true ? 'MFA blocked' : 'usable',
    };
  });
}
