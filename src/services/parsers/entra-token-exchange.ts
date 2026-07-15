// Microsoft identity-platform OAuth refresh-token exchange response.

import type { EdgeType, Finding, ParseContext } from '../../types.js';
import { credentialId } from '../parser-utils.js';

interface TokenExchangeResponse {
  token_type?: string;
  scope?: string;
  expires_in?: number;
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  error?: string;
  error_description?: string;
}

function jwtClaims(token: string | undefined): Record<string, unknown> {
  if (!token) return {};
  try {
    const segment = token.split('.')[1];
    if (!segment) return {};
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function concreteTenant(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  return /^(common|organizations|consumers|unknown)$/i.test(value) ? undefined : value;
}

export function parseEntraTokenExchange(
  output: string,
  agentId: string = 'entra-token-exchange-parser',
  context?: ParseContext,
): Finding {
  const now = new Date().toISOString();
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  let payload: TokenExchangeResponse;
  try {
    payload = JSON.parse(output) as TokenExchangeResponse;
  } catch {
    return { id: `entra-token-exchange-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const sourceCredentialId = context?.source_credential_id;
  const claims = jwtClaims(payload.access_token ?? payload.id_token);
  const tenantAlias = typeof context?.tenant_id === 'string' ? context.tenant_id : undefined;
  const tenant = concreteTenant(claims.tid) ?? concreteTenant(tenantAlias);
  const tenantLabel = tenant ?? 'unresolved';
  const issuer = typeof claims.iss === 'string' ? claims.iss
    : tenant ? `https://login.microsoftonline.com/${tenant}/v2.0` : undefined;
  const requestedScope = typeof context?.requested_scope === 'string' ? context.requested_scope : undefined;

  if (typeof payload.access_token === 'string' && payload.access_token.length > 0) {
    const accessCredentialId = credentialId('oidc_access_token', payload.access_token, undefined, tenant);
    const expiresIn = typeof payload.expires_in === 'number' && Number.isFinite(payload.expires_in)
      ? Math.max(0, payload.expires_in)
      : undefined;
    const scopes = (payload.scope ?? requestedScope)?.split(/\s+/).filter(Boolean);
    const graphScope = scopes?.find(scope => scope.startsWith('https://graph.microsoft.com/'));
    nodes.push({
      id: accessCredentialId,
      type: 'credential',
      label: `entra-access-token:${tenantLabel}`,
      cred_type: 'oidc_token',
      cred_material_kind: 'oidc_access_token',
      cred_value: payload.access_token,
      cred_audience: graphScope ? 'https://graph.microsoft.com' : undefined,
      cred_scopes: scopes,
      cred_issuer: issuer,
      cred_token_expires_at: expiresIn === undefined
        ? undefined
        : new Date(Date.now() + expiresIn * 1000).toISOString(),
      cred_evidence_kind: 'capture',
      cred_usable_for_auth: true,
      credential_status: 'active',
      tenant_id: tenant,
      token_endpoint_tenant_alias: tenantAlias,
      oauth_client_id: context?.client_id,
      refresh_token_rotated: typeof payload.refresh_token === 'string',
      discovered_at: now,
      confidence: 1.0,
    });

    if (typeof payload.refresh_token === 'string' && payload.refresh_token.length > 0) {
      const refreshCredentialId = credentialId('oidc_refresh_token', payload.refresh_token, undefined, tenant);
      if (refreshCredentialId !== sourceCredentialId) {
        nodes.push({
          id: refreshCredentialId,
          type: 'credential',
          label: `entra-refresh-token:${tenantLabel}`,
          cred_type: 'token',
          cred_material_kind: 'oidc_refresh_token',
          cred_value: payload.refresh_token,
          cred_scopes: scopes,
          cred_issuer: issuer,
          cred_evidence_kind: 'capture',
          cred_usable_for_auth: false,
          credential_status: 'active',
          tenant_id: tenant,
          token_endpoint_tenant_alias: tenantAlias,
          oauth_client_id: context?.client_id,
          discovered_at: now,
          confidence: 1.0,
        });
        if (sourceCredentialId) {
          edges.push({
            source: refreshCredentialId,
            target: sourceCredentialId,
            properties: {
              type: 'DERIVED_FROM' as EdgeType,
              confidence: 1.0,
              discovered_at: now,
              discovered_by: agentId,
              notes: 'Rotated refresh token returned by the Entra token endpoint',
            },
          });
          nodes.push({
            id: sourceCredentialId,
            type: 'credential',
            label: 'token-exchange-result',
            preserve_existing_label: true,
            credential_status: 'rotated',
            rotated_at: now,
            discovered_at: now,
            confidence: 1.0,
          });
        }
      }
    }
    if (sourceCredentialId) {
      edges.push({
        source: accessCredentialId,
        target: sourceCredentialId,
        properties: {
          type: 'DERIVED_FROM' as EdgeType,
          confidence: 1.0,
          discovered_at: now,
          discovered_by: agentId,
          notes: 'Access token minted from the selected Entra refresh token',
        },
      });
    }
  } else if (payload.error && sourceCredentialId) {
    const invalidGrant = payload.error === 'invalid_grant';
    nodes.push({
      id: sourceCredentialId,
      type: 'credential',
      label: 'token-exchange-result',
      preserve_existing_label: true,
      ...(invalidGrant ? { credential_status: 'expired' as const } : {}),
      token_exchange_error: payload.error,
      token_exchange_error_description: payload.error_description,
      token_exchange_observed_at: now,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  const inconclusiveError = !!payload.error && payload.error !== 'invalid_grant';
  return {
    id: `entra-token-exchange-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges,
    partial: inconclusiveError || undefined,
    partial_reason: inconclusiveError ? `entra_token_exchange_${payload.error}` : undefined,
  };
}
