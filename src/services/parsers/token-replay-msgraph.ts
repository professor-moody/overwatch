// ============================================================
// Microsoft Graph token-replay response parser.
//
// Consumes the captured stdout from a curl probe against
// https://graph.microsoft.com/v1.0/me (or another Graph endpoint)
// using a captured OIDC access token. The probe itself is run by the
// `validate_token_credential` tool through runInstrumentedProcess —
// this parser only consumes the output.
//
// On 200, the response is a JSON user object. We use it to:
//   - Update / create the matching idp_principal (refreshed UPN, oid).
//   - Mark the source credential cred_mfa_satisfied: true (the call
//     succeeded, so MFA was either not required or was already satisfied).
//
// On 401/403, no graph mutation — the tool layer marks the credential
// as expired / MFA-blocked based on the WWW-Authenticate hint.
//
// Inputs are operator-supplied via parser_context:
//   - source_credential_id: the credential node that was replayed.
//   - source_idp_application_id (optional): the app the token was
//     intended for; used as the target of VALID_FOR_APP.
//   - status_code: the HTTP status returned by curl (parsed at the
//     tool layer from `--write-out '%{http_code}'` output and prepended
//     to the response body before this parser sees it).
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { idpApplicationId, idpId, idpPrincipalId } from '../parser-utils.js';

interface ReplayContext extends ParseContext {
  source_credential_id?: string;
  source_idp_application_id?: string;
  tenant_id?: string;
  /** Operator-prefixed status code, e.g. "[STATUS:200]\n{...}". */
  status_code?: number;
}

function extractStatusAndBody(output: string): { status: number; body: string } {
  // The live curl path appends the marker with `-w`; prefix markers remain
  // accepted for compatibility with existing evidence and direct callers.
  let normalized = output.replace(/\r\n/g, '\n');
  const trailing = normalized.match(/\n?\[STATUS:(\d{3})\]\s*$/);
  const trailingStatus = trailing ? parseInt(trailing[1]) : undefined;
  if (trailing) normalized = normalized.slice(0, trailing.index).trimEnd();
  const prefixed = normalized.match(/^\[STATUS:(\d{3})\]\s*\n?([\s\S]*)$/);
  if (prefixed) return { status: trailingStatus ?? parseInt(prefixed[1]), body: prefixed[2] };
  const headerEnd = normalized.indexOf('\n\n');
  if (headerEnd > 0 && /^HTTP\//i.test(normalized.slice(0, headerEnd))) {
    const headers = normalized.slice(0, headerEnd);
    const statusMatch = headers.match(/^HTTP\/[\d.]+\s+(\d{3})/i);
    return {
      status: trailingStatus ?? (statusMatch ? parseInt(statusMatch[1]) : 0),
      body: normalized.slice(headerEnd + 2),
    };
  }
  return { status: trailingStatus ?? 0, body: normalized };
}

function isSuccessfulMsGraphMe(body: string): { id?: string; userPrincipalName?: string; mail?: string; displayName?: string } | null {
  try {
    const obj = JSON.parse(body) as Record<string, unknown>;
    if (typeof obj.userPrincipalName === 'string' || typeof obj.id === 'string' || typeof obj.mail === 'string') {
      return obj as { id?: string; userPrincipalName?: string; mail?: string; displayName?: string };
    }
    return null;
  } catch {
    return null;
  }
}

function concreteTenant(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  return /^(common|organizations|consumers|unknown)$/i.test(value) ? undefined : value;
}

export function parseTokenReplayMsGraph(output: string, agentId: string = 'token-replay-msgraph', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as ReplayContext;
  const credId = ctx.source_credential_id;
  let appId = ctx.source_idp_application_id;

  const { status, body } = extractStatusAndBody(output);

  // Failure paths — record findings but no graph mutation here.
  if (status === 401 || status === 403) {
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        preserve_existing_label: true,
        discovered_at: now,
        confidence: 1.0,
        // The replay returned auth-rejected — propagate to the credential
        // so isCredentialUsableForAuth flips false on next read.
        credential_status: status === 401 ? 'expired' : 'active',
        cred_mfa_required: status === 403 ? true : undefined,
        cred_mfa_satisfied: status === 403 ? false : undefined,
        notes: `msgraph replay returned ${status}`,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (status !== 200 && status !== 0) {
    // Inconclusive (5xx, 429, etc.) — emit a partial finding only.
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        preserve_existing_label: true,
        discovered_at: now,
        confidence: 0.5,
        notes: `msgraph replay returned ${status} — inconclusive`,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges,
      partial: true, partial_reason: `msgraph_http_${status}_inconclusive` };
  }

  const me = isSuccessfulMsGraphMe(body);
  if (!me) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const tenant = concreteTenant(ctx.tenant_id)
    ?? concreteTenant(me.userPrincipalName?.split('@')[1])
    ?? concreteTenant(me.mail?.split('@')[1]);
  if (!tenant) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }
  const tenantNodeId = idpId('entra', tenant);
  const principalKey = me.id ?? me.userPrincipalName ?? me.mail!;
  const principalId = idpPrincipalId('entra', tenant, principalKey);
  nodes.push({
    id: tenantNodeId,
    type: 'idp',
    label: `entra:${tenant}`,
    idp_kind: 'entra',
    tenant_id: tenant,
    discovered_at: now,
    confidence: 1.0,
  });
  nodes.push({
    id: principalId,
    type: 'idp_principal',
    label: me.userPrincipalName ?? me.mail ?? me.displayName ?? principalKey,
    idp_id: tenantNodeId,
    idp_kind: 'entra',
    tenant_id: tenant,
    idp_principal_kind: 'user',
    idp_user_id: me.id,
    object_id: me.id,
    upn: me.userPrincipalName,
    mail: me.mail,
    display_name: me.displayName,
    discovered_at: now,
    confidence: 1.0,
  });

  // The playbook probes Microsoft Graph itself. Materialize that canonical
  // target when callers did not provide a more specific application node.
  if (!appId) {
    appId = idpApplicationId('entra', tenant, 'microsoft-graph');
    nodes.push({
      id: appId,
      type: 'idp_application',
      label: 'Microsoft Graph',
      idp_id: tenantNodeId,
      idp_kind: 'entra',
      tenant_id: tenant,
      app_kind: 'entra_service_principal',
      client_id: '00000003-0000-0000-c000-000000000000',
      audience: 'https://graph.microsoft.com',
      discovered_at: now,
      confidence: 1.0,
    });
  }

  // Success: mark the credential MFA-satisfied and refresh principal info.
  if (credId) {
    nodes.push({
      id: credId,
      type: 'credential',
      label: 'replay-result',
      preserve_existing_label: true,
      discovered_at: now,
      confidence: 1.0,
      cred_usable_for_auth: true,
      cred_mfa_satisfied: true,
      credential_status: 'active',
      partial: false,
      cred_user: me.userPrincipalName ?? me.mail,
      credential_principal_id: principalId,
      tenant_id: tenant,
      notes: `msgraph /me replay succeeded for ${me.userPrincipalName ?? me.id ?? 'user'}`,
    });
  }

  // Emit the VALID_FOR_APP edge when the operator named a target app.
  if (credId) {
    edges.push({
      source: credId,
      target: appId,
      properties: {
        type: 'VALID_FOR_APP' as EdgeType,
        confidence: 1.0,
        discovered_at: now,
        discovered_by: agentId,
        notes: `msgraph replay confirmed token works for ${appId}`,
      },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
