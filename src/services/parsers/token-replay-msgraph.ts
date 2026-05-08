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

interface ReplayContext extends ParseContext {
  source_credential_id?: string;
  source_idp_application_id?: string;
  /** Operator-prefixed status code, e.g. "[STATUS:200]\n{...}". */
  status_code?: number;
}

function extractStatusAndBody(output: string): { status: number; body: string } {
  // Convention: when the tool fronts the response with "[STATUS:NNN]" we
  // strip it; otherwise we treat the full input as body and infer status
  // from JSON shape (best-effort).
  const m = output.match(/^\[STATUS:(\d{3})\]\s*\n?([\s\S]*)$/);
  if (m) return { status: parseInt(m[1]), body: m[2] };
  return { status: 0, body: output };
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

export function parseTokenReplayMsGraph(output: string, agentId: string = 'token-replay-msgraph', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as ReplayContext;
  const credId = ctx.source_credential_id;
  const appId = ctx.source_idp_application_id;

  const { status, body } = extractStatusAndBody(output);

  // Failure paths — record findings but no graph mutation here.
  if (status === 401 || status === 403) {
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        discovered_at: now,
        confidence: 1.0,
        // The replay returned auth-rejected — propagate to the credential
        // so isCredentialUsableForAuth flips false on next read.
        credential_status: status === 401 ? 'expired' : 'active',
        cred_mfa_required: status === 403 ? true : undefined,
        cred_mfa_satisfied: status === 403 ? false : undefined,
        notes: `msgraph replay returned ${status}`,
        partial: true,
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
        discovered_at: now,
        confidence: 0.5,
        partial: true,
        notes: `msgraph replay returned ${status} — inconclusive`,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const me = isSuccessfulMsGraphMe(body);
  if (!me) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Success: mark the credential MFA-satisfied and refresh principal info.
  if (credId) {
    nodes.push({
      id: credId,
      type: 'credential',
      label: 'replay-result',
      discovered_at: now,
      confidence: 1.0,
      cred_usable_for_auth: true,
      cred_mfa_satisfied: true,
      credential_status: 'active',
      notes: `msgraph /me replay succeeded for ${me.userPrincipalName ?? me.id ?? 'user'}`,
    });
  }

  // Emit the VALID_FOR_APP edge when the operator named a target app.
  if (credId && appId) {
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
