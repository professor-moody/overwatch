// ============================================================
// Okta token-replay response parser.
//
// Probes `/api/v1/users/me` (org-level read) and / or
// `/api/v1/sessions/me` (session validation) using a captured Okta
// access token or session cookie. Successful 200 confirms the
// credential is usable; 401 marks it expired.
//
// On a successful session-cookie probe, set cred_mfa_satisfied: true
// (an Okta session cookie post-MFA is the whole point of AiTM phish).
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';

interface ReplayContext extends ParseContext {
  source_credential_id?: string;
  source_idp_application_id?: string;
  status_code?: number;
}

function extractStatusAndBody(output: string): { status: number; body: string } {
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

interface OktaUser { id?: string; profile?: { login?: string; email?: string; firstName?: string; lastName?: string } }
interface OktaSession { id?: string; userId?: string; mfaActive?: boolean; status?: string }

function parseOktaResponse(body: string): { user?: OktaUser; session?: OktaSession } | null {
  try {
    const obj = JSON.parse(body) as Record<string, unknown>;
    // /users/me → user object with `profile.login`
    if (obj && (obj.profile as { login?: string } | undefined)?.login) {
      return { user: obj as OktaUser };
    }
    // /sessions/me → session object with `userId` and `mfaActive`
    if (obj && (obj.userId !== undefined || obj.mfaActive !== undefined)) {
      return { session: obj as OktaSession };
    }
    return null;
  } catch {
    return null;
  }
}

export function parseTokenReplayOkta(output: string, agentId: string = 'token-replay-okta', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as ReplayContext;
  const credId = ctx.source_credential_id;
  const appId = ctx.source_idp_application_id;

  const { status, body } = extractStatusAndBody(output);

  if (status === 401 || status === 403) {
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        preserve_existing_label: true,
        discovered_at: now,
        confidence: 1.0,
        credential_status: status === 401 ? 'expired' : 'active',
        cred_mfa_required: status === 403 ? true : undefined,
        cred_mfa_satisfied: status === 403 ? false : undefined,
        notes: `okta replay returned ${status}`,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (status !== 200 && status !== 0) {
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        preserve_existing_label: true,
        discovered_at: now,
        confidence: 0.5,
        notes: `okta replay returned ${status} — inconclusive`,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges,
      partial: true, partial_reason: `okta_http_${status}_inconclusive` };
  }

  const parsed = parseOktaResponse(body);
  if (!parsed) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (credId) {
    nodes.push({
      id: credId,
      type: 'credential',
      label: 'replay-result',
      preserve_existing_label: true,
      discovered_at: now,
      confidence: 1.0,
      cred_usable_for_auth: true,
      // /sessions/me returns `mfaActive: true` when the session was
      // established via MFA. Otherwise we mark satisfied because the
      // call succeeded — a non-MFA session that works is still working.
      cred_mfa_satisfied: parsed.session?.mfaActive === true ? true : true,
      credential_status: 'active',
      partial: false,
      notes: parsed.user
        ? `okta /users/me replay succeeded for ${parsed.user.profile?.login ?? parsed.user.id ?? 'user'}`
        : `okta /sessions/me replay succeeded for userId ${parsed.session?.userId ?? '?'}`,
    });
  }

  if (credId && appId) {
    edges.push({
      source: credId,
      target: appId,
      properties: {
        type: 'VALID_FOR_APP' as EdgeType,
        confidence: 1.0,
        discovered_at: now,
        discovered_by: agentId,
        notes: 'okta replay confirmed token works',
      },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
