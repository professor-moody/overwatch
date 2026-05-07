// ============================================================
// evilginx2 session-capture parser.
//
// evilginx logs captured sessions to its sessions database; operators
// commonly export them via `sessions <id>` in the evilginx console or
// dump the session table to JSON. The most operationally-relevant
// fields are:
//   - phishlet name → derives the IdP / app being phished
//   - username, password (when captured)
//   - cookies (the AiTM payload — the whole point of evilginx)
//   - tokens (sometimes, when the flow includes OAuth)
//
// Our model captures the cookies + tokens as `session_cookie` /
// `oidc_access_token` credentials with cred_mfa_satisfied: true (the
// AiTM bypassed MFA — that's why we ran the phishlet in the first
// place). Username/password are also captured if present.
//
// Accepts JSON output of the format:
//   { id, phishlet, username, password, custom, body_tokens, cookies: [...] }
// or an array of such objects.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, idpId, idpPrincipalId, userId } from '../parser-utils.js';

interface EvilginxSession {
  id?: string | number;
  phishlet?: string;
  username?: string;
  password?: string;
  custom?: Record<string, unknown>;
  body_tokens?: Record<string, unknown>;
  cookies?: Array<{ name?: string; value?: string; path?: string; domain?: string }>;
  tokens?: Record<string, unknown>;
  remote_addr?: string;
  user_agent?: string;
  create_time?: number | string;
  update_time?: number | string;
}

function tryJson(output: string): EvilginxSession[] | null {
  try {
    const obj = JSON.parse(output);
    if (Array.isArray(obj)) return obj as EvilginxSession[];
    if (obj && typeof obj === 'object' && (obj.phishlet || obj.cookies)) return [obj as EvilginxSession];
    return null;
  } catch {
    return null;
  }
}

function deriveIdpFromPhishlet(phishlet: string): { kind: NodeProperties['idp_kind']; tenant: string } | undefined {
  const p = phishlet.toLowerCase();
  if (p.includes('o365') || p.includes('office365') || p.includes('outlook') || p.includes('azuread') || p.includes('entra') || p.includes('microsoft')) {
    return { kind: 'entra', tenant: 'phished' };
  }
  if (p.includes('okta')) return { kind: 'okta', tenant: 'phished' };
  if (p.includes('auth0')) return { kind: 'auth0', tenant: 'phished' };
  if (p.includes('ping')) return { kind: 'ping', tenant: 'phished' };
  return undefined;
}

export function parseEvilginx(output: string, agentId: string = 'evilginx-parser', _context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const sessions = tryJson(output);
  if (!sessions) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const session of sessions) {
    const phishlet = String(session.phishlet ?? 'unknown');
    const username = session.username ?? '';
    const password = session.password ?? '';
    const idp = deriveIdpFromPhishlet(phishlet);

    // Synthesize an idp node when we recognize the phishlet.
    let idpNodeId: string | undefined;
    let principalNodeId: string | undefined;
    if (idp) {
      idpNodeId = idpId(idp.kind!, idp.tenant);
      if (!seenNodes.has(idpNodeId)) {
        nodes.push({
          id: idpNodeId,
          type: 'idp',
          label: `${idp.kind}:${idp.tenant}`,
          idp_kind: idp.kind,
          tenant_id: idp.tenant,
          discovered_via: agentId,
          discovered_at: now,
          confidence: 0.7, // phishlet-derived; not a confirmed enumeration
        });
        seenNodes.add(idpNodeId);
      }
      if (username) {
        principalNodeId = idpPrincipalId(idp.kind!, idp.tenant, username);
        if (!seenNodes.has(principalNodeId)) {
          nodes.push({
            id: principalNodeId,
            type: 'idp_principal',
            label: String(username),
            idp_user_id: String(username),
            idp_principal_kind: 'user',
            upn: String(username),
            discovered_at: now,
            confidence: 0.9,
          });
          seenNodes.add(principalNodeId);
        }
      }
    }

    // Plaintext password (if captured).
    if (username && password) {
      const credId = credentialId('plaintext_password', String(password), String(username), undefined);
      if (!seenNodes.has(credId)) {
        nodes.push({
          id: credId,
          type: 'credential',
          label: `phished:${username}`,
          cred_type: 'plaintext',
          cred_material_kind: 'plaintext_password',
          cred_value: String(password),
          cred_user: String(username),
          cred_evidence_kind: 'capture',
          cred_usable_for_auth: true,
          // The whole point of evilginx is to capture the second factor —
          // a phished password without the MFA-bypassing cookie is rarely
          // sufficient for modern accounts. Mark MFA as required so the
          // planner picks the cookie below over this password.
          cred_mfa_required: true,
          discovered_at: now,
          confidence: 1.0,
        });
        seenNodes.add(credId);
      }
      if (principalNodeId) {
        edges.push({ source: principalNodeId, target: credId, properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId } });
      }
      // Also create a generic user node for parity with non-IdP-aware consumers.
      if (username) {
        const userNodeId = userId(String(username));
        if (!seenNodes.has(userNodeId)) {
          nodes.push({
            id: userNodeId,
            type: 'user',
            label: String(username),
            username: String(username),
            discovered_at: now,
            confidence: 0.9,
          });
          seenNodes.add(userNodeId);
        }
        edges.push({ source: userNodeId, target: credId, properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId } });
      }
    }

    // Cookies → session_cookie credential. This is the AiTM bypass payload —
    // the cookie embodies the post-MFA session, so cred_mfa_satisfied: true.
    const cookies = Array.isArray(session.cookies) ? session.cookies : [];
    if (cookies.length > 0) {
      const cookieFingerprint = cookies.map(c => `${c.name}=${c.value}`).join(';');
      const credId = credentialId('session_cookie', cookieFingerprint, String(username || 'aitm'), undefined);
      if (!seenNodes.has(credId)) {
        nodes.push({
          id: credId,
          type: 'credential',
          label: `aitm:${phishlet}:${username || 'session'}`,
          cred_type: 'session_cookie',
          cred_material_kind: 'session_cookie',
          cred_value: cookieFingerprint,
          cred_user: username ? String(username) : undefined,
          cred_evidence_kind: 'capture',
          cred_usable_for_auth: true,
          cred_mfa_required: true,
          cred_mfa_satisfied: true,
          discovered_at: now,
          confidence: 1.0,
        });
        seenNodes.add(credId);
        if (principalNodeId) {
          edges.push({ source: principalNodeId, target: credId, properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId } });
        }
      }
    }

    // OAuth / OIDC tokens captured during the flow.
    const tokens = (session.tokens ?? session.body_tokens ?? {}) as Record<string, unknown>;
    for (const [tokenName, tokenVal] of Object.entries(tokens)) {
      if (typeof tokenVal !== 'string' || tokenVal.length === 0) continue;
      const isAccess = /access_token|access\b/i.test(tokenName);
      const isId = /id_token|id\b/i.test(tokenName);
      const kind: NodeProperties['cred_material_kind'] = isAccess ? 'oidc_access_token' : isId ? 'oidc_id_token' : 'oidc_access_token';
      const credId = credentialId(kind, tokenVal, String(username || 'aitm'), undefined);
      if (seenNodes.has(credId)) continue;
      nodes.push({
        id: credId,
        type: 'credential',
        label: `aitm:${tokenName}:${username || 'session'}`,
        cred_type: 'oidc_token',
        cred_material_kind: kind,
        cred_value: tokenVal,
        cred_user: username ? String(username) : undefined,
        cred_evidence_kind: 'capture',
        cred_usable_for_auth: true,
        cred_mfa_required: true,
        cred_mfa_satisfied: true,
        discovered_at: now,
        confidence: 1.0,
      });
      seenNodes.add(credId);
      if (principalNodeId) {
        edges.push({ source: principalNodeId, target: credId, properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId } });
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
