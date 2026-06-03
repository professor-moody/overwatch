// ============================================================
// JWT / OIDC token parser
//
// Accepts either:
//   1. A raw JWT string (`xxx.yyy.zzz` where each segment is base64url)
//   2. jwt-tool's decoded output (header + payload JSON dump)
//   3. A plain JSON object containing { header, payload } (programmatic
//      decode from any tool)
//
// Emits:
//   - `credential` node with cred_material_kind: 'oidc_access_token'
//     (or 'oidc_id_token' if the payload looks ID-token-shaped),
//     populated with cred_audience / cred_scopes / cred_issuer /
//     cred_token_expires_at.
//   - `idp` node back-referenced by issuer URL.
//   - `idp_principal` node for the `sub` claim.
//   - OWNS_CRED edge from principal → credential.
//   - VALID_FOR_APP edge when an idp_application matching the audience
//     is already in the graph (best-effort — left to the engine to
//     resolve at ingest time).
//
// This parser intentionally does NOT verify signatures. Operators run
// jwt-tool / equivalent for that; we model what the token claims.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, idpId, idpPrincipalId } from '../parser-utils.js';

interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature?: string;
  raw?: string;
}

function base64UrlDecode(part: string): string | null {
  try {
    const pad = '='.repeat((4 - (part.length % 4)) % 4);
    const b64 = (part + pad).replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(b64, 'base64').toString('utf-8');
  } catch {
    return null;
  }
}

function tryDecodeRawJwt(input: string): DecodedJwt | null {
  const trimmed = input.trim();
  // Strip "Bearer " prefix some operators paste in.
  const candidate = trimmed.replace(/^Bearer\s+/i, '');
  const parts = candidate.split('.');
  if (parts.length !== 3) return null;
  const headerJson = base64UrlDecode(parts[0]);
  const payloadJson = base64UrlDecode(parts[1]);
  if (!headerJson || !payloadJson) return null;
  try {
    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);
    return { header, payload, signature: parts[2], raw: candidate };
  } catch {
    return null;
  }
}

function tryDecodeJsonShape(input: string): DecodedJwt | null {
  try {
    const obj = JSON.parse(input);
    if (obj && typeof obj === 'object') {
      if (obj.header && obj.payload) {
        return { header: obj.header, payload: obj.payload, signature: obj.signature };
      }
      // Some tools dump the decoded payload at the top level.
      if (obj.iss && obj.sub) {
        return { header: {}, payload: obj };
      }
    }
  } catch {
    // not JSON
  }
  return null;
}

function tryDecodeJwtToolOutput(input: string): DecodedJwt | null {
  // jwt-tool prints sections like:
  //   Header values:
  //   [+] alg = "RS256"
  //   ...
  //   Payload values:
  //   [+] iss = "https://login.microsoftonline.com/<tenant>/v2.0"
  //   ...
  // We collect [+] kv pairs from the Payload section.
  if (!/Payload values:/i.test(input)) return null;
  const lines = input.split('\n');
  const payload: Record<string, unknown> = {};
  const header: Record<string, unknown> = {};
  let section: 'header' | 'payload' | null = null;
  for (const raw of lines) {
    const line = raw.trim();
    if (/^Header values:/i.test(line)) { section = 'header'; continue; }
    if (/^Payload values:/i.test(line)) { section = 'payload'; continue; }
    const kv = line.match(/^\[\+\]\s*([\w_-]+)\s*=\s*(.+)$/);
    if (!kv || !section) continue;
    const key = kv[1];
    let val: unknown = kv[2].trim();
    // Strip surrounding quotes; coerce numeric where reasonable.
    if (typeof val === 'string') {
      const s = val.replace(/^"|"$/g, '');
      if (/^-?\d+$/.test(s)) val = Number(s);
      else val = s;
    }
    (section === 'header' ? header : payload)[key] = val;
  }
  if (Object.keys(payload).length === 0) return null;
  return { header, payload };
}

function classifyTokenKind(payload: Record<string, unknown>): 'oidc_id_token' | 'oidc_access_token' {
  // ID tokens carry a nonce (per OIDC spec) and typically have an `at_hash`.
  // Access tokens often carry `scope` / `scp` and lack `nonce`.
  if (typeof payload.nonce === 'string') return 'oidc_id_token';
  if (typeof payload.at_hash === 'string') return 'oidc_id_token';
  return 'oidc_access_token';
}

function deriveIdpKind(issuer: string): 'okta' | 'entra' | 'auth0' | 'ping' | 'generic_oidc' {
  if (/login\.microsoftonline\.com|sts\.windows\.net|microsoftonline/i.test(issuer)) return 'entra';
  if (/\.okta\.com|\.oktapreview\.com/i.test(issuer)) return 'okta';
  if (/\.auth0\.com/i.test(issuer)) return 'auth0';
  if (/ping(?:identity|one|federate)/i.test(issuer)) return 'ping';
  return 'generic_oidc';
}

function deriveTenantId(issuer: string): string {
  // Best-effort tenant extraction. Falls back to the full issuer URL.
  // login.microsoftonline.com is followed by a tenant identifier (often a
  // GUID, sometimes "common"/"organizations", and occasionally an
  // operator-supplied placeholder for testing). Accept any non-slash run.
  const m = issuer.match(/login\.microsoftonline\.com\/([^/]+)/i);
  if (m) return m[1];
  const oktaM = issuer.match(/^https?:\/\/([^.]+)\.okta(?:preview)?\.com/i);
  if (oktaM) return oktaM[1];
  const auth0M = issuer.match(/^https?:\/\/([^.]+)\.auth0\.com/i);
  if (auth0M) return auth0M[1];
  return issuer;
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function asScopes(payload: Record<string, unknown>): string[] | undefined {
  // OIDC: `scope` (space-separated string) or `scp` (Microsoft access tokens).
  // SAML/OIDC variants sometimes use `scopes` (array).
  const raw = payload.scope ?? payload.scp ?? payload.scopes;
  if (Array.isArray(raw)) return raw.map(String).filter(Boolean);
  if (typeof raw === 'string' && raw.trim()) return raw.split(/\s+/).filter(Boolean);
  return undefined;
}

function asAudience(payload: Record<string, unknown>): string | undefined {
  // `aud` can be string or array; pick the first string when array.
  const raw = payload.aud;
  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw) && raw.length > 0 && typeof raw[0] === 'string') return raw[0];
  return undefined;
}

export function parseJwtTool(output: string, agentId: string = 'jwt-tool-parser', _context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const decoded = tryDecodeRawJwt(output) ?? tryDecodeJwtToolOutput(output) ?? tryDecodeJsonShape(output);
  if (!decoded) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const { header, payload, raw } = decoded;
  const issuer = asString(payload.iss);
  const subject = asString(payload.sub);
  const audience = asAudience(payload);
  const scopes = asScopes(payload);
  const exp = typeof payload.exp === 'number' ? new Date(payload.exp * 1000).toISOString() : undefined;
  const upn = asString(payload.upn) ?? asString(payload.preferred_username) ?? asString(payload.email);
  const tokenKind = classifyTokenKind(payload);

  // Issuer → idp node
  let idpNodeId: string | undefined;
  if (issuer) {
    const kind = deriveIdpKind(issuer);
    const tenant = deriveTenantId(issuer);
    idpNodeId = idpId(kind, tenant);
    if (!seenNodes.has(idpNodeId)) {
      nodes.push({
        id: idpNodeId,
        type: 'idp',
        label: `${kind}:${tenant}`,
        idp_kind: kind,
        tenant_id: tenant,
        issuer_url: issuer,
        discovered_via: agentId,
        discovered_at: now,
        confidence: 0.9,
      });
      seenNodes.add(idpNodeId);
    }
  }

  // Subject → idp_principal
  let principalNodeId: string | undefined;
  if (idpNodeId && subject) {
    const kind = (nodes.find(n => n.id === idpNodeId)?.idp_kind as string) ?? 'generic_oidc';
    const tenant = (nodes.find(n => n.id === idpNodeId)?.tenant_id as string) ?? '';
    principalNodeId = idpPrincipalId(kind, tenant, subject);
    if (!seenNodes.has(principalNodeId)) {
      nodes.push({
        id: principalNodeId,
        type: 'idp_principal',
        label: upn ?? subject,
        idp_user_id: subject,
        idp_principal_kind: 'user',
        upn,
        discovered_at: now,
        confidence: 0.9,
      });
      seenNodes.add(principalNodeId);
    }
  }

  // Token → credential
  // Use header.kid + payload.exp + sub as a stable fingerprint so duplicate
  // captures of the same token dedup, while two distinct tokens for the
  // same user remain distinct.
  const fingerprint =
    raw ??
    `${asString(header.kid) ?? ''}|${asString(header.alg) ?? ''}|${subject ?? ''}|${exp ?? ''}|${audience ?? ''}`;
  const credNodeId = credentialId(tokenKind, fingerprint, subject, undefined);
  if (!seenNodes.has(credNodeId)) {
    nodes.push({
      id: credNodeId,
      type: 'credential',
      label: tokenKind === 'oidc_id_token' ? `id_token:${upn ?? subject ?? '?'}` : `access_token:${upn ?? subject ?? '?'}`,
      cred_type: 'oidc_token',
      cred_material_kind: tokenKind,
      cred_value: raw,
      cred_user: upn,
      cred_audience: audience,
      cred_scopes: scopes,
      cred_issuer: idpNodeId ?? issuer,
      cred_token_expires_at: exp,
      cred_evidence_kind: 'capture',
      cred_usable_for_auth: true,
      // S4-A2: surface the captured `sub` claim on the credential so the
      // OIDC federation pivot rule in cross-tier-inference can validate it
      // against the idp_application's sub_claim_pattern. Without this the
      // pivot fired on audience match alone and a wildcard pattern like
      // `repo:*` produced ASSUMES_ROLE for any token.
      ...(subject ? { cred_subject: subject } : {}),
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(credNodeId);
  }

  if (principalNodeId && credNodeId) {
    edges.push({
      source: principalNodeId,
      target: credNodeId,
      properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
