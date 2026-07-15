import type { ExportedEdge, ExportedNode } from './types';

export interface CredentialKindSource {
  cred_material_kind?: unknown;
  cred_type?: unknown;
  credential_status?: unknown;
  cred_token_expires_at?: unknown;
  [key: string]: unknown;
}

const KIND_LABELS: Record<string, string> = {
  plaintext_password: 'Password',
  ntlm_hash: 'NTLM',
  ntlmv1_challenge: 'NTLMv1',
  ntlmv2_challenge: 'NTLMv2',
  kerberos_tgt: 'Kerberos TGT',
  kerberos_tgs: 'Kerberos TGS',
  kerberos_asrep: 'Kerberos ASREPRoast',
  aes256_key: 'AES-256',
  certificate: 'Certificate',
  token: 'Token',
  ssh_key: 'SSH Key',
  oidc_id_token: 'OIDC ID Token',
  oidc_access_token: 'OIDC Access Token',
  oidc_refresh_token: 'OIDC Refresh Token',
  saml_assertion: 'SAML Assertion',
  oauth_client_secret: 'OAuth Secret',
  pat: 'PAT',
  app_password: 'App Password',
  session_cookie: 'Session Cookie',
  aws_session_credentials: 'AWS Session Credentials',
};

export function getCredentialMaterialKind(cred: CredentialKindSource): string {
  if (typeof cred.cred_material_kind === 'string' && cred.cred_material_kind) return cred.cred_material_kind;
  switch (cred.cred_type) {
    case 'plaintext': return 'plaintext_password';
    case 'ntlm': return 'ntlm_hash';
    case 'token': return 'token';
    case 'ssh_key': return 'ssh_key';
    default:
      return typeof cred.cred_type === 'string' && cred.cred_type ? cred.cred_type : 'unknown';
  }
}

export function getCredentialKindLabel(credOrKind: CredentialKindSource | string | undefined): string {
  const kind = typeof credOrKind === 'string'
    ? credOrKind
    : credOrKind ? getCredentialMaterialKind(credOrKind) : 'unknown';
  return KIND_LABELS[kind] ?? (kind === 'unknown' ? 'Unknown' : kind);
}

export function getCredentialKindBadgeClass(kind: string | undefined): string {
  if (!kind || kind === 'unknown') return 'bg-elevated text-muted-foreground';
  if (kind.includes('oidc') || kind.includes('saml') || kind.includes('oauth') || kind === 'pat' || kind === 'token' || kind === 'aws_session_credentials') {
    return 'bg-accent-dim text-accent';
  }
  if (kind.includes('kerberos') || kind === 'aes256_key' || kind === 'certificate') {
    return 'bg-purple-dim text-purple';
  }
  if (kind === 'ssh_key') return 'bg-elevated text-foreground';
  return 'bg-elevated text-muted-foreground';
}

export function getCredentialStatusClass(status: string | undefined): string {
  switch (status) {
    case 'active': return 'text-success bg-success/10';
    case 'stale': return 'text-warning bg-warning/10';
    case 'expired': return 'text-muted-foreground bg-elevated';
    case 'rotated': return 'text-destructive bg-destructive/10';
    default: return 'text-muted-foreground bg-elevated';
  }
}

export function getEffectiveCredentialStatus(
  cred: CredentialKindSource,
  nowMs: number = Date.now(),
): string | undefined {
  const rawStatus = typeof cred.credential_status === 'string' ? cred.credential_status : undefined;
  if (rawStatus && rawStatus !== 'active') return rawStatus;

  if (typeof cred.cred_token_expires_at === 'string' && cred.cred_token_expires_at.trim()) {
    const expiresAt = new Date(cred.cred_token_expires_at).getTime();
    if (Number.isFinite(expiresAt) && expiresAt < nowMs) return 'expired';
  }

  return rawStatus;
}

export type CredentialExpiryUrgency = 'expired' | 'soon' | 'ok';

export interface CredentialExpiry {
  /** Absolute expiry instant (ms epoch). */
  expiresAtMs: number;
  /** Signed time-to-expiry in ms — negative once expired. */
  ms: number;
  urgency: CredentialExpiryUrgency;
}

/** Tokens within this window of expiring are flagged "soon" so the operator can
 *  act before they lapse (use-it-or-lose-it), not just after. */
export const CREDENTIAL_EXPIRY_SOON_MS = 60 * 60_000; // 1h

/**
 * Time-to-expiry classification for a credential with a token-expiry timestamp.
 * Returns null when the credential has no (or an unparseable) expiry — most
 * non-token credentials. Pure; the UI formats `ms` for display.
 */
export function credentialExpiry(
  cred: CredentialKindSource,
  nowMs: number = Date.now(),
): CredentialExpiry | null {
  const raw = cred.cred_token_expires_at;
  if (typeof raw !== 'string' || !raw.trim()) return null;
  const expiresAtMs = new Date(raw).getTime();
  if (!Number.isFinite(expiresAtMs)) return null;
  const ms = expiresAtMs - nowMs;
  const urgency: CredentialExpiryUrgency = ms < 0 ? 'expired' : ms <= CREDENTIAL_EXPIRY_SOON_MS ? 'soon' : 'ok';
  return { expiresAtMs, ms, urgency };
}

/** Compact relative TTL label: "expires in 3h" / "expired 2d ago". */
export function formatExpiryLabel(exp: CredentialExpiry): string {
  const abs = Math.abs(exp.ms);
  const d = Math.floor(abs / 86_400_000);
  const h = Math.floor(abs / 3_600_000);
  const m = Math.floor(abs / 60_000);
  const dur = d >= 1 ? `${d}d` : h >= 1 ? `${h}h` : m >= 1 ? `${m}m` : '<1m';
  return exp.urgency === 'expired' ? `expired ${dur} ago` : `expires in ${dur}`;
}

/** Edge types that prove a credential reaches a target (app/role/host/service). */
export const CREDENTIAL_REACH_EDGE_TYPES = ['VALID_FOR_APP', 'ASSUMES_ROLE', 'VALID_ON', 'AUTHENTICATES_TO'];

/** Target node ids this credential is confirmed to reach (one per reach edge). */
export function credentialReachTargets(
  cred: Pick<ExportedNode, 'id'>,
  edges: Pick<ExportedEdge, 'source' | 'type' | 'target'>[],
): string[] {
  return edges
    .filter(e => e.source === cred.id && CREDENTIAL_REACH_EDGE_TYPES.includes(e.type))
    .map(e => e.target);
}

export function isCredentialReachable(cred: ExportedNode, edges: Pick<ExportedEdge, 'source' | 'type'>[]): boolean {
  return edges.some(
    e => e.source === cred.id && CREDENTIAL_REACH_EDGE_TYPES.includes(e.type),
  );
}

/** A token/cloud credential that can still drive a credential playbook. */
export function isCredentialExpansionCandidate(
  cred: CredentialKindSource,
  nowMs: number = Date.now(),
  edges: Array<Pick<ExportedEdge, 'source' | 'target' | 'type'> & { binding_source?: unknown }> = [],
): boolean {
  const status = getEffectiveCredentialStatus(cred, nowMs);
  if (status === 'expired' || status === 'rotated') return false;
  const material = String(cred.cred_material_kind || cred.cred_type || '').toLowerCase();
  const tokenLike = material === 'token'
    || ['oidc', 'oauth', 'saml', 'pat', 'session', 'aws', 'github', 'entra'].some(marker => material.includes(marker));
  if (!tokenLike || typeof cred.cred_value !== 'string' || cred.cred_value.length === 0) return false;

  // Merely generating a playbook is not progress. A confirmed provider replay
  // or STS caller binding is: once either lands, the credential has left the
  // "needs first expansion" queue even though it remains usable elsewhere.
  const meaningfullyExpanded = edges.some(edge =>
    (edge.source === cred.id && (edge.type === 'VALID_FOR_APP' || edge.type === 'ASSUMES_ROLE'))
    || (edge.target === cred.id && edge.type === 'OWNS_CRED'
      && edge.binding_source === 'aws_sts_get_caller_identity'),
  );
  return !meaningfullyExpanded;
}
