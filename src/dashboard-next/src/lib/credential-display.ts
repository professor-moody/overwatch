import type { ExportedEdge, ExportedNode } from './types';

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
};

export function getCredentialMaterialKind(cred: Pick<ExportedNode, 'cred_material_kind' | 'cred_type'>): string {
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

export function getCredentialKindLabel(credOrKind: Pick<ExportedNode, 'cred_material_kind' | 'cred_type'> | string | undefined): string {
  const kind = typeof credOrKind === 'string'
    ? credOrKind
    : credOrKind ? getCredentialMaterialKind(credOrKind) : 'unknown';
  return KIND_LABELS[kind] ?? (kind === 'unknown' ? 'Unknown' : kind);
}

export function getCredentialKindBadgeClass(kind: string | undefined): string {
  if (!kind || kind === 'unknown') return 'bg-elevated text-muted-foreground';
  if (kind.includes('oidc') || kind.includes('saml') || kind.includes('oauth') || kind === 'pat' || kind === 'token') {
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

export function isCredentialReachable(cred: ExportedNode, edges: Pick<ExportedEdge, 'source' | 'type'>[]): boolean {
  return edges.some(
    e => e.source === cred.id &&
      ['VALID_FOR_APP', 'ASSUMES_ROLE', 'VALID_ON', 'AUTHENTICATES_TO'].includes(e.type),
  );
}
