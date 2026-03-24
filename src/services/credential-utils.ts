// ============================================================
// Credential Utilities
// Shared credential semantics for inference, state, and reporting.
// ============================================================

import type { NodeProperties } from '../types.js';
import type { OverwatchGraph } from './engine-context.js';

export function getCredentialMaterialKind(node: NodeProperties): string | undefined {
  if (typeof node.cred_material_kind === 'string') {
    return node.cred_material_kind;
  }

  switch (node.cred_type) {
    case 'plaintext':
    case 'cleartext':
      return 'plaintext_password';
    case 'ntlm':
      return 'ntlm_hash';
    case 'ntlmv2_challenge':
      return 'ntlmv2_challenge';
    case 'aes256':
      return 'aes256_key';
    case 'kerberos_tgt':
      return 'kerberos_tgt';
    case 'kerberos_tgs':
      return 'kerberos_tgs';
    case 'certificate':
      return 'certificate';
    case 'token':
      return 'token';
    case 'ssh_key':
      return 'ssh_key';
    default:
      return undefined;
  }
}

export function isCredentialUsableForAuth(node: NodeProperties): boolean {
  // Lifecycle gates — expired or rotated credentials are never usable
  if (node.credential_status === 'expired' || node.credential_status === 'rotated') {
    return false;
  }
  if (typeof node.valid_until === 'string') {
    const expiry = new Date(node.valid_until).getTime();
    if (Number.isFinite(expiry) && expiry < Date.now()) {
      return false;
    }
  }

  if (typeof node.cred_usable_for_auth === 'boolean') {
    return node.cred_usable_for_auth;
  }

  switch (getCredentialMaterialKind(node)) {
    case 'plaintext_password':
    case 'ntlm_hash':
    case 'aes256_key':
    case 'kerberos_tgt':
    case 'certificate':
    case 'token':
    case 'ssh_key':
      return true;
    default:
      return false;
  }
}

export function isCredentialStaleOrExpired(node: NodeProperties): boolean {
  if (node.credential_status === 'expired' || node.credential_status === 'stale' || node.credential_status === 'rotated') {
    return true;
  }
  if (typeof node.valid_until === 'string') {
    const expiry = new Date(node.valid_until).getTime();
    if (Number.isFinite(expiry) && expiry < Date.now()) {
      return true;
    }
  }
  return false;
}

export function isReusableDomainCredential(node: NodeProperties): boolean {
  if (!node.cred_domain || !isCredentialUsableForAuth(node)) {
    return false;
  }

  return [
    'plaintext_password',
    'ntlm_hash',
    'aes256_key',
    'kerberos_tgt',
  ].includes(getCredentialMaterialKind(node) || '');
}

export function getCredentialDisplayKind(node: NodeProperties): string {
  return getCredentialMaterialKind(node) || node.cred_type || 'unknown';
}

export function inferCredentialDomain(credNodeId: string, graph: OverwatchGraph): { domain: string } | null {
  if (!graph.hasNode(credNodeId)) return null;

  const candidateDomains = new Set<string>();

  // Walk inbound OWNS_CRED edges to find owner user(s)
  graph.forEachInEdge(credNodeId, (edgeId, edgeAttrs, source) => {
    if (edgeAttrs.type !== 'OWNS_CRED') return;
    const sourceAttrs = graph.getNodeAttributes(source);
    if (sourceAttrs.type !== 'user') return;

    // Walk outbound edges from the user to find MEMBER_OF_DOMAIN → domain
    graph.forEachOutEdge(source, (_eid, eAttrs, _src, target) => {
      if (eAttrs.type !== 'MEMBER_OF_DOMAIN') return;
      const targetAttrs = graph.getNodeAttributes(target);
      if (targetAttrs.type !== 'domain') return;
      const domainName = targetAttrs.domain_name || targetAttrs.label;
      if (typeof domainName === 'string' && domainName.length > 0) {
        candidateDomains.add(domainName.toLowerCase());
      }
    });
  });

  if (candidateDomains.size === 1) {
    return { domain: [...candidateDomains][0] };
  }

  return null;
}
