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
    case 'ntlmv1_challenge':
      return 'ntlmv1_challenge';
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

export interface CredentialExpiryEstimate {
  expires_at?: string;
  confidence: 'known' | 'estimated' | 'unknown';
  source: string;
}

/**
 * Estimate when a credential will expire based on its type and available metadata.
 * For Kerberos tickets, uses default lifetimes. For passwords, uses domain policy + pwdLastSet.
 */
export function estimateCredentialExpiry(
  node: NodeProperties,
  domainNode?: NodeProperties,
): CredentialExpiryEstimate {
  // If valid_until is explicitly set, use it
  if (typeof node.valid_until === 'string') {
    return { expires_at: node.valid_until, confidence: 'known', source: 'valid_until' };
  }

  const kind = getCredentialMaterialKind(node);
  const discoveredAt = node.discovered_at ? new Date(node.discovered_at).getTime() : Date.now();

  switch (kind) {
    case 'kerberos_tgt': {
      // Default TGT lifetime: 10 hours
      const expiresAt = new Date(discoveredAt + 10 * 60 * 60 * 1000).toISOString();
      return { expires_at: expiresAt, confidence: 'estimated', source: 'default_tgt_lifetime_10h' };
    }
    case 'kerberos_tgs': {
      // Default TGS lifetime: 10 hours
      const expiresAt = new Date(discoveredAt + 10 * 60 * 60 * 1000).toISOString();
      return { expires_at: expiresAt, confidence: 'estimated', source: 'default_tgs_lifetime_10h' };
    }
    case 'token': {
      // Tokens without explicit valid_until are unknown
      return { confidence: 'unknown', source: 'token_no_expiry' };
    }
    case 'plaintext_password':
    case 'ntlm_hash':
    case 'aes256_key': {
      // For password-based creds, use domain password policy + pwdLastSet
      if (domainNode?.password_policy?.max_pwd_age && node.pwd_last_set) {
        const pwdLastSet = new Date(node.pwd_last_set).getTime();
        if (Number.isFinite(pwdLastSet)) {
          const maxAgeSec = domainNode.password_policy.max_pwd_age;
          const expiresAt = new Date(pwdLastSet + maxAgeSec * 1000).toISOString();
          return { expires_at: expiresAt, confidence: 'estimated', source: 'domain_policy_max_pwd_age' };
        }
      }
      return { confidence: 'unknown', source: 'password_no_policy' };
    }
    default:
      return { confidence: 'unknown', source: 'unknown_cred_type' };
  }
}

/**
 * Returns milliseconds until estimated credential expiry, or Infinity if unknown.
 */
export function timeToExpiry(
  node: NodeProperties,
  domainNode?: NodeProperties,
): number {
  const estimate = estimateCredentialExpiry(node, domainNode);
  if (!estimate.expires_at) return Infinity;
  const expiresMs = new Date(estimate.expires_at).getTime();
  if (!Number.isFinite(expiresMs)) return Infinity;
  return Math.max(0, expiresMs - Date.now());
}

/**
 * Walk DERIVED_FROM edges to build a provenance chain string.
 */
export function getCredentialProvenance(credNodeId: string, graph: OverwatchGraph): string[] {
  const chain: string[] = [credNodeId];
  const visited = new Set<string>([credNodeId]);
  let current = credNodeId;

  for (let depth = 0; depth < 10; depth++) {
    let parent: string | undefined;
    graph.forEachOutEdge(current, (_edgeId, edgeAttrs, _src, target) => {
      if (edgeAttrs.type === 'DERIVED_FROM' && !visited.has(target)) {
        parent = target;
      }
    });
    if (!parent) break;
    chain.push(parent);
    visited.add(parent);
    current = parent;
  }

  return chain;
}

export function inferCredentialDomain(credNodeId: string, graph: OverwatchGraph): { domain: string } | null {
  if (!graph.hasNode(credNodeId)) return null;

  const candidateDomains = new Set<string>();

  // Walk inbound OWNS_CRED edges to find owner user(s)
  graph.forEachInEdge(credNodeId, (_edgeId, edgeAttrs, source) => {
    if (edgeAttrs.type !== 'OWNS_CRED') return;
    const sourceAttrs = graph.getNodeAttributes(source);
    if (sourceAttrs.type !== 'user') return;

    let foundEdgeDomain = false;
    // Walk outbound edges from the user to find MEMBER_OF_DOMAIN → domain
    graph.forEachOutEdge(source, (_eid, eAttrs, _src, target) => {
      if (eAttrs.type !== 'MEMBER_OF_DOMAIN') return;
      const targetAttrs = graph.getNodeAttributes(target);
      if (targetAttrs.type !== 'domain') return;
      const domainName = targetAttrs.domain_name || targetAttrs.label;
      if (typeof domainName === 'string' && domainName.length > 0) {
        candidateDomains.add(domainName.toLowerCase());
        foundEdgeDomain = true;
      }
    });

    // Fallback: use owner's domain_name property if no MEMBER_OF_DOMAIN edges found
    if (!foundEdgeDomain) {
      const dn = sourceAttrs.domain_name;
      if (typeof dn === 'string' && dn.length > 0) {
        candidateDomains.add(dn.toLowerCase());
      }
    }
  });

  if (candidateDomains.size === 1) {
    return { domain: [...candidateDomains][0] };
  }

  return null;
}
