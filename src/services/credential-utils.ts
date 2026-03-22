// ============================================================
// Credential Utilities
// Shared credential semantics for inference, state, and reporting.
// ============================================================

import type { NodeProperties } from '../types.js';

export function getCredentialMaterialKind(node: NodeProperties): string | undefined {
  if (typeof node.cred_material_kind === 'string') {
    return node.cred_material_kind;
  }

  switch (node.cred_type) {
    case 'plaintext':
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
