// ============================================================
// Parser Utilities
// Shared canonical ID and account parsing helpers.
// ============================================================

import { createHash } from 'crypto';

export function normalizeKeyPart(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[./\\\s]+/g, '-')
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

export function domainId(domain: string): string {
  return `domain-${normalizeKeyPart(domain)}`;
}

export function userId(username: string, domain?: string): string {
  const userKey = normalizeKeyPart(username);
  const domainKey = domain ? normalizeKeyPart(domain) : '';
  return domainKey ? `user-${domainKey}-${userKey}` : `user-${userKey}`;
}

export function groupId(name: string, domain?: string): string {
  const groupKey = normalizeKeyPart(name);
  const domainKey = domain ? normalizeKeyPart(domain) : '';
  return domainKey ? `group-${domainKey}-${groupKey}` : `group-${groupKey}`;
}

export function credentialId(
  materialKind: string,
  fingerprint: string,
  username?: string,
  domain?: string,
): string {
  const digest = createHash('sha1')
    .update(fingerprint)
    .digest('hex')
    .slice(0, 12);
  const parts = [
    'cred',
    normalizeKeyPart(materialKind),
    domain ? normalizeKeyPart(domain) : '',
    username ? normalizeKeyPart(username) : '',
    digest,
  ].filter(Boolean);
  return parts.join('-');
}

export function hostId(ip: string): string {
  // Handle IPv6: strip brackets, replace colons with dashes
  if (ip.includes(':')) {
    const stripped = ip.replace(/^\[|\]$/g, '');
    return `host-${stripped.replace(/:/g, '-')}`;
  }
  return `host-${ip.replace(/\./g, '-')}`;
}

export function caId(name: string): string {
  return `ca-${normalizeKeyPart(name)}`;
}

export function certTemplateId(name: string): string {
  return `cert-template-${normalizeKeyPart(name)}`;
}

export function pkiStoreId(kind: string, name: string): string {
  return `pki-store-${normalizeKeyPart(kind)}-${normalizeKeyPart(name)}`;
}

export function resolveDomainName(raw: string, aliases?: Record<string, string>): string {
  const trimmed = raw.trim();
  if (trimmed.includes('.')) return trimmed.toLowerCase();
  if (aliases) {
    const upper = trimmed.toUpperCase();
    const fqdn = aliases[upper];
    if (fqdn) return fqdn.toLowerCase();
  }
  return trimmed.toLowerCase();
}

export function webappId(url: string): string {
  let normalized = url.trim().toLowerCase();
  // Remove trailing slash
  normalized = normalized.replace(/\/+$/, '');
  // Strip default ports
  normalized = normalized.replace(/^(https?:\/\/[^/:]+):80(\/|$)/, '$1$2');
  normalized = normalized.replace(/^(https:\/\/[^/:]+):443(\/|$)/, '$1$2');
  return `webapp-${normalizeKeyPart(normalized)}`;
}

export function vulnerabilityId(identifier: string, targetNodeId: string): string {
  const idPart = normalizeKeyPart(identifier);
  const targetPart = normalizeKeyPart(targetNodeId);
  return `vuln-${idPart}-${targetPart}`;
}

export function cloudIdentityId(arn: string): string {
  return `cloud-identity-${normalizeKeyPart(arn)}`;
}

export function cloudResourceId(arn: string): string {
  return `cloud-resource-${normalizeKeyPart(arn)}`;
}

export function cloudPolicyId(provider: string, policyName: string): string {
  return `cloud-policy-${normalizeKeyPart(provider)}-${normalizeKeyPart(policyName)}`;
}

export function cloudNetworkId(arnOrLabel: string): string {
  return `cloud-network-${normalizeKeyPart(arnOrLabel)}`;
}

export function splitQualifiedAccount(raw: string): { domain?: string; username: string } {
  const match = raw.match(/^([^\\/]+)[\\/](.+)$/);
  if (!match) {
    return { username: raw };
  }
  return {
    domain: match[1],
    username: match[2],
  };
}
