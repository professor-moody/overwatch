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
