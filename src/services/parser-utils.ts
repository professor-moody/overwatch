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

/**
 * P4-IPv6: canonical service node ID for `(ip, port)`. Centralizes IPv4
 * vs IPv6 normalization so two parsers don't disagree on the ID for the
 * same target — previously each parser inlined `ip.replace(/\./g, '-')`,
 * which silently dropped colons in IPv6 addresses and produced
 * ambiguous/colliding IDs across hosts.
 */
export function serviceId(ip: string, port: number | string): string {
  const portStr = String(port);
  if (ip.includes(':')) {
    const stripped = ip.replace(/^\[|\]$/g, '');
    return `svc-${stripped.replace(/:/g, '-')}-${portStr}`;
  }
  return `svc-${ip.replace(/\./g, '-')}-${portStr}`;
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

// --- OSINT / external-recon tier (Phase 2A) ---

/** Canonical subdomain id. DNS labels can't contain '.', so the dot separator is
 *  PRESERVED (not collapsed to '-' like normalizeKeyPart would) — otherwise
 *  `api-gw.example.com` and `api.gw.example.com` would collide on one node. */
export function subdomainId(fqdn: string): string {
  const norm = fqdn
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '');
  return `subdomain-${norm}`;
}

/** ASN canonical id from a number or "AS13335"-style string. */
export function asnId(asn: string | number): string {
  const digits = String(asn).replace(/[^0-9]/g, '');
  return `asn-${digits || normalizeKeyPart(String(asn))}`;
}

export function organizationId(name: string): string {
  return `organization-${normalizeKeyPart(name)}`;
}

/** Canonical email id. Splits on the LAST '@' and normalizes local-part and
 *  domain separately so distinct mailboxes don't merge — e.g.
 *  `jane@doe.example.com` and `jane.doe@example.com` get different ids. */
export function emailId(address: string): string {
  const at = address.lastIndexOf('@');
  if (at <= 0) return `email-${normalizeKeyPart(address)}`;
  const local = normalizeKeyPart(address.slice(0, at));
  const domain = normalizeKeyPart(address.slice(at + 1));
  return `email-${local}-at-${domain}`;
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

/**
 * Origin-level webapp ID (scheme + host + port only, path stripped).
 * Produces the same ID regardless of path, so cross-tool correlation
 * converges on a single webapp node per origin.
 */
export function webappOriginId(url: string): string {
  try {
    const parsed = new URL(url.trim());
    const origin = `${parsed.protocol}//${parsed.host}`;
    return webappId(origin);
  } catch {
    // If URL parsing fails, strip anything after the third slash
    const m = url.match(/^(https?:\/\/[^/]+)/i);
    return webappId(m ? m[1] : url);
  }
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

// ============================================================
// Identity tier (Phase 1 enterprise readiness)
// ============================================================

/** Canonical id for an `idp` node (Okta org, Entra tenant, …). */
export function idpId(kind: string, tenantOrIssuer: string): string {
  return `idp-${normalizeKeyPart(kind)}-${normalizeKeyPart(tenantOrIssuer)}`;
}

/** Canonical id for an `idp_application` (registered app). */
export function idpApplicationId(idpKind: string, tenantOrIssuer: string, clientIdOrName: string): string {
  return `idp-app-${normalizeKeyPart(idpKind)}-${normalizeKeyPart(tenantOrIssuer)}-${normalizeKeyPart(clientIdOrName)}`;
}

/**
 * Canonical id for an `idp_principal`. Prefer the IdP-internal user id
 * when available (stable across renames); fall back to UPN/email.
 */
export function idpPrincipalId(idpKind: string, tenantOrIssuer: string, userIdOrUpn: string): string {
  return `idp-principal-${normalizeKeyPart(idpKind)}-${normalizeKeyPart(tenantOrIssuer)}-${normalizeKeyPart(userIdOrUpn)}`;
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
