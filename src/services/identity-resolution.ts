import type { NodeProperties, NodeType } from '../types.js';
import {
  caId,
  certTemplateId,
  credentialId,
  domainId,
  groupId,
  hostId,
  normalizeKeyPart,
  pkiStoreId,
  splitQualifiedAccount,
  userId,
} from './parser-utils.js';

type IdentityStatus = 'canonical' | 'unresolved';

export interface IdentityResolution {
  id: string;
  status: IdentityStatus;
  markers: string[];
  family?: string;
}

export interface PrincipalIdentity {
  nodeType: 'user' | 'group';
  id: string;
  label: string;
  domain_name?: string;
  username?: string;
  ambiguous?: boolean;
}

const WELL_KNOWN_GROUP_NAMES = new Set([
  'administrators',
  'account operators',
  'backup operators',
  'cert publishers',
  'domain admins',
  'domain computers',
  'domain controllers',
  'domain guests',
  'domain users',
  'dnsadmins',
  'enterprise admins',
  'enterprise key admins',
  'group policy creator owners',
  'key admins',
  'print operators',
  'protected users',
  'remote desktop users',
  'schema admins',
  'server operators',
  'users',
  'authenticated users',
  'everyone',
]);

const USER_LIKE_TYPES = new Set<NodeType>(['user']);
const GROUP_LIKE_TYPES = new Set<NodeType>(['group']);
const IDENTITY_TYPES = new Set<NodeType>(['host', 'user', 'group', 'domain', 'credential', 'ca', 'cert_template', 'pki_store']);

export function resolveNodeIdentity(
  node: Partial<NodeProperties> & { id: string; type: NodeType },
): IdentityResolution {
  const family = getIdentityFamily(node.type);
  const markers = getIdentityMarkers(node);

  switch (node.type) {
    case 'host': {
      const ip = normalizeString(node.ip);
      if (ip) return { id: hostId(ip), status: 'canonical', markers, family };
      const hostName = firstDefinedString(node.hostname, node.dnshostname, node.dNSHostName, isNonIpLabel(node.label) ? node.label : undefined);
      if (hostName) return { id: `host-${normalizeKeyPart(hostName)}`, status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'domain': {
      const name = firstDefinedString(node.domain_name, node.domain, isDomainLike(node.label) ? node.label : undefined);
      if (name) return { id: domainId(name), status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'user': {
      const principal = resolveAccountPrincipal(node, 'user');
      if (principal) return { id: userId(principal.name, principal.domain), status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'group': {
      const principal = resolveAccountPrincipal(node, 'group');
      if (principal) return { id: groupId(principal.name, principal.domain), status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'credential': {
      const account = resolveCredentialAccount(node);
      const materialKind = normalizeCredentialMaterialKind(node);
      const fingerprint = normalizeString(node.cred_hash) || normalizeString(node.cred_value);
      if (materialKind && fingerprint && account?.domain) {
        return {
          id: credentialId(materialKind, fingerprint, account.name, account.domain),
          status: 'canonical',
          markers,
          family,
        };
      }
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'ca': {
      const name = firstDefinedString(node.ca_name, node.label);
      if (name) return { id: caId(name), status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'cert_template': {
      const name = firstDefinedString(node.template_name, node.label);
      if (name) return { id: certTemplateId(name), status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    case 'pki_store': {
      const kind = normalizeString(node.pki_store_kind);
      const name = firstDefinedString(node.label, node.display_name);
      if (kind && name) return { id: pkiStoreId(kind, name), status: 'canonical', markers, family };
      return { id: node.id, status: 'unresolved', markers, family };
    }
    default:
      return { id: node.id, status: 'canonical', markers, family };
  }
}

export function getIdentityMarkers(
  node: Partial<NodeProperties> & { type: NodeType },
): string[] {
  const family = getIdentityFamily(node.type);
  if (!family) return [];

  const markers = new Set<string>();
  const sid = normalizeString(node.sid) || normalizeString(node.bh_sid);
  if (sid) markers.add(`${family}:sid:${normalizeKeyPart(sid)}`);

  switch (node.type) {
    case 'host': {
      const ip = normalizeString(node.ip);
      if (ip) markers.add(`host:ip:${normalizeKeyPart(ip)}`);
      for (const name of [node.hostname, node.dnshostname, node.dNSHostName, isNonIpLabel(node.label) ? node.label : undefined]) {
        const normalized = normalizeString(name);
        if (normalized) markers.add(`host:name:${normalizeKeyPart(normalized)}`);
      }
      break;
    }
    case 'domain': {
      for (const value of [node.domain_name, node.domain, isDomainLike(node.label) ? node.label : undefined]) {
        const normalized = normalizeString(value);
        if (normalized) markers.add(`domain:name:${normalizeKeyPart(normalized)}`);
      }
      break;
    }
    case 'user':
    case 'group': {
      const principal = resolveAccountPrincipal(node, node.type);
      if (principal) {
        const kind = node.type === 'group' ? 'group' : 'user';
        markers.add(`${kind}:acct:${normalizeKeyPart(principal.domain || '')}:${normalizeKeyPart(principal.name)}`);
      }
      break;
    }
    case 'credential': {
      const account = resolveCredentialAccount(node);
      if (account?.domain) {
        markers.add(`credential:acct:${normalizeKeyPart(account.domain)}:${normalizeKeyPart(account.name)}`);
      }
      break;
    }
    case 'ca': {
      const name = firstDefinedString(node.ca_name, node.label);
      if (name) markers.add(`ca:name:${normalizeKeyPart(name)}`);
      break;
    }
    case 'cert_template': {
      const name = firstDefinedString(node.template_name, node.label);
      if (name) markers.add(`cert_template:name:${normalizeKeyPart(name)}`);
      break;
    }
    case 'pki_store': {
      const kind = normalizeString(node.pki_store_kind);
      const name = firstDefinedString(node.label, node.display_name);
      if (kind && name) markers.add(`pki_store:name:${normalizeKeyPart(kind)}:${normalizeKeyPart(name)}`);
      break;
    }
  }

  return [...markers];
}

export function isIdentityType(nodeType: NodeType): boolean {
  return IDENTITY_TYPES.has(nodeType);
}

export function isUnresolvedIdentityNode(node: Partial<NodeProperties> & { id: string; type: NodeType }): boolean {
  return node.identity_status === 'unresolved' || node.id.startsWith('bh-');
}

export function isCanonicalIdentityNode(node: Partial<NodeProperties> & { id: string; type: NodeType }): boolean {
  return isIdentityType(node.type) && !isUnresolvedIdentityNode(node);
}

export function resolveTypedRelationRef(
  objectId: string,
  objectType: string | undefined,
  sidMap: ReadonlyMap<string, string>,
): string | null {
  if (sidMap.has(objectId)) {
    return sidMap.get(objectId)!;
  }
  if (!objectType) {
    return null;
  }

  const nodeType = bhObjectTypeToNodeType(objectType);
  if (!nodeType) {
    return null;
  }

  const synthetic = buildSyntheticNodeForRef(objectId, objectType, nodeType);
  return resolveNodeIdentity(synthetic).id;
}

export function classifyPrincipalIdentity(raw: string): PrincipalIdentity {
  const value = raw.trim();
  const slash = splitQualifiedAccount(value);
  const atMatch = value.match(/^([^@]+)@(.+)$/);
  const domain = normalizeString(slash.domain || atMatch?.[2]);
  const accountName = normalizeString(atMatch ? atMatch[1] : slash.username || value) || value;
  const groupLike = looksLikeGroupPrincipal(accountName);
  const userLike = !groupLike && looksLikeUserPrincipal(accountName, value);
  const ambiguous = !groupLike && !userLike;
  const nodeType: 'user' | 'group' = groupLike ? 'group' : 'user';
  const id = nodeType === 'group' ? groupId(accountName, domain) : userId(accountName, domain);

  return {
    nodeType,
    id,
    label: value,
    domain_name: domain,
    username: nodeType === 'user' ? accountName : undefined,
    ambiguous,
  };
}

function resolveAccountPrincipal(
  node: Partial<NodeProperties> & { type: NodeType },
  preferredType: 'user' | 'group',
): { name: string; domain?: string } | null {
  const explicitName = normalizeString(node.username)
    || normalizeString(node.samaccountname)
    || normalizeString(node.group_name);
  const explicitDomain = normalizeString(node.domain_name) || normalizeString(node.domain);

  if (explicitName) {
    return { name: explicitName, domain: explicitDomain };
  }

  const label = normalizeString(node.label);
  if (!label) return null;

  if (label.includes('\\') || label.includes('@')) {
    const qualified = splitQualifiedAccount(label);
    if (qualified.domain) {
      return { name: normalizeString(qualified.username) || qualified.username, domain: normalizeString(qualified.domain) };
    }
    const atMatch = label.match(/^([^@]+)@(.+)$/);
    if (atMatch) {
      return { name: normalizeString(atMatch[1]) || atMatch[1], domain: normalizeString(atMatch[2]) };
    }
  }

  if (preferredType === 'group') {
    return { name: label, domain: explicitDomain };
  }

  return null;
}

function resolveCredentialAccount(node: Partial<NodeProperties>): { name: string; domain?: string } | null {
  const name = normalizeString(node.cred_user);
  if (!name) return null;
  return { name, domain: normalizeString(node.cred_domain) };
}

function normalizeCredentialMaterialKind(node: Partial<NodeProperties>): string | undefined {
  if (typeof node.cred_material_kind === 'string') return node.cred_material_kind;
  if (node.cred_type === 'ntlm') return 'ntlm_hash';
  if (node.cred_type === 'plaintext') return 'plaintext_password';
  if (typeof node.cred_type === 'string') return node.cred_type;
  return undefined;
}

function buildSyntheticNodeForRef(objectId: string, objectType: string, nodeType: NodeType): Partial<NodeProperties> & { id: string; type: NodeType } {
  const lowerType = objectType.toLowerCase();
  if (looksLikeOpaqueIdentifier(objectId) && ['user', 'group', 'host', 'domain'].includes(nodeType)) {
    return {
      id: `bh-${nodeType}-${normalizeKeyPart(objectId)}`,
      type: nodeType,
      label: objectId,
      bh_sid: objectId,
      identity_status: 'unresolved',
    };
  }
  if (USER_LIKE_TYPES.has(nodeType) || GROUP_LIKE_TYPES.has(nodeType)) {
    const principal = classifyPrincipalIdentity(objectId);
    return {
      id: principal.id,
      type: principal.nodeType,
      label: principal.label,
      username: principal.username,
      domain_name: principal.domain_name,
    };
  }

  if (nodeType === 'domain') {
    return { id: domainId(objectId), type: 'domain', label: objectId, domain_name: objectId };
  }
  if (nodeType === 'host') {
    return /^\d+\.\d+\.\d+\.\d+$/.test(objectId)
      ? { id: hostId(objectId), type: 'host', label: objectId, ip: objectId }
      : { id: `host-${normalizeKeyPart(objectId)}`, type: 'host', label: objectId, hostname: objectId };
  }
  if (nodeType === 'ca') {
    return { id: caId(objectId), type: 'ca', label: objectId, ca_name: objectId };
  }
  if (nodeType === 'cert_template') {
    return { id: certTemplateId(objectId), type: 'cert_template', label: objectId, template_name: objectId };
  }
  if (nodeType === 'pki_store') {
    const storeKind = lowerType.includes('ntauth') ? 'ntauth_store' : lowerType.includes('issuance') ? 'issuance_policy' : 'unknown';
    return { id: pkiStoreId(storeKind, objectId), type: 'pki_store', label: objectId, pki_store_kind: storeKind === 'unknown' ? undefined : storeKind };
  }

  return { id: `${nodeType}-${normalizeKeyPart(objectId)}`, type: nodeType, label: objectId };
}

function bhObjectTypeToNodeType(objectType: string): NodeType | null {
  switch (objectType.toLowerCase()) {
    case 'user':
    case 'users':
      return 'user';
    case 'group':
    case 'groups':
      return 'group';
    case 'computer':
    case 'computers':
      return 'host';
    case 'domain':
    case 'domains':
      return 'domain';
    case 'enterpriseca':
    case 'enterprisecas':
    case 'rootca':
    case 'rootcas':
    case 'aiaca':
    case 'aiacas':
      return 'ca';
    case 'certtemplate':
    case 'certtemplates':
      return 'cert_template';
    case 'ntauthstore':
    case 'ntauthstores':
    case 'issuancepolicy':
    case 'issuancepolicies':
      return 'pki_store';
    default:
      return null;
  }
}

function looksLikeGroupPrincipal(account: string): boolean {
  const normalized = normalizeKeyPart(account).replace(/-/g, ' ');
  if (WELL_KNOWN_GROUP_NAMES.has(normalized)) return true;
  if (/\b(users|admins|operators|owners|publishers|computers|controllers)\b/i.test(account)) return true;
  return /\s/.test(account.trim());
}

function looksLikeUserPrincipal(account: string, raw: string): boolean {
  if (account.endsWith('$')) return false;
  if (/\s/.test(account.trim())) return false;
  return raw.includes('\\') || raw.includes('@');
}

function getIdentityFamily(nodeType: NodeType): string | undefined {
  if (!IDENTITY_TYPES.has(nodeType)) return undefined;
  return nodeType;
}

function normalizeString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function firstDefinedString(...values: Array<unknown>): string | undefined {
  for (const value of values) {
    const normalized = normalizeString(value);
    if (normalized) return normalized;
  }
  return undefined;
}

function isDomainLike(value: unknown): boolean {
  const normalized = normalizeString(value);
  return !!normalized && normalized.includes('.');
}

function isNonIpLabel(value: unknown): value is string {
  const normalized = normalizeString(value);
  return !!normalized && !/^\d+\.\d+\.\d+\.\d+$/.test(normalized);
}

function looksLikeOpaqueIdentifier(value: string): boolean {
  return /^S-\d+-/i.test(value) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(value);
}
