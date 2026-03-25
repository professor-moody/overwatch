// ============================================================
// BloodHound JSON Ingestion
// Parses SharpHound/bloodhound-python JSON output into Overwatch Findings
// ============================================================

import type { Finding, NodeType, EdgeType, NodeProperties } from '../types.js';
import { caId, certTemplateId, domainId, groupId, hostId, normalizeKeyPart, pkiStoreId, splitQualifiedAccount, userId } from './parser-utils.js';
import { resolveNodeIdentity, resolveTypedRelationRef } from './identity-resolution.js';

// --- BloodHound JSON structures (SharpHound v4/v5 compatible) ---

interface BHFile {
  data: BHObject[];
  meta: { type: string; count: number; version: number };
}

interface BHObject {
  ObjectIdentifier: string;
  Properties: Record<string, unknown>;
  Aces?: BHAce[];
  Members?: BHMember[];
  Sessions?: BHSession[];
  LocalAdmins?: BHLocalGroup[];
  RemoteDesktopUsers?: BHLocalGroup[];
  PSRemoteUsers?: BHLocalGroup[];
  DcomUsers?: BHLocalGroup[];
  AllowedToDelegate?: string[];
  AllowedToAct?: BHMember[];
  HasSIDHistory?: BHMember[];
  SPNTargets?: BHSPNTarget[];
  // Computers-specific
  Status?: { Connectable: boolean; Error?: string };
  [key: string]: unknown;
}

interface BHAce {
  PrincipalSID: string;
  PrincipalType: string;
  RightName: string;
  IsInherited: boolean;
}

interface BHMember {
  ObjectIdentifier: string;
  ObjectType: string;
}

interface BHSession {
  UserSID: string;
  ComputerSID: string;
}

interface BHLocalGroup {
  ObjectIdentifier: string;
  ObjectType: string;
}

interface BHSPNTarget {
  ComputerSID: string;
  Port: number;
  Service: string;
}

// --- Type Mappings ---

const BH_NODE_TYPE_MAP: Record<string, NodeType> = {
  'computer': 'host',
  'computers': 'host',
  'user': 'user',
  'users': 'user',
  'group': 'group',
  'groups': 'group',
  'domain': 'domain',
  'domains': 'domain',
  'ou': 'ou',
  'ous': 'ou',
  'gpo': 'gpo',
  'gpos': 'gpo',
  'container': 'ou',
  'containers': 'ou',
  'certtemplate': 'cert_template',
  'certtemplates': 'cert_template',
  'enterpriseca': 'ca',
  'enterprisecas': 'ca',
  'rootca': 'ca',
  'rootcas': 'ca',
  'aiaca': 'ca',
  'aiacas': 'ca',
  'ntauthstore': 'pki_store',
  'ntauthstores': 'pki_store',
  'issuancepolicy': 'pki_store',
  'issuancepolicies': 'pki_store',
};

const BH_EDGE_MAP: Record<string, EdgeType> = {
  'MemberOf': 'MEMBER_OF',
  'AdminTo': 'ADMIN_TO',
  'HasSession': 'HAS_SESSION',
  'CanRDP': 'CAN_RDPINTO',
  'CanPSRemote': 'CAN_PSREMOTE',
  'GenericAll': 'GENERIC_ALL',
  'GenericWrite': 'GENERIC_WRITE',
  'WriteOwner': 'WRITE_OWNER',
  'WriteDacl': 'WRITE_DACL',
  'AddMember': 'ADD_MEMBER',
  'ForceChangePassword': 'FORCE_CHANGE_PASSWORD',
  'AllowedToDelegate': 'DELEGATES_TO',
  'AllowedToAct': 'ALLOWED_TO_ACT',
  'DCSync': 'CAN_DCSYNC',
  'GetChanges': 'CAN_DCSYNC',
  'GetChangesAll': 'CAN_DCSYNC',
  'Owns': 'GENERIC_ALL',
  'WriteSPN': 'GENERIC_WRITE',
  'AddSelf': 'ADD_MEMBER',
  'ReadLAPSPassword': 'ADMIN_TO',
  'ReadGMSAPassword': 'ADMIN_TO',
  'HasSIDHistory': 'RELATED',
  'Contains': 'MEMBER_OF',
  'GPLink': 'RELATED',
  'TrustedBy': 'TRUSTS',
  'Enroll': 'CAN_ENROLL',
  'ADCSESC1': 'ESC1',
  'ADCSESC2': 'ESC2',
  'ADCSESC3': 'ESC3',
  'ADCSESC4': 'ESC4',
  'ADCSESC6': 'ESC6',
  'ADCSESC8': 'ESC8',
  'ManageCertificates': 'GENERIC_ALL',
  'ManageCA': 'GENERIC_ALL',
};

const BH_RELATION_ARRAY_MAP: Array<{
  key: string;
  edgeType: EdgeType;
  direction: 'inbound' | 'outbound';
}> = [
  { key: 'PublishedTo', edgeType: 'RELATED', direction: 'outbound' },
  { key: 'IssuedSignedBy', edgeType: 'RELATED', direction: 'outbound' },
  { key: 'EnterpriseCAFor', edgeType: 'RELATED', direction: 'outbound' },
  { key: 'Enroll', edgeType: 'CAN_ENROLL', direction: 'inbound' },
  { key: 'ADCSESC1', edgeType: 'ESC1', direction: 'inbound' },
  { key: 'ADCSESC2', edgeType: 'ESC2', direction: 'inbound' },
  { key: 'ADCSESC3', edgeType: 'ESC3', direction: 'inbound' },
  { key: 'ADCSESC4', edgeType: 'ESC4', direction: 'inbound' },
  { key: 'ADCSESC6', edgeType: 'ESC6', direction: 'inbound' },
  { key: 'ADCSESC8', edgeType: 'ESC8', direction: 'inbound' },
  { key: 'ManageCertificates', edgeType: 'GENERIC_ALL', direction: 'inbound' },
  { key: 'ManageCA', edgeType: 'GENERIC_ALL', direction: 'inbound' },
];

const BH_STANDARD_ARRAY_KEYS = new Set([
  'Aces', 'Members', 'Sessions', 'LocalAdmins', 'RemoteDesktopUsers',
  'PSRemoteUsers', 'DcomUsers', 'AllowedToDelegate', 'AllowedToAct',
  'HasSIDHistory', 'SPNTargets',
]);

// --- SharpHound CE Format Normalization ---

// SharpHound CE (v2 / BloodHound CE) uses PascalCase property keys and meta.version >= 5.
// Classic (bloodhound-python / SharpHound v4) uses lowercase property keys.
// This adapter normalizes CE format to classic format so the same parser handles both.

function isSharpHoundCE(parsed: BHFile): boolean {
  // CE uses meta.version >= 5; classic uses 3 or 4
  if (parsed.meta?.version >= 5) return true;

  // Heuristic: check if first object's Properties has PascalCase keys
  if (parsed.data?.length > 0) {
    const props = parsed.data[0].Properties;
    if (props) {
      const keys = Object.keys(props);
      // CE typically has keys like 'SAMAccountName', 'DisplayName', 'Enabled'
      // Classic has 'samaccountname', 'displayname', 'enabled'
      const hasPascalCase = keys.some(k => /^[A-Z]/.test(k) && k.length > 1 && k !== k.toUpperCase());
      const hasLowerCase = keys.some(k => /^[a-z]/.test(k));
      if (hasPascalCase && !hasLowerCase) return true;
    }
  }
  return false;
}

function lowercaseObjectKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key.toLowerCase()] = value;
  }
  return result;
}

export function normalizeSharpHoundCE(raw: string, filename: string): { normalized: string; wasCE: boolean; error?: string } {
  let parsed: BHFile;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { normalized: raw, wasCE: false, error: `Failed to parse ${filename}: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (!parsed.data || !Array.isArray(parsed.data)) {
    return { normalized: raw, wasCE: false };
  }

  if (!isSharpHoundCE(parsed)) {
    return { normalized: raw, wasCE: false };
  }

  // Normalize: lowercase all property keys in each object
  const normalizedData = parsed.data.map((obj: BHObject) => {
    const normalizedObj: Record<string, unknown> = { ...obj };

    // Normalize Properties keys to lowercase
    if (obj.Properties && typeof obj.Properties === 'object') {
      normalizedObj.Properties = lowercaseObjectKeys(obj.Properties);
    }

    return normalizedObj;
  });

  const normalizedFile = {
    ...parsed,
    data: normalizedData,
    meta: {
      ...parsed.meta,
      // Preserve original version but mark as normalized
      _original_version: parsed.meta?.version,
    },
  };

  return { normalized: JSON.stringify(normalizedFile), wasCE: true };
}

// --- Ingestion ---

export interface BloodHoundIngestResult {
  files_processed: number;
  total_nodes: number;
  total_edges: number;
  findings: Finding[];
  errors: string[];
}

export interface BloodHoundParseOptions {
  sidMap?: ReadonlyMap<string, string>;
}

interface ParsedBloodHoundDocument {
  parsed: BHFile | null;
  nodeType?: NodeType;
  errors: string[];
}

export function buildBloodHoundSidMap(files: Array<{ raw: string; filename: string }>): { sidMap: Map<string, string>; errors: string[] } {
  const sidMap = new Map<string, string>();
  const errors: string[] = [];

  for (const file of files) {
    const document = parseBloodHoundDocument(file.raw, file.filename);
    errors.push(...document.errors);
    if (!document.parsed || !document.nodeType) continue;

    for (const obj of document.parsed.data) {
      const sid = obj.ObjectIdentifier;
      if (!sid) continue;
      sidMap.set(
        sid,
        resolveCanonicalId(sid, document.nodeType, obj.Properties || {}, document.parsed.meta?.type?.toLowerCase()),
      );
    }
  }

  return { sidMap, errors };
}

export function parseBloodHoundFile(
  raw: string,
  filename: string,
  options: BloodHoundParseOptions = {},
): { finding: Finding | null; errors: string[]; wasCE?: boolean } {
  // Auto-detect and normalize SharpHound CE format
  const ceResult = normalizeSharpHoundCE(raw, filename);
  const effectiveRaw = ceResult.normalized;
  const wasCE = ceResult.wasCE;

  const document = parseBloodHoundDocument(effectiveRaw, filename);
  const errors: string[] = [];
  errors.push(...document.errors);
  if (!document.parsed) return { finding: null, errors };

  const parsed = document.parsed;
  const nodeType = document.nodeType;
  const metaType = (parsed.meta?.type || filename.replace(/\.json$/i, '')).toLowerCase();

  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const relationWarnings = new Set<string>();

  // Build SID -> ID lookup for nodes in this file and merge with any external directory-wide map.
  const sidMap = new Map<string, string>(options.sidMap ? Array.from(options.sidMap.entries()) : []);

  for (const obj of parsed.data) {
    const sid = obj.ObjectIdentifier;
    if (!sid) continue;

    const props = obj.Properties || {};
    const nodeId = nodeType
      ? resolveCanonicalId(sid, nodeType, props, metaType)
      : makeNodeId(sid, 'user');

    if (!sidMap.has(sid)) {
      sidMap.set(sid, nodeId);
    }

    // Create node
    if (nodeType) {
      const nodeProps = extractNodeProperties(props, nodeType, obj, metaType);
      const label = (nodeProps.ca_name as string | undefined)
        || (nodeProps.template_name as string | undefined)
        || (props.name as string)
        || (props.displayname as string)
        || sid;
      const identity = resolveNodeIdentity({
        id: sidMap.get(sid)!,
        type: nodeType,
        label,
        ...nodeProps,
      });
      nodes.push({
        id: identity.id,
        type: nodeType,
        label,
        bh_sid: sid,
        identity_status: identity.status,
        identity_family: identity.family,
        canonical_id: identity.status === 'canonical' ? identity.id : undefined,
        identity_markers: identity.markers,
        ...nodeProps,
      });
    }
  }

  // Helper: resolve SID to canonical ID if known, else fallback to SID-based
  const resolveSid = (sid: string, fallbackType: NodeType): string =>
    sidMap.get(sid) || makeNodeId(sid, fallbackType);

  // Second pass: build edges using resolved IDs
  for (const obj of parsed.data) {
    const sid = obj.ObjectIdentifier;
    if (!sid) continue;

    const nodeId = resolveSid(sid, nodeType || 'user');

    // ACEs → edges
    if (obj.Aces) {
      for (const ace of obj.Aces) {
        const edgeType = BH_EDGE_MAP[ace.RightName];
        if (!edgeType) continue;
        const sourceId = resolveSid(ace.PrincipalSID, bhTypeToNodeType(ace.PrincipalType));
        edges.push({
          source: sourceId,
          target: nodeId,
          properties: {
            type: edgeType,
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
            inherited: ace.IsInherited,
          },
        });
      }
    }

    // Members → MEMBER_OF edges
    if (obj.Members) {
      for (const member of obj.Members) {
        const memberId = resolveSid(member.ObjectIdentifier, bhTypeToNodeType(member.ObjectType));
        edges.push({
          source: memberId,
          target: nodeId,
          properties: {
            type: 'MEMBER_OF',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // Sessions → HAS_SESSION edges
    if (obj.Sessions) {
      for (const session of obj.Sessions) {
        const sessUserId = resolveSid(session.UserSID, 'user');
        const computerId = resolveSid(session.ComputerSID, 'host');
        edges.push({
          source: sessUserId,
          target: computerId,
          properties: {
            type: 'HAS_SESSION',
            confidence: 0.9,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // LocalAdmins → ADMIN_TO edges
    if (obj.LocalAdmins) {
      for (const admin of obj.LocalAdmins) {
        const adminId = resolveSid(admin.ObjectIdentifier, bhTypeToNodeType(admin.ObjectType));
        edges.push({
          source: adminId,
          target: nodeId,
          properties: {
            type: 'ADMIN_TO',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // RemoteDesktopUsers → CAN_RDPINTO edges
    if (obj.RemoteDesktopUsers) {
      for (const rdp of obj.RemoteDesktopUsers) {
        const rdpId = resolveSid(rdp.ObjectIdentifier, bhTypeToNodeType(rdp.ObjectType));
        edges.push({
          source: rdpId,
          target: nodeId,
          properties: {
            type: 'CAN_RDPINTO',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // PSRemoteUsers → CAN_PSREMOTE edges
    if (obj.PSRemoteUsers) {
      for (const ps of obj.PSRemoteUsers) {
        const psId = resolveSid(ps.ObjectIdentifier, bhTypeToNodeType(ps.ObjectType));
        edges.push({
          source: psId,
          target: nodeId,
          properties: {
            type: 'CAN_PSREMOTE',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // AllowedToDelegate → DELEGATES_TO edges
    if (obj.AllowedToDelegate) {
      for (const delegateSid of obj.AllowedToDelegate) {
        const targetId = resolveSid(delegateSid, 'host');
        edges.push({
          source: nodeId,
          target: targetId,
          properties: {
            type: 'DELEGATES_TO',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // AllowedToAct → ALLOWED_TO_ACT edges
    if (obj.AllowedToAct) {
      for (const actor of obj.AllowedToAct) {
        const actorId = resolveSid(actor.ObjectIdentifier, bhTypeToNodeType(actor.ObjectType));
        edges.push({
          source: actorId,
          target: nodeId,
          properties: {
            type: 'ALLOWED_TO_ACT',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    for (const relation of BH_RELATION_ARRAY_MAP) {
      const refs = extractRelationRefs(obj[relation.key]);
      for (const ref of refs) {
        const relatedNodeId = resolveRelationRef(ref, sidMap);
        if (!relatedNodeId) continue;

        const source = relation.direction === 'inbound' ? relatedNodeId : nodeId;
        const target = relation.direction === 'inbound' ? nodeId : relatedNodeId;
        edges.push({
          source,
          target,
          properties: {
            type: relation.edgeType,
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    // MEMBER_OF_DOMAIN edges for nodes with an explicit domain property
    if (nodeType && ['user', 'host', 'group'].includes(nodeType)) {
      const props = obj.Properties || {};
      const domainName = props.domain as string | undefined;
      if (domainName) {
        const resolvedDomainId = domainId(domainName);
        edges.push({
          source: nodeId,
          target: resolvedDomainId,
          properties: {
            type: 'MEMBER_OF_DOMAIN',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'bloodhound-ingest',
          },
        });
      }
    }

    if (isAdcsMetaType(metaType)) {
      for (const [key, value] of Object.entries(obj)) {
        if (!Array.isArray(value) || value.length === 0 || BH_STANDARD_ARRAY_KEYS.has(key)) continue;
        if (BH_RELATION_ARRAY_MAP.some((relation) => relation.key === key)) continue;
        if (key.startsWith('ADCS') || ['Enroll', 'PublishedTo', 'IssuedSignedBy', 'EnterpriseCAFor', 'ManageCertificates', 'ManageCA'].includes(key)) {
          relationWarnings.add(`${filename}: unmapped ADCS relationship '${key}', skipping`);
        }
      }
    }
  }

  errors.push(...relationWarnings);

  if (nodes.length === 0 && edges.length === 0) {
    return { finding: null, errors, wasCE };
  }

  const finding: Finding = {
    id: `bh-${metaType}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: 'bloodhound-ingest',
    timestamp: new Date().toISOString(),
    nodes,
    edges,
  };

  return { finding, errors, wasCE };
}

// --- Helpers ---

function parseBloodHoundDocument(raw: string, filename: string): ParsedBloodHoundDocument {
  let parsed: BHFile;

  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return {
      parsed: null,
      errors: [`Failed to parse ${filename}: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (!parsed.data || !Array.isArray(parsed.data)) {
    return {
      parsed: null,
      errors: [`${filename}: missing or invalid 'data' array`],
    };
  }

  const metaType = (parsed.meta?.type || filename.replace(/\.json$/i, '')).toLowerCase();
  const nodeType = BH_NODE_TYPE_MAP[metaType];
  const errors = nodeType
    ? []
    : [`${filename}: unknown BloodHound type '${metaType}', skipping node creation`];

  return { parsed, nodeType, errors };
}

function makeNodeId(sid: string, nodeType: NodeType): string {
  // Fallback SID-based ID for objects without identity fields
  const cleanSid = sid.replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase();
  return `bh-${nodeType}-${cleanSid}`;
}

function normalizeBhFallbackId(prefix: string, objectId: string): string {
  return `${prefix}-${normalizeKeyPart(objectId)}`;
}

function resolveRelationRef(
  ref: { objectId: string; objectType?: string },
  sidMap: ReadonlyMap<string, string>,
): string | null {
  return resolveTypedRelationRef(ref.objectId, ref.objectType, sidMap);
}

function isAdcsMetaType(metaType?: string): boolean {
  if (!metaType) return false;
  return [
    'certtemplate', 'certtemplates',
    'enterpriseca', 'enterprisecas',
    'rootca', 'rootcas',
    'aiaca', 'aiacas',
    'ntauthstore', 'ntauthstores',
    'issuancepolicy', 'issuancepolicies',
  ].includes(metaType);
}

function resolveCanonicalId(
  sid: string,
  nodeType: NodeType,
  props: Record<string, unknown>,
  metaType?: string,
): string {
  switch (nodeType) {
    case 'user': {
      const sam = props.samaccountname as string | undefined;
      const domain = props.domain as string | undefined;
      if (sam) return userId(sam, domain);
      // Try name field (format: USER@DOMAIN or DOMAIN\USER)
      const name = props.name as string | undefined;
      if (name) {
        const atMatch = name.match(/^([^@]+)@(.+)$/);
        if (atMatch) return userId(atMatch[1], atMatch[2]);
        const slashMatch = name.match(/^([^\\]+)\\(.+)$/);
        if (slashMatch) return userId(slashMatch[2], slashMatch[1]);
      }
      return makeNodeId(sid, nodeType);
    }
    case 'group': {
      const name = (props.samaccountname as string | undefined)
        || (props.name as string | undefined)
        || (props.displayname as string | undefined);
      const domain = props.domain as string | undefined;
      if (name) {
        const atMatch = name.match(/^([^@]+)@(.+)$/);
        if (atMatch) {
          return groupId(atMatch[1], atMatch[2]);
        }
        const qualified = splitQualifiedAccount(name);
        if (qualified.domain) {
          return groupId(qualified.username, qualified.domain);
        }
        return groupId(name, domain);
      }
      return makeNodeId(sid, nodeType);
    }
    case 'host': {
      // Prefer IP if available, else use hostname
      // BH computers don't typically have IPs in Properties, but some enriched exports do
      const ip = props.ip as string | undefined;
      if (ip) return hostId(ip);
      const name = props.name as string | undefined;
      const dns = props.dnshostname as string | undefined;
      const hostname = dns || name;
      if (hostname) return `host-${normalizeKeyPart(hostname)}`;
      return makeNodeId(sid, nodeType);
    }
    case 'domain': {
      const name = props.name as string | undefined;
      const domain = props.domain as string | undefined;
      const domainName = name || domain;
      if (domainName) return domainId(domainName);
      return makeNodeId(sid, nodeType);
    }
    case 'ca': {
      const caName = (props.caname as string | undefined) || (props.name as string | undefined);
      if (caName) return caId(caName);
      return normalizeBhFallbackId('bh-ca', sid);
    }
    case 'cert_template': {
      const templateName = (props.templatename as string | undefined) || (props.name as string | undefined);
      if (templateName) return certTemplateId(templateName);
      return normalizeBhFallbackId('bh-cert-template', sid);
    }
    case 'pki_store': {
      const storeName = (props.name as string | undefined) || (props.displayname as string | undefined);
      const storeKind = metaType === 'ntauthstore' || metaType === 'ntauthstores'
        ? 'ntauth_store'
        : metaType === 'issuancepolicy' || metaType === 'issuancepolicies'
          ? 'issuance_policy'
          : undefined;
      if (storeName && storeKind) return pkiStoreId(storeKind, storeName);
      return normalizeBhFallbackId('bh-pki-store', sid);
    }
    default:
      // group, ou, gpo — no canonical equivalent in other parsers
      return makeNodeId(sid, nodeType);
  }
}

function bhTypeToNodeType(bhType: string): NodeType {
  const lower = bhType.toLowerCase();
  return BH_NODE_TYPE_MAP[lower] || 'user';
}

function extractNodeProperties(
  props: Record<string, unknown>,
  nodeType: NodeType,
  obj: BHObject,
  metaType?: string,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // Common properties
  if (props.description) result.notes = props.description;
  if (props.enabled !== undefined) result.enabled = props.enabled;
  if (props.domain) result.domain_name = props.domain;

  switch (nodeType) {
    case 'host':
      if (props.ip) result.ip = props.ip;
      if (props.dnshostname || props.name) result.hostname = (props.dnshostname as string | undefined) || (props.name as string | undefined);
      if (props.operatingsystem) result.os = props.operatingsystem;
      if (props.unconstraineddelegation) result.unconstrained_delegation = props.unconstraineddelegation;
      if (props.enabled !== undefined) result.alive = props.enabled;
      result.domain_joined = true;
      if (obj.Status) result.alive = obj.Status.Connectable;
      break;

    case 'user':
      if (props.displayname) result.display_name = props.displayname;
      if (props.admincount !== undefined) result.privileged = !!props.admincount;
      if (props.hasspn) result.has_spn = props.hasspn;
      if (props.sensitive) result.sensitive = props.sensitive;
      if (props.dontreqpreauth) result.asrep_roastable = props.dontreqpreauth;
      if (props.sid) result.sid = props.sid;
      break;

    case 'group':
      if (props.admincount !== undefined) result.privileged = !!props.admincount;
      if (props.sid) result.sid = props.sid;
      break;

    case 'domain':
      if (props.functionallevel) result.functional_level = props.functionallevel;
      break;

    case 'subnet':
      if (props.name) result.cidr = props.name;
      break;

    case 'gpo':
      if (props.gpcpath) result.share_path = props.gpcpath;
      break;

    case 'ca':
      if (props.caname || props.name) result.ca_name = (props.caname as string | undefined) || (props.name as string | undefined);
      if (metaType === 'enterpriseca' || metaType === 'enterprisecas') result.ca_kind = 'enterprise_ca';
      else if (metaType === 'rootca' || metaType === 'rootcas') result.ca_kind = 'root_ca';
      else if (metaType === 'aiaca' || metaType === 'aiacas') result.ca_kind = 'aia_ca';
      break;

    case 'cert_template':
      if (props.templatename || props.name) result.template_name = (props.templatename as string | undefined) || (props.name as string | undefined);
      if (props.caservicename || props.caname) result.ca_name = (props.caservicename as string | undefined) || (props.caname as string | undefined);
      if (props.enrolleesuppliessubject !== undefined) result.enrollee_supplies_subject = !!props.enrolleesuppliessubject;
      if (Array.isArray(props.eku)) result.eku = props.eku;
      else if (Array.isArray(props.ekus)) result.eku = props.ekus;
      break;

    case 'pki_store':
      if (metaType === 'ntauthstore' || metaType === 'ntauthstores') result.pki_store_kind = 'ntauth_store';
      else if (metaType === 'issuancepolicy' || metaType === 'issuancepolicies') result.pki_store_kind = 'issuance_policy';
      break;
  }

  return result;
}

function extractRelationRefs(value: unknown): Array<{ objectId: string; objectType?: string }> {
  if (!Array.isArray(value)) return [];
  const refs: Array<{ objectId: string; objectType?: string }> = [];
  for (const entry of value) {
    if (typeof entry === 'string' && entry.length > 0) {
      refs.push({ objectId: entry });
      continue;
    }
    if (entry && typeof entry === 'object' && typeof (entry as Record<string, unknown>).ObjectIdentifier === 'string') {
      refs.push({
        objectId: (entry as Record<string, string>).ObjectIdentifier,
        objectType: typeof (entry as Record<string, unknown>).ObjectType === 'string'
          ? (entry as Record<string, string>).ObjectType
          : undefined,
      });
    }
  }
  return refs;
}
