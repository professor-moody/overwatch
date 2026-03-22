// ============================================================
// BloodHound JSON Ingestion
// Parses SharpHound/bloodhound-python JSON output into Overwatch Findings
// ============================================================

import type { Finding, NodeType, EdgeType, NodeProperties } from '../types.js';
import { userId, hostId, domainId, normalizeKeyPart } from './parser-utils.js';

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
};

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
      sidMap.set(sid, resolveCanonicalId(sid, document.nodeType, obj.Properties || {}));
    }
  }

  return { sidMap, errors };
}

export function parseBloodHoundFile(
  raw: string,
  filename: string,
  options: BloodHoundParseOptions = {},
): { finding: Finding | null; errors: string[] } {
  const document = parseBloodHoundDocument(raw, filename);
  const errors: string[] = [];
  errors.push(...document.errors);
  if (!document.parsed) return { finding: null, errors };

  const parsed = document.parsed;
  const nodeType = document.nodeType;
  const metaType = (parsed.meta?.type || filename.replace(/\.json$/i, '')).toLowerCase();

  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];

  // Build SID -> ID lookup for nodes in this file and merge with any external directory-wide map.
  const sidMap = new Map<string, string>(options.sidMap ? Array.from(options.sidMap.entries()) : []);

  for (const obj of parsed.data) {
    const sid = obj.ObjectIdentifier;
    if (!sid) continue;

    const props = obj.Properties || {};
    const nodeId = nodeType
      ? resolveCanonicalId(sid, nodeType, props)
      : makeNodeId(sid, 'user');

    if (!sidMap.has(sid)) {
      sidMap.set(sid, nodeId);
    }

    // Create node
    if (nodeType) {
      const nodeProps = extractNodeProperties(props, nodeType, obj);
      nodes.push({
        id: sidMap.get(sid)!,
        type: nodeType,
        label: (props.name as string) || (props.displayname as string) || sid,
        bh_sid: sid,
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
  }

  if (nodes.length === 0 && edges.length === 0) {
    return { finding: null, errors };
  }

  const finding: Finding = {
    id: `bh-${metaType}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: 'bloodhound-ingest',
    timestamp: new Date().toISOString(),
    nodes,
    edges,
  };

  return { finding, errors };
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

function resolveCanonicalId(
  sid: string,
  nodeType: NodeType,
  props: Record<string, unknown>,
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
  obj: BHObject
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // Common properties
  if (props.description) result.notes = props.description;
  if (props.enabled !== undefined) result.enabled = props.enabled;
  if (props.domain) result.domain_name = props.domain;

  switch (nodeType) {
    case 'host':
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

    case 'gpo':
      if (props.gpcpath) result.share_path = props.gpcpath;
      break;
  }

  return result;
}
