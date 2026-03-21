// ============================================================
// BloodHound JSON Ingestion
// Parses SharpHound/bloodhound-python JSON output into Overwatch Findings
// ============================================================

import type { Finding, NodeType, EdgeType, NodeProperties } from '../types.js';

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

export function parseBloodHoundFile(raw: string, filename: string): { finding: Finding; errors: string[] } | null {
  const errors: string[] = [];
  let parsed: BHFile;

  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { finding: null as any, errors: [`Failed to parse ${filename}: ${err instanceof Error ? err.message : String(err)}`] };
  }

  if (!parsed.data || !Array.isArray(parsed.data)) {
    return { finding: null as any, errors: [`${filename}: missing or invalid 'data' array`] };
  }

  const metaType = (parsed.meta?.type || filename.replace(/\.json$/i, '')).toLowerCase();
  const nodeType = BH_NODE_TYPE_MAP[metaType];

  if (!nodeType) {
    errors.push(`${filename}: unknown BloodHound type '${metaType}', skipping node creation`);
  }

  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];

  for (const obj of parsed.data) {
    const sid = obj.ObjectIdentifier;
    if (!sid) continue;

    const props = obj.Properties || {};
    const nodeId = makeNodeId(sid, nodeType || 'user');

    // Create node
    if (nodeType) {
      const nodeProps = extractNodeProperties(props, nodeType, obj);
      nodes.push({
        id: nodeId,
        type: nodeType,
        label: (props.name as string) || (props.displayname as string) || sid,
        ...nodeProps,
      });
    }

    // ACEs → edges
    if (obj.Aces) {
      for (const ace of obj.Aces) {
        const edgeType = BH_EDGE_MAP[ace.RightName];
        if (!edgeType) continue;
        const sourceId = makeNodeId(ace.PrincipalSID, bhTypeToNodeType(ace.PrincipalType));
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
        const memberId = makeNodeId(member.ObjectIdentifier, bhTypeToNodeType(member.ObjectType));
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
        const userId = makeNodeId(session.UserSID, 'user');
        const computerId = makeNodeId(session.ComputerSID, 'host');
        edges.push({
          source: userId,
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
        const adminId = makeNodeId(admin.ObjectIdentifier, bhTypeToNodeType(admin.ObjectType));
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
        const rdpId = makeNodeId(rdp.ObjectIdentifier, bhTypeToNodeType(rdp.ObjectType));
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
        const psId = makeNodeId(ps.ObjectIdentifier, bhTypeToNodeType(ps.ObjectType));
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
        const targetId = makeNodeId(delegateSid, 'host');
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
        const actorId = makeNodeId(actor.ObjectIdentifier, bhTypeToNodeType(actor.ObjectType));
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
    return null;
  }

  const finding: Finding = {
    id: `bh-${metaType}-${Date.now()}`,
    agent_id: 'bloodhound-ingest',
    timestamp: new Date().toISOString(),
    nodes,
    edges,
  };

  return { finding, errors };
}

// --- Helpers ---

function makeNodeId(sid: string, nodeType: NodeType): string {
  // Normalize SID to a consistent node ID format
  const cleanSid = sid.replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase();
  return `bh-${nodeType}-${cleanSid}`;
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
      if (props.admincount) result.privileged = props.admincount;
      if (props.hasspn) result.has_spn = props.hasspn;
      if (props.sensitive) result.sensitive = props.sensitive;
      if (props.dontreqpreauth) result.asrep_roastable = props.dontreqpreauth;
      if (props.sid) result.sid = props.sid;
      break;

    case 'group':
      if (props.admincount) result.privileged = props.admincount;
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
