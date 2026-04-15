import type { Finding, EdgeType, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { domainId, groupId, hostId, normalizeKeyPart, resolveDomainName, userId } from '../parser-utils.js';

export function parseEnum4linux(output: string, agentId: string = 'enum4linux-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenEdges.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenEdges.add(key);
  }

  // Try JSON first (enum4linux-ng -oJ)
  try {
    const data = JSON.parse(output);
    return parseEnum4linuxJson(data, agentId, context);
  } catch {
    // Fall back to text parsing
  }

  // Text-mode parsing
  let targetIp: string | undefined;
  let domain: string | undefined;
  let nullSession = false;

  for (const line of output.split('\n')) {
    // Target IP (IPv4, IPv6, or hostname)
    const targetMatch = line.match(/Target:\s*(\S+)/i) ||
                         line.match(/\|\s*Target\s*\|\s*(\S+)/);
    if (targetMatch) { targetIp = targetMatch[1]; continue; }

    // Domain/Workgroup
    const domainMatch = line.match(/Domain:\s*(\S+)/i) ||
                         line.match(/\[\+\]\s*.*domain\s+name:\s*(\S+)/i);
    if (domainMatch && !domain) { domain = resolveDomainName(domainMatch[1], context?.domain_aliases); continue; }

    // Null session
    if (/null session/i.test(line) && /\[\+\]/.test(line)) {
      nullSession = true;
      continue;
    }

    // RID-cycled users: 500: ACME\Administrator or 1103: ACME\jdoe (SidTypeUser)
    const ridMatch = line.match(/(\d+):\s*([^\\]+)\\(\S+)\s*\(SidTypeUser\)/i);
    if (ridMatch) {
      const [, , ridDomain, username] = ridMatch;
      const resolvedDomain = ridDomain ? resolveDomainName(ridDomain, context?.domain_aliases) : domain;
      const resolvedUserId = userId(username, resolvedDomain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: resolvedDomain ? `${resolvedDomain}\\${username}` : username,
          username,
          domain_name: resolvedDomain,
        });
        seenNodes.add(resolvedUserId);
      }
      if (resolvedDomain) {
        const resolvedDomainId = domainId(resolvedDomain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: resolvedDomain, domain_name: resolvedDomain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }
      continue;
    }

    // RID-cycled groups: 513: ACME\Domain Users (SidTypeGroup)
    const ridGroupMatch = line.match(/(\d+):\s*([^\\]+)\\(.+?)\s*\(SidTypeGroup\)/i);
    if (ridGroupMatch) {
      const [, , gDomain, gName] = ridGroupMatch;
      const resolvedGDomain = gDomain ? resolveDomainName(gDomain, context?.domain_aliases) : domain;
      const resolvedGroupId = groupId(gName, resolvedGDomain);
      if (!seenNodes.has(resolvedGroupId)) {
        nodes.push({ id: resolvedGroupId, type: 'group', label: gName, domain_name: resolvedGDomain });
        seenNodes.add(resolvedGroupId);
      }
      continue;
    }

    // Share enumeration: [+] sharename ... READ/WRITE or Mapping: OK, Listing: OK
    const shareMatch = line.match(/\[\+\]\s*(\S+)\s+.*(?:READ|WRITE|Mapping:\s*OK)/i);
    if (shareMatch && targetIp) {
      const shareName = shareMatch[1];
      if (shareName.startsWith('[') || shareName === 'Enumerating') continue;
      const shareNodeId = `share-${hostId(targetIp).replace(/^host-/, '')}-${normalizeKeyPart(shareName)}`;
      if (!seenNodes.has(shareNodeId)) {
        const readable = /READ/i.test(line) || /Listing:\s*OK/i.test(line);
        const writable = /WRITE/i.test(line);
        nodes.push({
          id: shareNodeId,
          type: 'share',
          label: `\\\\${targetIp}\\${shareName}`,
          share_name: shareName,
          readable: readable || undefined,
          writable: writable || undefined,
        });
        seenNodes.add(shareNodeId);
      }
    }
  }

  // Create host and SMB service context if we found a target
  if (targetIp) {
    const resolvedHostId = hostId(targetIp);
    const serviceNodeId = `svc-${resolvedHostId.replace(/^host-/, '')}-445`;

    if (!seenNodes.has(resolvedHostId)) {
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: targetIp,
        ip: targetIp,
        alive: true,
        domain_joined: domain ? true : undefined,
        null_session: nullSession || undefined,
      });
      seenNodes.add(resolvedHostId);
    }
    if (!seenNodes.has(serviceNodeId)) {
      nodes.push({
        id: serviceNodeId,
        type: 'service',
        label: 'smb/445',
        port: 445,
        protocol: 'tcp',
        service_name: 'smb',
      });
      seenNodes.add(serviceNodeId);
    }
    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);

    if (nullSession) {
      addEdgeOnce(resolvedHostId, serviceNodeId, 'NULL_SESSION', 1.0);
    }

    // Attach shares to host
    for (const node of nodes) {
      if (node.type === 'share') {
        addEdgeOnce(resolvedHostId, node.id, 'RELATED', 1.0);
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseEnum4linuxJson(data: Record<string, unknown>, agentId: string, context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenEdges.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenEdges.add(key);
  }

  const target = data.target as Record<string, unknown> | undefined;
  const domainInfoObj = data.domain_info as Record<string, unknown> | undefined;
  const osInfo = data.os_info as Record<string, unknown> | undefined;
  const sessionCheck = data.session_check as Record<string, unknown> | undefined;
  const smbInfo = data.smb_info as Record<string, unknown> | undefined;

  const targetIp = (target?.host || target?.ip || osInfo?.target) as string | undefined;
  const rawDomain = (domainInfoObj?.domain || target?.domain) as string | undefined;
  const domain = rawDomain ? resolveDomainName(rawDomain, context?.domain_aliases) : undefined;
  const nullSession = sessionCheck?.null_session_allowed === true ||
                       sessionCheck?.null_session === true;
  const smbSigning = smbInfo?.signing_required;

  // Host + service
  if (targetIp) {
    const resolvedHostId = hostId(targetIp);
    const serviceNodeId = `svc-${resolvedHostId.replace(/^host-/, '')}-445`;

    nodes.push({
      id: resolvedHostId,
      type: 'host',
      label: targetIp,
      ip: targetIp,
      hostname: (osInfo?.hostname as string) || undefined,
      os: (osInfo?.os || osInfo?.os_version) as string | undefined,
      alive: true,
      domain_joined: domain ? true : undefined,
      null_session: nullSession || undefined,
    });
    seenNodes.add(resolvedHostId);

    nodes.push({
      id: serviceNodeId,
      type: 'service',
      label: 'smb/445',
      port: 445,
      protocol: 'tcp',
      service_name: 'smb',
      smb_signing: smbSigning,
    });
    seenNodes.add(serviceNodeId);
    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);

    if (nullSession) {
      addEdgeOnce(resolvedHostId, serviceNodeId, 'NULL_SESSION', 1.0);
    }
  }

  // Users
  const users = data.users || {};
  for (const [_rid, rawUser] of Object.entries(users as Record<string, unknown>)) {
    const userObj = rawUser as Record<string, unknown>;
    const username = (userObj.username || userObj.name) as string | undefined;
    if (!username) continue;
    const resolvedUserId = userId(username, domain);
    if (seenNodes.has(resolvedUserId)) continue;

    nodes.push({
      id: resolvedUserId,
      type: 'user',
      label: domain ? `${domain}\\${username}` : username,
      username,
      domain_name: domain,
    });
    seenNodes.add(resolvedUserId);

    if (domain) {
      const resolvedDomainId = domainId(domain);
      if (!seenNodes.has(resolvedDomainId)) {
        nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(resolvedDomainId);
      }
      addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
    }
  }

  // Groups
  const groups = data.groups || {};
  for (const [_rid, rawGroup] of Object.entries(groups as Record<string, unknown>)) {
    const grpObj = rawGroup as Record<string, unknown>;
    const gName = (grpObj.groupname || grpObj.name) as string | undefined;
    if (!gName) continue;
    const resolvedGroupId = groupId(gName, domain);
    if (seenNodes.has(resolvedGroupId)) continue;

    nodes.push({
      id: resolvedGroupId,
      type: 'group',
      label: gName,
      domain_name: domain,
    });
    seenNodes.add(resolvedGroupId);

    // Members — create user nodes for any members not already seen
    for (const member of (Array.isArray(grpObj.members) ? grpObj.members as unknown[] : [])) {
      const mObj = typeof member !== 'string' ? member as Record<string, unknown> : null;
      const memberName = (typeof member === 'string' ? member : mObj?.name || mObj?.username) as string | undefined;
      if (!memberName) continue;
      const resolvedUserId = userId(memberName, domain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${memberName}` : memberName,
          username: memberName,
          domain_name: domain,
        });
        seenNodes.add(resolvedUserId);
      }
      addEdgeOnce(resolvedUserId, resolvedGroupId, 'MEMBER_OF', 1.0);
    }
  }

  // Shares
  const shares = data.shares || {};
  for (const [shareName, rawShare] of Object.entries(shares as Record<string, unknown>)) {
    const shareObj = rawShare as Record<string, unknown>;
    if (!targetIp) continue;
    const shareNodeId = `share-${hostId(targetIp).replace(/^host-/, '')}-${normalizeKeyPart(shareName)}`;
    if (seenNodes.has(shareNodeId)) continue;

    const access = (shareObj.access || {}) as Record<string, unknown>;
    nodes.push({
      id: shareNodeId,
      type: 'share',
      label: `\\\\${targetIp}\\${shareName}`,
      share_name: shareName,
      readable: access.mapping === 'OK' || access.readable === true || undefined,
      writable: access.writable === true || undefined,
    });
    seenNodes.add(shareNodeId);

    const resolvedHostId = hostId(targetIp);
    addEdgeOnce(resolvedHostId, shareNodeId, 'RELATED', 1.0);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
