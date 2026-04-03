import type { Finding, EdgeType, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, domainId, groupId, hostId, resolveDomainName, userId } from '../parser-utils.js';

// --- NetExec (NXC) Parser ---

export function parseNxc(output: string, agentId: string = 'nxc-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const lines = output.split('\n');
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  // Per-IP context accumulated from [*] info lines
  const hostMeta = new Map<string, { hostname?: string; domain?: string; os?: string; signing?: boolean; smbv1?: boolean; nullAuth?: boolean }>();
  // Track whether we're inside a user enumeration table for a given IP
  let userTableIp: string | undefined;

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const edgeKey = `${source}--${type}--${target}`;
    if (seenEdges.has(edgeKey)) return;
    edges.push({
      source,
      target,
      properties: { type, confidence, discovered_at: now, discovered_by: agentId },
    });
    seenEdges.add(edgeKey);
  }

  function ensureSmbContext(ip: string): { hostNodeId: string; serviceNodeId: string } {
    const resolvedHostId = hostId(ip);
    const serviceNodeId = `svc-${ip.replace(/\./g, '-')}-445`;

    if (!seenNodes.has(resolvedHostId)) {
      const meta = hostMeta.get(ip);
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: meta?.hostname || ip,
        ip,
        alive: true,
        hostname: meta?.hostname,
        domain_name: meta?.domain,
        os: meta?.os,
        null_session: meta?.nullAuth || undefined,
      });
      seenNodes.add(resolvedHostId);
    }

    if (!seenNodes.has(serviceNodeId)) {
      const meta = hostMeta.get(ip);
      nodes.push({
        id: serviceNodeId,
        type: 'service',
        label: 'smb/445',
        port: 445,
        protocol: 'tcp',
        service_name: 'smb',
        smb_signing: meta?.signing,
        smbv1: meta?.smbv1,
      });
      seenNodes.add(serviceNodeId);
    }

    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);
    return { hostNodeId: resolvedHostId, serviceNodeId };
  }

  function ensureDomainContext(domain: string): string {
    const resolvedDomainId = domainId(domain);
    if (!seenNodes.has(resolvedDomainId)) {
      nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
      seenNodes.add(resolvedDomainId);
    }
    return resolvedDomainId;
  }

  function addUserNode(username: string, domain: string | undefined, description?: string): string {
    const resolvedUserId = userId(username, domain);
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${username}` : username,
        username,
        domain_name: domain,
        description: description || undefined,
      });
      seenNodes.add(resolvedUserId);
    }
    if (domain) {
      const resolvedDomainId = ensureDomainContext(domain);
      addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
    }
    return resolvedUserId;
  }

  // Broad prefix regex for all SMB lines: SMB  IP  PORT  HOSTNAME  <rest>
  const smbLineRe = /^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(.*)/i;

  for (const line of lines) {
    const smbLine = line.match(smbLineRe);
    if (!smbLine) {
      userTableIp = undefined;
      continue;
    }

    const [, ip, port, hostname, rest] = smbLine;
    if (port !== '445') continue;

    // --- [*] Info line: extract host metadata ---
    const infoMatch = rest.match(/^\[\*\]\s*(.*)/);
    if (infoMatch) {
      const infoMsg = infoMatch[1];

      // "Enumerated N local users: DOMAIN" — end of user table
      if (/Enumerated\s+\d+/i.test(infoMsg)) {
        userTableIp = undefined;
        continue;
      }

      // Host info: Windows ... (name:X) (domain:X) (signing:X) (SMBv1:X) (Null Auth:X)
      if (!hostMeta.has(ip)) {
        hostMeta.set(ip, {});
      }
      const meta = hostMeta.get(ip)!;

      const nameMatch = infoMsg.match(/\(name:([^)]+)\)/i);
      if (nameMatch) meta.hostname = nameMatch[1].trim();

      const domainMatch = infoMsg.match(/\(domain:([^)]+)\)/i);
      if (domainMatch) meta.domain = resolveDomainName(domainMatch[1].trim(), context?.domain_aliases);

      const signingMatch = infoMsg.match(/\(signing:(True|False)\)/i);
      if (signingMatch) meta.signing = signingMatch[1].toLowerCase() === 'true';

      const smbv1Match = infoMsg.match(/\(SMBv1:(True|False)\)/i);
      if (smbv1Match) meta.smbv1 = smbv1Match[1].toLowerCase() === 'true';

      const nullAuthMatch = infoMsg.match(/\(Null Auth:(True|False)\)/i);
      if (nullAuthMatch) meta.nullAuth = nullAuthMatch[1].toLowerCase() === 'true';

      // Extract OS from the info text before first parenthetical
      const osMatch = infoMsg.match(/^(Windows\s[^(]+)/i);
      if (osMatch) meta.os = osMatch[1].trim();

      continue;
    }

    // --- [+] or [-] Status lines: auth results ---
    const statusMatch = rest.match(/^\[([+-])\]\s*(.*)/);
    if (statusMatch) {
      userTableIp = undefined;
      const [, status, message] = statusMatch;
      const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);

      // Check for Pwn3d! (admin access)
      if (message.includes('Pwn3d!')) {
        const credMatch = message.match(/([^\\]+)\\([^\s]+)/);
        if (credMatch) {
          const [, rawCredDomain, username] = credMatch;
          const credDomain = resolveDomainName(rawCredDomain, context?.domain_aliases);
          const resolvedUserId = addUserNode(username, credDomain);
          // Upgrade to privileged
          const userNode = nodes.find(n => n.id === resolvedUserId);
          if (userNode) userNode.privileged = true;
          addEdgeOnce(resolvedUserId, resolvedHostId, 'ADMIN_TO', 1.0);
        }
      }

      // Valid auth (+ status) with domain\user pattern
      if (status === '+') {
        const credMatch = message.match(/([^\\]+)\\([^\s:]+)/);
        if (credMatch) {
          const [, rawCredDomain, username] = credMatch;
          const credDomain = resolveDomainName(rawCredDomain, context?.domain_aliases);
          if (username && username !== '') {
            addUserNode(username, credDomain);
            addEdgeOnce(userId(username, credDomain), resolvedHostId, 'VALID_ON', 0.9);
          }
        }
      }

      continue;
    }

    // --- User enumeration table header ---
    if (rest.includes('-Username-') && rest.includes('-Description-')) {
      userTableIp = ip;
      ensureSmbContext(ip);
      continue;
    }

    // --- User enumeration table rows ---
    if (userTableIp === ip) {
      // Table row format: username  date  badpw  description
      // Fields are separated by variable whitespace. Username is first non-empty field.
      const trimmedRest = rest.trim();
      if (!trimmedRest || trimmedRest.startsWith('[')) {
        userTableIp = undefined;
        continue;
      }

      // Parse: username  YYYY-MM-DD HH:MM:SS  badpw  description
      // Or:   username  <never>  badpw  description
      const userRowMatch = trimmedRest.match(
        /^(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|<never>)\s+(\d+)\s+(.*)/
      );
      if (userRowMatch) {
        const [, username, , , description] = userRowMatch;
        if (username.toLowerCase() === 'guest') continue;

        const domain = hostMeta.get(ip)?.domain;
        const resolvedUserId = addUserNode(username, domain, description);

        // Check for password in description: (Password : value) or (Password: value)
        const pwMatch = description.match(/\(Password\s*:\s*(.+?)\)/i);
        if (pwMatch) {
          const password = pwMatch[1].trim();
          const credNodeId = credentialId('plaintext_password', password, username, domain);
          if (!seenNodes.has(credNodeId)) {
            nodes.push({
              id: credNodeId,
              type: 'credential',
              label: `${username} cleartext password`,
              cred_user: username,
              cred_domain: domain,
              cred_type: 'plaintext',
              cred_value: password,
              cred_evidence_kind: 'manual',
            });
            seenNodes.add(credNodeId);
          }
          addEdgeOnce(resolvedUserId, credNodeId, 'OWNS_CRED', 1.0);
        }
      }
      continue;
    }

    // --- Share enumeration: HOSTNAME  sharename  READ/WRITE ---
    const shareMatch = rest.match(/^(\S+)\s+(READ|WRITE|READ,\s*WRITE)/i);
    if (shareMatch) {
      const [, shareName, perms] = shareMatch;
      if (shareName.startsWith('[') || shareName === '-Username-') continue;
      const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);
      const shareId = `share-${ip.replace(/\./g, '-')}-${shareName.toLowerCase()}`;

      if (!seenNodes.has(shareId)) {
        nodes.push({
          id: shareId,
          type: 'share',
          label: `\\\\${ip}\\${shareName}`,
          share_name: shareName,
          readable: perms.includes('READ'),
          writable: perms.includes('WRITE'),
        });
        seenNodes.add(shareId);
      }
      addEdgeOnce(resolvedHostId, shareId, 'RELATED', 1.0);
    }
  }

  // --- MSSQL linked server detection ---
  // NXC mssql module: MSSQL  IP  PORT  HOST  [*] Linked SQL Servers: SERVER1, SERVER2
  const mssqlLineRe = /^MSSQL\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(.*)/i;
  const mssqlLinkedServers = new Map<string, string[]>(); // ip -> linked server names
  for (const line of lines) {
    const mssqlLine = line.match(mssqlLineRe);
    if (!mssqlLine) continue;
    const [, mssqlIp, mssqlPort, mssqlHostname, mssqlRest] = mssqlLine;

    // Ensure MSSQL host + service nodes exist
    const mssqlHostId = hostId(mssqlIp);
    if (!seenNodes.has(mssqlHostId)) {
      nodes.push({
        id: mssqlHostId,
        type: 'host',
        label: mssqlHostname || mssqlIp,
        ip: mssqlIp,
        hostname: mssqlHostname,
        alive: true,
      });
      seenNodes.add(mssqlHostId);
    }
    const mssqlSvcId = `svc-${mssqlIp.replace(/\./g, '-')}-${mssqlPort}`;
    if (!seenNodes.has(mssqlSvcId)) {
      nodes.push({
        id: mssqlSvcId,
        type: 'service',
        label: `mssql/${mssqlPort}`,
        port: parseInt(mssqlPort, 10),
        protocol: 'tcp',
        service_name: 'mssql',
      });
      seenNodes.add(mssqlSvcId);
      addEdgeOnce(mssqlHostId, mssqlSvcId, 'RUNS', 1.0);
    }

    // Detect linked server lines
    const linkedMatch = mssqlRest.match(/\[\*\]\s*(?:Linked\s+(?:SQL\s+)?Servers?|Link):\s*(.*)/i);
    if (linkedMatch) {
      const serverNames = linkedMatch[1].split(/[,;]/).map(s => s.trim()).filter(Boolean);
      if (serverNames.length > 0) {
        const existing = mssqlLinkedServers.get(mssqlSvcId) || [];
        for (const name of serverNames) {
          if (!existing.includes(name)) existing.push(name);
        }
        mssqlLinkedServers.set(mssqlSvcId, existing);
      }
    }
  }
  // Apply linked_servers to MSSQL service nodes
  for (const [svcId, servers] of mssqlLinkedServers) {
    const svcNode = nodes.find(n => n.id === svcId);
    if (svcNode) {
      svcNode.linked_servers = servers;
    }
  }

  // Post-processing: create NULL_SESSION edges for hosts with null auth
  for (const [ip, meta] of hostMeta) {
    if (!meta.nullAuth) continue;
    const resolvedHostId = hostId(ip);
    const serviceNodeId = `svc-${ip.replace(/\./g, '-')}-445`;
    // Ensure context exists (may not have been created yet if only [*] lines were seen)
    ensureSmbContext(ip);
    addEdgeOnce(resolvedHostId, serviceNodeId, 'NULL_SESSION', 1.0);
  }

  // Post-processing: update host nodes with metadata that arrived after node creation
  for (const node of nodes) {
    if (node.type === 'host' && typeof node.ip === 'string') {
      const meta = hostMeta.get(node.ip);
      if (meta) {
        if (meta.hostname && !node.hostname) node.hostname = meta.hostname;
        if (meta.domain && !node.domain_name) node.domain_name = meta.domain;
        if (meta.os && !node.os) node.os = meta.os;
        if (meta.nullAuth && !node.null_session) node.null_session = true;
        if (meta.hostname && node.label === node.ip) node.label = meta.hostname;
      }
    }
  }

  return {
    id: uuidv4(),
    agent_id: agentId,
    timestamp: new Date().toISOString(),
    nodes,
    edges,
  };
}
