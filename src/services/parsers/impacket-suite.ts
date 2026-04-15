// ============================================================
// Overwatch — Impacket Suite Parser
// Parsers for GetNPUsers, GetUserSPNs, getTGT, getST,
// smbclient, wmiexec, and psexec output.
// ============================================================

import type { Finding, EdgeType, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, domainId, hostId, resolveDomainName, userId } from '../parser-utils.js';

// --- GetNPUsers (AS-REP Roasting) ---
// Output lines like: $krb5asrep$23$user@DOMAIN:hash...
const ASREP_HASH = /^\$krb5asrep\$\d+\$([^@]+)@([^:]+):(.+)$/i;

export function parseGetNPUsers(output: string, agentId: string = 'getnpusers-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    const m = line.trim().match(ASREP_HASH);
    if (!m) continue;

    const [, username, rawDomain, hashValue] = m;
    const domain = resolveDomainName(rawDomain, context?.domain_aliases);

    const resolvedUserId = userId(username, domain);
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${username}` : username,
        username,
        domain_name: domain,
        asrep_roastable: true,
      });
      seenNodes.add(resolvedUserId);
    }

    // AS-REP hash is a TGS-equivalent (not directly usable for auth)
    const credNodeId = credentialId('kerberos_tgs', hashValue.substring(0, 32), username, domain);
    if (!seenNodes.has(credNodeId)) {
      nodes.push({
        id: credNodeId,
        type: 'credential',
        label: `AS-REP:${username}`,
        cred_type: 'kerberos_tgs',
        cred_material_kind: 'kerberos_tgs',
        cred_usable_for_auth: false,
        cred_evidence_kind: 'capture',
        cred_user: username,
        cred_domain: domain,
      });
      seenNodes.add(credNodeId);
    }

    edges.push({
      source: resolvedUserId,
      target: credNodeId,
      properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });

    // Domain node + roasting edge
    if (domain) {
      const domId = domainId(domain);
      if (!seenNodes.has(domId)) {
        nodes.push({ id: domId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(domId);
      }
      edges.push({
        source: resolvedUserId,
        target: domId,
        properties: { type: 'AS_REP_ROASTABLE' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- GetUserSPNs (Kerberoasting) ---
// Output: $krb5tgs$23$*user$DOMAIN$spn*$hash...
const KERBEROAST_HASH = /^\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$(.+)$/i;
// Also handles tabular output: user  SPN  ...
const SPN_TABLE = /^(\S+)\s+(\S+\/\S+)\s/;

export function parseGetUserSPNs(output: string, agentId: string = 'getuserspns-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    // Hash line
    const hashMatch = line.trim().match(KERBEROAST_HASH);
    if (hashMatch) {
      const [, username, rawDomain, _spn, hashValue] = hashMatch;
      const domain = resolveDomainName(rawDomain, context?.domain_aliases);

      const resolvedUserId = userId(username, domain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
          has_spn: true,
        });
        seenNodes.add(resolvedUserId);
      }

      const credNodeId = credentialId('kerberos_tgs', hashValue.substring(0, 32), username, domain);
      if (!seenNodes.has(credNodeId)) {
        nodes.push({
          id: credNodeId,
          type: 'credential',
          label: `TGS:${username}`,
          cred_type: 'kerberos_tgs',
          cred_material_kind: 'kerberos_tgs',
          cred_usable_for_auth: false,
          cred_evidence_kind: 'capture',
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(credNodeId);
      }

      edges.push({
        source: resolvedUserId,
        target: credNodeId,
        properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });

      if (domain) {
        const domId = domainId(domain);
        if (!seenNodes.has(domId)) {
          nodes.push({ id: domId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(domId);
        }
        edges.push({
          source: resolvedUserId,
          target: domId,
          properties: { type: 'KERBEROASTABLE' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // Table row: user SPN
    const tableMatch = line.trim().match(SPN_TABLE);
    if (tableMatch && !line.includes('ServicePrincipalName')) {
      const [, username] = tableMatch;
      const domain = context?.domain;
      const resolvedUserId = userId(username, domain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
          has_spn: true,
        });
        seenNodes.add(resolvedUserId);
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- getTGT ---
// Success: [*] Saving ticket in user.ccache
// Failure: [-] Kerberos SessionError: ...
const TGT_SUCCESS = /Saving ticket in (\S+)/i;
export function parseGetTGT(output: string, agentId: string = 'gettgt-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const success = TGT_SUCCESS.test(output);
  if (!success) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Extract user from ccache filename or context
  const ccacheMatch = output.match(/Saving ticket in (\S+)/i);
  const ccacheName = ccacheMatch ? ccacheMatch[1] : '';
  // Filename format: user.ccache or domain/user.ccache
  const nameMatch = ccacheName.match(/(?:([^/]+)\/)?([^.]+)\.ccache$/);
  const username = nameMatch?.[2] || context?.domain?.split('.')[0] || 'unknown';
  const domain = nameMatch?.[1] ? resolveDomainName(nameMatch[1], context?.domain_aliases) : context?.domain;

  // TGT credential with ~10h lifetime
  const tgtExpiry = new Date(Date.now() + 10 * 60 * 60 * 1000).toISOString();
  const credNodeId = credentialId('kerberos_tgt', ccacheName || 'tgt', username, domain);

  if (!seenNodes.has(credNodeId)) {
    nodes.push({
      id: credNodeId,
      type: 'credential',
      label: `TGT:${username}`,
      cred_type: 'kerberos_tgt',
      cred_material_kind: 'kerberos_tgt',
      cred_usable_for_auth: true,
      cred_evidence_kind: 'capture',
      cred_user: username,
      cred_domain: domain,
      valid_until: tgtExpiry,
    });
    seenNodes.add(credNodeId);
  }

  const resolvedUserId = userId(username, domain);
  if (!seenNodes.has(resolvedUserId)) {
    nodes.push({
      id: resolvedUserId,
      type: 'user',
      label: domain ? `${domain}\\${username}` : username,
      username,
      domain_name: domain,
    });
    seenNodes.add(resolvedUserId);
  }

  edges.push({
    source: resolvedUserId,
    target: credNodeId,
    properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
  });

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- getST ---
// Success: [*] Saving ticket in user.ccache
const ST_SUCCESS = /Saving ticket in (\S+)/i;

export function parseGetST(output: string, agentId: string = 'getst-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const success = ST_SUCCESS.test(output);
  if (!success) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const ccacheMatch = output.match(/Saving ticket in (\S+)/i);
  const ccacheName = ccacheMatch ? ccacheMatch[1] : 'st';
  const domain = context?.domain;

  const credNodeId = credentialId('kerberos_tgs', ccacheName, 'service-ticket', domain);
  if (!seenNodes.has(credNodeId)) {
    nodes.push({
      id: credNodeId,
      type: 'credential',
      label: `ST:${ccacheName}`,
      cred_type: 'kerberos_tgs',
      cred_material_kind: 'kerberos_tgs',
      cred_usable_for_auth: true,
      cred_evidence_kind: 'capture',
      cred_domain: domain,
      valid_until: new Date(Date.now() + 10 * 60 * 60 * 1000).toISOString(),
    });
    seenNodes.add(credNodeId);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- smbclient ---
// Share listing: SHARENAME  Disk  Comment
const SMBCLIENT_SHARE = /^\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)/;

export function parseSmbclient(output: string, agentId: string = 'smbclient-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  const targetHost = context?.source_host;
  let resolvedHostId: string | undefined;

  if (targetHost) {
    resolvedHostId = hostId(targetHost);
    if (!seenNodes.has(resolvedHostId)) {
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: targetHost,
        ...(isIp ? { ip: targetHost } : { hostname: targetHost }),
      });
      seenNodes.add(resolvedHostId);
    }
  }

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenEdges.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenEdges.add(key);
  }

  for (const line of output.split('\n')) {
    const shareMatch = line.match(SMBCLIENT_SHARE);
    if (!shareMatch) continue;

    const [, shareName, shareType] = shareMatch;
    if (shareType === 'IPC' || shareName === 'IPC$') continue;

    const shareId = resolvedHostId
      ? `share-${resolvedHostId.replace(/^host-/, '')}-${shareName.toLowerCase()}`
      : `share-unknown-${shareName.toLowerCase()}`;

    if (!seenNodes.has(shareId)) {
      nodes.push({
        id: shareId,
        type: 'share',
        label: targetHost ? `\\\\${targetHost}\\${shareName}` : shareName,
        share_name: shareName,
      });
      seenNodes.add(shareId);
    }

    if (resolvedHostId) {
      addEdgeOnce(resolvedHostId, shareId, 'RELATED', 1.0);
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- wmiexec / psexec ---
// Success: output from the command (indicates code execution achieved)
// Detection: [*] SMBv3.0 ... [*] Opening SVCManager ... [*] Creating service ...
const EXEC_SUCCESS = /Launching semi-interactive|Opening SVCManager|wmiexec|Process .* created/i;
const EXEC_TARGET = /Target\s*:\s*(\S+)|^Impacket.*@(\S+)/i;

export function parseWmiexec(output: string, agentId: string = 'wmiexec-parser', context?: ParseContext): Finding {
  return parseExecOutput(output, agentId, context, 'wmiexec');
}

export function parsePsexec(output: string, agentId: string = 'psexec-parser', context?: ParseContext): Finding {
  return parseExecOutput(output, agentId, context, 'psexec');
}

function parseExecOutput(output: string, agentId: string, context: ParseContext | undefined, tool: string): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  // Try to extract target
  let targetHost = context?.source_host;
  if (!targetHost) {
    const targetMatch = output.match(EXEC_TARGET);
    if (targetMatch) {
      targetHost = targetMatch[1] || targetMatch[2];
    }
  }

  if (!targetHost || !EXEC_SUCCESS.test(output)) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const resolvedHostId = hostId(targetHost);
  if (!seenNodes.has(resolvedHostId)) {
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
    nodes.push({
      id: resolvedHostId,
      type: 'host',
      label: targetHost,
      ...(isIp ? { ip: targetHost } : { hostname: targetHost }),
    });
    seenNodes.add(resolvedHostId);
  }

  // If context provides domain/user, create HAS_SESSION edge
  if (context?.domain) {
    // Try to extract user from Impacket header: domain/user@target
    const headerMatch = output.match(/(?:Impacket|impacket).*?([^/\s]+)\/([^@\s]+)@/);
    if (headerMatch) {
      const [, rawDomain, username] = headerMatch;
      const domain = resolveDomainName(rawDomain, context?.domain_aliases);
      const resolvedUserId = userId(username, domain);

      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
        });
        seenNodes.has(resolvedUserId);
      }

      edges.push({
        source: resolvedUserId,
        target: resolvedHostId,
        properties: {
          type: 'HAS_SESSION' as EdgeType,
          confidence: 1.0,
          discovered_at: now,
          discovered_by: agentId,
          notes: `${tool} execution confirmed`,
        },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
