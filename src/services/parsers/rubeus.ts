import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, splitQualifiedAccount, userId } from '../parser-utils.js';

// --- Rubeus Parser (kerberoast, asreproast, monitor/triage) ---

export function parseRubeus(output: string, agentId: string = 'rubeus-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Detect subcommand from content patterns
  const hasKerberoastHash = /\$krb5tgs\$/i.test(output);
  const hasAsrepHash = /\$krb5asrep\$/i.test(output);
  const hasBase64Ticket = /Base64EncodedTicket/i.test(output);

  // Parse stanza-based output: blocks delimited by [*] lines
  if (hasKerberoastHash) {
    parseRubeusKerberoast(output, nodes, edges, seenNodes, now, agentId);
  }
  if (hasAsrepHash) {
    parseRubeusAsreproast(output, nodes, edges, seenNodes, now, agentId);
  }
  if (hasBase64Ticket) {
    parseRubeusMonitor(output, nodes, edges, seenNodes, now, agentId);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseRubeusKerberoast(
  output: string, nodes: Finding['nodes'], edges: Finding['edges'],
  seenNodes: Set<string>, now: string, agentId: string,
): void {
  // Split into blocks per user — Rubeus outputs [*] SamAccountName : ... per entry
  const blocks = output.split(/(?=\[\*\]\s*SamAccountName\s*:)/i);

  for (const block of blocks) {
    const samMatch = block.match(/SamAccountName\s*:\s*(\S+)/i);
    const spnMatch = block.match(/ServicePrincipalName\s*:\s*(\S+)/i);
    const hashMatch = block.match(/Hash\s*:\s*(\$krb5tgs\$[^\s]+)/i);
    // Handle multi-line hashes (Rubeus wraps long hashes)
    const multiLineHash = block.match(/Hash\s*:\s*([\s\S]*?)(?=\n\s*\n|\[\*\]|$)/i);

    if (!samMatch) continue;
    const username = samMatch[1];
    let hash = hashMatch ? hashMatch[1] : undefined;

    // For multi-line hashes, join and clean
    if (!hash && multiLineHash) {
      hash = multiLineHash[1].replace(/\s+/g, '').trim();
      if (!hash.startsWith('$krb5tgs$')) hash = undefined;
    }

    // Extract domain from SPN or hash
    let domain: string | undefined;
    const domainFromHash = hash?.match(/\$krb5tgs\$\d+\$\*[^$]+\$([^$*]+)\$/);
    if (domainFromHash) domain = domainFromHash[1];

    // User node with has_spn
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

    // Credential node for the TGS hash
    if (hash) {
      const resolvedCredId = credentialId('kerberos_tgs', hash, username, domain);
      if (!seenNodes.has(resolvedCredId)) {
        nodes.push({
          id: resolvedCredId,
          type: 'credential',
          label: `TGS:${username}`,
          cred_type: 'kerberos_tgs',
          cred_material_kind: 'kerberos_tgs',
          cred_usable_for_auth: false,
          cred_evidence_kind: 'dump',
          cred_value: hash,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(resolvedCredId);
      }
      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }
}

function parseRubeusAsreproast(
  output: string, nodes: Finding['nodes'], edges: Finding['edges'],
  seenNodes: Set<string>, now: string, agentId: string,
): void {
  const blocks = output.split(/(?=\[\*\]\s*User\s*:)/i);

  for (const block of blocks) {
    const userMatch = block.match(/User\s*:\s*(\S+)/i);
    const hashMatch = block.match(/Hash\s*:\s*(\$krb5asrep\$[^\s]+)/i);
    const multiLineHash = block.match(/Hash\s*:\s*([\s\S]*?)(?=\n\s*\n|\[\*\]|$)/i);

    if (!userMatch) continue;
    const username = userMatch[1];
    let hash = hashMatch ? hashMatch[1] : undefined;

    if (!hash && multiLineHash) {
      hash = multiLineHash[1].replace(/\s+/g, '').trim();
      if (!hash.startsWith('$krb5asrep$')) hash = undefined;
    }

    // Extract domain from hash: $krb5asrep$user@DOMAIN:...
    let domain: string | undefined;
    const domainFromHash = hash?.match(/\$krb5asrep\$[^@]*@([^:]+)/);
    if (domainFromHash) domain = domainFromHash[1];

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

    if (hash) {
      const resolvedCredId = credentialId('kerberos_tgs', hash, username, domain);
      if (!seenNodes.has(resolvedCredId)) {
        nodes.push({
          id: resolvedCredId,
          type: 'credential',
          label: `ASREP:${username}`,
          cred_type: 'kerberos_tgs',
          cred_material_kind: 'kerberos_tgs',
          cred_usable_for_auth: false,
          cred_evidence_kind: 'dump',
          cred_value: hash,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(resolvedCredId);
      }
      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }
}

function parseRubeusMonitor(
  output: string, nodes: Finding['nodes'], edges: Finding['edges'],
  seenNodes: Set<string>, now: string, agentId: string,
): void {
  // Split on User lines in monitor/triage output
  const blocks = output.split(/(?=\[\*\]\s*User\s*:)/i);

  for (const block of blocks) {
    const userMatch = block.match(/User\s*:\s*(\S+)/i);
    const ticketMatch = block.match(/Base64EncodedTicket\s*:\s*(\S+)/i);
    const serviceMatch = block.match(/Service\s*:\s*(\S+)/i);

    if (!userMatch || !ticketMatch) continue;
    const rawUser = userMatch[1];
    const ticket = ticketMatch[1];
    const service = serviceMatch ? serviceMatch[1] : undefined;

    // Parse DOMAIN\user or user
    const { domain, username } = splitQualifiedAccount(rawUser);

    // Skip machine accounts
    if (username.endsWith('$')) continue;

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

    // Determine if TGT or TGS based on service field
    const isTgt = !service || service.toLowerCase().startsWith('krbtgt/');
    const credType = isTgt ? 'kerberos_tgt' : 'kerberos_tgs';
    const materialKind = isTgt ? 'kerberos_tgt' : 'kerberos_tgs';

    const resolvedCredId = credentialId(materialKind, ticket.slice(0, 40), username, domain);
    if (!seenNodes.has(resolvedCredId)) {
      nodes.push({
        id: resolvedCredId,
        type: 'credential',
        label: `${isTgt ? 'TGT' : 'TGS'}:${username}`,
        cred_type: credType,
        cred_material_kind: materialKind,
        cred_usable_for_auth: true,
        cred_evidence_kind: 'capture',
        cred_value: ticket,
        cred_user: username,
        cred_domain: domain,
      });
      seenNodes.add(resolvedCredId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }
}
