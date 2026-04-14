import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, domainId, userId } from '../parser-utils.js';

// --- Kerbrute Parser ---

export function parseKerbrute(output: string, agentId: string = 'kerbrute-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    // Valid username: [+] VALID USERNAME:\tuser@domain
    const enumMatch = line.match(/\[\+\]\s*VALID USERNAME:\s*(\S+)/i);
    if (enumMatch) {
      const upn = parseUpn(enumMatch[1]);
      if (!upn) continue;
      const { username, domain } = upn;
      const resolvedUserId = userId(username, domain);
      const resolvedDomainId = domainId(domain);

      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({ id: resolvedUserId, type: 'user', label: `${username}@${domain}`, username, domain_name: domain });
        seenNodes.add(resolvedUserId);
      }
      if (!seenNodes.has(resolvedDomainId)) {
        nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(resolvedDomainId);
      }
      edges.push({
        source: resolvedUserId,
        target: resolvedDomainId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      continue;
    }

    // Password spray: [+] VALID LOGIN:\tuser@domain:password
    const sprayPayloadMatch = line.match(/\[\+\]\s*VALID LOGIN:\s*(.+)$/i);
    if (sprayPayloadMatch) {
      const parsed = parseKerbruteLogin(sprayPayloadMatch[1]);
      if (!parsed) continue;
      const { username, domain, password } = parsed;
      const resolvedUserId = userId(username, domain);
      const resolvedDomainId = domainId(domain);
      const resolvedCredId = credentialId('plaintext_password', password, username, domain);

      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({ id: resolvedUserId, type: 'user', label: `${username}@${domain}`, username, domain_name: domain });
        seenNodes.add(resolvedUserId);
      }
      if (!seenNodes.has(resolvedDomainId)) {
        nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(resolvedDomainId);
      }
      if (!seenNodes.has(resolvedCredId)) {
        nodes.push({
          id: resolvedCredId,
          type: 'credential',
          label: `${username}:***`,
          cred_type: 'plaintext',
          cred_material_kind: 'plaintext_password',
          cred_usable_for_auth: true,
          cred_evidence_kind: 'spray_success',
          cred_value: password,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(resolvedCredId);
      }

      edges.push({
        source: resolvedUserId,
        target: resolvedDomainId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseUpn(value: string): { username: string; domain: string } | null {
  const atIndex = value.indexOf('@');
  if (atIndex <= 0 || atIndex === value.length - 1) return null;
  return {
    username: value.slice(0, atIndex),
    domain: value.slice(atIndex + 1),
  };
}

function parseKerbruteLogin(value: string): { username: string; domain: string; password: string } | null {
  const atIndex = value.indexOf('@');
  if (atIndex <= 0 || atIndex === value.length - 1) return null;

  const username = value.slice(0, atIndex);
  const remainder = value.slice(atIndex + 1);
  const colonIndex = remainder.indexOf(':');
  // colonIndex <= 0: no domain; colonIndex at end: empty password (Kerbrute won't report empty-password success)
  if (colonIndex <= 0 || colonIndex >= remainder.length - 1) return null;

  return {
    username,
    domain: remainder.slice(0, colonIndex),
    password: remainder.slice(colonIndex + 1),
  };
}
