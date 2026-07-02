import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, hostId, userId } from '../parser-utils.js';

// --- Responder Parser ---
// Handles NTLMv2-SSP and NTLMv1-SSP stanzas with field accumulation
// (tolerates blank lines and interleaving between stanza fields).

interface ResponderStanza {
  clientIp: string;
  domain: string;
  username: string;
  hash: string;
  version: 'ntlmv2' | 'ntlmv1';
}

function parseUsername(raw: string): { domain: string; username: string } | null {
  // DOMAIN\user format
  const backslash = raw.match(/^([^\\]+)\\(.+)$/);
  if (backslash) return { domain: backslash[1].trim(), username: backslash[2].trim() };
  // user@domain (UPN) format
  const upn = raw.match(/^([^@]+)@(.+)$/);
  if (upn) return { domain: upn[2].trim(), username: upn[1].trim() };
  return null;
}

export function parseResponder(output: string, agentId: string = 'responder-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const completed: ResponderStanza[] = [];

  // Responder prints each capture as a CONTIGUOUS block: the `Client` line
  // (which carries the IP) is immediately followed by that capture's `Username`
  // and `Hash` lines (which do NOT carry the IP). So correlate POSITIONALLY —
  // a `Client` line opens the current stanza and the following Username/Hash
  // attach to it. The old approach scanned a Map "for the most recent entry
  // missing that field", which is Map INSERTION order, not recency, so under
  // concurrent captures it mis-paired a hash with the wrong client/user.
  let current: { clientIp: string; version: 'ntlmv2' | 'ntlmv1'; domain?: string; username?: string } | undefined;

  for (const line of output.split('\n')) {
    // NTLMv2 or NTLMv1 Client line — opens a fresh stanza.
    const clientMatch = line.match(/NTLM(v[12])-SSP Client\s*:\s*(\S+)/i);
    if (clientMatch) {
      const version = clientMatch[1].toLowerCase() === 'v2' ? 'ntlmv2' as const : 'ntlmv1' as const;
      current = { clientIp: clientMatch[2], version };
      continue;
    }

    // Username line — belongs to the current stanza.
    const userMatch = line.match(/NTLM(?:v[12])-SSP Username\s*:\s*(.+)/i);
    if (userMatch) {
      const parsed = parseUsername(userMatch[1].trim());
      if (parsed && current && !current.username) {
        current.domain = parsed.domain;
        current.username = parsed.username;
      }
      continue;
    }

    // Hash line — completes the current stanza.
    const hashMatch = line.match(/NTLM(?:v[12])-SSP Hash\s*:\s*(.+)/i);
    if (hashMatch) {
      const hash = hashMatch[1].trim();
      if (current && current.username) {
        completed.push({
          clientIp: current.clientIp,
          domain: current.domain!,
          username: current.username,
          hash,
          version: current.version,
        });
        current = undefined;
      }
      continue;
    }
  }

  // Emit nodes and edges for each complete stanza
  for (const stanza of completed) {
    const credType = stanza.version === 'ntlmv1' ? 'ntlmv1_challenge' : 'ntlmv2_challenge';
    const materialKind = stanza.version === 'ntlmv1' ? 'ntlmv1_challenge' : 'ntlmv2_challenge';
    const labelPrefix = stanza.version === 'ntlmv1' ? 'NTLMv1' : 'NTLMv2';

    const resolvedHostId = hostId(stanza.clientIp);
    const resolvedUserId = userId(stanza.username, stanza.domain);
    const resolvedCredId = credentialId(materialKind, stanza.hash, stanza.username, stanza.domain);

    if (!seenNodes.has(resolvedHostId)) {
      nodes.push({ id: resolvedHostId, type: 'host', label: stanza.clientIp, ip: stanza.clientIp, alive: true });
      seenNodes.add(resolvedHostId);
    }
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({ id: resolvedUserId, type: 'user', label: `${stanza.domain}\\${stanza.username}`, username: stanza.username, domain_name: stanza.domain });
      seenNodes.add(resolvedUserId);
    }
    if (!seenNodes.has(resolvedCredId)) {
      nodes.push({
        id: resolvedCredId,
        type: 'credential',
        label: `${labelPrefix}:${stanza.username}`,
        cred_type: credType,
        cred_material_kind: materialKind,
        cred_usable_for_auth: false,
        cred_evidence_kind: 'capture',
        cred_value: stanza.hash,
        cred_user: stanza.username,
        cred_domain: stanza.domain,
        observed_from_ip: stanza.clientIp,
      });
      seenNodes.add(resolvedCredId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
