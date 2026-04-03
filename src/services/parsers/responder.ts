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

  // Field accumulator keyed by client IP — collects fields as they appear
  const pending = new Map<string, {
    clientIp?: string;
    domain?: string;
    username?: string;
    hash?: string;
    version?: 'ntlmv2' | 'ntlmv1';
  }>();

  const completed: ResponderStanza[] = [];

  for (const line of output.split('\n')) {
    // NTLMv2 or NTLMv1 Client line
    const clientMatch = line.match(/NTLM(v[12])-SSP Client\s*:\s*(\S+)/i);
    if (clientMatch) {
      const version = clientMatch[1].toLowerCase() === 'v2' ? 'ntlmv2' as const : 'ntlmv1' as const;
      const clientIp = clientMatch[2];
      const key = `${clientIp}-${version}`;
      if (!pending.has(key)) pending.set(key, {});
      const p = pending.get(key)!;
      p.clientIp = clientIp;
      p.version = version;
      continue;
    }

    // Username line
    const userMatch = line.match(/NTLM(?:v[12])-SSP Username\s*:\s*(.+)/i);
    if (userMatch) {
      const parsed = parseUsername(userMatch[1].trim());
      if (parsed) {
        // Find the most recent pending entry missing a username
        for (const [, p] of pending) {
          if (!p.username && p.clientIp) {
            p.domain = parsed.domain;
            p.username = parsed.username;
            break;
          }
        }
      }
      continue;
    }

    // Hash line
    const hashMatch = line.match(/NTLM(?:v[12])-SSP Hash\s*:\s*(.+)/i);
    if (hashMatch) {
      const hash = hashMatch[1].trim();
      // Find the most recent pending entry missing a hash
      for (const [key, p] of pending) {
        if (!p.hash && p.clientIp && p.username) {
          p.hash = hash;
          // Stanza complete
          completed.push({
            clientIp: p.clientIp,
            domain: p.domain!,
            username: p.username,
            hash: p.hash,
            version: p.version || 'ntlmv2',
          });
          pending.delete(key);
          break;
        }
      }
      continue;
    }
  }

  // Emit nodes and edges for each complete stanza
  for (const stanza of completed) {
    const credType = stanza.version === 'ntlmv1' ? 'ntlmv2_challenge' : 'ntlmv2_challenge';
    const materialKind = stanza.version === 'ntlmv1' ? 'ntlmv2_challenge' : 'ntlmv2_challenge';
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
