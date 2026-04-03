import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, hostId, userId } from '../parser-utils.js';

// --- Responder Parser ---

export function parseResponder(output: string, agentId: string = 'responder-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    // Look for NTLMv2-SSP Client line as stanza start
    const clientMatch = lines[i].match(/NTLMv2-SSP Client\s*:\s*(\d+\.\d+\.\d+\.\d+)/);
    if (!clientMatch) continue;
    const clientIp = clientMatch[1];

    // Next line should be Username
    const userLine = lines[i + 1] || '';
    const userMatch = userLine.match(/NTLMv2-SSP Username\s*:\s*([^\\]+)\\(.+)/);
    if (!userMatch) continue;
    const domain = userMatch[1].trim();
    const username = userMatch[2].trim();

    // Next line should be Hash
    const hashLine = lines[i + 2] || '';
    const hashMatch = hashLine.match(/NTLMv2-SSP Hash\s*:\s*(.+)/);
    if (!hashMatch) continue;
    const hash = hashMatch[1].trim();

    const resolvedHostId = hostId(clientIp);
    const resolvedUserId = userId(username, domain);
    const resolvedCredId = credentialId('ntlmv2_challenge', hash, username, domain);

    if (!seenNodes.has(resolvedHostId)) {
      nodes.push({ id: resolvedHostId, type: 'host', label: clientIp, ip: clientIp, alive: true });
      seenNodes.add(resolvedHostId);
    }
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({ id: resolvedUserId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain });
      seenNodes.add(resolvedUserId);
    }
    if (!seenNodes.has(resolvedCredId)) {
      nodes.push({
        id: resolvedCredId,
        type: 'credential',
        label: `NTLMv2:${username}`,
        cred_type: 'ntlmv2_challenge',
        cred_material_kind: 'ntlmv2_challenge',
        cred_usable_for_auth: false,
        cred_evidence_kind: 'capture',
        cred_value: hash,
        cred_user: username,
        cred_domain: domain,
        observed_from_ip: clientIp,
      });
      seenNodes.add(resolvedCredId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });

    // Skip past the stanza we just consumed
    i += 2;
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
