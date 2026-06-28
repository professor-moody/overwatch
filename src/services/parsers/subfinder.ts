import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { subdomainId, domainId, apexDomain } from '../parser-utils.js';

// --- subfinder Parser (Phase 2C) ---
// Input: subfinder output — plaintext (one host per line) OR JSON-lines
// (`-oJ`: {"host":"api.example.com","source":"..."}). Passive subdomain sources.
// Emits subdomain nodes + SUBDOMAIN_OF edges to the apex domain node.

export function parseSubfinder(output: string, agentId: string = 'subfinder-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();
  const names = new Set<string>();

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let host = trimmed;
    if (trimmed.startsWith('{')) {
      try {
        const obj = JSON.parse(trimmed) as { host?: unknown };
        if (typeof obj.host === 'string') host = obj.host; else continue;
      } catch { continue; }
    }
    host = host.toLowerCase().replace(/^\*\./, '');
    if (host.includes('.') && !host.includes('*') && /^[a-z0-9.-]+$/.test(host)) names.add(host);
  }

  for (const fqdn of names) {
    const apex = apexDomain(fqdn);
    const apexNodeId = domainId(apex);
    if (!seen.has(apexNodeId)) {
      nodes.push({ id: apexNodeId, type: 'domain', label: apex, domain_name: apex });
      seen.add(apexNodeId);
    }
    if (fqdn === apex) continue;
    const subId = subdomainId(fqdn);
    if (!seen.has(subId)) {
      nodes.push({ id: subId, type: 'subdomain', label: fqdn, subdomain_name: fqdn, parent_domain: apex });
      seen.add(subId);
    }
    edges.push({
      source: subId,
      target: apexNodeId,
      properties: { type: 'SUBDOMAIN_OF', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
