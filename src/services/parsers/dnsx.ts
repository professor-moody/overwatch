import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { subdomainId, domainId, hostId, apexDomain } from '../parser-utils.js';
import { isIPv4 } from '../cidr.js';

// --- dnsx Parser (Phase 2C) ---
// Input: `dnsx -json` JSON-lines — {"host":"api.example.com","a":["1.2.3.4"],
// "aaaa":[...],"cname":["..."]}. Light-active: resolves in-scope names.
// Emits subdomain + domain (SUBDOMAIN_OF) and resolved host (RESOLVES_TO) nodes.

export function parseDnsx(output: string, agentId: string = 'dnsx-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();
  const add = (node: Finding['nodes'][number]) => { if (!seen.has(node.id)) { nodes.push(node); seen.add(node.id); } };

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let rec: { host?: unknown; a?: unknown; aaaa?: unknown };
    try { rec = JSON.parse(trimmed); } catch { continue; }
    const host = typeof rec.host === 'string' ? rec.host.toLowerCase() : undefined;
    // Skip IP-literal hosts: in reverse mode (`dnsx -ptr`) the `host` field is an
    // IP, which must not become a bogus subdomain under a fake apex.
    if (!host || !host.includes('.') || isIPv4(host)) continue;
    const apex = apexDomain(host);
    const apexNodeId = domainId(apex);
    add({ id: apexNodeId, type: 'domain', label: apex, domain_name: apex });

    let nameNodeId = apexNodeId;
    if (host !== apex) {
      nameNodeId = subdomainId(host);
      add({ id: nameNodeId, type: 'subdomain', label: host, subdomain_name: host, parent_domain: apex });
      edges.push({ source: nameNodeId, target: apexNodeId, properties: { type: 'SUBDOMAIN_OF', confidence: 1.0, discovered_at: now, discovered_by: agentId } });
    }

    const ips = [
      ...(Array.isArray(rec.a) ? rec.a : []),
      ...(Array.isArray(rec.aaaa) ? rec.aaaa : []),
    ].filter((ip): ip is string => typeof ip === 'string');
    for (const ip of ips) {
      const hId = hostId(ip);
      add({ id: hId, type: 'host', label: ip, ip });
      if (nameNodeId !== apexNodeId) {
        edges.push({ source: nameNodeId, target: hId, properties: { type: 'RESOLVES_TO', confidence: 1.0, discovered_at: now, discovered_by: agentId } });
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
