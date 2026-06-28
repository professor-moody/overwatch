import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { subdomainId, domainId, hostId, asnId, apexDomain } from '../parser-utils.js';
import { isIPv4 } from '../cidr.js';

// --- amass Parser (Phase 2C) ---
// Input: `amass enum -json` JSON-lines — one record per name:
//   {"name":"api.example.com","domain":"example.com",
//    "addresses":[{"ip":"1.2.3.4","cidr":"1.2.3.0/24","asn":13335,"desc":"ACME"}]}
// Emits subdomain + domain (SUBDOMAIN_OF), resolved host (RESOLVES_TO), and asn
// (IN_NETBLOCK) nodes. Passive in `-passive` mode; active resolution otherwise.

type AsnNode = Finding['nodes'][number] & { cidr_ranges?: string[] };

export function parseAmass(output: string, agentId: string = 'amass-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const asnNodes = new Map<string, AsnNode>();
  const now = new Date().toISOString();
  const add = (node: Finding['nodes'][number]) => { if (!seen.has(node.id)) { nodes.push(node); seen.add(node.id); } };

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let rec: { name?: unknown; domain?: unknown; addresses?: unknown };
    try { rec = JSON.parse(trimmed); } catch { continue; }
    const name = typeof rec.name === 'string' ? rec.name.toLowerCase() : undefined;
    // Skip empty / non-name / IP-literal `name` values (amass occasionally emits these).
    if (!name || !name.includes('.') || isIPv4(name)) continue;
    const apex = (typeof rec.domain === 'string' && rec.domain.includes('.')) ? rec.domain.toLowerCase() : apexDomain(name);
    const apexNodeId = domainId(apex);
    add({ id: apexNodeId, type: 'domain', label: apex, domain_name: apex });

    let nameNodeId = apexNodeId;
    if (name !== apex) {
      nameNodeId = subdomainId(name);
      add({ id: nameNodeId, type: 'subdomain', label: name, subdomain_name: name, parent_domain: apex });
      edges.push({ source: nameNodeId, target: apexNodeId, properties: { type: 'SUBDOMAIN_OF', confidence: 1.0, discovered_at: now, discovered_by: agentId } });
    }

    const addresses = Array.isArray(rec.addresses) ? rec.addresses : [];
    for (const addr of addresses) {
      if (!addr || typeof addr !== 'object') continue; // guard null / non-object elements
      const a = addr as Record<string, unknown>;
      const ip = typeof a.ip === 'string' ? a.ip : undefined;
      if (!ip) continue;
      const hId = hostId(ip);
      add({ id: hId, type: 'host', label: ip, ip });
      // Only a subdomain resolves TO a host; an apex-only record just yields the host.
      if (nameNodeId !== apexNodeId) {
        edges.push({ source: nameNodeId, target: hId, properties: { type: 'RESOLVES_TO', confidence: 1.0, discovered_at: now, discovered_by: agentId } });
      }
      // Only a real ASN number becomes an asn node (a bare CIDR has no stable id).
      const asn = typeof a.asn === 'number' ? a.asn : undefined;
      if (asn === undefined) continue;
      const cidr = typeof a.cidr === 'string' ? a.cidr : undefined;
      const aId = asnId(String(asn));
      const existing = asnNodes.get(aId);
      if (!existing) {
        const node: AsnNode = {
          id: aId, type: 'asn', label: `AS${asn}`, asn_number: asn,
          ...(typeof a.desc === 'string' && a.desc ? { asn_org: a.desc } : {}),
          ...(cidr ? { cidr_ranges: [cidr] } : {}),
        };
        asnNodes.set(aId, node);
        add(node);
      } else if (cidr) {
        // Same ASN spans multiple netblocks — accumulate ranges on the one node.
        (existing.cidr_ranges ??= []);
        if (!existing.cidr_ranges.includes(cidr)) existing.cidr_ranges.push(cidr);
      }
      edges.push({ source: hId, target: aId, properties: { type: 'IN_NETBLOCK', confidence: 0.9, discovered_at: now, discovered_by: agentId } });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
