import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { emailId, subdomainId, domainId, apexDomain } from '../parser-utils.js';
import { isIPv4 } from '../cidr.js';

// --- theHarvester Parser (Phase 2C) ---
// Input: theHarvester `-f out.json` → {"emails":["a@x.com"],
// "hosts":["sub.x.com","sub.x.com:1.2.3.4"], "ips":[...]}. Passive: search
// engines / public datasets. Emits email nodes (the person anchor) and the
// harvested subdomains (+ their apex domain).

export function parseTheHarvester(output: string, agentId: string = 'theharvester-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();
  const add = (node: Finding['nodes'][number]) => { if (!seen.has(node.id)) { nodes.push(node); seen.add(node.id); } };

  let rec: { emails?: unknown; hosts?: unknown };
  try { rec = JSON.parse(output); } catch { return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges }; }
  // JSON.parse("null") / a bare scalar succeeds but isn't an object — guard before deref.
  if (!rec || typeof rec !== 'object') return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };

  const emails = Array.isArray(rec.emails) ? rec.emails.filter((e): e is string => typeof e === 'string') : [];
  for (const raw of emails) {
    const addr = raw.trim().toLowerCase();
    if (!addr.includes('@')) continue;
    add({ id: emailId(addr), type: 'email', label: addr, email_address: addr, email_source: 'harvest' });
  }

  const hosts = Array.isArray(rec.hosts) ? rec.hosts.filter((h): h is string => typeof h === 'string') : [];
  for (const raw of hosts) {
    // theHarvester sometimes appends ":<ip>" to a host entry — keep only the name.
    const fqdn = raw.split(':')[0].trim().toLowerCase();
    if (!fqdn.includes('.') || !/^[a-z0-9.-]+$/.test(fqdn) || isIPv4(fqdn)) continue;
    const apex = apexDomain(fqdn);
    const apexNodeId = domainId(apex);
    add({ id: apexNodeId, type: 'domain', label: apex, domain_name: apex });
    if (fqdn === apex) continue;
    const subId = subdomainId(fqdn);
    add({ id: subId, type: 'subdomain', label: fqdn, subdomain_name: fqdn, parent_domain: apex });
    edges.push({ source: subId, target: apexNodeId, properties: { type: 'SUBDOMAIN_OF', confidence: 1.0, discovered_at: now, discovered_by: agentId } });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
