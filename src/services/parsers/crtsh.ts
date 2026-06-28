import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { subdomainId, domainId, apexDomain } from '../parser-utils.js';

// --- crt.sh Parser (Phase 2C) ---
// Input: crt.sh JSON output (`?q=example.com&output=json`) — an array of
// certificate records. `name_value` / `common_name` may each hold several
// newline-separated names, including wildcards (`*.example.com`). Passive: this
// reads public certificate-transparency logs, never the target.
// Emits subdomain nodes + SUBDOMAIN_OF edges to their apex domain node.

export function parseCrtSh(output: string, agentId: string = 'crtsh-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();

  let entries: Array<Record<string, unknown>> = [];
  try {
    const parsed = JSON.parse(output);
    if (Array.isArray(parsed)) entries = parsed as Array<Record<string, unknown>>;
  } catch { /* not JSON → no findings */ }

  const names = new Set<string>();
  for (const entry of entries) {
    for (const field of ['name_value', 'common_name']) {
      const value = entry[field];
      if (typeof value !== 'string') continue;
      for (const raw of value.split('\n')) {
        const name = raw.trim().toLowerCase().replace(/^\*\./, ''); // drop wildcard prefix
        if (name && name.includes('.') && !name.includes('*') && /^[a-z0-9.-]+$/.test(name)) {
          names.add(name);
        }
      }
    }
  }

  for (const fqdn of names) {
    const apex = apexDomain(fqdn);
    const apexNodeId = domainId(apex);
    if (!seen.has(apexNodeId)) {
      nodes.push({ id: apexNodeId, type: 'domain', label: apex, domain_name: apex });
      seen.add(apexNodeId);
    }
    // The apex itself appears in CT logs too; only emit a subdomain node + edge
    // for actual sub-levels.
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
