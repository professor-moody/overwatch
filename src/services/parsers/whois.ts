import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { organizationId, domainId, asnId } from '../parser-utils.js';

// --- whois Parser (Phase 2C) ---
// Input: whois text. Handles domain whois (Registrant Organization, Domain Name)
// and IP/netblock whois (OrgName, CIDR, OriginAS). Passive: public registry data.
// Emits an organization node plus the domain / asn it OWNS_ASSET. Best-effort
// field extraction — anything missing is simply skipped.

export function parseWhois(output: string, agentId: string = 'whois-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();

  const first = (re: RegExp): string | undefined => {
    const m = output.match(re);
    return m ? m[1].trim() : undefined;
  };

  const org = first(/^\s*(?:Registrant Organization|OrgName|org-name|organisation|owner)\s*:\s*(.+?)\s*$/im);
  const domain = first(/^\s*Domain Name\s*:\s*([^\s]+)\s*$/im)?.toLowerCase();
  const cidr = first(/^\s*(?:CIDR|route)\s*:\s*([0-9./,\s]+?)\s*$/im);
  const originAs = first(/^\s*(?:OriginAS|origin)\s*:\s*(AS?\d+)/im);

  let orgNodeId: string | undefined;
  if (org) {
    orgNodeId = organizationId(org);
    nodes.push({ id: orgNodeId, type: 'organization', label: org, org_name: org });
  }

  if (domain && domain.includes('.')) {
    const dId = domainId(domain);
    nodes.push({ id: dId, type: 'domain', label: domain, domain_name: domain });
    if (orgNodeId) {
      edges.push({ source: orgNodeId, target: dId, properties: { type: 'OWNS_ASSET', confidence: 0.9, discovered_at: now, discovered_by: agentId } });
    }
  }

  if (originAs || cidr) {
    const asNum = originAs ? Number(originAs.replace(/[^0-9]/g, '')) : undefined;
    const ranges = cidr ? cidr.split(',').map(s => s.trim()).filter(Boolean) : undefined;
    const asKey = originAs || (ranges && ranges[0]) || 'unknown';
    const aId = asnId(asKey);
    nodes.push({
      id: aId,
      type: 'asn',
      label: originAs || (ranges ? ranges[0] : 'netblock'),
      ...(asNum !== undefined && Number.isFinite(asNum) ? { asn_number: asNum } : {}),
      ...(ranges && ranges.length ? { cidr_ranges: ranges } : {}),
      ...(org ? { asn_org: org } : {}),
    });
    if (orgNodeId) {
      edges.push({ source: orgNodeId, target: aId, properties: { type: 'OWNS_ASSET', confidence: 0.8, discovered_at: now, discovered_by: agentId } });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
