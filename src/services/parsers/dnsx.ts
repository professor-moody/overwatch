import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { subdomainId, domainId, hostId, apexDomain } from '../parser-utils.js';
import { isIPv4 } from '../cidr.js';

// --- dnsx Parser (Phase 2C) ---
// Input: `dnsx -json` JSON-lines — {"host":"api.example.com","a":["1.2.3.4"],
// "aaaa":[...],"cname":["..."]}. Light-active: resolves in-scope names.
// Emits subdomain + domain (SUBDOMAIN_OF) and resolved host (RESOLVES_TO) nodes.

// CNAME target suffixes for services with open registration — a dangling CNAME
// (no A/AAAA) to one of these is a claimable subdomain-takeover candidate. A
// dangling CNAME to an arbitrary internal host is NOT claimable, so we don't
// flag it. (can-i-take-over-xyz / subjack fingerprint set, high-confidence subset.)
const TAKEOVER_CNAME_SUFFIXES = [
  'github.io', 'herokuapp.com', 'herokudns.com', 'herokussl.com',
  'azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net',
  'blob.core.windows.net', 'azureedge.net', 'azure-api.net',
  'ghost.io', 'surge.sh', 'bitbucket.io', 'wpengine.com', 'pantheonsite.io',
  'readme.io', 'statuspage.io', 'launchrock.com', 'unbouncepages.com',
  'myshopify.com', 'desk.com', 'zendesk.com', 'freshdesk.com', 'helpscoutdocs.com',
  'fastly.net', 'netlify.app', 'netlify.com', 'ghs.googlehosted.com',
];
// AWS S3 specifically (global / regional / website endpoints) — a dangling
// CNAME to a deleted bucket is claimable. Other *.amazonaws.com (ELB/EC2/RDS/API
// GW) is NOT re-claimable, so we match S3 endpoints only. The `s3` must be its
// own label (bounded by `.`/`-`) and the name must end at the real `.amazonaws.com`
// zone — so a lookalike like `bucket.s3.evilamazonaws.com` does NOT match.
const S3_CNAME = /(^|\.)s3(-[a-z0-9-]+)?(\.[a-z0-9-]+)*\.amazonaws\.com$/;

/** A CNAME target under a service with open registration (claimable on takeover). */
function isClaimableCname(cname: string): boolean {
  if (S3_CNAME.test(cname)) return true;
  return TAKEOVER_CNAME_SUFFIXES.some(s => cname === s || cname.endsWith(`.${s}`));
}

export function parseDnsx(output: string, agentId: string = 'dnsx-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();
  const add = (node: Finding['nodes'][number]) => { if (!seen.has(node.id)) { nodes.push(node); seen.add(node.id); } };

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let rec: { host?: unknown; a?: unknown; aaaa?: unknown; cname?: unknown };
    try { rec = JSON.parse(trimmed); } catch { continue; }
    const host = typeof rec.host === 'string' ? rec.host.toLowerCase().replace(/\.$/, '') : undefined;
    // Skip IP-literal hosts: in reverse mode (`dnsx -ptr`) the `host` field is an
    // IP, which must not become a bogus subdomain under a fake apex.
    if (!host || !host.includes('.') || isIPv4(host)) continue;
    const apex = apexDomain(host);
    const apexNodeId = domainId(apex);
    add({ id: apexNodeId, type: 'domain', label: apex, domain_name: apex });

    const ips = [
      ...(Array.isArray(rec.a) ? rec.a : []),
      ...(Array.isArray(rec.aaaa) ? rec.aaaa : []),
    ].filter((ip): ip is string => typeof ip === 'string');
    const cnames = (Array.isArray(rec.cname) ? rec.cname : typeof rec.cname === 'string' ? [rec.cname] : [])
      .filter((c): c is string => typeof c === 'string' && c.length > 0)
      .map(c => c.toLowerCase().replace(/\.$/, ''));

    let nameNodeId = apexNodeId;
    if (host !== apex) {
      nameNodeId = subdomainId(host);
      // A CNAME to a claimable third-party service that resolves to NO address
      // is the canonical dangling-CNAME subdomain-takeover signal (the target
      // resource no longer exists and can be re-registered). A dangling CNAME to
      // an arbitrary internal host isn't claimable, so it isn't flagged.
      const dangling = ips.length === 0 && cnames.some(isClaimableCname);
      add({
        id: nameNodeId, type: 'subdomain', label: host, subdomain_name: host, parent_domain: apex,
        ...(ips.length ? { resolved_ips: ips } : {}),
        ...(cnames.length ? { dns_records: cnames.map(c => `CNAME ${c}`) } : {}),
        ...(dangling ? { takeover_candidate: true } : {}),
      });
      edges.push({ source: nameNodeId, target: apexNodeId, properties: { type: 'SUBDOMAIN_OF', confidence: 1.0, discovered_at: now, discovered_by: agentId } });
    }
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
