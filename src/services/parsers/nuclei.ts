import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { apexDomain, domainId, hostId, serviceIdFromUrl, subdomainId, vulnerabilityId, webappOriginId } from '../parser-utils.js';

const NUCLEI_SEVERITY_CVSS: Record<string, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  info: 0,
};

function extractCveFromNuclei(info: Record<string, unknown>): string | undefined {
  // Check classification.cve-id first
  const classification = info.classification as Record<string, unknown> | undefined;
  if (classification) {
    const cveId = classification['cve-id'] as string | string[] | undefined;
    if (Array.isArray(cveId) && cveId.length > 0) return cveId[0];
    if (typeof cveId === 'string' && cveId.startsWith('CVE-')) return cveId;
  }
  // Fall back to tags
  const tags = info.tags as string | string[] | undefined;
  const tagList = Array.isArray(tags) ? tags : typeof tags === 'string' ? tags.split(',').map(t => t.trim()) : [];
  return tagList.find(t => /^CVE-\d{4}-\d+$/i.test(t))?.toUpperCase();
}

function extractVulnTypeFromNuclei(info: Record<string, unknown>): string {
  const tags = info.tags as string | string[] | undefined;
  const tagList = Array.isArray(tags) ? tags : typeof tags === 'string' ? tags.split(',').map(t => t.trim()) : [];
  const vulnTags = ['sqli', 'xss', 'ssrf', 'rce', 'lfi', 'rfi', 'idor', 'xxe', 'ssti', 'crlf', 'open-redirect', 'traversal', 'upload', 'deserialization'];
  for (const tag of tagList) {
    if (vulnTags.includes(tag.toLowerCase())) return tag.toLowerCase();
  }
  return 'misc';
}

/**
 * Subdomain-takeover class result. nuclei's `http/takeovers/*` templates all
 * carry a `takeover` tag — that tag is the reliable signal (real template-ids
 * are flat slugs like `aws-bucket-takeover`, so the tag, not the id, does the
 * work). We deliberately do NOT match a bare `takeover` substring in the id,
 * which would misclassify unrelated templates like `account-takeover-via-oauth`;
 * the id is only matched on an explicit `takeovers/` path segment, for the rare
 * output where the template path is embedded in the id. Takeovers confirm a
 * dangling third-party resource and are a vulnerability regardless of the
 * template's declared severity.
 */
function isTakeoverResult(info: Record<string, unknown>, templateId: string): boolean {
  const tags = info.tags as string | string[] | undefined;
  const tagList = Array.isArray(tags) ? tags : typeof tags === 'string' ? tags.split(',').map(t => t.trim()) : [];
  if (tagList.some(t => t.toLowerCase() === 'takeover')) return true;
  return /(^|\/)takeovers?\//i.test(templateId);
}

/** Best-effort hostname for the affected target (URL or bare host). */
function hostnameOf(matchedAt: string, host: string): string | undefined {
  const candidate = matchedAt || host;
  if (!candidate) return undefined;
  let name: string;
  try {
    name = new URL(candidate.includes('://') ? candidate : `http://${candidate}`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    name = candidate.replace(/^https?:\/\//, '').replace(/[[\]]/g, '').split('/')[0].split(':')[0];
  }
  name = name.toLowerCase().replace(/\.$/, ''); // normalize a trailing FQDN dot
  return name || undefined;
}

export function parseNuclei(output: string, agentId: string = 'nuclei-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Support JSON array, JSONL, and plain text output
  let entries: Record<string, unknown>[];
  try {
    const parsed = JSON.parse(output);
    if (Array.isArray(parsed)) {
      entries = parsed;
    } else {
      entries = [parsed];
    }
  } catch {
    // Try JSONL first, then fall back to text parsing
    entries = [];
    const textLines: string[] = [];
    for (const line of output.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        entries.push(JSON.parse(trimmed));
      } catch {
        textLines.push(trimmed);
      }
    }
    // If no JSON was parsed, try Nuclei text format
    if (entries.length === 0 && textLines.length > 0) {
      for (const textEntry of parseNucleiTextLines(textLines)) {
        entries.push(textEntry);
      }
    }
  }

  for (const entry of entries) {

    const info = (entry.info || {}) as Record<string, unknown>;
    const templateId = (entry['template-id'] || entry['templateID'] || 'unknown') as string;
    const matchedAt = (entry['matched-at'] || entry['matched_at'] || '') as string;
    const host = (entry.host || '') as string;
    const entryType = (entry.type || 'http') as string;
    const severity = ((info.severity || 'info') as string).toLowerCase();

    // Determine target: webapp for HTTP, service for others
    const isHttp = entryType === 'http' || matchedAt.startsWith('http');
    let targetNodeId: string;
    // Host node id + hostname the HTTP branch created — captured so the takeover
    // block flags the SAME hostname and connects the subdomain to that exact
    // host node (no id drift from trailing dot / vhost / IP host).
    let httpHostNodeId: string | undefined;
    let httpHostName: string | undefined;

    if (isHttp && matchedAt) {
      // Webapp keyed by origin (scheme+host+port), path stored as attribute
      const waId = webappOriginId(matchedAt);
      targetNodeId = waId;
      if (!seenNodes.has(waId)) {
        seenNodes.add(waId);
        let originUrl: string;
        try {
          const parsed = new URL(matchedAt);
          originUrl = `${parsed.protocol}//${parsed.host}`;
        } catch {
          originUrl = matchedAt;
        }
        nodes.push({
          id: waId,
          type: 'webapp',
          label: originUrl,
          discovered_at: now,
          confidence: 1.0,
          url: originUrl,
        } as Finding['nodes'][0]);
      }

      // Create service node + HOSTS edge. seenNodes is marked only AFTER a
      // successful push, and the HOSTS/RUNS edges are gated on the service node
      // actually existing — so a matched-at we can't parse (schemeless, etc.)
      // never leaves a dangling edge that fails ingest validation.
      const svcId = serviceIdFromUrl(matchedAt);
      let svcCreated = seenNodes.has(svcId);
      if (!svcCreated) {
        try {
          const parsed = new URL(matchedAt);
          const port = parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80);
          const proto = parsed.protocol === 'https:' ? 'https' : 'http';
          nodes.push({
            id: svcId,
            type: 'service',
            label: `${proto}/${port}`,
            discovered_at: now,
            confidence: 1.0,
            port,
            protocol: 'tcp',
            service_name: proto,
          } as Finding['nodes'][0]);
          seenNodes.add(svcId);
          svcCreated = true;
        } catch { /* unparseable matched-at — no service node */ }
      }

      if (svcCreated) {
        const hostsKey = `${svcId}->${waId}`;
        if (!seenEdges.has(hostsKey)) {
          seenEdges.add(hostsKey);
          edges.push({
            source: svcId,
            target: waId,
            properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now },
          });
        }
      }

      // Create host node if identifiable
      if (host) {
        let ipOrHostname: string;
        try {
          const parsed = new URL(host.includes('://') ? host : `http://${host}`);
          ipOrHostname = parsed.hostname.replace(/^\[|\]$/g, '');
        } catch {
          ipOrHostname = host.replace(/^https?:\/\//, '').replace(/[\[\]]/g, '').split('/')[0];
        }
        const hId = hostId(ipOrHostname);
        httpHostNodeId = hId;
        httpHostName = ipOrHostname.replace(/\.$/, ''); // strip a trailing FQDN dot for the subdomain name
        if (!seenNodes.has(hId)) {
          seenNodes.add(hId);
          const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(ipOrHostname) || ipOrHostname.includes(':');
          nodes.push({
            id: hId,
            type: 'host',
            label: ipOrHostname,
            discovered_at: now,
            confidence: 1.0,
            ...(isIp ? { ip: ipOrHostname } : { hostname: ipOrHostname }),
          } as Finding['nodes'][0]);
        }
        if (svcCreated) {
          const runsKey = `${hId}->${svcId}`;
          if (!seenEdges.has(runsKey)) {
            seenEdges.add(runsKey);
            edges.push({
              source: hId,
              target: svcId,
              properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
            });
          }
        }
      }
    } else {
      // Non-HTTP: target is a service node. A result with no host has no
      // identifiable target, so we skip it rather than invent a shared
      // `svc-unknown` node that collides across findings and orphans.
      if (!host) continue;
      const svcId = serviceIdFromUrl(host);
      targetNodeId = svcId;
      if (!seenNodes.has(svcId)) {
        let label = host;
        let port: number | undefined;
        try {
          const parsed = new URL(host.includes('://') ? host : `tcp://${host}`);
          port = parseInt(parsed.port) || undefined;
          label = `${parsed.hostname}:${port ?? 0}`;
        } catch { /* keep the raw host as the label */ }
        nodes.push({
          id: svcId,
          type: 'service',
          label,
          discovered_at: now,
          confidence: 1.0,
          port,
          protocol: 'tcp',
        } as Finding['nodes'][0]);
        seenNodes.add(svcId);
      }
    }

    // Create vulnerability node
    const cve = extractCveFromNuclei(info);
    const isTakeover = isTakeoverResult(info, templateId);
    const vulnType = isTakeover ? 'subdomain_takeover' : extractVulnTypeFromNuclei(info);
    const name = (info.name || templateId) as string;

    // Phase F: severity=info templates (tech-detect, banner grabs, etc.) are
    // not vulnerabilities — they are service enrichments. Treat them as such
    // unless they carry a CVE. This prevents the graph from drowning in
    // "info" severity vulnerability nodes that tools like nuclei emit by the
    // hundreds during recon.
    if (severity === 'info' && !cve && !isTakeover) {
      // Best-effort: enrich the target service/webapp with detected
      // technology and tags. Don't create a vulnerability node, don't
      // create a VULNERABLE_TO edge.
      for (const node of nodes) {
        if (node.id !== targetNodeId) continue;
        const tags = Array.isArray(info.tags)
          ? (info.tags as unknown[]).filter((t): t is string => typeof t === 'string')
          : typeof info.tags === 'string'
            ? (info.tags as string).split(',').map(s => s.trim()).filter(Boolean)
            : [];
        const existingTech = Array.isArray((node as Record<string, unknown>).technologies)
          ? ((node as Record<string, unknown>).technologies as string[])
          : [];
        const techSet = new Set<string>(existingTech);
        // tech-detect:<name> templates encode the technology in the template id.
        const techMatch = templateId.match(/^tech-detect:(.+)$/i);
        if (techMatch) techSet.add(techMatch[1].toLowerCase());
        for (const t of tags) {
          if (t.startsWith('tech') || t === 'detect') continue;
          techSet.add(t.toLowerCase());
        }
        if (techSet.size > 0) {
          (node as Record<string, unknown>).technologies = Array.from(techSet);
        }
        const existingNotes = ((node as Record<string, unknown>).notes as string | undefined) || '';
        const enrichLine = `nuclei:${templateId}`;
        if (!existingNotes.includes(enrichLine)) {
          (node as Record<string, unknown>).notes = existingNotes
            ? `${existingNotes}\n${enrichLine}`
            : enrichLine;
        }
        break;
      }
      continue;
    }

    const vulnId = vulnerabilityId(cve || templateId, targetNodeId);
    const cvss = NUCLEI_SEVERITY_CVSS[severity] ?? 0;

    if (!seenNodes.has(vulnId)) {
      seenNodes.add(vulnId);
      nodes.push({
        id: vulnId,
        type: 'vulnerability',
        label: cve || name,
        discovered_at: now,
        confidence: 1.0,
        cve,
        cvss,
        vuln_type: vulnType,
        affected_component: name,
        // A confirmed subdomain takeover is exploitable regardless of the
        // template's declared severity. (CWE is derived from vuln_type by the
        // finding-classifier; no need to stamp it on the node here.)
        exploitable: isTakeover || severity === 'critical' || severity === 'high',
      } as Finding['nodes'][0]);
    }

    // VULNERABLE_TO edge
    const vulnEdgeKey = `${targetNodeId}->${vulnId}`;
    if (!seenEdges.has(vulnEdgeKey)) {
      seenEdges.add(vulnEdgeKey);
      edges.push({
        source: targetNodeId,
        target: vulnId,
        properties: {
          type: 'VULNERABLE_TO',
          confidence: severity === 'info' && !isTakeover ? 0.5 : 0.9,
          discovered_at: now,
        },
      });
    }

    // Populate the affected subdomain's `takeover_candidate` field (queryable,
    // and cross-referenced by dnsx recon; the confirmed takeover also emits the
    // vulnerability node above, which the frontier/report consume). Prefer the
    // exact hostname of the host node the HTTP branch created so the subdomain
    // and its RESOLVES_TO host stay consistent (vhost-safe); fall back to the
    // matched-at hostname only when no host node was made. Emit the parent
    // domain + SUBDOMAIN_OF so the node is never orphaned and merges with a
    // recon-discovered subdomain of the same name.
    if (isTakeover) {
      const fqdn = httpHostName ?? hostnameOf(matchedAt, host);
      const isIp = fqdn ? /^\d+\.\d+\.\d+\.\d+$/.test(fqdn) || fqdn.includes(':') : false;
      const apex = fqdn ? apexDomain(fqdn) : undefined;
      if (fqdn && apex && !isIp && fqdn.includes('.') && fqdn !== apex) {
        const sdId = subdomainId(fqdn);
        if (!seenNodes.has(sdId)) {
          seenNodes.add(sdId);
          nodes.push({
            id: sdId,
            type: 'subdomain',
            label: fqdn,
            discovered_at: now,
            confidence: 1.0,
            subdomain_name: fqdn,
            parent_domain: apex,
            takeover_candidate: true,
          } as Finding['nodes'][0]);
        }
        const domId = domainId(apex);
        if (!seenNodes.has(domId)) {
          seenNodes.add(domId);
          nodes.push({ id: domId, type: 'domain', label: apex, discovered_at: now, confidence: 1.0, domain_name: apex } as Finding['nodes'][0]);
        }
        const subEdgeKey = `${sdId}->${domId}:SUBDOMAIN_OF`;
        if (!seenEdges.has(subEdgeKey)) {
          seenEdges.add(subEdgeKey);
          edges.push({ source: sdId, target: domId, properties: { type: 'SUBDOMAIN_OF', confidence: 1.0, discovered_at: now } });
        }
        // When the HTTP branch created a host node for this target, tie the
        // subdomain to it (RESOLVES_TO, using the captured id — robust to
        // trailing-dot / vhost / IP drift) so the takeover_candidate flag sits
        // in the vulnerability's component. Otherwise (non-HTTP, or no host
        // field) the subdomain still connects via SUBDOMAIN_OF to its domain —
        // and merges with a recon-discovered subdomain that carries the host
        // linkage. We deliberately do NOT synthesize a host here: that proved
        // fragile (phantom services / dangling edges) for degenerate inputs.
        if (httpHostNodeId) {
          const resolvesKey = `${sdId}->${httpHostNodeId}:RESOLVES_TO`;
          if (!seenEdges.has(resolvesKey)) {
            seenEdges.add(resolvesKey);
            edges.push({ source: sdId, target: httpHostNodeId, properties: { type: 'RESOLVES_TO', confidence: 1.0, discovered_at: now } });
          }
        }
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// Nuclei text output format: [template-id] [protocol] [severity] matched-url [extra-info]
// Examples:
//   [CVE-2021-41773] [http] [critical] http://10.10.10.5/cgi-bin/.%2e/...
//   [tech-detect:nginx] [http] [info] http://10.10.10.5
const NUCLEI_TEXT_RE = /^\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)(.*)$/;

function parseNucleiTextLines(lines: string[]): Record<string, unknown>[] {
  const entries: Record<string, unknown>[] = [];
  for (const line of lines) {
    const m = line.match(NUCLEI_TEXT_RE);
    if (!m) continue;

    const templateId = m[1];
    const protocol = m[2].toLowerCase();
    const severity = m[3].toLowerCase();
    const matchedUrl = m[4];
    const extraInfo = m[5]?.trim() || '';

    const cveMatch = templateId.match(/^(CVE-\d{4}-\d+)/i);
    const tags: string[] = [];
    if (cveMatch) tags.push(cveMatch[1].toUpperCase());

    entries.push({
      'template-id': templateId,
      type: protocol,
      host: matchedUrl,
      'matched-at': matchedUrl,
      info: {
        name: extraInfo || templateId,
        severity,
        tags,
        ...(cveMatch ? { classification: { 'cve-id': cveMatch[1].toUpperCase() } } : {}),
      },
    });
  }
  return entries;
}
