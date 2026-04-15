import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, vulnerabilityId, webappOriginId } from '../parser-utils.js';

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

function serviceIdFromUrl(urlStr: string): string {
  try {
    const url = new URL(urlStr);
    const ip = url.hostname;
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    return `svc-${hostId(ip).replace(/^host-/, '')}-${port}`;
  } catch {
    // Handle plain host:port (e.g. 10.10.10.5:6379 or [::1]:6379 from non-HTTP Nuclei)
    const bracketMatch = urlStr.match(/^\[([^\]]+)\]:(\d+)$/);
    if (bracketMatch) {
      return `svc-${hostId(bracketMatch[1]).replace(/^host-/, '')}-${bracketMatch[2]}`;
    }
    const hostPortMatch = urlStr.match(/^([\d.]+|[\w.-]+):(\d+)$/);
    if (hostPortMatch) {
      return `svc-${hostId(hostPortMatch[1]).replace(/^host-/, '')}-${hostPortMatch[2]}`;
    }
    return `svc-unknown-http`;
  }
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

      // Create service node + HOSTS edge
      const svcId = serviceIdFromUrl(matchedAt);
      if (!seenNodes.has(svcId)) {
        seenNodes.add(svcId);
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
        } catch { /* skip malformed URLs */ }
      }

      const hostsKey = `${svcId}->${waId}`;
      if (!seenEdges.has(hostsKey)) {
        seenEdges.add(hostsKey);
        edges.push({
          source: svcId,
          target: waId,
          properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now },
        });
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
    } else {
      // Non-HTTP: target is a service node
      const svcId = host ? serviceIdFromUrl(host) : 'svc-unknown';
      targetNodeId = svcId;
      if (!seenNodes.has(svcId) && host) {
        seenNodes.add(svcId);
        try {
          const parsed = new URL(host.includes('://') ? host : `tcp://${host}`);
          const port = parseInt(parsed.port) || 0;
          nodes.push({
            id: svcId,
            type: 'service',
            label: `${parsed.hostname}:${port}`,
            discovered_at: now,
            confidence: 1.0,
            port: port || undefined,
            protocol: 'tcp',
          } as Finding['nodes'][0]);
        } catch { /* skip */ }
      }
    }

    // Create vulnerability node
    const cve = extractCveFromNuclei(info);
    const vulnType = extractVulnTypeFromNuclei(info);
    const vulnId = vulnerabilityId(cve || templateId, targetNodeId);
    const cvss = NUCLEI_SEVERITY_CVSS[severity] ?? 0;
    const name = (info.name || templateId) as string;

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
        exploitable: severity === 'critical' || severity === 'high',
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
          confidence: severity === 'info' ? 0.5 : 0.9,
          discovered_at: now,
        },
      });
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
