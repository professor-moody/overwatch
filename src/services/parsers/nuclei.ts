import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, vulnerabilityId, webappId } from '../parser-utils.js';

// --- Nuclei JSONL Parser ---

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
    return `svc-${ip.replace(/\./g, '-')}-${port}`;
  } catch {
    // Handle plain host:port (e.g. 10.10.10.5:6379 from non-HTTP Nuclei)
    const hostPortMatch = urlStr.match(/^([\d.]+|[\w.-]+):(\d+)$/);
    if (hostPortMatch) {
      return `svc-${hostPortMatch[1].replace(/\./g, '-')}-${hostPortMatch[2]}`;
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

  // Support both JSONL (one object per line) and single JSON array
  let entries: Record<string, unknown>[];
  try {
    const parsed = JSON.parse(output);
    if (Array.isArray(parsed)) {
      entries = parsed;
    } else {
      entries = [parsed];
    }
  } catch {
    // Fall back to JSONL: one JSON object per line
    entries = [];
    for (const line of output.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        entries.push(JSON.parse(trimmed));
      } catch {
        continue;
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
      // Create webapp node from matched-at URL
      const waId = webappId(matchedAt);
      targetNodeId = waId;
      if (!seenNodes.has(waId)) {
        seenNodes.add(waId);
        let waUrl: string;
        try {
          const parsed = new URL(matchedAt);
          waUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`.replace(/\/+$/, '');
        } catch {
          waUrl = matchedAt;
        }
        nodes.push({
          id: waId,
          type: 'webapp',
          label: waUrl,
          discovered_at: now,
          confidence: 1.0,
          url: waUrl,
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
        const hId = hostId(host.replace(/^https?:\/\//, '').split(':')[0]);
        if (!seenNodes.has(hId)) {
          seenNodes.add(hId);
          const ipOrHostname = host.replace(/^https?:\/\//, '').split(':')[0];
          const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(ipOrHostname);
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
