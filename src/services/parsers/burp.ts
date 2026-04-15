// ============================================================
// Burp Suite XML Parser
// Parses Burp Suite Pro XML reports into graph findings.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { hostId, vulnerabilityId, webappOriginId, normalizeKeyPart } from '../parser-utils.js';

// --- Severity / confidence mappings ---

const SEVERITY_CVSS: Record<string, number> = {
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  information: 1.0,
};

const CONFIDENCE_MAP: Record<string, number> = {
  certain: 0.95,
  firm: 0.8,
  tentative: 0.5,
};

// --- XML parser ---

const burpXmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (name) => ['issue'].includes(name),
  commentPropName: false,
});

// --- Types ---

interface BurpIssue {
  type?: string | number;
  name?: string;
  host?: { '#text'?: string; '@_ip'?: string } | string;
  path?: string;
  location?: string;
  severity?: string;
  confidence?: string;
  issueBackground?: string;
  remediationBackground?: string;
  issueDetail?: string;
  references?: string;
}

// --- Main parser ---

export function parseBurp(output: string, agentId: string = 'burp-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  let issues: BurpIssue[] = [];
  try {
    const parsed = burpXmlParser.parse(output) as Record<string, unknown>;
    const root = (parsed.issues ?? parsed) as Record<string, unknown>;
    const raw = root.issue;
    issues = Array.isArray(raw) ? raw as BurpIssue[] : raw ? [raw as BurpIssue] : [];
  } catch {
    // Not valid XML — return empty finding
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const issue of issues) {
    // Resolve host IP and URL
    let ip = '';
    let hostUrl = '';
    if (typeof issue.host === 'object' && issue.host !== null) {
      ip = issue.host['@_ip'] || '';
      hostUrl = issue.host['#text'] || '';
    } else if (typeof issue.host === 'string') {
      hostUrl = issue.host;
    }

    if (!ip && hostUrl) {
      try {
        const parsed = new URL(hostUrl);
        ip = parsed.hostname;
      } catch { /* skip */ }
    }
    if (!ip) continue;

    // Derive port and protocol from URL
    let port = 80;
    let proto = 'http';
    if (hostUrl) {
      try {
        const parsed = new URL(hostUrl);
        proto = parsed.protocol.replace(':', '');
        port = parsed.port ? parseInt(parsed.port) : (proto === 'https' ? 443 : 80);
      } catch { /* defaults */ }
    }

    const targetUrl = `${proto}://${ip}:${port}`;

    // Host node
    const hId = hostId(ip);
    if (!seenNodes.has(hId)) {
      seenNodes.add(hId);
      const isIpAddr = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
      nodes.push({
        id: hId,
        type: 'host',
        label: ip,
        discovered_at: now,
        confidence: 1.0,
        ...(isIpAddr ? { ip } : { hostname: ip }),
      } as Finding['nodes'][0]);
    }

    // Service node
    const svcId = `svc-${ip.replace(/\./g, '-')}-${port}`;
    if (!seenNodes.has(svcId)) {
      seenNodes.add(svcId);
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
      edges.push({
        source: hId,
        target: svcId,
        properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
      });
    }

    // Webapp node
    const waId = webappOriginId(targetUrl);
    if (!seenNodes.has(waId)) {
      seenNodes.add(waId);
      nodes.push({
        id: waId,
        type: 'webapp',
        label: targetUrl,
        discovered_at: now,
        confidence: 1.0,
        url: targetUrl,
      } as Finding['nodes'][0]);
      const hostEdge = `${svcId}->${waId}`;
      if (!seenEdges.has(hostEdge)) {
        seenEdges.add(hostEdge);
        edges.push({
          source: svcId,
          target: waId,
          properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now },
        });
      }
    }

    // Vulnerability node
    const issueName = issue.name || `Burp-${issue.type || 'unknown'}`;
    const path = issue.path || issue.location || '';
    const pathSuffix = path ? `-${normalizeKeyPart(path)}` : '';
    const typeId = String(issue.type || issueName);
    const vulnId = vulnerabilityId(typeId + pathSuffix, waId);

    const severity = (issue.severity || 'information').toLowerCase();
    const confidence = (issue.confidence || 'tentative').toLowerCase();
    const cvss = SEVERITY_CVSS[severity] ?? 1.0;
    const conf = CONFIDENCE_MAP[confidence] ?? 0.5;

    if (!seenNodes.has(vulnId)) {
      seenNodes.add(vulnId);
      nodes.push({
        id: vulnId,
        type: 'vulnerability',
        label: path ? `${issueName} (${path})` : issueName,
        discovered_at: now,
        confidence: conf,
        vuln_type: classifyBurpVuln(issueName),
        cvss,
        affected_component: issueName,
        affected_path: path || undefined,
      } as Finding['nodes'][0]);
    }

    const vulnEdge = `${waId}->${vulnId}`;
    if (!seenEdges.has(vulnEdge)) {
      seenEdges.add(vulnEdge);
      edges.push({
        source: waId,
        target: vulnId,
        properties: {
          type: 'VULNERABLE_TO',
          confidence: conf,
          discovered_at: now,
          ...(path ? { affected_path: path } : {}),
        },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Helpers ---

function classifyBurpVuln(name: string): string {
  const lower = name.toLowerCase();
  if (lower.includes('sql injection') || lower.includes('sqli')) return 'sqli';
  if (lower.includes('cross-site scripting') || lower.includes('xss')) return 'xss';
  if (lower.includes('cross-site request forgery') || lower.includes('csrf')) return 'csrf';
  if (lower.includes('xml external entity') || lower.includes('xxe')) return 'xxe';
  if (lower.includes('server-side request forgery') || lower.includes('ssrf')) return 'ssrf';
  if (lower.includes('command injection') || lower.includes('os command')) return 'command-injection';
  if (lower.includes('file inclusion') || lower.includes('path traversal') || lower.includes('directory traversal')) return 'path-traversal';
  if (lower.includes('open redirect')) return 'open-redirect';
  if (lower.includes('information disclosure') || lower.includes('information leak')) return 'info-disclosure';
  if (lower.includes('authentication') || lower.includes('session')) return 'auth';
  return 'misc';
}
