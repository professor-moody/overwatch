// ============================================================
// OWASP ZAP XML Parser
// Parses ZAP XML reports into graph findings.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { hostId, vulnerabilityId, webappOriginId, normalizeKeyPart } from '../parser-utils.js';

// --- Risk / confidence mappings ---

const RISK_CVSS: Record<number, number> = {
  3: 7.5,   // High
  2: 5.0,   // Medium
  1: 2.5,   // Low
  0: 1.0,   // Informational
};

const CONFIDENCE_MAP: Record<number, number> = {
  3: 0.95,  // High / Confirmed
  2: 0.8,   // Medium
  1: 0.5,   // Low
  0: 0.3,   // False Positive
};

// --- XML parser ---

const zapXmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (name) => ['site', 'alertitem', 'instance'].includes(name),
  commentPropName: false,
});

// --- Types ---

interface ZapAlertItem {
  pluginid?: string | number;
  alert?: string;
  name?: string;
  riskcode?: string | number;
  confidence?: string | number;
  riskdesc?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string | number;
  wascid?: string | number;
  instances?: { instance?: ZapInstance | ZapInstance[] };
  uri?: string;         // fallback if no instances
  method?: string;
  param?: string;
}

interface ZapInstance {
  uri?: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
}

interface ZapSite {
  '@_name'?: string;
  '@_host'?: string;
  '@_port'?: string;
  '@_ssl'?: string;
  alerts?: { alertitem?: ZapAlertItem | ZapAlertItem[] };
}

// --- Main parser ---

export function parseZap(output: string, agentId: string = 'zap-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  let sites: ZapSite[] = [];
  try {
    const parsed = zapXmlParser.parse(output) as Record<string, unknown>;
    const root = (parsed.OWASPZAPReport ?? parsed) as Record<string, unknown>;
    const rawSites = root.site;
    sites = Array.isArray(rawSites) ? rawSites as ZapSite[] : rawSites ? [rawSites as ZapSite] : [];
  } catch {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const site of sites) {
    const siteUrl = site['@_name'] || '';
    const siteHost = site['@_host'] || '';
    const sitePort = site['@_port'] ? parseInt(site['@_port']) : 0;
    const isSsl = site['@_ssl'] === 'true';

    // Resolve host/port/proto from site attributes or URL
    let ip = siteHost;
    let port = sitePort || (isSsl ? 443 : 80);
    let proto = isSsl ? 'https' : 'http';

    if (!ip && siteUrl) {
      try {
        const parsed = new URL(siteUrl);
        ip = parsed.hostname;
        proto = parsed.protocol.replace(':', '');
        port = parsed.port ? parseInt(parsed.port) : (proto === 'https' ? 443 : 80);
      } catch { /* skip site */ }
    }
    if (!ip) continue;

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

    // Alerts
    const rawAlerts = site.alerts?.alertitem;
    const alerts: ZapAlertItem[] = Array.isArray(rawAlerts) ? rawAlerts : rawAlerts ? [rawAlerts] : [];

    for (const alert of alerts) {
      const alertName = alert.alert || alert.name || `ZAP-${alert.pluginid || 'unknown'}`;
      const pluginId = String(alert.pluginid || alertName);
      const riskCode = typeof alert.riskcode === 'string' ? parseInt(alert.riskcode) : (alert.riskcode ?? 0);
      const confCode = typeof alert.confidence === 'string' ? parseInt(alert.confidence) : (alert.confidence ?? 1);

      const cvss = RISK_CVSS[riskCode] ?? 1.0;
      const conf = CONFIDENCE_MAP[confCode] ?? 0.5;

      // Collect affected paths from instances
      const rawInstances = alert.instances?.instance;
      const instances: ZapInstance[] = Array.isArray(rawInstances) ? rawInstances : rawInstances ? [rawInstances] : [];
      const affectedPaths: string[] = [];
      for (const inst of instances) {
        if (inst.uri) {
          try {
            const p = new URL(inst.uri).pathname;
            if (p && !affectedPaths.includes(p)) affectedPaths.push(p);
          } catch { /* skip */ }
        }
      }

      // Fallback to alert-level uri
      if (affectedPaths.length === 0 && alert.uri) {
        try {
          affectedPaths.push(new URL(alert.uri).pathname);
        } catch { /* skip */ }
      }

      // One vulnerability node per (pluginid + alert name) per webapp
      const vulnId = vulnerabilityId(`zap-${pluginId}-${normalizeKeyPart(alertName)}`, waId);

      const cweId = alert.cweid ? Number(alert.cweid) : undefined;

      if (!seenNodes.has(vulnId)) {
        seenNodes.add(vulnId);
        nodes.push({
          id: vulnId,
          type: 'vulnerability',
          label: alertName,
          discovered_at: now,
          confidence: conf,
          vuln_type: classifyZapAlert(alertName, riskCode),
          cvss,
          affected_component: alertName,
          ...(cweId ? { cwe: `CWE-${cweId}` } : {}),
          ...(affectedPaths.length > 0 ? { affected_paths: affectedPaths } : {}),
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
          },
        });
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Helpers ---

function classifyZapAlert(name: string, _riskCode: number): string {
  const lower = name.toLowerCase();
  if (lower.includes('sql injection') || lower.includes('sqli')) return 'sqli';
  if (lower.includes('cross site scripting') || lower.includes('xss')) return 'xss';
  if (lower.includes('cross-site request forgery') || lower.includes('csrf')) return 'csrf';
  if (lower.includes('xml external entity') || lower.includes('xxe')) return 'xxe';
  if (lower.includes('server side request forgery') || lower.includes('ssrf')) return 'ssrf';
  if (lower.includes('remote code execution') || lower.includes('command injection')) return 'command-injection';
  if (lower.includes('path traversal') || lower.includes('directory browsing')) return 'path-traversal';
  if (lower.includes('open redirect') || lower.includes('external redirect')) return 'open-redirect';
  if (lower.includes('information disclosure')) return 'info-disclosure';
  if (lower.includes('authentication') || lower.includes('session')) return 'auth';
  return 'misc';
}
