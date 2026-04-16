// ============================================================
// WPScan JSON Parser
// Parses WPScan JSON output (--format json) into graph findings
// with WordPress-specific vulnerability, user, and credential nodes.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, vulnerabilityId, webappOriginId, userId, credentialId } from '../parser-utils.js';

// --- Types ---

interface WpVulnerability {
  title?: string;
  fixed_in?: string;
  references?: {
    cve?: string[];
    url?: string[];
    wpvulndb?: string[];
  };
  vuln_type?: string;
}

interface WpComponent {
  slug?: string;
  version?: { number?: string };
  vulnerabilities?: WpVulnerability[];
  [key: string]: unknown;
}

interface WpUser {
  id?: number;
  slug?: string;
  status?: string;
}

interface WpScanData {
  target_url?: string;
  effective_url?: string;
  interesting_findings?: Array<{
    url?: string;
    type?: string;
    to_s?: string;
    references?: Record<string, unknown>;
  }>;
  version?: {
    number?: string;
    status?: string;
    release_date?: string;
    vulnerabilities?: WpVulnerability[];
  };
  main_theme?: WpComponent;
  plugins?: Record<string, WpComponent>;
  themes?: Record<string, WpComponent>;
  users?: Record<string, WpUser>;
  password_attack?: Record<string, Array<{ password?: string }>>;
  [key: string]: unknown;
}

// --- Main parser ---

export function parseWpscan(output: string, agentId: string = 'wpscan-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  let data: WpScanData;
  try {
    data = JSON.parse(output) as WpScanData;
  } catch {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const targetUrl = data.effective_url || data.target_url || '';
  if (!targetUrl) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Parse URL components
  let ip = '';
  let port = 80;
  let proto = 'http';
  try {
    const parsed = new URL(targetUrl);
    ip = parsed.hostname;
    proto = parsed.protocol.replace(':', '');
    port = parsed.port ? parseInt(parsed.port) : (proto === 'https' ? 443 : 80);
  } catch {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const targetOrigin = `${proto}://${ip}:${port}`;

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
    addEdge(hId, svcId, 'RUNS', 1.0, now, edges, seenEdges);
  }

  // Webapp node — WordPress-enriched
  const waId = webappOriginId(targetOrigin);
  if (!seenNodes.has(waId)) {
    seenNodes.add(waId);
    nodes.push({
      id: waId,
      type: 'webapp',
      label: targetOrigin,
      discovered_at: now,
      confidence: 1.0,
      url: targetOrigin,
      cms_type: 'wordpress',
      technology: 'WordPress',
      ...(data.version?.number ? { version: data.version.number } : {}),
    } as Finding['nodes'][0]);
    addEdge(svcId, waId, 'HOSTS', 1.0, now, edges, seenEdges);
  }

  // WordPress core vulnerabilities
  if (data.version?.vulnerabilities) {
    for (const vuln of data.version.vulnerabilities) {
      addWpVulnerability(vuln, 'wordpress-core', data.version.number, waId, nodes, edges, seenNodes, seenEdges, now);
    }
  }

  // Plugin vulnerabilities
  if (data.plugins) {
    for (const [slug, plugin] of Object.entries(data.plugins)) {
      const effectiveSlug = plugin.slug || slug;
      const version = plugin.version?.number;
      if (plugin.vulnerabilities) {
        for (const vuln of plugin.vulnerabilities) {
          addWpVulnerability(vuln, `plugin-${effectiveSlug}`, version, waId, nodes, edges, seenNodes, seenEdges, now);
        }
      }
    }
  }

  // Theme vulnerabilities
  if (data.themes) {
    for (const [slug, theme] of Object.entries(data.themes)) {
      const effectiveSlug = theme.slug || slug;
      const version = theme.version?.number;
      if (theme.vulnerabilities) {
        for (const vuln of theme.vulnerabilities) {
          addWpVulnerability(vuln, `theme-${effectiveSlug}`, version, waId, nodes, edges, seenNodes, seenEdges, now);
        }
      }
    }
  }

  // Main theme vulnerabilities
  if (data.main_theme?.vulnerabilities) {
    const slug = data.main_theme.slug || 'main-theme';
    const version = data.main_theme.version?.number;
    for (const vuln of data.main_theme.vulnerabilities) {
      addWpVulnerability(vuln, `theme-${slug}`, version, waId, nodes, edges, seenNodes, seenEdges, now);
    }
  }

  // Enumerated users
  if (data.users) {
    for (const [username, userData] of Object.entries(data.users)) {
      const uId = userId(username);
      if (!seenNodes.has(uId)) {
        seenNodes.add(uId);
        nodes.push({
          id: uId,
          type: 'user',
          label: username,
          discovered_at: now,
          confidence: 0.9,
          ...(userData.id ? { wp_user_id: userData.id } : {}),
          ...(userData.slug ? { slug: userData.slug } : {}),
        } as Finding['nodes'][0]);
      }

      // POTENTIAL_AUTH: enumerated user is an auth candidate for the webapp
      addEdge(uId, waId, 'POTENTIAL_AUTH', 0.4, now, edges, seenEdges);
    }
  }

  // Password attack results
  if (data.password_attack) {
    for (const [username, results] of Object.entries(data.password_attack)) {
      for (const result of results) {
        if (!result.password) continue;
        const cId = credentialId('password', result.password, username);
        if (!seenNodes.has(cId)) {
          seenNodes.add(cId);
          nodes.push({
            id: cId,
            type: 'credential',
            label: `${username}:password`,
            discovered_at: now,
            confidence: 0.95,
            cred_material_kind: 'plaintext_password',
            cred_type: 'plaintext',
            cred_user: username,
            cred_value: result.password,
            cred_usable_for_auth: true,
          } as Finding['nodes'][0]);
        }

        // Confirmed WordPress login for the webapp, plus service-level validity
        // for graph consumers that require VALID_ON targets to be host/service.
        addEdge(cId, waId, 'AUTHENTICATED_AS', 0.95, now, edges, seenEdges);
        addEdge(cId, svcId, 'VALID_ON', 0.95, now, edges, seenEdges);
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Helpers ---

function addWpVulnerability(
  vuln: WpVulnerability,
  component: string,
  componentVersion: string | undefined,
  waId: string,
  nodes: Finding['nodes'],
  edges: Finding['edges'],
  seenNodes: Set<string>,
  seenEdges: Set<string>,
  now: string,
): void {
  const title = vuln.title || `WordPress vulnerability in ${component}`;
  const cves = vuln.references?.cve || [];
  const cve = cves[0] ? `CVE-${cves[0]}` : undefined;
  const identifier = cve || title;

  const vulnId = vulnerabilityId(`wp-${component}-${identifier}`, waId);

  if (!seenNodes.has(vulnId)) {
    seenNodes.add(vulnId);
    nodes.push({
      id: vulnId,
      type: 'vulnerability',
      label: title,
      discovered_at: now,
      confidence: 0.85,
      vuln_type: 'cms-vuln',
      affected_component: componentVersion ? `${component}@${componentVersion}` : component,
      ...(cve ? { cve } : {}),
      ...(vuln.fixed_in ? { fixed_in: vuln.fixed_in } : {}),
      exploitable: true,
    } as Finding['nodes'][0]);
  }

  addEdge(waId, vulnId, 'VULNERABLE_TO', 0.85, now, edges, seenEdges);
}

function addEdge(
  source: string,
  target: string,
  type: string,
  confidence: number,
  now: string,
  edges: Finding['edges'],
  seenEdges: Set<string>,
): void {
  const key = `${source}->${target}:${type}`;
  if (!seenEdges.has(key)) {
    seenEdges.add(key);
    edges.push({
      source,
      target,
      properties: { type: type as Finding['edges'][0]['properties']['type'], confidence, discovered_at: now },
    });
  }
}
