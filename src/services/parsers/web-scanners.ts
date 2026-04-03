import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId } from '../parser-utils.js';

// --- gobuster / feroxbuster / ffuf Parser ---

const LOGIN_PATH_PATTERNS = /\/(login|signin|auth|wp-login|admin|weblogin|sso|cas|saml|oauth)/i;

export function parseWebDirEnum(output: string, agentId: string = 'webdirenum-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();

  const discoveredPaths: Array<{ path: string; status: number; size?: number }> = [];
  let targetUrl: string | undefined;
  let hasLoginForm = false;

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Try ffuf JSON first
  try {
    const data = JSON.parse(output);
    if (data.results && Array.isArray(data.results)) {
      targetUrl = data.commandline?.match(/(?:-u\s+)(\S+)/)?.[1] || data.config?.url;
      // Normalize target URL from ffuf config
      if (!targetUrl && data.results.length > 0) {
        const firstUrl = data.results[0].url || '';
        const parsed = firstUrl.match(/^(https?:\/\/[^/]+)/i);
        if (parsed) targetUrl = parsed[1];
      }

      for (const r of data.results) {
        const url = r.url || '';
        const status = r.status || 0;
        const size = r.length || r.content_length || r.words || undefined;
        const path = url.replace(/^https?:\/\/[^/]+/i, '') || '/';
        discoveredPaths.push({ path, status, size });
        if (LOGIN_PATH_PATTERNS.test(path)) hasLoginForm = true;
      }
      return buildWebDirEnumFinding(targetUrl, discoveredPaths, hasLoginForm, agentId, now);
    }
  } catch {
    // Not JSON — try line-based
  }

  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    // Gobuster: /path (Status: 200) [Size: 1234]
    const gobusterMatch = line.match(/^(\/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/);
    if (gobusterMatch) {
      const [, path, status, size] = gobusterMatch;
      discoveredPaths.push({ path, status: parseInt(status), size: size ? parseInt(size) : undefined });
      if (LOGIN_PATH_PATTERNS.test(path)) hasLoginForm = true;
      continue;
    }

    // Feroxbuster: 200 GET 1234l 5678w 91011c http://target/path
    const feroxMatch = line.match(/^(\d{3})\s+\w+\s+\d+l?\s+\d+w?\s+(\d+)c?\s+(https?:\/\/\S+)/);
    if (feroxMatch) {
      const [, status, size, url] = feroxMatch;
      const path = url.replace(/^https?:\/\/[^/]+/i, '') || '/';
      if (!targetUrl) {
        const baseMatch = url.match(/^(https?:\/\/[^/]+)/i);
        if (baseMatch) targetUrl = baseMatch[1];
      }
      discoveredPaths.push({ path, status: parseInt(status), size: parseInt(size) });
      if (LOGIN_PATH_PATTERNS.test(path)) hasLoginForm = true;
      continue;
    }

    // Gobuster URL in output header: Url: http://target
    const urlMatch = line.match(/^(?:Target|Url):\s*(https?:\/\/\S+)/i);
    if (urlMatch && !targetUrl) {
      targetUrl = urlMatch[1].replace(/\/+$/, '');
    }
  }

  return buildWebDirEnumFinding(targetUrl, discoveredPaths, hasLoginForm, agentId, now);
}

function buildWebDirEnumFinding(
  targetUrl: string | undefined,
  discoveredPaths: Array<{ path: string; status: number; size?: number }>,
  hasLoginForm: boolean,
  agentId: string,
  now: string,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];

  if (discoveredPaths.length === 0) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Build a synthetic service node for enrichment
  // Extract host:port from URL to create a stable service node ID
  let serviceId = 'svc-unknown-http';
  let hostNodeId: string | undefined;

  if (targetUrl) {
    const urlParts = targetUrl.match(/^(https?):\/\/([^:/]+)(?::(\d+))?/i);
    if (urlParts) {
      const [, scheme, host, portStr] = urlParts;
      const port = portStr ? parseInt(portStr) : (scheme === 'https' ? 443 : 80);
      const hostKey = host.replace(/[.\s]/g, '-');
      serviceId = `svc-${hostKey}-${port}`;
      hostNodeId = `host-${hostKey}`;

      // Create host node
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host);
      nodes.push({
        id: hostNodeId,
        type: 'host',
        label: host,
        ip: isIp ? host : undefined,
        hostname: isIp ? undefined : host,
        alive: true,
      });

      // Create service node
      nodes.push({
        id: serviceId,
        type: 'service',
        label: `${scheme}/${port}`,
        port,
        protocol: 'tcp',
        service_name: scheme,
        discovered_paths: discoveredPaths,
        has_login_form: hasLoginForm || undefined,
      });

      edges.push({
        source: hostNodeId,
        target: serviceId,
        properties: { type: 'RUNS', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  // If we couldn't parse a URL, still emit a service-like node
  if (nodes.length === 0) {
    nodes.push({
      id: serviceId,
      type: 'service',
      label: 'http (unknown target)',
      service_name: 'http',
      discovered_paths: discoveredPaths,
      has_login_form: hasLoginForm || undefined,
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
