import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, serviceIdFromUrl, webappOriginId } from '../parser-utils.js';

// --- httpx Parser (Phase 2C) ---
// Input: `httpx -json` JSON-lines — {"url":"https://api.example.com",
// "status_code":200,"title":"...","tech":["nginx","php"],"webserver":"nginx"}.
// Light-active: probes in-scope hosts. Emits a webapp node with detected tech,
// PLUS the backing host → RUNS → service(http/https) → HOSTS → webapp chain (as
// nuclei/nikto/burp/zap do) so the discovered web target participates in scope,
// service enumeration, and credential coverage — not just a bare webapp node.

export function parseHttpx(output: string, agentId: string = 'httpx-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let rec: { url?: unknown; status_code?: unknown; title?: unknown; tech?: unknown; webserver?: unknown };
    try { rec = JSON.parse(trimmed); } catch { continue; }
    const url = typeof rec.url === 'string' ? rec.url : undefined;
    if (!url) continue;
    // Origin-level id (scheme+host+port, path stripped) so httpx webapps converge
    // on the same node as nuclei/nikto/etc. rather than splitting per path.
    const id = webappOriginId(url);
    if (seen.has(id)) continue;
    seen.add(id);

    const tech = [
      ...(Array.isArray(rec.tech) ? rec.tech.filter((t): t is string => typeof t === 'string') : []),
      ...(typeof rec.webserver === 'string' && rec.webserver ? [rec.webserver] : []),
    ];
    const technology = [...new Set(tech)].join(', ') || undefined;

    nodes.push({
      id, type: 'webapp', label: typeof rec.title === 'string' && rec.title ? rec.title : url,
      url, discovered_at: now, confidence: 1.0,
      ...(technology ? { technology } : {}),
      ...(typeof rec.status_code === 'number' ? { http_status: rec.status_code } : {}),
    } as Finding['nodes'][number]);

    // Backing host → service chain (shared serviceIdFromUrl so httpx + nuclei
    // converge on one service node per origin). A malformed url still yields the
    // webapp node above; we just skip the chain.
    try {
      const parsed = new URL(url);
      const port = parseInt(parsed.port, 10) || (parsed.protocol === 'https:' ? 443 : 80);
      const proto = parsed.protocol === 'https:' ? 'https' : 'http';
      const svcId = serviceIdFromUrl(url);
      if (!seen.has(svcId)) {
        seen.add(svcId);
        nodes.push({
          id: svcId, type: 'service', label: `${proto}/${port}`,
          discovered_at: now, confidence: 1.0,
          port, protocol: 'tcp', service_name: proto,
        } as Finding['nodes'][number]);
      }
      const rawHost = parsed.hostname.replace(/^\[|\]$/g, '');
      const hId = hostId(rawHost);
      if (!seen.has(hId)) {
        seen.add(hId);
        const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(rawHost) || rawHost.includes(':');
        nodes.push({
          id: hId, type: 'host', label: rawHost,
          discovered_at: now, confidence: 1.0,
          ...(isIp ? { ip: rawHost } : { hostname: rawHost }),
        } as Finding['nodes'][number]);
      }
      const runsKey = `${hId}->${svcId}`;
      if (!seen.has(runsKey)) {
        seen.add(runsKey);
        edges.push({ source: hId, target: svcId, properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } });
      }
      const hostsKey = `${svcId}->${id}`;
      if (!seen.has(hostsKey)) {
        seen.add(hostsKey);
        edges.push({ source: svcId, target: id, properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now } });
      }
    } catch { /* malformed url — webapp node already emitted */ }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
