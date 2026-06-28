import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { webappOriginId } from '../parser-utils.js';

// --- httpx Parser (Phase 2C) ---
// Input: `httpx -json` JSON-lines — {"url":"https://api.example.com",
// "status_code":200,"title":"...","tech":["nginx","php"],"webserver":"nginx"}.
// Light-active: probes in-scope hosts. Emits webapp nodes with detected tech.

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
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
