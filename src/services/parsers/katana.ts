// ============================================================
// Crawl output → api_endpoint nodes (katana / hakrawler / gau / waybackurls).
//
// The authenticated-crawl half of the web surface: an operator/agent runs a
// crawler against a web app — authenticated by passing the session cookie saved
// by `test_webapp_credential` (session_jar_id) — through the instrumented
// `run_tool`, then feeds the output here. Each crawled URL becomes an
// `api_endpoint` node (path, method, http_status) under the `webapp` for its
// origin, linked with `HAS_ENDPOINT` (and sets `has_api`). This is the crawl
// sibling of the LinkFinder (JS) and OpenAPI/GraphQL (schema) endpoint parsers.
//
// Input shapes:
//   - katana `-jsonl`: {request:{method,endpoint}, response:{status_code}} per line
//   - katana plain / hakrawler / gau / waybackurls: one absolute URL per line
// (gospider's `[tag] - URL` / `{output}` formats differ and are not handled.)
//
// Each entry carries an ABSOLUTE url; the owning webapp is resolved per-URL from
// its origin, but restricted to the crawl's own site (same eTLD+1 as
// source_host, or as the first URL seen) so off-site links (trackers, CDNs,
// fonts, off-domain gau hits) don't pollute the graph. Query + fragment are
// stripped so `/x?a=1` and `/x?a=2` collapse to one endpoint. To bound a
// pathological historical dump (gau/waybackurls can return tens of thousands),
// the parser stops after MAX_ENDPOINTS distinct endpoints PER PARSE — narrow the
// crawl scope if you hit it. Per-line fault tolerant.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { apexDomain, apiEndpointId, resolveWebappOrigin, webappOriginId } from '../parser-utils.js';

const MAX_ENDPOINTS = 5000;

interface Ctx {
  nodes: Finding['nodes'];
  edges: Finding['edges'];
  seen: Set<string>;
  byId: Map<string, NodeProperties>;
  now: string;
  agentId: string;
  endpointCount: number;
  // eTLD+1 the crawl is scoped to — off-site hosts (trackers/CDNs/fonts) are
  // dropped. Anchored from parser_context.source_host, else the first URL seen.
  anchorApex?: string;
}

function addEdge(ctx: Ctx, source: string, target: string, type: string, confidence: number): void {
  const key = `${source}->${target}:${type}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.edges.push({ source, target, properties: { type: type as Finding['edges'][0]['properties']['type'], confidence, discovered_at: ctx.now, discovered_by: ctx.agentId } });
}

/** Path only: fragment + query stripped, `//` collapsed, trailing slash trimmed. */
function normalizePath(pathname: string): string {
  let path = pathname.split('#')[0].split('?')[0];
  if (!path.startsWith('/')) path = `/${path}`;
  path = path.replace(/\/{2,}/g, '/');
  if (path.length > 1) path = path.replace(/\/+$/, '') || '/';
  return path || '/';
}

/** Emit an api_endpoint for one crawled absolute URL, under its origin webapp. */
function emitEndpoint(ctx: Ctx, rawUrl: string | undefined, method?: string, status?: number): void {
  if (typeof rawUrl !== 'string') return;
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.length > 2048) return;
  const resolved = resolveWebappOrigin(trimmed);
  if (!resolved) return; // not an http(s) URL we can key a webapp on
  let path: string;
  try { path = normalizePath(new URL(trimmed).pathname); } catch { return; }

  // Scope filter: keep only the crawl's own site (same eTLD+1). A crawl follows
  // off-site links (trackers, CDNs, fonts, historical off-domain gau hits) — those
  // must NOT become webapp nodes. Anchor on source_host, else the first URL seen.
  const apex = apexDomain(resolved.hostname);
  if (ctx.anchorApex === undefined) ctx.anchorApex = apex;
  if (apex !== ctx.anchorApex) return; // off-site — drop

  const waId = webappOriginId(resolved.origin);
  const epId = apiEndpointId(waId, path);
  const newEndpoint = !ctx.seen.has(epId);
  // Enforce the cap BEFORE materializing anything, so a capped URL leaves no
  // stray webapp node and never dangles a HAS_ENDPOINT edge.
  if (newEndpoint && ctx.endpointCount >= MAX_ENDPOINTS) return;

  // Materialize the origin webapp lazily (only now that an endpoint lands on it).
  if (!ctx.seen.has(waId)) {
    ctx.seen.add(waId);
    const wa = { id: waId, type: 'webapp', label: resolved.origin, url: resolved.origin, discovered_at: ctx.now, confidence: 1.0 } as NodeProperties;
    ctx.nodes.push(wa);
    ctx.byId.set(waId, wa);
  }
  if (newEndpoint) {
    ctx.endpointCount += 1;
    ctx.seen.add(epId);
    ctx.nodes.push({
      id: epId,
      type: 'api_endpoint',
      label: path,
      discovered_at: ctx.now,
      confidence: 0.8,
      path,
      ...(method ? { method: method.toUpperCase() } : {}),
      ...(status !== undefined ? { http_status: status } : {}),
    } as NodeProperties);
  }
  addEdge(ctx, waId, epId, 'HAS_ENDPOINT', 0.8);
  const waNode = ctx.byId.get(waId);
  if (waNode) waNode.has_api = true;
}

/** Pull {url, method, status} from a katana `-jsonl` record. */
function fromKatanaJson(obj: Record<string, unknown>): { url?: string; method?: string; status?: number } {
  const req = obj.request && typeof obj.request === 'object' ? obj.request as Record<string, unknown> : undefined;
  const res = obj.response && typeof obj.response === 'object' ? obj.response as Record<string, unknown> : undefined;
  const url = (req && typeof req.endpoint === 'string' ? req.endpoint : undefined)
    ?? (typeof obj.endpoint === 'string' ? obj.endpoint : undefined)
    ?? (typeof obj.url === 'string' ? obj.url : undefined);
  const method = req && typeof req.method === 'string' ? req.method : undefined;
  const sc = res ? res.status_code : obj.status_code;
  const status = typeof sc === 'number' && sc >= 100 && sc <= 599 ? sc : undefined;
  return { url, method, status };
}

export function parseKatana(output: string, agentId: string = 'katana-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx: Ctx = { nodes: [], edges: [], seen: new Set(), byId: new Map(), now, agentId, endpointCount: 0 };
  // Anchor the scope filter on the crawl target when the caller supplies it;
  // otherwise emitEndpoint anchors on the first URL seen.
  const srcHost = typeof context?.source_host === 'string' ? context.source_host : undefined;
  const srcResolved = resolveWebappOrigin(srcHost);
  if (srcResolved) ctx.anchorApex = apexDomain(srcResolved.hostname);
  if (!output || !output.trim()) return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };

  for (const line of output.split('\n')) {
    const l = line.trim();
    if (!l) continue;
    try {
      if (l.startsWith('{')) {
        // katana -jsonl (a bare `[...]` array of records is handled too).
        const obj = JSON.parse(l);
        if (obj && typeof obj === 'object') {
          const { url, method, status } = fromKatanaJson(obj as Record<string, unknown>);
          emitEndpoint(ctx, url, method, status);
        }
      } else if (l.startsWith('[')) {
        const arr = JSON.parse(l);
        if (Array.isArray(arr)) for (const o of arr) if (o && typeof o === 'object') { const r = fromKatanaJson(o as Record<string, unknown>); emitEndpoint(ctx, r.url, r.method, r.status); }
      } else if (/^https?:\/\//i.test(l)) {
        // Plain URL per line (katana plain, hakrawler, gau, waybackurls).
        emitEndpoint(ctx, l);
      }
    } catch { /* skip malformed line */ }
  }
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}
