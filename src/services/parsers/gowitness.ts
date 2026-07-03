// ============================================================
// Screenshot ingestion: gowitness / aquatone.
//
// Turns a visual-recon report into graph data — each captured URL becomes a
// `webapp` node (merging with the httpx/nuclei webapp for the same origin) with
// its title, HTTP status, detected technology, and a `screenshot_path` reference
// to the image on disk, plus the backing host → RUNS → service → HOSTS → webapp
// chain (as httpx does) so the target participates in scope + service coverage.
//
// Scope: this is a PARSER — it only sees the report's text, so it records the
// screenshot's PATH, not its bytes. Ingesting the image itself (viewable in the
// dashboard) is a separate concern (a tool that reads the file into the evidence
// store), intentionally out of scope here.
//
// Handles the format drift across tools/versions defensively:
//   - gowitness v3 JSON-lines / array: {url, final_url, response_code, title,
//     file_name, failed, technologies:[{value}|string]}
//   - gowitness v2: {URL, FinalURL, ResponseCode, Title, Filename}
//   - aquatone session.json: {pages: {<id>: {url, hostname, status ("200 OK"),
//     pageTitle, screenshotPath, ...}}}
// The node is keyed on the SCANNED url (converging with httpx/nuclei); the
// post-redirect final_url and a `failed:true` skip are handled. `response_code`
// is the HTTP status, with `0` treated as a no-response sentinel. Per-entry
// fault tolerant.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, serviceIdFromUrl, webappOriginId } from '../parser-utils.js';

type Rec = Record<string, unknown>;

/** First defined string among candidate keys (case-sensitive keys, tried in order). */
function pickString(r: Rec, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return undefined;
}

/** HTTP status code from any candidate key. Accepts a bare number, and a string
 * that STARTS with a 3-digit code (aquatone stores the full status line, e.g.
 * "200 OK"). gowitness uses `response_code: 0` as a no-response sentinel, so only
 * a valid 1xx–5xx code is accepted. */
function pickStatus(r: Rec, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'number' && v >= 100 && v <= 599) return v;
    if (typeof v === 'string') {
      const m = v.trim().match(/^(\d{3})\b/);
      if (m) { const n = parseInt(m[1], 10); if (n >= 100 && n <= 599) return n; }
    }
  }
  return undefined;
}

/** Technology list from `technologies`/`tech`/`Technologies` — strings or
 * objects with a `.value`/`.name`/`.app` field (Wappalyzer-style). */
function pickTech(r: Rec): string | undefined {
  const raw = r.technologies ?? r.tech ?? r.Technologies;
  if (!Array.isArray(raw)) return undefined;
  const names: string[] = [];
  for (const t of raw) {
    if (typeof t === 'string' && t.trim()) names.push(t.trim());
    else if (t && typeof t === 'object') {
      const o = t as Rec;
      const name = pickString(o, ['value', 'name', 'app']);
      if (name) names.push(name);
    }
  }
  const uniq = [...new Set(names)];
  return uniq.length ? uniq.join(', ') : undefined;
}

/** Flatten whatever top-level JSON shape into a flat list of per-URL entries. */
function entriesFrom(parsed: unknown): Rec[] {
  if (Array.isArray(parsed)) return parsed.filter((e): e is Rec => !!e && typeof e === 'object');
  if (!parsed || typeof parsed !== 'object') return [];
  const o = parsed as Rec;
  // aquatone session.json: pages is an object keyed by id (or, defensively, an array).
  if (o.pages && typeof o.pages === 'object') {
    const pages = o.pages;
    const vals = Array.isArray(pages) ? pages : Object.values(pages as Rec);
    return vals.filter((e): e is Rec => !!e && typeof e === 'object');
  }
  // gowitness wrappers.
  for (const key of ['results', 'urls', 'data', 'entries']) {
    if (Array.isArray(o[key])) return (o[key] as unknown[]).filter((e): e is Rec => !!e && typeof e === 'object');
  }
  // A single entry object.
  if (pickString(o, ['url', 'URL', 'final_url', 'FinalURL'])) return [o];
  return [];
}

export function parseGowitness(output: string, agentId: string = 'gowitness-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seen = new Set<string>();
  const now = new Date().toISOString();

  // Collect entries from whichever shape we got: a single JSON value (object /
  // array / aquatone container), else JSON-lines (gowitness `--write-jsonl`).
  const entries: Rec[] = [];
  const trimmedAll = output.trim();
  let wholeParsed = false;
  if (trimmedAll.startsWith('{') || trimmedAll.startsWith('[')) {
    try { entries.push(...entriesFrom(JSON.parse(trimmedAll))); wholeParsed = true; } catch { wholeParsed = false; }
  }
  if (!wholeParsed || (entries.length === 0 && trimmedAll.includes('\n'))) {
    for (const line of output.split('\n')) {
      const l = line.trim();
      if (!l.startsWith('{')) continue;
      try { entries.push(...entriesFrom(JSON.parse(l))); } catch { /* skip line */ }
    }
  }

  const waById = new Map<string, NodeProperties>();
  for (const rec of entries) {
    try {
      // Skip a capture that failed to load — gowitness v3 flags these with
      // `failed:true`; turning an unreachable URL into a live webapp+service
      // chain would be misleading.
      if (rec.failed === true) continue;

      // Key on the SCANNED url (not the post-redirect final_url) so the node +
      // host/service chain converge on the SAME origin httpx/nuclei used. The
      // redirect target is recorded as a property, not a separate node.
      const rawUrl = pickString(rec, ['url', 'URL', 'final_url', 'FinalURL']);
      if (!rawUrl) continue;
      const id = webappOriginId(rawUrl);
      // Parse once — the node's `url` is the ORIGIN (path stripped, matching the
      // origin-level id); a malformed url still yields a bare webapp, no chain.
      let parsed: URL | null = null;
      try { parsed = new URL(rawUrl); } catch { parsed = null; }
      const originUrl = parsed ? parsed.origin : rawUrl;

      const title = pickString(rec, ['title', 'Title', 'pageTitle']);
      const status = pickStatus(rec, ['response_code', 'ResponseCode', 'status', 'status_code']);
      const technology = pickTech(rec);
      // gowitness v3 emits the screenshot under `file_name`; v2 used `Filename`;
      // aquatone uses `screenshotPath`. Accept every known variant.
      const screenshot = pickString(rec, ['file_name', 'filename', 'Filename', 'FileName', 'screenshotPath', 'screenshot_path', 'path']);
      const finalUrl = pickString(rec, ['final_url', 'FinalURL']);

      // A report lists one entry per captured URL, but webappOriginId collapses
      // paths — so several entries can share one origin. Merge (fill-if-missing)
      // rather than dropping the later ones. First non-empty value per field wins;
      // the first capture's screenshot is kept.
      const existing = waById.get(id);
      if (existing) {
        if (!existing.technology && technology) existing.technology = technology;
        if (existing.http_status === undefined && status !== undefined) existing.http_status = status;
        if (!existing.title && title) { existing.title = title; if (existing.label === existing.url) existing.label = title; }
        if (!existing.screenshot_path && screenshot) existing.screenshot_path = screenshot;
        if (!existing.final_url && finalUrl && finalUrl !== rawUrl) existing.final_url = finalUrl;
        continue; // host/service chain for this origin already built
      }

      const waNode = {
        id, type: 'webapp', label: title || originUrl,
        url: originUrl, discovered_at: now, confidence: 1.0,
        ...(technology ? { technology } : {}),
        ...(status !== undefined ? { http_status: status } : {}),
        ...(title ? { title } : {}),
        ...(screenshot ? { screenshot_path: screenshot } : {}),
        ...(finalUrl && finalUrl !== rawUrl ? { final_url: finalUrl } : {}),
      } as NodeProperties;
      waById.set(id, waNode);
      nodes.push(waNode);
      seen.add(id);

      // Backing host → service chain (shared ids so gowitness converges with
      // httpx/nuclei on one webapp + service node per origin). Skip if the url
      // didn't parse (bare webapp already emitted).
      if (!parsed) continue;
      const port = parseInt(parsed.port, 10) || (parsed.protocol === 'https:' ? 443 : 80);
      const proto = parsed.protocol === 'https:' ? 'https' : 'http';
      const svcId = serviceIdFromUrl(rawUrl);
      if (!seen.has(svcId)) {
        seen.add(svcId);
        nodes.push({
          id: svcId, type: 'service', label: `${proto}/${port}`,
          discovered_at: now, confidence: 1.0,
          port, protocol: 'tcp', service_name: proto,
        } as NodeProperties);
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
        } as NodeProperties);
      }
      const runsKey = `${hId}->${svcId}:RUNS`;
      if (!seen.has(runsKey)) {
        seen.add(runsKey);
        edges.push({ source: hId, target: svcId, properties: { type: 'RUNS', confidence: 1.0, discovered_at: now } });
      }
      const hostsKey = `${svcId}->${id}:HOSTS`;
      if (!seen.has(hostsKey)) {
        seen.add(hostsKey);
        edges.push({ source: svcId, target: id, properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now } });
      }
    } catch { /* malformed entry / url — skip (webapp node, if any, already emitted) */ }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
