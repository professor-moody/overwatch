// ============================================================
// CORS + HTTP security-header analysis.
//
// Ingests a target's HTTP response headers — captured however the operator has
// them (raw `curl -sI` / `curl -sD -` text, an httpx `-json -irh` line, or a
// plain `{url, headers}` object/array) — and surfaces two hardening gaps as
// `vulnerability` nodes on the source webapp:
//
//   - `cors_misconfig` (CWE-942): a permissive `Access-Control-Allow-Origin`
//     (wildcard `*` or `null`), escalated when `Access-Control-Allow-Credentials`
//     is also `true`.
//   - `missing_security_header` (CWE-16): absent or ineffective baseline response
//     headers (HSTS on https, CSP, X-Frame-Options unless a restrictive CSP
//     frame-ancestors covers it, X-Content-Type-Options `nosniff`, Referrer-Policy).
//
// The source webapp is resolved from each target's own URL when present, else
// from parser_context.source_host (the only source for raw `curl -I` text, which
// carries no URL). The webapp node is materialized lazily — a fully-hardened
// target with no findings produces no node, so a clean scan leaves no trace.
// Parsing is per-target fault tolerant.
//
// Scope / limitations (so the operator isn't misled):
//   - Detection is STATIC — one captured response, not a reflected-Origin probe.
//     So nothing is marked `exploitable`, and an ACAO that REFLECTS an arbitrary
//     request Origin (the highest-impact CORS bug, especially with credentials)
//     is NOT detected here — only literal `*`/`null`. Confirm reflection with a
//     probe request.
//   - Missing-header detection is presence + basic effectiveness (empty value,
//     wrong X-Content-Type-Options, non-DENY/SAMEORIGIN XFO, permissive CSP
//     frame-ancestors). Deeper value strength (HSTS max-age, full CSP policy
//     analysis) is out of scope.
//   - Feed the FINAL page's headers (a 2xx). Headers scraped from a 401/403/5xx
//     or a redirect stub are analyzed as-is — status is not validated.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { resolveWebappOrigin, vulnerabilityId, webappOriginId } from '../parser-utils.js';

interface Ctx {
  nodes: Finding['nodes'];
  edges: Finding['edges'];
  seen: Set<string>;
  now: string;
  agentId: string;
}

function emptyFinding(agentId: string, now: string): Finding {
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
}

/** Lowercase-keyed header map. A repeated header keeps its first value; array
 * values (from JSON header maps) are joined so `analyze` sees one string. */
function lowerHeaders(raw: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    const key = k.trim().toLowerCase();
    if (!key || key in out) continue; // first occurrence wins
    const val = Array.isArray(v) ? v.filter(x => typeof x === 'string').join(', ') : v;
    if (typeof val === 'string') out[key] = val.trim();
    else if (typeof val === 'number' || typeof val === 'boolean') out[key] = String(val);
  }
  return out;
}

/** Parse a raw HTTP response-header block. Across a redirect chain (several
 * `HTTP/x` status lines) ONLY the final response block is returned — it
 * describes the final page; a header set on an intermediate 301 but absent on
 * the final 200 must not count as present. Supports obs-fold continuation lines. */
function parseRawHeaderText(text: string): Record<string, string> {
  let cur: Record<string, string> = {};
  const blocks: Record<string, string>[] = [];
  let lastKey: string | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\r$/, '');
    if (/^HTTP\/\d/i.test(line)) {
      // New response block begins — reset so ONLY the final block survives.
      cur = {};
      lastKey = null;
      blocks.push(cur);
      continue;
    }
    // obs-fold: a line starting with SP/HTAB continues the previous header value
    // (RFC 7230 §3.2.4). Must be checked BEFORE the colon split — a folded CSP
    // `\tframe-ancestors 'none'` has no colon and would otherwise be dropped.
    if (lastKey && /^[ \t]/.test(line) && line.trim()) {
      cur[lastKey] += ' ' + line.trim();
      continue;
    }
    const idx = line.indexOf(':');
    if (idx <= 0) continue; // blank line or non-header
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (!key) continue;
    // No `HTTP/x` status line yet (a bare header dump) — open an implicit block.
    if (!blocks.length) blocks.push(cur);
    if (!(key in cur)) cur[key] = val;
    lastKey = key;
  }
  // Only the FINAL response block describes the final page (after redirects).
  // Earlier blocks are discarded — a header set on a 301 but absent on the 200
  // must NOT count as present.
  return blocks.length ? blocks[blocks.length - 1] : cur;
}

/** A CSP `frame-ancestors` directive supersedes X-Frame-Options — but only when
 * it is RESTRICTIVE. A permissive `frame-ancestors *` (or an empty directive)
 * provides no clickjacking protection and must not exempt XFO. */
function hasRestrictiveFrameAncestors(csp: string | undefined): boolean {
  if (!csp) return false;
  // Anchor the directive: it starts a policy or follows a `;`, and the negative
  // lookahead stops `frame-ancestorsX` (a typo/unknown directive) from matching.
  const m = csp.match(/(?:^|;)\s*frame-ancestors(?![\w-])([^;]*)/i);
  if (!m) return false;
  const sources = m[1].trim();
  if (!sources) return false; // `frame-ancestors;` with no source list → no protection
  // A bare `*` source allows any origin to frame the page → permissive.
  return !/(^|\s)\*(\s|$)/.test(sources);
}

/** Analyze one target's headers, emitting cors_misconfig / missing_security_header. */
function analyze(ctx: Ctx, origin: string, hostname: string, isHttps: boolean, headers: Record<string, string>): void {
  const waId = webappOriginId(origin);
  let materialized = false;
  const ensureWebapp = (): void => {
    if (materialized || ctx.seen.has(waId)) { materialized = true; return; }
    ctx.seen.add(waId);
    materialized = true;
    ctx.nodes.push({ id: waId, type: 'webapp', label: origin, url: origin, discovered_at: ctx.now, confidence: 1.0 } as NodeProperties);
  };
  const emitVuln = (vulnType: string, cvss: number, component: string, extra: Record<string, unknown>): void => {
    ensureWebapp();
    const vId = vulnerabilityId(vulnType, waId);
    if (!ctx.seen.has(vId)) {
      ctx.seen.add(vId);
      ctx.nodes.push({
        id: vId,
        type: 'vulnerability',
        label: `${vulnType} on ${hostname}`,
        discovered_at: ctx.now,
        confidence: 0.9,
        vuln_type: vulnType,
        cvss,
        exploitable: false,
        affected_component: component,
        ...extra,
      } as NodeProperties);
    }
    const edgeKey = `${waId}->${vId}:VULNERABLE_TO`;
    if (!ctx.seen.has(edgeKey)) {
      ctx.seen.add(edgeKey);
      ctx.edges.push({ source: waId, target: vId, properties: { type: 'VULNERABLE_TO', confidence: 0.9, discovered_at: ctx.now, discovered_by: ctx.agentId } });
    }
  };

  // --- CORS ---
  const acao = headers['access-control-allow-origin'];
  if (acao !== undefined) {
    const val = acao.trim().toLowerCase();
    const permissive = val === '*' || val === 'null';
    if (permissive) {
      const credentials = (headers['access-control-allow-credentials'] || '').trim().toLowerCase() === 'true';
      // Wildcard+credentials is browser-blocked (not directly exploitable) but is
      // a clear server misconfig; `null` is reflectable from sandboxed contexts.
      const cvss = credentials ? 6.1 : (val === 'null' ? 5.3 : 4.3);
      emitVuln('cors_misconfig', cvss, `Access-Control-Allow-Origin: ${acao.trim()}`, {
        cors_allow_origin: acao.trim(),
        cors_allow_credentials: credentials,
      });
    }
  }

  // --- Missing security headers ---
  // A header that is PRESENT but empty/whitespace (or carries an ineffective
  // value) gives no protection — treat it as missing. `val()` returns the
  // trimmed value only when non-empty.
  const val = (h: string): string | undefined => {
    const v = headers[h];
    const t = typeof v === 'string' ? v.trim() : '';
    return t ? t : undefined;
  };
  const missing: string[] = [];
  // HSTS — only meaningful over https (browsers ignore it on http).
  if (isHttps && !val('strict-transport-security')) missing.push('Strict-Transport-Security');
  // CSP — any non-empty policy (policy-strength analysis is out of scope).
  const csp = val('content-security-policy');
  if (!csp) missing.push('Content-Security-Policy');
  // X-Content-Type-Options — only `nosniff` is effective.
  const xcto = val('x-content-type-options');
  if (!xcto || xcto.toLowerCase() !== 'nosniff') missing.push('X-Content-Type-Options');
  // X-Frame-Options — only DENY/SAMEORIGIN are effective (ALLOW-FROM is dead);
  // a restrictive CSP `frame-ancestors` supersedes it.
  const xfo = val('x-frame-options');
  const xfoEffective = !!xfo && ['deny', 'sameorigin'].includes(xfo.toLowerCase());
  if (!xfoEffective && !hasRestrictiveFrameAncestors(csp)) missing.push('X-Frame-Options');
  // Referrer-Policy — any non-empty value.
  if (!val('referrer-policy')) missing.push('Referrer-Policy');
  if (missing.length) {
    emitVuln('missing_security_header', 3.1, `Missing: ${missing.join(', ')}`, { missing_security_headers: missing });
  }
}

/** Extract {url, headers} pairs from a parsed JSON value (object, array, or an
 * httpx-style line with a raw `header`/`raw_header` string). Returns [] if the
 * shape isn't recognized. */
function pairsFromJson(value: unknown): Array<{ url?: string; headers: Record<string, string> }> {
  const items = Array.isArray(value) ? value : [value];
  const out: Array<{ url?: string; headers: Record<string, string> }> = [];
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    const o = item as Record<string, unknown>;
    const url = typeof o.url === 'string' ? o.url : undefined;
    let headers: Record<string, string> | undefined;
    if (o.headers && typeof o.headers === 'object' && !Array.isArray(o.headers)) {
      headers = lowerHeaders(o.headers as Record<string, unknown>);
    } else if (o.header && typeof o.header === 'object' && !Array.isArray(o.header)) {
      headers = lowerHeaders(o.header as Record<string, unknown>);
    } else if (typeof o.raw_header === 'string') {
      headers = parseRawHeaderText(o.raw_header);
    } else if (typeof o.header === 'string') {
      headers = parseRawHeaderText(o.header);
    }
    if (headers && Object.keys(headers).length) out.push({ url, headers });
  }
  return out;
}

export function parseSecurityHeaders(output: string, agentId: string = 'security-headers-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx: Ctx = { nodes: [], edges: [], seen: new Set(), now, agentId };
  if (!output || !output.trim()) return emptyFinding(agentId, now);

  const ctxOrigin = resolveWebappOrigin(typeof context?.source_host === 'string' ? context.source_host : undefined);

  // Build the list of {origin, headers} targets from whichever input shape we got.
  const targets: Array<{ origin: string; hostname: string; isHttps: boolean; headers: Record<string, string> }> = [];
  const addTarget = (rawUrl: string | undefined, headers: Record<string, string>): void => {
    // Prefer the item's own URL; fall back to source_host. Skip if neither
    // resolves — a vuln node keyed to no webapp would collide across targets.
    const resolved = resolveWebappOrigin(rawUrl) || ctxOrigin;
    if (!resolved) return;
    targets.push({ origin: resolved.origin, hostname: resolved.hostname, isHttps: resolved.origin.startsWith('https:'), headers });
  };

  const trimmed = output.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    // Try the whole body as a single JSON value (object or array) first.
    let ok = false; let parsed: unknown;
    try { parsed = JSON.parse(trimmed); ok = true; } catch { ok = false; }
    if (ok) for (const p of pairsFromJson(parsed)) { try { addTarget(p.url, p.headers); } catch { /* skip */ } }
    // JSON-lines (httpx `-json`): the whole body isn't valid JSON, or it parsed
    // but yielded no target. Retry line-by-line when nothing landed.
    if (targets.length === 0 && trimmed.includes('\n')) {
      for (const line of trimmed.split(/\r?\n/)) {
        const l = line.trim();
        if (!l.startsWith('{')) continue;
        try { for (const p of pairsFromJson(JSON.parse(l))) addTarget(p.url, p.headers); } catch { /* skip line */ }
      }
    }
  } else {
    // Raw `curl -I` / `curl -sD -` header text — origin only from source_host.
    const headers = parseRawHeaderText(trimmed);
    if (Object.keys(headers).length) addTarget(undefined, headers);
  }

  for (const t of targets) {
    try { analyze(ctx, t.origin, t.hostname, t.isHttps, t.headers); } catch { /* skip target */ }
  }
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}
