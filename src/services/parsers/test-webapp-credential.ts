// ============================================================
// test_webapp_credential response parser.
//
// Consumes the curl output from the test_webapp_credential tool and the
// success criteria threaded through parser_context, decides whether the
// credential authenticated, and stamps graph state accordingly:
//
//   - confirmed success  → host → service → webapp chain +
//       AUTHENTICATED_AS (cred → webapp)  ← fires rule-authenticated-rescan
//       VALID_ON (cred → service)         ← retires credential coverage
//   - definitive failure → host → service chain + TESTED_CRED (cred →
//       service), which retires the coverage item WITHOUT claiming validity
//       (so a wrong password doesn't get re-suggested forever, and isn't
//       mistaken for access).
//   - inconclusive (no HTTP response / no trustworthy status) → nothing;
//       the attempt is still recorded by the action lifecycle / evidence.
//
// The parser NEVER re-emits the credential node: doing so with
// cred_usable_for_auth=true but no material would trip
// `credential_material_missing` and get the WHOLE finding rejected, and a
// partial re-emit would shallow-merge over (and clobber) the live
// credential's label / confidence. Validity is carried entirely by the
// edges, whose endpoints resolve against the existing graph.
//
// Status trust: the verdict status comes ONLY from curl's -w marker
// `[OWSTATUS:<code>:<nonce>]`, where <nonce> is a per-call secret the
// target can't predict — so a target can't spoof a success status by
// echoing a fake marker in its (attacker-controlled) response body.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, serviceIdFromUrl, webappOriginId } from '../parser-utils.js';

interface WebCredContext extends ParseContext {
  source_credential_id?: string;
  request_url?: string;
  target_url?: string;
  method?: string;
  cred_user?: string;
  status_nonce?: string;
  success_status?: number[];
  success_body_contains?: string;
  success_body_excludes?: string;
  success_redirect_contains?: string;
}

const STATUS_LINE = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/;
const BLANK_LINE = /\r?\n\r?\n/;

/**
 * Extract the nonce-verified status and the headers + body of the REAL
 * response by walking curl's block structure — NOT by regex-searching for a
 * status code anywhere in the (target-controlled) output. Each block is
 * `status-line CRLF headers CRLF CRLF`; interim 1xx blocks (100 Continue / 103
 * Early Hints) are skipped whole. The status code is read from each block's
 * FIRST line only, so a colon-bearing header line the target plants inside a
 * 1xx block (e.g. `HTTP/1.1 302 Found: forged`) is treated as that block's
 * header, never as a status line. The real response is the first non-1xx block;
 * its body is the full remainder (NOT bounded at an embedded `HTTP/…` line —
 * doing so let a target hide a body_excludes phrase behind such a line, and
 * dropped a legitimate body_contains marker that followed one). The body is
 * target-controlled either way: against a fully hostile target no body/redirect
 * signal is trustworthy, so body checks are only meaningful for honest targets;
 * the nonce (status) and block-structure (headers) are what resist injection.
 *
 * `parsed` is false when we can't isolate a well-formed block (no nonce marker,
 * junk before the real response, or no header terminator) — the caller treats
 * that as inconclusive so a malformed / evasive response can't be scored as a
 * confirmed success.
 */
function extractResponse(output: string, nonce: string | undefined): { status: number; headers: string; body: string; parsed: boolean } {
  let rest = output;
  let status = 0;
  if (nonce) {
    const marker = rest.match(new RegExp(`\\n?\\[OWSTATUS:(\\d{3}):${nonce}\\]\\s*$`));
    if (marker && marker.index !== undefined) {
      status = parseInt(marker[1], 10);
      rest = rest.slice(0, marker.index);
    }
  }
  if (status === 0) return { status, headers: '', body: '', parsed: false };

  let s = rest;
  while (STATUS_LINE.test(s)) {
    const codeMatch = s.match(STATUS_LINE)!;
    const code = parseInt(codeMatch[1], 10);
    const sepMatch = s.match(BLANK_LINE);
    if (!sepMatch || sepMatch.index === undefined) {
      // Header block with no terminator → malformed framing. Inconclusive.
      return { status, headers: '', body: '', parsed: false };
    }
    const headers = s.slice(0, sepMatch.index);
    const afterHeaders = s.slice(sepMatch.index + sepMatch[0].length);
    if (code >= 100 && code < 200) {
      // Interim block — skip it whole and continue to the next block.
      s = afterHeaders;
      continue;
    }
    // Real response — the body is the full remainder (target-controlled).
    return { status, headers, body: afterHeaders, parsed: true };
  }
  // Ran out of blocks without reaching a real response (junk framing).
  return { status, headers: '', body: '', parsed: false };
}

function locationHeader(headers: string): string | undefined {
  const m = headers.match(/^Location:\s*(.+?)\s*$/im);
  return m ? m[1] : undefined;
}

/**
 * Positive test: is this response a CONFIRMED authentication? Confirmation
 * requires an EXPLICIT operator success criterion that matched — there is no
 * method-based default, because every status-only heuristic (form 302, API
 * 200, even Basic 2xx on a path that ignores the header) is target-controlled
 * and can't distinguish real access from a benign / crafted response.
 *
 * Criteria are ANDed. When success_status is given it is the authoritative
 * status gate; the built-in "redirect ⇒ 3xx" / "body ⇒ <400" gates apply only
 * as safety defaults when the operator did NOT constrain the status, so an
 * explicit `success.status` isn't contradicted by them.
 */
function isConfirmedSuccess(ctx: WebCredContext, status: number, headers: string, body: string): boolean {
  const hasStatus = !!ctx.success_status?.length;
  const hasExplicit = hasStatus || !!ctx.success_body_contains || !!ctx.success_redirect_contains;
  if (!hasExplicit) return false;

  if (hasStatus && !ctx.success_status!.includes(status)) return false;
  if (ctx.success_body_contains) {
    const statusOk = hasStatus || status < 400;
    if (!(statusOk && body.includes(ctx.success_body_contains))) return false;
  }
  if (ctx.success_redirect_contains) {
    const statusOk = hasStatus || (status >= 300 && status < 400);
    const loc = locationHeader(headers);
    if (!(statusOk && loc && loc.includes(ctx.success_redirect_contains))) return false;
  }
  return true;
}

/**
 * Three-way verdict. A confirmed failure retires coverage (TESTED_CRED); an
 * inconclusive result leaves the pair on the frontier to retry with a better
 * criterion.
 */
function classify(ctx: WebCredContext, status: number, headers: string, body: string, parsed: boolean): 'success' | 'failure' | 'inconclusive' {
  if (status === 0) return 'inconclusive'; // no trustworthy status
  if (status === 401 || status === 403) return 'failure'; // auth rejected — body-independent
  if (!parsed) return 'inconclusive'; // malformed framing → can't trust header/body
  if (ctx.success_body_excludes && body.includes(ctx.success_body_excludes)) return 'failure';
  if (isConfirmedSuccess(ctx, status, headers, body)) return 'success';
  const hadExplicit = !!(ctx.success_status?.length || ctx.success_body_contains || ctx.success_redirect_contains);
  if (hadExplicit) return 'failure'; // operator defined success; it wasn't met
  // No criteria + a non-401/403 status → we can't tell. Leave it on the
  // frontier to retry with a success criterion rather than guessing.
  return 'inconclusive';
}

/** Minimal host → service (→ webapp) chain so the emitted edges have endpoints. */
function emitChain(originUrl: string, withWebapp: boolean, now: string): { nodes: NodeProperties[]; edges: Finding['edges']; svcId: string; waId: string } {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const waId = webappOriginId(originUrl);
  const svcId = serviceIdFromUrl(originUrl);
  try {
    const parsed = new URL(originUrl);
    const rawHost = parsed.hostname.replace(/^\[|\]$/g, '');
    const port = parseInt(parsed.port, 10) || (parsed.protocol === 'https:' ? 443 : 80);
    const proto = parsed.protocol === 'https:' ? 'https' : 'http';
    // Origin (scheme + host [+ port]) with the path stripped, so the webapp
    // node converges with httpx/nuclei/wpscan rather than splitting per path.
    const origin = `${parsed.protocol}//${parsed.host}`;
    const hId = hostId(rawHost);
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(rawHost) || rawHost.includes(':');
    nodes.push({ id: hId, type: 'host', label: rawHost, discovered_at: now, confidence: 1.0, ...(isIp ? { ip: rawHost } : { hostname: rawHost }) } as NodeProperties);
    nodes.push({ id: svcId, type: 'service', label: `${proto}/${port}`, discovered_at: now, confidence: 1.0, port, protocol: 'tcp', service_name: proto } as NodeProperties);
    edges.push({ source: hId, target: svcId, properties: { type: 'RUNS' as EdgeType, confidence: 1.0, discovered_at: now } });
    if (withWebapp) {
      nodes.push({ id: waId, type: 'webapp', label: origin, url: origin, discovered_at: now, confidence: 1.0 } as NodeProperties);
      edges.push({ source: svcId, target: waId, properties: { type: 'HOSTS' as EdgeType, confidence: 1.0, discovered_at: now } });
    }
  } catch {
    if (withWebapp) {
      nodes.push({ id: waId, type: 'webapp', label: originUrl, url: originUrl, discovered_at: now, confidence: 1.0 } as NodeProperties);
    }
  }
  return { nodes, edges, svcId, waId };
}

export function parseTestWebappCredential(output: string, agentId: string = 'webcred-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as WebCredContext;
  const credId = ctx.source_credential_id;
  const originUrl = ctx.request_url ?? ctx.target_url;

  if (!credId || !originUrl) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const { status, headers, body, parsed } = extractResponse(output, ctx.status_nonce);
  const verdict = classify(ctx, status, headers, body, parsed);

  if (verdict === 'inconclusive') {
    // Unreachable / curl killed / ambiguous status with no criteria. Emit
    // nothing so coverage isn't retired and the pair can be retried.
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  if (verdict === 'success') {
    const { nodes, edges, svcId, waId } = emitChain(originUrl, true, now);
    edges.push({ source: credId, target: waId, properties: { type: 'AUTHENTICATED_AS' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId, notes: `authenticated via ${ctx.method ?? 'web'} credential test (HTTP ${status})` } });
    edges.push({ source: credId, target: svcId, properties: { type: 'VALID_ON' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId } });
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Confirmed failure — record TESTED_CRED so the frontier stops re-suggesting
  // the pair, without claiming any validity. No webapp node: the credential
  // did not authenticate to it.
  const { nodes, edges, svcId } = emitChain(originUrl, false, now);
  edges.push({ source: credId, target: svcId, properties: { type: 'TESTED_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId, notes: `web credential test not authenticated (HTTP ${status})` } });
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
