// ============================================================
// JS / client-side secret + endpoint parsers.
//
// Web recon frequently pulls apart a target's JavaScript bundles for two
// classes of finding:
//   - leaked secrets (API keys, tokens, passwords) — trufflehog + a normalized
//     "SecretFinder-style" shape
//   - reachable endpoints/paths — LinkFinder
//
// A leaked secret becomes a `credential` node (so it flows into credential
// coverage + the spray loop) attached to the source webapp via an
// information-disclosure `vulnerability` + `EXPLOITS` edge (the same shape
// sqlmap uses for dumped creds). A discovered endpoint becomes an
// `api_endpoint` node linked to the source webapp with `HAS_ENDPOINT`.
//
// The source webapp is resolved from a per-record URL when the tool emits one,
// otherwise from parser_context.source_host (the URL the operator scanned).
// Every parser is per-element fault tolerant: one malformed entry is skipped,
// never fatal to the batch. Edges are only ever emitted between nodes this
// finding also emits, so nothing dangles at ingest.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { credentialId, vulnerabilityId, webappOriginId } from '../parser-utils.js';

type Kind = NonNullable<NodeProperties['cred_material_kind']>;

/** trufflehog / SecretFinder detector name → credential material kind. */
function materialKindFor(detector: string | undefined): Kind {
  const d = (detector || '').toLowerCase();
  if (d.includes('ssh') || d.includes('private key') || d.includes('privatekey') || d.includes('rsa private') || d.includes('pem')) return 'ssh_key';
  if (d.includes('github') || d.includes('gitlab')) return 'pat';
  if (d.includes('password')) return 'plaintext_password';
  return 'token';
}

/** cred_type descriptor consistent with the material kind. */
function credTypeFor(kind: Kind): string {
  if (kind === 'plaintext_password') return 'plaintext';
  if (kind === 'ssh_key') return 'ssh_key';
  if (kind === 'pat') return 'pat';
  return 'token';
}

interface Ctx {
  nodes: Finding['nodes'];
  edges: Finding['edges'];
  seen: Set<string>;
  byId: Map<string, NodeProperties>;
  now: string;
  agentId: string;
  context?: ParseContext;
}

function newCtx(now: string, agentId: string, context?: ParseContext): Ctx {
  return { nodes: [], edges: [], seen: new Set(), byId: new Map(), now, agentId, context };
}

/** Push a node once (deterministic id in `seen`) and index it by id for O(1) lookup. */
function pushNode(ctx: Ctx, node: NodeProperties): void {
  ctx.nodes.push(node);
  ctx.byId.set(node.id, node);
}

function addEdge(ctx: Ctx, source: string, target: string, type: string, confidence: number): void {
  const key = `${source}->${target}:${type}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.edges.push({ source, target, properties: { type: type as Finding['edges'][0]['properties']['type'], confidence, discovered_at: ctx.now, discovered_by: ctx.agentId } });
}

/**
 * Resolve + emit (once) the source webapp node; returns its id, origin, and
 * hostname. An explicit http(s) URL is used as-is; a non-http scheme (ftp:, ssh:,
 * file:, mailto:, javascript:, data:, …) is rejected rather than mangled into
 * a fabricated https origin. A schemeless value — including a bare `host:port`,
 * which `new URL` would otherwise misparse as a scheme — is treated as an
 * authority and given https://.
 */
function ensureWebapp(ctx: Ctx, recordUrl: string | undefined): { id: string; origin: string; hostname: string } | undefined {
  const raw = recordUrl || (typeof ctx.context?.source_host === 'string' ? ctx.context.source_host : undefined);
  if (!raw || typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  let candidate: string;
  if (/^https?:\/\//i.test(trimmed)) {
    candidate = trimmed;
  } else {
    // A leading `token:` may be a real scheme (reject) OR a `host:port`
    // authority (`app.acme.com:8080`, `localhost:8080`). Real URL schemes have
    // no dots, so a dotted "scheme" or a numeric remainder (a port) means it is
    // actually an authority — otherwise it is a non-http scheme we reject.
    const m = trimmed.match(/^([a-z][a-z0-9+.-]*):(.*)$/i);
    if (m) {
      const isAuthority = m[1].includes('.') || /^\d+([/?#]|$)/.test(m[2]);
      if (!isAuthority) return undefined;
    }
    candidate = `https://${trimmed}`;
  }
  let u: URL;
  try { u = new URL(candidate); } catch { return undefined; }
  if (!/^https?:$/.test(u.protocol) || !u.host) return undefined;
  const origin = `${u.protocol}//${u.host}`;
  const id = webappOriginId(origin);
  if (!ctx.seen.has(id)) {
    ctx.seen.add(id);
    pushNode(ctx, { id, type: 'webapp', label: origin, url: origin, discovered_at: ctx.now, confidence: 1.0 } as NodeProperties);
  }
  return { id, origin, hostname: u.hostname };
}

/** Emit a leaked-secret credential (+ source-webapp vuln/EXPLOITS when known). */
function emitSecret(ctx: Ctx, value: string | undefined, detector: string | undefined, verified: boolean, recordUrl: string | undefined): void {
  if (typeof value !== 'string' || !value.trim()) return;
  const secret = value.trim();
  const kind = materialKindFor(detector);
  const cId = credentialId(kind, secret);
  if (!ctx.seen.has(cId)) {
    ctx.seen.add(cId);
    pushNode(ctx, {
      id: cId,
      type: 'credential',
      label: `${detector || 'secret'} (leaked in JS)`,
      discovered_at: ctx.now,
      confidence: verified ? 0.95 : 0.6,
      cred_material_kind: kind,
      cred_type: credTypeFor(kind),
      cred_value: secret,
      cred_evidence_kind: 'dump',
      // Only a live-verified secret is treated as usable — an unverified regex
      // hit is often a false positive and shouldn't drive the spray loop.
      cred_usable_for_auth: verified === true,
      ...(detector ? { notes: `detector:${detector}` } : {}),
    } as NodeProperties);
  } else if (verified) {
    // Upgrade a previously-seen unverified hit for the same secret to usable.
    const existing = ctx.byId.get(cId);
    if (existing && existing.cred_usable_for_auth !== true) {
      existing.cred_usable_for_auth = true;
      existing.confidence = 0.95;
    }
  }

  const wa = ensureWebapp(ctx, recordUrl);
  if (wa) {
    const vId = vulnerabilityId(`js-secret-${detector || 'generic'}`, wa.id);
    if (!ctx.seen.has(vId)) {
      ctx.seen.add(vId);
      pushNode(ctx, {
        id: vId,
        type: 'vulnerability',
        label: `Hardcoded secret in client-side JS${detector ? ` (${detector})` : ''}`,
        discovered_at: ctx.now,
        confidence: 0.8,
        vuln_type: 'hardcoded_secret',
        exploitable: verified === true,
      } as NodeProperties);
    } else if (verified) {
      // A later verified hit upgrades the already-emitted vuln to exploitable.
      const existingVuln = ctx.byId.get(vId);
      if (existingVuln && existingVuln.exploitable !== true) existingVuln.exploitable = true;
    }
    addEdge(ctx, wa.id, vId, 'VULNERABLE_TO', 0.8);
    addEdge(ctx, vId, cId, 'EXPLOITS', 0.8);
  }
}

function apiEndpointId(waId: string | undefined, path: string): string {
  const digest = createHash('sha1').update(`${waId || ''}|${path}`).digest('hex').slice(0, 12);
  return `apiendpoint-${digest}`;
}

/** Path-only, canonical form: drop query + fragment, collapse duplicate + trailing slashes. */
function normalizePath(p: string): string | undefined {
  // Collapse duplicate slashes EXCEPT after a colon, so an embedded absolute
  // URL in the path (`/proxy/https://x/y`) keeps its `://` intact.
  let path = p.split('#')[0].split('?')[0].replace(/([^:])\/{2,}/g, '$1/').replace(/^\/{2,}/, '/');
  if (path.length > 1) path = path.replace(/\/+$/, '') || '/';
  return path && path !== '/' ? path : undefined;
}

/**
 * Emit a discovered endpoint (+ HAS_ENDPOINT + has_api when the webapp is
 * known). When a source webapp is known, the raw item is resolved against its
 * origin (`new URL(item, origin)`), which handles absolute, protocol-relative,
 * root-relative, and dir-relative forms uniformly; only SAME-HOST links are
 * kept (off-origin CDNs/third parties are dropped), reduced to a normalized
 * path so `/a`, `/a/`, `/a?x=1`, `/a#f`, and `api/a` collapse to one node.
 */
function emitEndpoint(ctx: Ctx, rawPath: string | undefined, method: string | undefined, recordUrl: string | undefined): void {
  if (typeof rawPath !== 'string') return;
  const trimmed = rawPath.trim();
  if (!trimmed || trimmed.length > 2048) return;
  const wa = ensureWebapp(ctx, recordUrl);

  let norm: string | undefined;
  if (wa) {
    let u: URL;
    try { u = new URL(trimmed, wa.origin); } catch { return; }
    // Compare by hostname (ignoring port representation) — a same-host bundle
    // ref hardcoded to the canonical/no-port URL is still this app's endpoint.
    if (u.hostname !== wa.hostname) return; // off-origin — not this app's endpoint
    norm = normalizePath(u.pathname);
  } else {
    // No webapp to resolve against — keep only clearly root-relative paths.
    if (!trimmed.startsWith('/') || trimmed.startsWith('//')) return;
    norm = normalizePath(trimmed);
  }
  if (!norm) return;

  const epId = apiEndpointId(wa?.id, norm);
  if (!ctx.seen.has(epId)) {
    ctx.seen.add(epId);
    pushNode(ctx, {
      id: epId,
      type: 'api_endpoint',
      label: norm,
      discovered_at: ctx.now,
      confidence: 0.7,
      path: norm,
      ...(method ? { method: method.toUpperCase() } : {}),
    } as NodeProperties);
  }
  if (wa) {
    addEdge(ctx, wa.id, epId, 'HAS_ENDPOINT', 0.7);
    const waNode = ctx.byId.get(wa.id);
    if (waNode) waNode.has_api = true;
  }
}

/** Parse a single JSON document (array/object) if possible; else JSON-lines. */
function eachRecord(output: string, onObject: (obj: Record<string, unknown>) => void): void {
  const trimmed = output.trim();
  if (!trimmed) return;
  try {
    const doc = JSON.parse(trimmed);
    if (Array.isArray(doc)) { for (const r of doc) if (r && typeof r === 'object') onObject(r as Record<string, unknown>); return; }
    if (doc && typeof doc === 'object') { onObject(doc as Record<string, unknown>); return; }
    return;
  } catch { /* JSON-lines */ }
  for (const line of trimmed.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    try {
      const obj = JSON.parse(t);
      if (obj && typeof obj === 'object') onObject(obj as Record<string, unknown>);
    } catch { /* skip malformed line */ }
  }
}

// --- trufflehog v3 (JSON-lines: {DetectorName, Verified, Raw, RawV2, Redacted, SourceMetadata}) ---
export function parseTrufflehog(output: string, agentId: string = 'trufflehog-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx = newCtx(now, agentId, context);
  eachRecord(output, rec => {
    try {
      const detector = typeof rec.DetectorName === 'string' ? rec.DetectorName : (typeof rec.detector_name === 'string' ? rec.detector_name : undefined);
      // `Raw` is the detected secret; `RawV2` is a composite form for some
      // detectors. `Redacted` is a MASKED display string — never a usable
      // secret — so it is deliberately excluded from cred_value.
      const value = [rec.Raw, rec.RawV2].find((v): v is string => typeof v === 'string' && v.length > 0);
      emitSecret(ctx, value, detector, rec.Verified === true, undefined);
    } catch { /* per-element fault tolerance */ }
  });
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}

// --- Normalized JS-secrets JSON (SecretFinder-style / jq-mapped): ---
//     {url, results:[{name, matches:[]}]} | [{name, matches}] | {url, results:{name:[..]}}
// SecretFinder itself has no native JSON mode (HTML / cli text), so this
// consumes a normalized shape the operator maps its output into (or ingest_json).
export function parseSecretfinder(output: string, agentId: string = 'secretfinder-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx = newCtx(now, agentId, context);
  const handleEntry = (entry: unknown, url: string | undefined) => {
    if (!entry || typeof entry !== 'object') return;
    const e = entry as Record<string, unknown>;
    const name = typeof e.name === 'string' ? e.name : (typeof e.type === 'string' ? e.type : undefined);
    const matches: string[] = Array.isArray(e.matches)
      ? e.matches.filter((m): m is string => typeof m === 'string')
      : (typeof e.match === 'string' ? [e.match] : (typeof e.value === 'string' ? [e.value] : []));
    for (const m of matches) emitSecret(ctx, m, name, false, url);
  };
  const handleObject = (obj: Record<string, unknown>) => {
    try {
      const url = typeof obj.url === 'string' ? obj.url : undefined;
      if (Array.isArray(obj.results)) {
        for (const entry of obj.results) handleEntry(entry, url);
      } else if (obj.results && typeof obj.results === 'object') {
        for (const [name, vals] of Object.entries(obj.results as Record<string, unknown>)) {
          const list = Array.isArray(vals) ? vals : [vals];
          for (const v of list) emitSecret(ctx, typeof v === 'string' ? v : undefined, name, false, url);
        }
      } else if (typeof obj.name === 'string' || typeof obj.type === 'string') {
        handleEntry(obj, url);
      }
    } catch { /* per-element fault tolerance */ }
  };
  eachRecord(output, handleObject);
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}

// --- LinkFinder (`-o cli` prints one endpoint per line — the real format;
//     also tolerant of a JSON array / {endpoints:[...]} some wrappers emit) ---
export function parseLinkfinder(output: string, agentId: string = 'linkfinder-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx = newCtx(now, agentId, context);
  const ctxUrl = typeof context?.source_host === 'string' ? context.source_host : undefined;
  const emitFrom = (list: unknown[], recUrl: string | undefined) => {
    for (const item of list) {
      try {
        if (typeof item === 'string') emitEndpoint(ctx, item, undefined, recUrl);
        else if (item && typeof item === 'object') {
          const o = item as Record<string, unknown>;
          const p = typeof o.link === 'string' ? o.link : (typeof o.endpoint === 'string' ? o.endpoint : (typeof o.path === 'string' ? o.path : undefined));
          emitEndpoint(ctx, p, typeof o.method === 'string' ? o.method : undefined, typeof o.url === 'string' ? o.url : recUrl);
        }
      } catch { /* skip */ }
    }
  };
  const trimmed = output.trim();
  let doc: unknown;
  let isJson = false;
  if (trimmed) {
    try { doc = JSON.parse(trimmed); isJson = true; } catch { /* plain text */ }
  }
  if (isJson) {
    // Any valid JSON is handled structurally — never fed to the text line-parser.
    if (Array.isArray(doc)) emitFrom(doc, ctxUrl);
    else if (typeof doc === 'string') emitEndpoint(ctx, doc, undefined, ctxUrl); // a lone quoted endpoint
    else if (doc && typeof doc === 'object') {
      const d = doc as Record<string, unknown>;
      if (Array.isArray(d.endpoints)) emitFrom(d.endpoints, typeof d.url === 'string' ? d.url : ctxUrl);
      else emitFrom([d], ctxUrl); // a single {link|endpoint|path} object
    }
  } else if (trimmed) {
    for (const line of trimmed.split('\n')) {
      const t = line.trim();
      if (t) emitEndpoint(ctx, t, undefined, ctxUrl);
    }
  }
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}
