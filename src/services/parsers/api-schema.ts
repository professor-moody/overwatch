// ============================================================
// API-schema enumeration: OpenAPI/Swagger + GraphQL introspection.
//
// Populates the (previously-dead) `api_endpoint` node from a target's own API
// description:
//   - OpenAPI 3 / Swagger 2 JSON → one api_endpoint per path × method, with
//     `method`, `auth_required` (from global/per-operation `security`), and
//     `response_type` (from response content-types / `produces`).
//   - GraphQL introspection JSON → one api_endpoint per query/mutation field
//     (POST to the GraphQL path). Subscriptions are WebSocket, not modeled here.
//
// Each endpoint is linked to the source webapp with `HAS_ENDPOINT` (and sets
// `has_api` on the webapp). The source webapp is resolved from the schema's own
// server URL when absolute, otherwise from parser_context.source_host. Parsing
// is per-element fault tolerant and only emits edges between emitted nodes.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { apiEndpointId, resolveWebappOrigin, webappOriginId } from '../parser-utils.js';

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace'];

interface Ctx {
  nodes: Finding['nodes'];
  edges: Finding['edges'];
  seen: Set<string>;
  byId: Map<string, NodeProperties>;
  now: string;
  agentId: string;
}

function newCtx(now: string, agentId: string): Ctx {
  return { nodes: [], edges: [], seen: new Set(), byId: new Map(), now, agentId };
}
function pushNode(ctx: Ctx, node: NodeProperties): void { ctx.nodes.push(node); ctx.byId.set(node.id, node); }
function addEdge(ctx: Ctx, source: string, target: string, type: string, confidence: number): void {
  const key = `${source}->${target}:${type}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.edges.push({ source, target, properties: { type: type as Finding['edges'][0]['properties']['type'], confidence, discovered_at: ctx.now, discovered_by: ctx.agentId } });
}

/** Resolve the source webapp id (no node emitted yet — it's materialized lazily
 * on the first endpoint so an empty/subscription-only schema leaves no bare node). */
function resolveWa(rawUrl: string | undefined): { id: string; origin: string } | undefined {
  const r = resolveWebappOrigin(rawUrl);
  if (!r) return undefined;
  return { id: webappOriginId(r.origin), origin: r.origin };
}

interface EndpointAttrs { path: string; method?: string; auth_required?: boolean; response_type?: string; label: string }
function emitEndpoint(ctx: Ctx, wa: { id: string; origin: string } | undefined, key: string, a: EndpointAttrs): void {
  // Endpoints are keyed by their owning webapp; without one, a bare path+method
  // id would collide across DIFFERENT scan targets ingested into one graph. So
  // an endpoint requires a resolvable source webapp (schema server / source_host).
  if (!wa) return;
  // Materialize the webapp node lazily (only now that it actually has an endpoint).
  if (!ctx.seen.has(wa.id)) {
    ctx.seen.add(wa.id);
    pushNode(ctx, { id: wa.id, type: 'webapp', label: wa.origin, url: wa.origin, discovered_at: ctx.now, confidence: 1.0 } as NodeProperties);
  }
  const epId = apiEndpointId(wa.id, key);
  if (!ctx.seen.has(epId)) {
    ctx.seen.add(epId);
    pushNode(ctx, {
      id: epId,
      type: 'api_endpoint',
      label: a.label,
      discovered_at: ctx.now,
      confidence: 0.9,
      path: a.path,
      ...(a.method ? { method: a.method } : {}),
      ...(a.auth_required !== undefined ? { auth_required: a.auth_required } : {}),
      ...(a.response_type ? { response_type: a.response_type } : {}),
    } as NodeProperties);
  }
  addEdge(ctx, wa.id, epId, 'HAS_ENDPOINT', 0.9);
  const waNode = ctx.byId.get(wa.id);
  if (waNode) waNode.has_api = true;
}

/** Join a server basePath with an operation path, single-slash separated + trailing-trimmed. */
function joinPath(basePath: string, path: string): string {
  const b = basePath.replace(/\/+$/, '');
  const p = path.startsWith('/') ? path : `/${path}`;
  let joined = `${b}${p}`.replace(/\/{2,}/g, '/');
  if (joined.length > 1) joined = joined.replace(/\/+$/, '') || '/';
  return joined || '/';
}

/** Substitute OpenAPI-3 server variable defaults into a `{var}` templated url. */
function applyServerVars(url: string, variables: unknown): string {
  if (!variables || typeof variables !== 'object') return url;
  return url.replace(/\{([^}]+)\}/g, (whole, name) => {
    const v = (variables as Record<string, unknown>)[name];
    const def = v && typeof v === 'object' ? (v as Record<string, unknown>).default : undefined;
    return typeof def === 'string' ? def : whole;
  });
}

/** Resolve the server origin URL + basePath from an OpenAPI/Swagger doc. */
function resolveServer(doc: Record<string, unknown>, context?: ParseContext): { serverUrl: string | undefined; basePath: string } {
  const ctxHost = typeof context?.source_host === 'string' ? context.source_host : undefined;
  // Path portion of a server url (drops scheme / authority / query / fragment).
  // Any leftover `{var}` template is replaced with a safe token first so a
  // templated scheme/host (`{protocol}://…`, `https://{host}/v1`) still parses
  // to its real path rather than a percent-encoded blob.
  const serverBasePath = (url: string): string => {
    try { return new URL(url.replace(/\{[^}]*\}/g, 'x'), 'https://x.invalid').pathname.replace(/\/+$/, ''); } catch { return ''; }
  };

  // OpenAPI 3: servers: [{ url, variables }]. There can be several (a doc may
  // list a relative one first), so prefer the first that resolves to an absolute
  // http(s) origin before falling back to context + basePath. Only a REAL
  // Swagger-2 doc (swagger key AND a host) suppresses the servers block, so a
  // hybrid doc carrying a stray `swagger` key without a host still uses servers.
  const isRealSwagger2 = !!doc.swagger && typeof doc.host === 'string';
  const servers = doc.servers;
  if (Array.isArray(servers) && servers.length && !isRealSwagger2) {
    for (const srv of servers) {
      if (!srv || typeof srv !== 'object' || typeof (srv as Record<string, unknown>).url !== 'string') continue;
      const s = srv as Record<string, unknown>;
      const url = applyServerVars(s.url as string, s.variables);
      // A protocol-relative server (`//host/path`) is absolute-but-schemeless →
      // default to https so its host isn't discarded.
      const abs = /^https?:\/\//i.test(url) ? url : (url.startsWith('//') ? `https:${url}` : undefined);
      if (abs && !/[{}]/.test(abs)) {
        try { const u = new URL(abs); return { serverUrl: `${u.protocol}//${u.host}${u.pathname}`, basePath: u.pathname.replace(/\/+$/, '') }; } catch { /* try next */ }
      }
    }
    // No absolute server — take the first server's PATH as basePath, origin from context.
    for (const srv of servers) {
      if (!srv || typeof srv !== 'object' || typeof (srv as Record<string, unknown>).url !== 'string') continue;
      const s = srv as Record<string, unknown>;
      return { serverUrl: ctxHost, basePath: serverBasePath(applyServerVars(s.url as string, s.variables)) };
    }
  }
  // Swagger 2: host + basePath + schemes
  if (typeof doc.host === 'string' || doc.swagger) {
    const schemes = Array.isArray(doc.schemes) ? doc.schemes.filter((x): x is string => typeof x === 'string') : [];
    const scheme = schemes.includes('https') ? 'https' : (schemes[0] || 'https');
    // `host` is a bare authority per the Swagger 2 spec; strip a stray scheme/path
    // so a malformed `host: "https://x/y"` can't produce a garbage origin.
    const rawHost = typeof doc.host === 'string' ? doc.host : undefined;
    const host = rawHost ? rawHost.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/.*$/, '').trim() : undefined;
    const basePath = typeof doc.basePath === 'string' ? doc.basePath.replace(/\/+$/, '') : '';
    return { serverUrl: host ? `${scheme}://${host}` : ctxHost, basePath };
  }
  return { serverUrl: ctxHost, basePath: '' };
}

/** response_type from an operation (OpenAPI-3 response content-types / Swagger-2 produces). */
function responseTypeFor(op: Record<string, unknown>, globalProduces: string[] | undefined): string | undefined {
  const opProduces = Array.isArray(op.produces) ? op.produces.find((x): x is string => typeof x === 'string') : undefined;
  if (opProduces) return opProduces; // Swagger 2
  const responses = op.responses;
  if (responses && typeof responses === 'object') {
    // Only a SUCCESS response (2xx, or `default`) describes the endpoint's
    // response type — never a 4xx/5xx error body's content-type.
    const success = Object.entries(responses as Record<string, unknown>)
      .filter(([code]) => /^2(\d\d|XX)$/i.test(code) || code === 'default') // 2xx code or the 2XX range wildcard
      .sort(([a], [b]) => (/^2/.test(a) ? 0 : 1) - (/^2/.test(b) ? 0 : 1)); // 2xx before default
    for (const [, r] of success) {
      const content = r && typeof r === 'object' ? (r as Record<string, unknown>).content : undefined;
      if (content && typeof content === 'object') {
        const ct = Object.keys(content as Record<string, unknown>)[0];
        if (ct) return ct;
      }
    }
  }
  return globalProduces && globalProduces[0];
}

// --- OpenAPI 3 / Swagger 2 JSON ---
export function parseOpenapi(output: string, agentId: string = 'openapi-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx = newCtx(now, agentId);
  let doc: unknown;
  try { doc = JSON.parse(output); } catch { return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] }; }
  if (!doc || typeof doc !== 'object') return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  const d = doc as Record<string, unknown>;

  const { serverUrl, basePath } = resolveServer(d, context);
  const wa = resolveWa(serverUrl);
  const globalSecurity = Array.isArray(d.security) ? d.security : undefined;
  const globalProduces = Array.isArray(d.produces) ? d.produces.filter((x): x is string => typeof x === 'string') : undefined;

  // NB: path-item / operation-level `servers` overrides are not applied — the
  // root server governs all paths (the common case); per-path overrides are rare.
  const paths = d.paths;
  if (paths && typeof paths === 'object') {
    for (const [rawPath, item] of Object.entries(paths as Record<string, unknown>)) {
      if (!item || typeof item !== 'object' || rawPath.startsWith('x-')) continue;
      const pathItem = item as Record<string, unknown>;
      const fullPath = joinPath(basePath, rawPath);
      for (const method of HTTP_METHODS) {
        const op = pathItem[method];
        if (!op || typeof op !== 'object') continue;
        try {
          const o = op as Record<string, unknown>;
          // Per-operation `security` overrides global. `security: []` is public,
          // and an EMPTY requirement object `{}` anywhere in the array is the
          // spec's "anonymous access is an accepted alternative" (optional auth)
          // → also public.
          const sec = o.security !== undefined ? o.security : globalSecurity;
          const auth_required = Array.isArray(sec)
            ? sec.length > 0 && !sec.some(rq => rq && typeof rq === 'object' && Object.keys(rq as object).length === 0)
            : undefined;
          const response_type = responseTypeFor(o, globalProduces);
          const label = `${method.toUpperCase()} ${fullPath}`;
          // Keyed by method+path (GET /users ≠ POST /users), so these are
          // intentionally distinct from LinkFinder's path-only endpoint nodes.
          emitEndpoint(ctx, wa, `openapi:${method}:${fullPath}`, { path: fullPath, method: method.toUpperCase(), auth_required, response_type, label });
        } catch { /* skip malformed operation */ }
      }
    }
  }
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}

/** GraphQL endpoint path from the introspected URL (source_host), else /graphql. */
function graphqlPath(context?: ParseContext): string {
  const raw = typeof context?.source_host === 'string' ? context.source_host : undefined;
  const r = resolveWebappOrigin(raw);
  if (raw && r) {
    try {
      const u = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
      if (u.pathname && u.pathname !== '/') return u.pathname.replace(/\/+$/, '') || '/';
    } catch { /* fall through */ }
  }
  return '/graphql';
}

// --- GraphQL introspection JSON ({data:{__schema}} | {__schema}) ---
export function parseGraphqlSchema(output: string, agentId: string = 'graphql-parser', context?: ParseContext): Finding {
  const now = new Date().toISOString();
  const ctx = newCtx(now, agentId);
  let doc: unknown;
  try { doc = JSON.parse(output); } catch { return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] }; }
  const root = doc as Record<string, unknown> | null;
  const schema = (root?.data as Record<string, unknown> | undefined)?.__schema ?? root?.__schema;
  if (!schema || typeof schema !== 'object') return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  const s = schema as Record<string, unknown>;

  const wa = resolveWa(typeof context?.source_host === 'string' ? context.source_host : undefined);
  const gqlPath = graphqlPath(context);
  // Query + Mutation are POST /graphql operations; Subscriptions are served over
  // WebSocket, not POST, so they aren't modeled as HTTP api_endpoints here.
  const opTypes: Array<[string, unknown]> = [
    ['Query', s.queryType], ['Mutation', s.mutationType],
  ];
  const types = Array.isArray(s.types) ? s.types : [];
  const byName = new Map<string, Record<string, unknown>>();
  for (const t of types) if (t && typeof t === 'object' && typeof (t as Record<string, unknown>).name === 'string') byName.set((t as Record<string, unknown>).name as string, t as Record<string, unknown>);

  for (const [opKind, typeRef] of opTypes) {
    const typeName = typeRef && typeof typeRef === 'object' ? (typeRef as Record<string, unknown>).name : undefined;
    if (typeof typeName !== 'string') continue;
    const t = byName.get(typeName);
    if (!t || !Array.isArray(t.fields)) continue;
    for (const field of t.fields) {
      try {
        if (!field || typeof field !== 'object' || typeof (field as Record<string, unknown>).name !== 'string') continue;
        const fieldName = (field as Record<string, unknown>).name as string;
        if (fieldName.startsWith('__')) continue; // introspection meta-field, not a real operation
        const op = `${opKind}.${fieldName}`;
        emitEndpoint(ctx, wa, `graphql:${op}`, { path: gqlPath, method: 'POST', response_type: 'application/json', label: `POST ${gqlPath} (${op})` });
      } catch { /* skip malformed field */ }
    }
  }
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: ctx.nodes, edges: ctx.edges };
}
