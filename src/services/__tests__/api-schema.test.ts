import { describe, it, expect } from 'vitest';
import { parseOpenapi, parseGraphqlSchema } from '../parsers/index.js';
import { prepareFindingForIngest } from '../finding-validation.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const eps = (f: { nodes: unknown[] }) => nodesOf(f).filter(n => n.type === 'api_endpoint');
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);
const ep = (f: { nodes: unknown[] }, method: string, path: string) =>
  eps(f).find(n => n.method === method && n.path === path) as AnyNode | undefined;

function assertNoDangling(f: { nodes: AnyNode[]; edges: Array<{ source: string; target: string }> }) {
  const ids = new Set(f.nodes.map(n => n.id));
  for (const e of f.edges) { expect(ids.has(e.source)).toBe(true); expect(ids.has(e.target)).toBe(true); }
  expect(prepareFindingForIngest(f as any, () => null).errors).toEqual([]);
}

describe('api-schema: OpenAPI 3', () => {
  const doc = JSON.stringify({
    openapi: '3.0.0',
    servers: [{ url: 'https://api.acme.com/v1' }],
    security: [{ bearerAuth: [] }],
    paths: {
      '/users': {
        get: { responses: { '200': { content: { 'application/json': {} } } } },
        post: { security: [], responses: { '201': { content: { 'application/json': {} } } } },
      },
      '/health': { get: { security: [], responses: { '200': {} } } },
      'x-internal': { get: {} }, // vendor extension key — skipped
    },
  });

  it('emits one api_endpoint per path×method with method/auth/response_type + HAS_ENDPOINT + has_api', () => {
    const f = parseOpenapi(doc, 'a');
    expect(eps(f)).toHaveLength(3); // GET/POST /v1/users, GET /v1/health (x-internal skipped)
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://api.acme.com')).toBe(true);
    expect((nodesOf(f).find(n => n.type === 'webapp') as AnyNode)?.has_api).toBe(true);
    expect(edgeTypes(f).every(t => t === 'HAS_ENDPOINT')).toBe(true);
    expect(edgeTypes(f)).toHaveLength(3);

    const get = ep(f, 'GET', '/v1/users')!;
    expect(get.auth_required).toBe(true); // inherits global security
    expect(get.response_type).toBe('application/json');
    // per-operation `security: []` overrides global → public
    expect(ep(f, 'POST', '/v1/users')!.auth_required).toBe(false);
    expect(ep(f, 'GET', '/v1/health')!.auth_required).toBe(false);
    assertNoDangling(f);
  });

  it('a relative server url uses source_host for the origin and the url as basePath', () => {
    const rel = JSON.stringify({ openapi: '3.0.0', servers: [{ url: '/api' }], paths: { '/x': { get: {} } } });
    const f = parseOpenapi(rel, 'a', { source_host: 'https://app.acme.com' } as any);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://app.acme.com')).toBe(true);
    expect(ep(f, 'GET', '/api/x')).toBeDefined();
  });

  it('templated server variables are substituted from their defaults', () => {
    const t = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'https://{host}/v3', variables: { host: { default: 'api.acme.com' } } }], paths: { '/y': { get: {} } } });
    const f = parseOpenapi(t, 'a');
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://api.acme.com')).toBe(true);
    expect(ep(f, 'GET', '/v3/y')).toBeDefined();
  });

  it('tolerates a malformed operation (skipped, not fatal)', () => {
    const bad = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'https://api.acme.com' }], paths: { '/a': { get: { responses: {} }, post: null, 'x-y': {} }, '/b': 'nope' } });
    const f = parseOpenapi(bad, 'a');
    expect(ep(f, 'GET', '/a')).toBeDefined();
    assertNoDangling(f);
  });
});

describe('api-schema: Swagger 2', () => {
  it('resolves host+basePath+schemes and derives response_type from produces', () => {
    const doc = JSON.stringify({
      swagger: '2.0', host: 'api.acme.com', basePath: '/v2', schemes: ['https'],
      produces: ['application/json'],
      paths: { '/things': { get: { responses: { '200': { schema: {} } } } } },
    });
    const f = parseOpenapi(doc, 'a');
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://api.acme.com')).toBe(true);
    const t = ep(f, 'GET', '/v2/things')!;
    expect(t.response_type).toBe('application/json');
    assertNoDangling(f);
  });
});

describe('api-schema: GraphQL introspection', () => {
  const intro = JSON.stringify({ data: { __schema: {
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: [
      { name: 'Query', fields: [{ name: 'users' }, { name: 'me' }] },
      { name: 'Mutation', fields: [{ name: 'createUser' }] },
      { name: 'User', fields: [{ name: 'id' }] },
    ],
  } } });

  it('emits an api_endpoint per query/mutation field (POST to the graphql path) + HAS_ENDPOINT', () => {
    const f = parseGraphqlSchema(intro, 'a', { source_host: 'https://api.acme.com/graphql' } as any);
    const ops = eps(f);
    expect(ops).toHaveLength(3); // Query.users, Query.me, Mutation.createUser (User.id excluded)
    expect(ops.every(n => n.method === 'POST' && n.path === '/graphql')).toBe(true);
    expect(ops.map(n => n.label).sort()).toEqual([
      'POST /graphql (Mutation.createUser)', 'POST /graphql (Query.me)', 'POST /graphql (Query.users)',
    ]);
    expect((nodesOf(f).find(n => n.type === 'webapp') as AnyNode)?.has_api).toBe(true);
    assertNoDangling(f);
  });

  it('accepts a bare {__schema} (no data wrapper) and defaults the path to /graphql', () => {
    const bare = JSON.stringify({ __schema: { queryType: { name: 'Query' }, types: [{ name: 'Query', fields: [{ name: 'ping' }] }] } });
    const f = parseGraphqlSchema(bare, 'a', { source_host: 'https://api.acme.com' } as any);
    expect(ep(f, 'POST', '/graphql')).toBeDefined();
    assertNoDangling(f);
  });

  it('returns empty on non-introspection JSON', () => {
    const f = parseGraphqlSchema(JSON.stringify({ data: { users: [] } }), 'a', { source_host: 'https://api.acme.com' } as any);
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });
});

describe('api-schema: no source webapp', () => {
  it('OpenAPI with no server AND no context emits nothing (endpoints need a webapp to avoid cross-target collision)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', paths: { '/x': { get: {} } } });
    const f = parseOpenapi(doc, 'a');
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });
});

describe('api-schema: security + response_type edge cases', () => {
  it('security:[{}] and security:[{bearer},{}] are public (anonymous alternative)', () => {
    const doc = JSON.stringify({
      openapi: '3.0.0', servers: [{ url: 'https://api.acme.com' }],
      paths: {
        '/pub': { get: { security: [{}] } },
        '/opt': { get: { security: [{ bearerAuth: [] }, {}] } },
        '/authed': { get: { security: [{ bearerAuth: [] }] } },
      },
    });
    const f = parseOpenapi(doc, 'a');
    expect(ep(f, 'GET', '/pub')!.auth_required).toBe(false);
    expect(ep(f, 'GET', '/opt')!.auth_required).toBe(false);
    expect(ep(f, 'GET', '/authed')!.auth_required).toBe(true);
  });

  it('response_type ignores a 4xx error body and falls back to global produces', () => {
    const doc = JSON.stringify({
      openapi: '3.0.0', servers: [{ url: 'https://api.acme.com' }], produces: ['application/json'],
      paths: { '/a': { get: { responses: { '200': {}, '404': { content: { 'application/problem+json': {} } } } } } },
    });
    const f = parseOpenapi(doc, 'a');
    expect(ep(f, 'GET', '/a')!.response_type).toBe('application/json');
  });

  it('a root path "/" under a basePath is trailing-trimmed (consistent with other paths)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'https://api.acme.com/v1' }], paths: { '/': { get: {} } } });
    const f = parseOpenapi(doc, 'a');
    expect(ep(f, 'GET', '/v1')).toBeDefined();
  });

  it('a templated server with no resolvable default falls back to source_host (no {var} origin)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'https://{host}/v3' }], paths: { '/y': { get: {} } } });
    const f = parseOpenapi(doc, 'a', { source_host: 'https://app.acme.com' } as any);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://app.acme.com')).toBe(true);
    expect(nodesOf(f).some(n => String(n.url).includes('{'))).toBe(false);
    expect(ep(f, 'GET', '/v3/y')).toBeDefined();
  });

  it('a non-slash relative server url keeps its path as basePath', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'api/v1' }], paths: { '/z': { get: {} } } });
    const f = parseOpenapi(doc, 'a', { source_host: 'https://app.acme.com' } as any);
    expect(ep(f, 'GET', '/api/v1/z')).toBeDefined();
  });

  it('a protocol-relative / query-bearing relative server url yields a clean basePath (no authority/query leak)', () => {
    const proto = parseOpenapi(JSON.stringify({ openapi: '3.0.0', servers: [{ url: '//cdn.acme.com/v1' }], paths: { '/x': { get: {} } } }), 'a', { source_host: 'https://app.acme.com' } as any);
    expect(ep(proto, 'GET', '/v1/x')).toBeDefined();
    const q = parseOpenapi(JSON.stringify({ openapi: '3.0.0', servers: [{ url: '/v1?trace=1' }], paths: { '/y': { get: {} } } }), 'a', { source_host: 'https://app.acme.com' } as any);
    expect(ep(q, 'GET', '/v1/y')).toBeDefined();
  });

  it('picks the FIRST absolute server (relative first, then two absolutes)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: '/' }, { url: 'https://a.acme.com/v1' }, { url: 'https://b.acme.com/v2' }], paths: { '/w': { get: {} } } });
    const f = parseOpenapi(doc, 'a');
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://a.acme.com')).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://b.acme.com')).toBe(false);
    expect(ep(f, 'GET', '/v1/w')).toBeDefined();
  });

  it('a protocol-relative server (//host/path) keeps its host as the origin (not source_host)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: '//cdn.acme.com/v1' }], paths: { '/x': { get: {} } } });
    const f = parseOpenapi(doc, 'a', { source_host: 'https://app.acme.com' } as any);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://cdn.acme.com')).toBe(true);
    expect(ep(f, 'GET', '/v1/x')).toBeDefined();
  });

  it('a templated SCHEME server ({protocol}://host/v1, no default) yields a clean basePath (no %7B blob)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: '{protocol}://api.acme.com/v1', variables: { protocol: { enum: ['https', 'http'] } } }], paths: { '/users': { get: {} } } });
    const f = parseOpenapi(doc, 'a', { source_host: 'https://api.acme.com' } as any);
    expect(ep(f, 'GET', '/v1/users')).toBeDefined();
    expect(eps(f).some(n => String(n.path).includes('%7B') || String(n.path).includes('{'))).toBe(false);
  });

  it('a hybrid doc (swagger:2.0 + stray servers) uses the Swagger host/basePath, not the servers array', () => {
    const doc = JSON.stringify({ swagger: '2.0', host: 'api.acme.com', basePath: '/v1', schemes: ['https'], servers: [{ url: '/other' }], paths: { '/things': { get: {} } } });
    const f = parseOpenapi(doc, 'a');
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://api.acme.com')).toBe(true);
    expect(ep(f, 'GET', '/v1/things')).toBeDefined();
  });

  it('an OpenAPI-3 doc with a stray swagger key but NO host still uses its servers[] origin', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', swagger: '2.0', servers: [{ url: 'https://api.acme.com/v1' }], paths: { '/users': { get: {} } } });
    const f = parseOpenapi(doc, 'a', { source_host: 'https://ctx.acme.com' } as any);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://api.acme.com')).toBe(true);
    expect(ep(f, 'GET', '/v1/users')).toBeDefined();
  });

  it('a Swagger-2 host carrying a stray scheme/path is sanitized to a bare authority', () => {
    const doc = JSON.stringify({ swagger: '2.0', host: 'https://api.acme.com/junk', schemes: ['https'], paths: { '/x': { get: {} } } });
    const f = parseOpenapi(doc, 'a');
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://api.acme.com')).toBe(true);
    expect(nodesOf(f).every(n => n.type !== 'webapp' || !String(n.url).includes('junk'))).toBe(true);
  });

  it('an empty-paths OpenAPI doc emits nothing (no bare webapp node)', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'https://api.acme.com' }], paths: {} });
    const f = parseOpenapi(doc, 'a');
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });

  it('reads response_type from a 2XX range-wildcard response', () => {
    const doc = JSON.stringify({ openapi: '3.0.0', servers: [{ url: 'https://api.acme.com' }], paths: { '/w': { get: { responses: { '2XX': { content: { 'application/json': {} } } } } } } });
    const f = parseOpenapi(doc, 'a');
    expect(ep(f, 'GET', '/w')!.response_type).toBe('application/json');
  });

  it('Swagger-2 global security propagates auth_required to operations', () => {
    const doc = JSON.stringify({
      swagger: '2.0', host: 'api.acme.com', schemes: ['https'], security: [{ apiKey: [] }],
      paths: { '/secured': { get: { responses: { '200': {} } } } },
    });
    const f = parseOpenapi(doc, 'a');
    expect(ep(f, 'GET', '/secured')!.auth_required).toBe(true);
  });
});

describe('api-schema: GraphQL meta-fields', () => {
  it('skips __-prefixed introspection meta-fields', () => {
    const intro = JSON.stringify({ __schema: { queryType: { name: 'Query' }, types: [
      { name: 'Query', fields: [{ name: 'users' }, { name: '__typename' }, { name: '__schema' }] },
    ] } });
    const f = parseGraphqlSchema(intro, 'a', { source_host: 'https://api.acme.com/graphql' } as any);
    const labels = eps(f).map(n => n.label);
    expect(labels).toEqual(['POST /graphql (Query.users)']);
  });

  it('does NOT emit subscription fields as POST endpoints (WebSocket, not HTTP POST)', () => {
    const intro = JSON.stringify({ __schema: {
      queryType: { name: 'Query' }, subscriptionType: { name: 'Subscription' },
      types: [
        { name: 'Query', fields: [{ name: 'users' }] },
        { name: 'Subscription', fields: [{ name: 'onMessage' }] },
      ],
    } });
    const f = parseGraphqlSchema(intro, 'a', { source_host: 'https://api.acme.com/graphql' } as any);
    expect(eps(f).map(n => n.label)).toEqual(['POST /graphql (Query.users)']);
  });

  it('a subscription-ONLY schema emits nothing (no bare webapp node)', () => {
    const intro = JSON.stringify({ __schema: { subscriptionType: { name: 'Subscription' }, types: [
      { name: 'Subscription', fields: [{ name: 'onMessage' }] },
    ] } });
    const f = parseGraphqlSchema(intro, 'a', { source_host: 'https://api.acme.com/graphql' } as any);
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });
});
