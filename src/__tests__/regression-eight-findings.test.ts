// ============================================================
// Regressions for the eight findings filed against Phase 2/3/4 +
// the session-default-technique fix. F1 and F2 (sub-agent runner)
// already have tests in src/services/__tests__/subagent-ipc.test.ts;
// this file covers F3–F8.
// ============================================================

import { describe, it, expect, vi } from 'vitest';
import Graph from 'graphology';
import type { EdgeProperties, NodeProperties } from '../types.js';
import type { OverwatchGraph } from '../services/engine-context.js';
import { EngineContext } from '../services/engine-context.js';
import { runCrossTierCorrelator } from '../services/cross-tier-correlator.js';
import { runCrossTierInference } from '../services/cross-tier-inference.js';
import { parseEvilginx, parseMicroBurst, parseRoadrecon } from '../services/parsers/index.js';

const now = new Date().toISOString();

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, allowSelfLoops: true, type: 'directed' }) as OverwatchGraph;
}
function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}
function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}
function makeConfig(crossTierLinks?: any) {
  return {
    id: 'test-eight-findings',
    name: 'eight findings',
    created_at: '2026-05-07T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [], cross_tier_links: crossTierLinks },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  } as any;
}
function buildHost(graph: OverwatchGraph, config: any) {
  const ctx = new EngineContext(graph, config, './test-state-eight.json');
  return {
    ctx,
    addNode: (props: NodeProperties) => {
      if (graph.hasNode(props.id)) graph.replaceNodeAttributes(props.id, props);
      else graph.addNode(props.id, props);
      return props.id;
    },
    addEdge: (src: string, tgt: string, props: EdgeProperties) => {
      const existing = graph.edges(src, tgt).find(eid => graph.getEdgeAttributes(eid).type === props.type);
      if (existing) return { id: existing, isNew: false };
      const id = graph.addEdge(src, tgt, props);
      return { id, isNew: true };
    },
    log: () => {},
  };
}

// =============================================
// F3 — OIDC pivot gates on usable token material
// =============================================

describe('F3 — OIDC_FEDERATION_PIVOT only fires on usable access tokens', () => {
  function setupGraph(credProps: Partial<NodeProperties>) {
    const graph = makeGraph();
    addNode(graph, 'idp-app', { type: 'idp_application', client_id: 'app-1', audience: 'arn:aws:iam::123:role/PowerUser' });
    addNode(graph, 'cloud-id', { type: 'cloud_identity', principal_type: 'role' });
    addEdge(graph, 'idp-app', 'cloud-id', 'ISSUES_TOKENS_FOR');
    addNode(graph, 'cred-1', {
      type: 'credential',
      cred_audience: 'arn:aws:iam::123:role/PowerUser',
      ...credProps,
    });
    return graph;
  }

  it('does NOT pivot on an ID token', () => {
    const graph = setupGraph({ cred_material_kind: 'oidc_id_token' });
    const r = runCrossTierInference(buildHost(graph, makeConfig()));
    expect(r.oidc_federation_pivot).toBe(0);
  });

  it('does NOT pivot on an expired access token', () => {
    const graph = setupGraph({
      cred_material_kind: 'oidc_access_token',
      cred_token_expires_at: new Date(Date.now() - 60_000).toISOString(),
    });
    const r = runCrossTierInference(buildHost(graph, makeConfig()));
    expect(r.oidc_federation_pivot).toBe(0);
  });

  it('does NOT pivot on an MFA-blocked token', () => {
    const graph = setupGraph({
      cred_material_kind: 'oidc_access_token',
      cred_mfa_required: true,
    });
    const r = runCrossTierInference(buildHost(graph, makeConfig()));
    expect(r.oidc_federation_pivot).toBe(0);
  });

  it('does NOT pivot on a non-token credential', () => {
    const graph = setupGraph({ cred_material_kind: 'plaintext_password' });
    const r = runCrossTierInference(buildHost(graph, makeConfig()));
    expect(r.oidc_federation_pivot).toBe(0);
  });

  it('DOES pivot on an unexpired, MFA-satisfied access token', () => {
    const graph = setupGraph({
      cred_material_kind: 'oidc_access_token',
      cred_token_expires_at: new Date(Date.now() + 60 * 60_000).toISOString(),
      cred_mfa_required: true,
      cred_mfa_satisfied: true,
    });
    const r = runCrossTierInference(buildHost(graph, makeConfig()));
    expect(r.oidc_federation_pivot).toBe(1);
  });
});

// =============================================
// F4 — evilginx decodes captured JWTs
// =============================================

describe('F4 — evilginx populates audience/issuer/expiry from captured JWTs', () => {
  it('decodes JWT-shaped tokens into cred_audience / cred_issuer / cred_token_expires_at / cred_scopes', () => {
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = {
      iss: 'https://login.microsoftonline.com/tenant/v2.0',
      sub: 'user-id',
      aud: '00000003-0000-0000-c000-000000000000',
      scp: 'User.Read Mail.ReadWrite',
      exp: 9999999999,
    };
    const access = `${enc(header)}.${enc(payload)}.fakesig`;

    const session = {
      id: 1, phishlet: 'o365', username: 'alice@acme.com',
      cookies: [{ name: 'ESTSAUTH', value: 'cookie-val', domain: 'login.microsoftonline.com' }],
      tokens: { access_token: access },
    };
    const finding = parseEvilginx(JSON.stringify([session]));
    const accessCred = finding.nodes.find(n => n.cred_material_kind === 'oidc_access_token');
    expect(accessCred).toBeDefined();
    expect(accessCred!.cred_audience).toBe('00000003-0000-0000-c000-000000000000');
    expect(accessCred!.cred_issuer).toBe('https://login.microsoftonline.com/tenant/v2.0');
    expect(accessCred!.cred_token_expires_at).toBeDefined();
    expect(accessCred!.cred_scopes).toEqual(['User.Read', 'Mail.ReadWrite']);
  });

  it('classifies tokens with a nonce claim as id_token regardless of the token-name hint', () => {
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const idTokenPayload = { iss: 'https://accounts.google.com', sub: 's', aud: 'app', nonce: 'abc', exp: 9999999999 };
    const idJwt = `${enc({ alg: 'RS256' })}.${enc(idTokenPayload)}.sig`;
    const session = { phishlet: 'google', username: 'a@b.com', cookies: [], tokens: { access_token: idJwt } };
    const finding = parseEvilginx(JSON.stringify([session]));
    const cred = finding.nodes.find(n => n.cred_audience === 'app');
    expect(cred!.cred_material_kind).toBe('oidc_id_token');
  });
});

// =============================================
// F5 — microburst CSV with embedded commas + table partial flag
// =============================================

describe('F5 — microburst handles CSV connection strings and flags Format-Table partials', () => {
  it('parses CSV values containing commas without splitting them', () => {
    const csv = [
      '"Type","Name","Value","Source"',
      '"Key Vault Secret","db-conn","Server=db1;Database=app,Pool=true;User=x;Password=p","kv-acme"',
    ].join('\n');
    const finding = parseMicroBurst(csv);
    const cred = finding.nodes.find(n => n.cred_user === 'db-conn');
    expect(cred).toBeDefined();
    // The full connection string survives intact (commas inside the quoted value).
    expect(cred!.cred_value).toBe('Server=db1;Database=app,Pool=true;User=x;Password=p');
  });

  it('marks Format-Table-parsed rows as partial and not directly usable', () => {
    const table = [
      'Type                       Name              Value                Source',
      '-----                      ----              -----                ------',
      'Storage Account Key        acmestorage       AAAAAAAAAAAAAAAAAAA  rg-acme/acme',
    ].join('\n');
    const finding = parseMicroBurst(table);
    const cred = finding.nodes.find(n => n.type === 'credential');
    expect(cred).toBeDefined();
    expect(cred!.cred_usable_for_auth).toBe(false);
    expect(cred!.partial).toBe(true);
  });
});

// =============================================
// F6 — cross-tier prefix without ARN refuses match
// =============================================

describe('F6 — cross_tier_link with cloud_resource_prefix requires the resource to have an ARN', () => {
  it('skips resources missing arn even when the account matches', () => {
    const graph = makeGraph();
    addNode(graph, 'webapp-1', { type: 'webapp', url: 'https://app.client.com/api' });
    // Resource with the right account but no ARN.
    addNode(graph, 'res-no-arn', { type: 'cloud_resource', cloud_account: '123', resource_type: 'Lambda' });
    // Resource with the right account AND a matching ARN.
    addNode(graph, 'res-with-arn', { type: 'cloud_resource', cloud_account: '123', arn: 'arn:aws:lambda:us-east-1:123:function:client-api-handler' });
    const config = makeConfig([{
      url_pattern: '*.client.com/*',
      aws_account: '123',
      cloud_resource_prefix: 'arn:aws:lambda:us-east-1:123:function:client-api-*',
    }]);
    const host = buildHost(graph, config);
    const r = runCrossTierCorrelator(host);
    expect(r.backed_by_added).toBe(1);
    // The ARN-bearing resource is linked; the no-ARN one is not.
    expect(graph.edges('webapp-1', 'res-with-arn').filter(e => graph.getEdgeAttributes(e).type === 'BACKED_BY').length).toBe(1);
    expect(graph.edges('webapp-1', 'res-no-arn').filter(e => graph.getEdgeAttributes(e).type === 'BACKED_BY').length).toBe(0);
  });
});

// =============================================
// F7 — roadrecon expands `includeApplications: ['All']` to tenant-wide MFA
// =============================================

describe('F7 — roadrecon: tenant-wide MFA conditional access applies to every app', () => {
  it('emits MFA_REQUIRED_FOR for every idp_application when policy targets All', () => {
    const bundle = {
      tenant: { tenantId: 'tenant-1', displayName: 'Acme' },
      applications: [
        { appId: 'app-A', displayName: 'App A' },
        { appId: 'app-B', displayName: 'App B' },
      ],
      conditionalaccess: [{
        displayName: 'Org-wide MFA',
        grantControls: { builtInControls: ['mfa'] },
        conditions: { applications: { includeApplications: ['All'] } },
      }],
    };
    const finding = parseRoadrecon(JSON.stringify(bundle));
    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps).toHaveLength(2);
    // Both apps have app_mfa_required set.
    expect(apps.every(a => a.app_mfa_required === true)).toBe(true);
    // Both have a self-loop MFA_REQUIRED_FOR edge.
    const mfaEdges = finding.edges.filter(e => e.properties.type === 'MFA_REQUIRED_FOR');
    expect(mfaEdges).toHaveLength(2);
    expect(mfaEdges.every(e => (e.properties as any).ca_scope === 'all_applications')).toBe(true);
  });
});

// =============================================
// F8 — send_to_session falls back to session.host
// =============================================

describe('F8 — send_to_session falls back to session.host when no explicit target_ip', () => {
  // The full integration test would spin up registerSessionTools with a
  // mocked session manager; that's covered indirectly via the existing
  // session-instrumentation tests. Here we cover the helper directly: an
  // SSH session opened with a host but no default_validation should
  // surface that host as the validateAction target_ip.
  it('uses session.host as target_ip when default_validation is not set explicitly', async () => {
    // Construct a minimal MCP-style fake server like the existing
    // session-instrumentation test does.
    const { registerSessionTools } = await import('../tools/sessions.js');
    const handlers: Record<string, (a: any) => Promise<any>> = {};
    const fakeServer = { registerTool(name: string, _: unknown, h: any) { handlers[name] = h; } } as any;

    const validateMock = vi.fn(() => ({
      valid: true,
      errors: [],
      warnings: [],
      opsec_context: { global_noise_spent: 0, noise_budget_remaining: 1, recommended_approach: 'normal', defensive_signals: [] },
    }));
    const events: any[] = [];
    const sessionMeta = {
      id: 'sess-ssh',
      kind: 'ssh',
      transport: 'pty',
      state: 'connected',
      title: 'lab',
      host: '10.10.10.7',
      started_at: now,
      last_activity_at: now,
      capabilities: { has_stdin: true, has_stdout: true, supports_resize: true, supports_signals: true, tty_quality: 'full' },
      buffer_end_pos: 0,
      // No default_validation set!
    };
    const sessionManager: any = {
      create: vi.fn(),
      list: vi.fn(() => []),
      getSession: vi.fn(() => sessionMeta),
      sendCommand: vi.fn(async () => ({
        session_id: 'sess-ssh', start_pos: 0, end_pos: 5, text: 'ok', truncated: false,
        completion_reason: 'idle', timed_out: false,
      })),
    };
    const engine: any = {
      getConfig: () => ({ scope: { cidrs: ['10.10.10.0/24'], domains: [] } }),
      getNode: () => null,
      validateAction: validateMock,
      logActionEvent: (e: any) => events.push(e),
      persist: () => {},
      now: () => now,
      nextDeterministicSeq: () => 1,
      recordOpsecNoise: () => {},
      getEvidenceStore: () => ({ store: () => 'ev-1' }),
    };

    registerSessionTools(fakeServer, sessionManager, engine);
    await handlers.send_to_session({ session_id: 'sess-ssh', command: 'whoami' });

    expect(validateMock).toHaveBeenCalled();
    const callArgs = validateMock.mock.calls[0] as unknown as Array<{ target_ip?: string }>;
    expect(callArgs[0].target_ip).toBe('10.10.10.7');
  });
});
