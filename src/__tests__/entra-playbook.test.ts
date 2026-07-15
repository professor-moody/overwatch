// ============================================================
// A.4 — Entra/Azure playbook + msgraph parsers.
// ============================================================

import { describe, it, expect } from 'vitest';
import { parseMsGraphUsers } from '../services/parsers/msgraph-users.js';
import { parseMsGraphApplications } from '../services/parsers/msgraph-applications.js';
import { parseMsGraphServicePrincipals } from '../services/parsers/msgraph-serviceprincipals.js';
import { parseMsGraphGroups } from '../services/parsers/msgraph-groups.js';

const TENANT = 'acme.onmicrosoft.com';

describe('parseMsGraphUsers', () => {
  it('emits idp_principal per user with UPN/oid', () => {
    const output = JSON.stringify({
      value: [
        { id: '11111111-1111-1111-1111-111111111111', userPrincipalName: 'alice@acme.local', displayName: 'Alice', mail: 'alice@acme.local', accountEnabled: true },
        { id: '22222222-2222-2222-2222-222222222222', userPrincipalName: 'bob@acme.local', displayName: 'Bob' },
      ],
    });
    const finding = parseMsGraphUsers(output, 'test', { tenant_id: TENANT });
    const principals = finding.nodes.filter(n => n.type === 'idp_principal');
    expect(principals).toHaveLength(2);
    expect(principals[0].upn).toBe('alice@acme.local');
    expect(principals[0].account_enabled).toBe(true);
    expect(principals[0].idp_kind).toBe('entra');
    expect(principals[0].tenant_id).toBe(TENANT);
  });

  it('returns empty for malformed payload', () => {
    expect(parseMsGraphUsers('garbage', 'test').nodes).toHaveLength(0);
    expect(parseMsGraphUsers('{}', 'test').nodes).toHaveLength(0);
  });
});

describe('parseMsGraphApplications', () => {
  it('emits idp_application with multi_tenant flag and requested permission IDs', () => {
    const output = JSON.stringify({
      value: [
        {
          id: 'aaaa', appId: 'cccc', displayName: 'Internal',
          signInAudience: 'AzureADMyOrg',
          requiredResourceAccess: [
            { resourceAppId: '00000003-0000-0000-c000-000000000000', resourceAccess: [{ id: 'scope-1', type: 'Scope' }] },
          ],
        },
        {
          id: 'bbbb', appId: 'dddd', displayName: 'Multi-Tenant',
          signInAudience: 'AzureADMultipleOrgs',
          web: { redirectUris: ['https://app.example.com/cb'] },
        },
      ],
    });
    const finding = parseMsGraphApplications(output, 'test', { tenant_id: TENANT });
    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps).toHaveLength(2);
    const internal = apps.find(a => a.label === 'Internal')!;
    expect(internal.tenant_id).toBe(TENANT);
    expect(internal.multi_tenant).toBe(false);
    expect(internal.requested_permission_ids).toEqual(['scope-1']);
    expect(internal.app_scopes).toBeUndefined();
    const mt = apps.find(a => a.label === 'Multi-Tenant')!;
    expect(mt.multi_tenant).toBe(true);
    expect((mt.redirect_uris as string[])[0]).toBe('https://app.example.com/cb');
  });
});

describe('parseMsGraphServicePrincipals', () => {
  it('captures scopes and roles exposed by a service principal without treating them as grants', () => {
    const output = JSON.stringify({
      value: [
        {
          id: 'sp-1', appId: 'app-1', displayName: 'High-Priv App',
          servicePrincipalType: 'Application',
          oauth2PermissionScopes: [
            { id: 's1', value: 'Mail.ReadWrite', type: 'User' },
            { id: 's2', value: 'User.Read.All', type: 'Admin' },
          ],
          appRoles: [{ value: 'Directory.ReadWrite.All' }],
          appOwnerOrganizationId: 'external-tenant',
        },
      ],
    });
    const finding = parseMsGraphServicePrincipals(output, 'test', { tenant_id: TENANT });
    const sp = finding.nodes.find(n => n.type === 'idp_application')!;
    expect(sp.app_kind).toBe('entra_service_principal');
    expect(sp.tenant_id).toBe(TENANT);
    expect(sp.exposed_oauth_scopes).toContain('Mail.ReadWrite');
    expect(sp.exposed_app_roles).toContain('Directory.ReadWrite.All');
    expect(sp.app_scopes).toBeUndefined();
    // Domain aliases and owner GUIDs are not directly comparable.
    expect(sp.external_app).toBeUndefined();
  });
});

describe('parseMsGraphGroups', () => {
  it('emits group nodes for security/unified groups, skips distribution-only', () => {
    const output = JSON.stringify({
      value: [
        { id: 'g1', displayName: 'IT Admins', securityEnabled: true, mailEnabled: false, groupTypes: [] },
        { id: 'g2', displayName: 'M365 Group', securityEnabled: true, mailEnabled: true, groupTypes: ['Unified'] },
        { id: 'g3', displayName: 'Newsletter', securityEnabled: false, mailEnabled: true, groupTypes: [] },
      ],
    });
    const finding = parseMsGraphGroups(output, 'test', { tenant_id: TENANT });
    const groups = finding.nodes.filter(n => n.type === 'group');
    expect(groups).toHaveLength(2);
    expect(groups.every(group => group.tenant_id === TENANT)).toBe(true);
    expect(groups.find(g => g.label === 'IT Admins')!.group_kind).toBe('security');
    expect(groups.find(g => g.label === 'M365 Group')!.group_kind).toBe('unified');
    // Distribution-only group is skipped.
    expect(groups.find(g => g.label === 'Newsletter')).toBeUndefined();
  });
});

describe('exchange_refresh_token', () => {
  it('returns a curl command targeting the configured tenant', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'entra-test', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-entra-refresh.json');
    engine.addNode({
      id: 'cred-rt-1',
      type: 'credential',
      label: 'entra-refresh-token',
      cred_type: 'token',
      cred_material_kind: 'oidc_refresh_token',
      cred_issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`,
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerEntraPlaybookTools } = await import('../tools/entra-playbook.js');
    const handlers: Record<string, any> = {};
    const fakeServer = {
      registerTool: (name: string, _meta: unknown, handler: any) => { handlers[name] = handler; },
    };
    registerEntraPlaybookTools(fakeServer as any, engine);

    const r = await handlers['exchange_refresh_token']({
      credential_id: 'cred-rt-1',
      client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
      scope: 'https://graph.microsoft.com/.default offline_access',
    });
    const payload = JSON.parse(r.content[0].text);
    if (!payload.command) throw new Error(`unexpected payload: ${JSON.stringify(payload)}`);
    expect(payload.command).toContain(`login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
    expect(payload.command).toContain('grant_type=refresh_token');
    // Refresh-token value is referenced via the run_bash.env binding, never inlined.
    expect(payload.command).toContain('$OVERWATCH_ENTRA_REFRESH_TOKEN');
    expect(payload.command).toContain('--fail-with-body');
    expect(payload.env_from_credential).toEqual({ OVERWATCH_ENTRA_REFRESH_TOKEN: 'cred-rt-1' });
  });
});

describe('expand_entra_credential', () => {
  it('emits a 5-step plan covering me/users/applications/servicePrincipals/groups', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'entra-test-2', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-entra-expand.json');
    engine.addNode({
      id: 'cred-at-1',
      type: 'credential',
      label: 'entra-access-token',
      cred_type: 'token',
      cred_material_kind: 'oidc_access_token',
      cred_audience: 'https://graph.microsoft.com',
      tenant_id: TENANT,
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerEntraPlaybookTools } = await import('../tools/entra-playbook.js');
    const handlers: Record<string, any> = {};
    const fakeServer = {
      registerTool: (name: string, _meta: unknown, handler: any) => { handlers[name] = handler; },
    };
    registerEntraPlaybookTools(fakeServer as any, engine);

    const r = await handlers['expand_entra_credential']({
      credential_id: 'cred-at-1',
      include_groups: true,
    });
    const payload = JSON.parse(r.content[0].text);
    expect(payload.step_count).toBe(5);
    expect(payload.steps[0].command).toContain('/v1.0/me');
    expect(payload.steps[1].parse_with).toBe('msgraph-users');
    expect(payload.steps[4].parse_with).toBe('msgraph-groups');
    expect(payload.tenant).toBe(TENANT);
    expect(payload.steps.every((step: any) => step.parser_context.tenant_id === TENANT)).toBe(true);
    expect(payload.steps.every((step: any) => step.parser_context.source_credential_id === 'cred-at-1')).toBe(true);
    expect(engine.getNode('cred-at-1')?.recon_playbook_invoked_at).toBeUndefined();
  });

  it('skips groups step when include_groups is false', async () => {
    const { GraphEngine } = await import('../services/graph-engine.js');
    const config = {
      id: 'entra-test-3', name: 'test', created_at: '2026-01-01T00:00:00Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.5 },
    } as any;
    const engine = new GraphEngine(config, './state-test-entra-expand-nogroups.json');
    engine.addNode({
      id: 'cred-at-2',
      type: 'credential',
      label: 'entra-token',
      cred_type: 'token',
      cred_material_kind: 'oidc_access_token',
      tenant_id: TENANT,
      credential_status: 'active',
      cred_token_expires_at: '2099-01-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      confidence: 1.0,
    } as any);

    const { registerEntraPlaybookTools } = await import('../tools/entra-playbook.js');
    const handlers: Record<string, any> = {};
    const fakeServer = {
      registerTool: (name: string, _meta: unknown, handler: any) => { handlers[name] = handler; },
    };
    registerEntraPlaybookTools(fakeServer as any, engine);

    const r = await handlers['expand_entra_credential']({
      credential_id: 'cred-at-2',
      include_groups: false,
    });
    const payload = JSON.parse(r.content[0].text);
    expect(payload.step_count).toBe(4);
    expect(payload.steps.find((s: any) => s.parse_with === 'msgraph-groups')).toBeUndefined();
  });
});
