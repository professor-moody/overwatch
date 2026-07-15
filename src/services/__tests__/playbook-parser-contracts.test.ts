import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { EngagementConfig, ParseContext } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { parseAndMaybeIngest, type ParseOutcome } from '../parse-ingest.js';
import {
  credentialId,
  idpApplicationId,
  idpId,
  idpPrincipalId,
} from '../parser-utils.js';

const GH_CREDENTIAL_ID = 'cred-github-contract';
const ENTRA_ACCESS_CREDENTIAL_ID = 'cred-entra-access-contract';
const ENTRA_REFRESH_CREDENTIAL_ID = 'cred-entra-refresh-contract';
const GITHUB_REPO = 'acme/webapp';
const GITHUB_OWNER = 'acme';
const ENTRA_TENANT = '11111111-1111-4111-8111-111111111111';

const GH_BINDING = 'env:OVERWATCH_GITHUB_TOKEN';
const ENTRA_BINDING = 'env:OVERWATCH_ENTRA_TOKEN';
const ENTRA_REFRESH_BINDING = 'env:OVERWATCH_ENTRA_REFRESH_TOKEN';

function config(): EngagementConfig {
  return {
    id: 'playbook-parser-contracts',
    name: 'Playbook parser contracts',
    created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
  };
}

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.fixture`;
}

const exchangedAccessToken = unsignedJwt({
  tid: ENTRA_TENANT,
  iss: `https://login.microsoftonline.com/${ENTRA_TENANT}/v2.0`,
  oid: 'entra-user-1',
});
const rotatedRefreshToken = 'rotated-refresh-token-fixture';

function seedContractAnchors(engine: GraphEngine): void {
  engine.addNode({
    id: GH_CREDENTIAL_ID,
    type: 'credential',
    label: 'github-contract-token',
    cred_type: 'token',
    cred_material_kind: 'pat',
    credential_status: 'active',
    cred_usable_for_auth: true,
    discovered_at: '2026-01-01T00:00:00Z',
    confidence: 1,
  });
  engine.addNode({
    id: ENTRA_ACCESS_CREDENTIAL_ID,
    type: 'credential',
    label: 'entra-contract-access-token',
    cred_type: 'oidc_token',
    cred_material_kind: 'oidc_access_token',
    credential_status: 'active',
    cred_usable_for_auth: true,
    tenant_id: ENTRA_TENANT,
    discovered_at: '2026-01-01T00:00:00Z',
    confidence: 1,
  });
  engine.addNode({
    id: ENTRA_REFRESH_CREDENTIAL_ID,
    type: 'credential',
    label: 'entra-contract-refresh-token',
    cred_type: 'token',
    cred_material_kind: 'oidc_refresh_token',
    cred_value: 'original-refresh-token-fixture',
    credential_status: 'active',
    cred_usable_for_auth: false,
    tenant_id: ENTRA_TENANT,
    discovered_at: '2026-01-01T00:00:00Z',
    confidence: 1,
  });

  const githubOrgId = idpId('github_org', GITHUB_OWNER);
  engine.addNode({
    id: githubOrgId,
    type: 'idp',
    label: `github:${GITHUB_OWNER}`,
    idp_kind: 'github_org',
    tenant_id: GITHUB_OWNER,
    discovered_at: '2026-01-01T00:00:00Z',
    confidence: 1,
  });
  engine.addNode({
    id: idpApplicationId('github_org', GITHUB_OWNER, GITHUB_REPO),
    type: 'idp_application',
    label: GITHUB_REPO,
    idp_id: githubOrgId,
    idp_kind: 'github_org',
    tenant_id: GITHUB_OWNER,
    app_kind: 'github_repo',
    repo_full_name: GITHUB_REPO,
    discovered_at: '2026-01-01T00:00:00Z',
    confidence: 1,
  });
}

function graphEdges(engine: GraphEngine, type: string) {
  return engine.exportGraph().edges.filter(edge => edge.properties.type === type);
}

interface ParserContract {
  name: string;
  parser: string;
  context: ParseContext;
  output: string;
  outcome: ParseOutcome;
  assertGraph: (engine: GraphEngine) => void;
}

const contracts: ParserContract[] = [
  {
    name: 'GitHub token replay accepts the live curl suffix and lands identity plus access',
    parser: 'token_replay_github',
    context: {
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: [
      'HTTP/2 200\r',
      'X-OAuth-Scopes: repo, read:org\r',
      'Content-Type: application/json\r',
      '\r',
      JSON.stringify({ login: 'octocat', id: 42, name: 'Octo Cat', email: 'octo@example.test' }),
      '[STATUS:200]',
    ].join('\n'),
    outcome: 'ok',
    assertGraph: engine => {
      expect(engine.getNode(GH_CREDENTIAL_ID)).toMatchObject({
        label: 'github-contract-token',
        cred_user: 'octocat',
        cred_scopes: ['repo', 'read:org'],
        cred_usable_for_auth: true,
      });
      const principal = engine.getNodesByType('idp_principal').find(node => node.username === 'octocat');
      const app = engine.getNodesByType('idp_application').find(node => node.app_kind === 'github_api');
      expect(principal).toMatchObject({ tenant_id: 'github.com', idp_user_id: '42' });
      expect(app).toMatchObject({ audience: 'https://api.github.com' });
      expect(graphEdges(engine, 'VALID_FOR_APP')).toContainEqual(expect.objectContaining({
        source: GH_CREDENTIAL_ID,
        target: app?.id,
      }));
    },
  },
  {
    name: 'GitHub organizations preserve slurped pages and source credential attribution',
    parser: 'gh-api-orgs',
    context: {
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: JSON.stringify([
      [{ login: 'acme', id: 1 }],
      [{ login: 'acme-labs', id: 2 }],
    ]),
    outcome: 'ok',
    assertGraph: engine => {
      expect(engine.getNode(GH_CREDENTIAL_ID)?.cred_orgs).toEqual(['acme', 'acme-labs']);
      expect(engine.getNodesByType('idp').filter(node => node.idp_kind === 'github_org').map(node => node.tenant_id))
        .toEqual(expect.arrayContaining(['acme', 'acme-labs']));
    },
  },
  {
    name: 'GitHub repositories land canonical applications and credential reachability',
    parser: 'gh-api-repos',
    context: {
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: JSON.stringify([[
      {
        id: 10,
        full_name: GITHUB_REPO,
        owner: { login: GITHUB_OWNER },
        private: true,
        default_branch: 'trunk',
        language: 'TypeScript',
        archived: false,
        fork: false,
      },
    ]]),
    outcome: 'ok',
    assertGraph: engine => {
      const appId = idpApplicationId('github_org', GITHUB_OWNER, GITHUB_REPO);
      expect(engine.getNode(appId)).toMatchObject({
        app_kind: 'github_repo',
        repo_full_name: GITHUB_REPO,
        private: true,
        default_branch: 'trunk',
      });
      expect(graphEdges(engine, 'VALID_FOR_APP')).toContainEqual(expect.objectContaining({
        source: GH_CREDENTIAL_ID,
        target: appId,
      }));
    },
  },
  {
    name: 'GitHub Actions secrets retain the usable page and report incomplete pagination',
    parser: 'gh-api-secrets',
    context: {
      repo_full_name: GITHUB_REPO,
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: JSON.stringify([{
      total_count: 2,
      secrets: [{ name: 'DEPLOY_TOKEN', created_at: '2026-01-02T00:00:00Z' }],
    }]),
    outcome: 'partial',
    assertGraph: engine => {
      const secret = engine.getNodesByType('credential').find(node => node.cred_user === 'DEPLOY_TOKEN');
      expect(secret).toMatchObject({
        cred_material_kind: 'app_password',
        cred_audience: GITHUB_REPO,
        cred_usable_for_auth: false,
      });
      expect(secret?.cred_value).toContain('<gh-actions-secret');
      expect(graphEdges(engine, 'OWNS_CRED')).toContainEqual(expect.objectContaining({
        source: idpApplicationId('github_org', GITHUB_OWNER, GITHUB_REPO),
        target: secret?.id,
      }));
    },
  },
  {
    name: 'GitHub branch protection updates the requested repository and branch',
    parser: 'gh-api-branch-protection',
    context: {
      repo_full_name: GITHUB_REPO,
      branch_name: 'trunk',
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: JSON.stringify({
      required_status_checks: { strict: true, contexts: ['ci'] },
      required_pull_request_reviews: {
        required_approving_review_count: 1,
        require_code_owner_reviews: true,
      },
      enforce_admins: { enabled: false },
      required_signatures: { enabled: false },
    }),
    outcome: 'ok',
    assertGraph: engine => {
      expect(engine.getNode(idpApplicationId('github_org', GITHUB_OWNER, GITHUB_REPO))).toMatchObject({
        branch_protection: { branch: 'trunk', status: 'weak' },
        branch_protection_gaps: ['admins can bypass protection', 'commit signatures not required'],
        finding_severity: 'medium',
      });
    },
  },
  {
    name: 'GitHub deploy keys land public-half credentials with capability metadata',
    parser: 'gh-api-deploy-keys',
    context: {
      repo_full_name: GITHUB_REPO,
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: JSON.stringify([[
      {
        id: 20,
        key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture',
        title: 'release-deploy',
        read_only: false,
      },
    ]]),
    outcome: 'ok',
    assertGraph: engine => {
      const key = engine.getNodesByType('credential').find(node => node.cred_user === 'release-deploy');
      expect(key).toMatchObject({
        cred_material_kind: 'ssh_key',
        cred_audience: GITHUB_REPO,
        cred_usable_for_auth: false,
        deploy_key_write_access: true,
        finding_severity: 'high',
      });
      expect(graphEdges(engine, 'OWNS_CRED')).toContainEqual(expect.objectContaining({
        source: idpApplicationId('github_org', GITHUB_OWNER, GITHUB_REPO),
        target: key?.id,
      }));
    },
  },
  {
    name: 'GitHub Actions OIDC customization keeps repository context and trust shape',
    parser: 'github-actions-oidc',
    context: {
      repo_full_name: GITHUB_REPO,
      owner: GITHUB_OWNER,
      source_credential_id: GH_CREDENTIAL_ID,
      credential_execution_binding: GH_BINDING,
    },
    output: JSON.stringify({
      use_default: false,
      include_claim_keys: ['repo', 'context'],
      sub_claim_pattern: `repo:${GITHUB_REPO}:ref:refs/heads/trunk`,
    }),
    outcome: 'ok',
    assertGraph: engine => {
      const appId = idpApplicationId('ci_github_actions', 'public', GITHUB_REPO);
      expect(engine.getNode(appId)).toMatchObject({
        repo_full_name: GITHUB_REPO,
        oidc_use_default: false,
        oidc_include_claim_keys: ['repo', 'context'],
        sub_claim_pattern: `repo:${GITHUB_REPO}:ref:refs/heads/trunk`,
      });
      expect(graphEdges(engine, 'TRUSTS')).toContainEqual(expect.objectContaining({
        source: appId,
        target: idpId('ci_github_actions', 'public'),
      }));
    },
  },
  {
    name: 'Entra refresh exchange lands rotated and derived credentials',
    parser: 'entra-token-exchange',
    context: {
      source_credential_id: ENTRA_REFRESH_CREDENTIAL_ID,
      tenant_id: ENTRA_TENANT,
      client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
      requested_scope: 'https://graph.microsoft.com/.default offline_access',
      credential_execution_binding: ENTRA_REFRESH_BINDING,
    },
    output: JSON.stringify({
      token_type: 'Bearer',
      scope: 'https://graph.microsoft.com/.default offline_access',
      expires_in: 3600,
      access_token: exchangedAccessToken,
      refresh_token: rotatedRefreshToken,
    }),
    outcome: 'ok',
    assertGraph: engine => {
      const accessId = credentialId('oidc_access_token', exchangedAccessToken, undefined, ENTRA_TENANT);
      const refreshId = credentialId('oidc_refresh_token', rotatedRefreshToken, undefined, ENTRA_TENANT);
      expect(engine.getNode(ENTRA_REFRESH_CREDENTIAL_ID)).toMatchObject({ credential_status: 'rotated' });
      expect(engine.getNode(accessId)).toMatchObject({
        cred_material_kind: 'oidc_access_token',
        tenant_id: ENTRA_TENANT,
        cred_audience: 'https://graph.microsoft.com',
        refresh_token_rotated: true,
      });
      expect(engine.getNode(refreshId)).toMatchObject({
        cred_material_kind: 'oidc_refresh_token',
        tenant_id: ENTRA_TENANT,
      });
      expect(graphEdges(engine, 'DERIVED_FROM')).toEqual(expect.arrayContaining([
        expect.objectContaining({ source: accessId, target: ENTRA_REFRESH_CREDENTIAL_ID }),
        expect.objectContaining({ source: refreshId, target: ENTRA_REFRESH_CREDENTIAL_ID }),
      ]));
    },
  },
  {
    name: 'Microsoft Graph token replay accepts the live curl suffix and lands identity plus access',
    parser: 'token_replay_msgraph',
    context: {
      source_credential_id: ENTRA_ACCESS_CREDENTIAL_ID,
      tenant_id: ENTRA_TENANT,
      credential_execution_binding: ENTRA_BINDING,
    },
    output: [
      'HTTP/2 200\r',
      'Content-Type: application/json\r',
      '\r',
      JSON.stringify({
        id: 'entra-user-1',
        userPrincipalName: 'alice@acme.example',
        displayName: 'Alice Example',
        mail: 'alice@acme.example',
      }),
      '[STATUS:200]',
    ].join('\n'),
    outcome: 'ok',
    assertGraph: engine => {
      const principalId = idpPrincipalId('entra', ENTRA_TENANT, 'entra-user-1');
      const graphAppId = idpApplicationId('entra', ENTRA_TENANT, 'microsoft-graph');
      expect(engine.getNode(ENTRA_ACCESS_CREDENTIAL_ID)).toMatchObject({
        tenant_id: ENTRA_TENANT,
        cred_user: 'alice@acme.example',
        cred_mfa_satisfied: true,
        credential_principal_id: principalId,
      });
      expect(engine.getNode(principalId)).toMatchObject({
        upn: 'alice@acme.example',
        object_id: 'entra-user-1',
      });
      expect(engine.getNode(graphAppId)).toMatchObject({ audience: 'https://graph.microsoft.com' });
      expect(graphEdges(engine, 'VALID_FOR_APP')).toContainEqual(expect.objectContaining({
        source: ENTRA_ACCESS_CREDENTIAL_ID,
        target: graphAppId,
      }));
    },
  },
  {
    name: 'Microsoft Graph users retain a valid page and surface the continuation as partial',
    parser: 'msgraph-users',
    context: {
      tenant_id: ENTRA_TENANT,
      source_credential_id: ENTRA_ACCESS_CREDENTIAL_ID,
      credential_execution_binding: ENTRA_BINDING,
    },
    output: JSON.stringify({
      value: [{
        id: 'entra-user-2',
        userPrincipalName: 'bob@acme.example',
        displayName: 'Bob Example',
        accountEnabled: true,
      }],
      '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=fixture',
    }),
    outcome: 'partial',
    assertGraph: engine => {
      expect(engine.getNode(idpPrincipalId('entra', ENTRA_TENANT, 'entra-user-2'))).toMatchObject({
        upn: 'bob@acme.example',
        account_enabled: true,
        tenant_id: ENTRA_TENANT,
      });
      expect(engine.getNode(idpId('entra', ENTRA_TENANT))).toMatchObject({ idp_kind: 'entra' });
    },
  },
  {
    name: 'Microsoft Graph applications preserve requested permission IDs without inventing grants',
    parser: 'msgraph-applications',
    context: {
      tenant_id: ENTRA_TENANT,
      source_credential_id: ENTRA_ACCESS_CREDENTIAL_ID,
      credential_execution_binding: ENTRA_BINDING,
    },
    output: JSON.stringify({
      value: [{
        id: 'app-object-1',
        appId: 'app-client-1',
        displayName: 'Contract Application',
        signInAudience: 'AzureADMultipleOrgs',
        requiredResourceAccess: [{
          resourceAppId: '00000003-0000-0000-c000-000000000000',
          resourceAccess: [{ id: 'permission-guid-1', type: 'Scope' }],
        }],
        web: { redirectUris: ['https://app.example.test/callback'] },
      }],
    }),
    outcome: 'ok',
    assertGraph: engine => {
      expect(engine.getNode(idpApplicationId('entra', ENTRA_TENANT, 'app-client-1'))).toMatchObject({
        app_kind: 'entra_application',
        requested_permission_ids: ['permission-guid-1'],
        multi_tenant: true,
        redirect_uris: ['https://app.example.test/callback'],
      });
    },
  },
  {
    name: 'Microsoft Graph service principals distinguish exposed capabilities from grants',
    parser: 'msgraph-serviceprincipals',
    context: {
      tenant_id: ENTRA_TENANT,
      source_credential_id: ENTRA_ACCESS_CREDENTIAL_ID,
      credential_execution_binding: ENTRA_BINDING,
    },
    output: JSON.stringify({
      value: [{
        id: 'sp-object-1',
        appId: 'sp-client-1',
        displayName: 'Contract Service Principal',
        servicePrincipalType: 'Application',
        appOwnerOrganizationId: '22222222-2222-4222-8222-222222222222',
        oauth2PermissionScopes: [{ id: 'scope-1', value: 'User.Read.All', type: 'Admin' }],
        appRoles: [{ value: 'Directory.ReadWrite.All' }],
      }],
    }),
    outcome: 'ok',
    assertGraph: engine => {
      expect(engine.getNode(idpApplicationId('entra', `${ENTRA_TENANT}-sp`, 'sp-client-1'))).toMatchObject({
        app_kind: 'entra_service_principal',
        exposed_oauth_scopes: ['User.Read.All'],
        exposed_app_roles: ['Directory.ReadWrite.All'],
        external_app: true,
      });
    },
  },
  {
    name: 'Microsoft Graph groups land access-control groups and omit distribution lists',
    parser: 'msgraph-groups',
    context: {
      tenant_id: ENTRA_TENANT,
      source_credential_id: ENTRA_ACCESS_CREDENTIAL_ID,
      credential_execution_binding: ENTRA_BINDING,
    },
    output: JSON.stringify({
      value: [
        {
          id: 'group-object-1',
          displayName: 'Platform Administrators',
          securityEnabled: true,
          mailEnabled: false,
          groupTypes: [],
        },
        {
          id: 'group-object-2',
          displayName: 'Announcements',
          securityEnabled: false,
          mailEnabled: true,
          groupTypes: [],
        },
      ],
    }),
    outcome: 'ok',
    assertGraph: engine => {
      const securityGroup = engine.getNodesByType('group').find(node => node.object_id === 'group-object-1');
      expect(securityGroup).toMatchObject({
        label: 'Platform Administrators',
        group_kind: 'security',
        tenant_id: ENTRA_TENANT,
      });
      expect(engine.getNodesByType('group').find(node => node.label === 'Announcements')).toBeUndefined();
    },
  },
];

describe('GitHub and Entra playbook parser contracts through the shared pipeline', () => {
  let dir: string;
  let engine: GraphEngine;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-playbook-parser-contracts-'));
    engine = new GraphEngine(config(), join(dir, 'state.json'));
    seedContractAnchors(engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  it.each(contracts)('$name', contract => {
    const actionId = `act-contract-${contract.parser}`;
    const result = parseAndMaybeIngest(engine, {
      tool_name: contract.parser,
      outputText: contract.output,
      agent_id: 'playbook-parser-contract-test',
      action_id: actionId,
      context: contract.context,
      ingest: true,
    });

    expect(result).toMatchObject({
      parsed: true,
      parse_outcome: contract.outcome,
      parse_status: 'ok',
      isError: false,
    });
    expect(result.ingested).not.toBe(false);

    const parseEvent = engine.getFullHistory().find(event =>
      event.action_id === actionId && event.event_type === 'parse_output');
    const details = parseEvent?.details as Record<string, unknown> | undefined;
    expect(details?.parser_context).toEqual(contract.context);

    contract.assertGraph(engine);
  });

  it('treats invalid_grant as a complete terminal refresh-token result', () => {
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'entra-token-exchange',
      outputText: JSON.stringify({ error: 'invalid_grant', error_description: 'refresh token expired' }),
      action_id: 'act-entra-invalid-grant', ingest: true,
      context: { source_credential_id: ENTRA_REFRESH_CREDENTIAL_ID, tenant_id: ENTRA_TENANT },
    });
    expect(result).toMatchObject({ parse_outcome: 'ok', isError: false });
    expect(engine.getNode(ENTRA_REFRESH_CREDENTIAL_ID)).toMatchObject({
      label: 'entra-contract-refresh-token',
      cred_material_kind: 'oidc_refresh_token',
      cred_value: 'original-refresh-token-fixture',
      credential_status: 'expired',
      token_exchange_error: 'invalid_grant',
    });
  });

  it('keeps invalid_client inconclusive without corrupting the source credential', () => {
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'entra-token-exchange',
      outputText: JSON.stringify({ error: 'invalid_client', error_description: 'client mismatch' }),
      action_id: 'act-entra-invalid-client', ingest: true,
      context: { source_credential_id: ENTRA_REFRESH_CREDENTIAL_ID, tenant_id: ENTRA_TENANT },
    });
    expect(result).toMatchObject({
      parse_status: 'ok', parse_outcome: 'partial', partial: true, isError: false,
    });
    expect(engine.getNode(ENTRA_REFRESH_CREDENTIAL_ID)).toMatchObject({
      label: 'entra-contract-refresh-token',
      cred_material_kind: 'oidc_refresh_token',
      cred_value: 'original-refresh-token-fixture',
      credential_status: 'active',
      token_exchange_error: 'invalid_client',
    });
    expect(engine.getNode(ENTRA_REFRESH_CREDENTIAL_ID)?.partial).toBeUndefined();
  });
});
