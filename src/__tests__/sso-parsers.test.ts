// ============================================================
// Phase 2 (enterprise readiness) — SSO / cloud-identity parsers.
//
// Each parser has fixture-based tests using representative real (sanitized)
// outputs. The shape of the assertions is uniform: the parser produces
// idp / idp_application / idp_principal / credential nodes with the right
// properties and edges populated by the Phase 1 model.
// ============================================================

import { describe, it, expect } from 'vitest';
import {
  parseJwtTool,
  parseRoadrecon,
  parseOkta,
  parseMicroBurst,
  parseAadInternals,
  parseEvilginx,
} from '../services/parsers/index.js';

// =============================================
// jwt-tool / OIDC token parser
// =============================================

describe('parseJwtTool', () => {
  // Minimal RS256 token for testing — payload only matters; signature is faked.
  // Header: { "alg": "RS256", "typ": "JWT", "kid": "abc" }
  // Payload: { "iss": "https://login.microsoftonline.com/xyz/v2.0",
  //            "sub": "user-oid", "upn": "alice@acme.local",
  //            "aud": "00000003-0000-0000-c000-000000000000",
  //            "scp": "User.Read Mail.ReadWrite",
  //            "exp": 9999999999, "iat": 1000 }
  function makeJwt(payload: Record<string, unknown>): string {
    const header = { alg: 'RS256', typ: 'JWT', kid: 'abc' };
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    return `${enc(header)}.${enc(payload)}.fakesig`;
  }

  it('extracts an idp, idp_principal, and access_token credential from a raw JWT', () => {
    const jwt = makeJwt({
      iss: 'https://login.microsoftonline.com/xyz-tenant-id/v2.0',
      sub: 'user-object-id',
      upn: 'alice@acme.local',
      aud: '00000003-0000-0000-c000-000000000000',
      scp: 'User.Read Mail.ReadWrite',
      exp: 9999999999,
    });

    const finding = parseJwtTool(jwt);
    const idp = finding.nodes.find(n => n.type === 'idp');
    expect(idp).toBeDefined();
    expect(idp!.idp_kind).toBe('entra');
    expect(idp!.tenant_id).toBe('xyz-tenant-id');

    const principal = finding.nodes.find(n => n.type === 'idp_principal');
    expect(principal).toBeDefined();
    expect(principal!.upn).toBe('alice@acme.local');

    const cred = finding.nodes.find(n => n.type === 'credential');
    expect(cred).toBeDefined();
    expect(cred!.cred_material_kind).toBe('oidc_access_token');
    expect(cred!.cred_audience).toBe('00000003-0000-0000-c000-000000000000');
    expect(cred!.cred_scopes).toEqual(['User.Read', 'Mail.ReadWrite']);
    expect(cred!.cred_token_expires_at).toBeDefined();
  });

  it('detects ID tokens via nonce claim', () => {
    const jwt = makeJwt({
      iss: 'https://accounts.google.com',
      sub: 'user-id',
      aud: 'client-abc',
      nonce: 'random-nonce',
      exp: 9999999999,
    });
    const finding = parseJwtTool(jwt);
    const cred = finding.nodes.find(n => n.type === 'credential');
    expect(cred!.cred_material_kind).toBe('oidc_id_token');
  });

  it('detects Okta and Auth0 IdP kinds from issuer URL', () => {
    const oktaToken = parseJwtTool(makeJwt({
      iss: 'https://acme.okta.com', sub: 'u1', exp: 9999999999,
    }));
    const auth0Token = parseJwtTool(makeJwt({
      iss: 'https://acme.auth0.com/', sub: 'u1', exp: 9999999999,
    }));
    expect(oktaToken.nodes.find(n => n.type === 'idp')!.idp_kind).toBe('okta');
    expect(auth0Token.nodes.find(n => n.type === 'idp')!.idp_kind).toBe('auth0');
  });

  it('returns empty finding for non-JWT input', () => {
    const finding = parseJwtTool('not a token');
    expect(finding.nodes.length).toBe(0);
  });
});

// =============================================
// roadrecon (Entra ID enumeration)
// =============================================

describe('parseRoadrecon', () => {
  it('extracts tenant + apps + users + service principals from a bundled dump', () => {
    const bundle = {
      tenant: { tenantId: 'tenant-guid', displayName: 'Acme Corp', verifiedDomains: [{ name: 'acme.local' }] },
      applications: [
        { appId: 'app-guid-1', displayName: 'Internal API', signInAudience: 'AzureADMyOrg' },
        { appId: 'app-guid-2', displayName: 'Customer Portal' },
      ],
      serviceprincipals: [
        { appId: 'app-guid-1', displayName: 'Internal API SP' },
      ],
      users: [
        { userPrincipalName: 'alice@acme.local', objectId: 'user-1', accountEnabled: true,
          strongAuthenticationMethods: [{ methodType: 'PhoneAppOTP' }] },
        { userPrincipalName: 'bob@acme.local', objectId: 'user-2', accountEnabled: false },
      ],
    };
    const finding = parseRoadrecon(JSON.stringify(bundle));

    const idp = finding.nodes.find(n => n.type === 'idp');
    expect(idp).toBeDefined();
    expect(idp!.idp_kind).toBe('entra');
    expect(idp!.tenant_id).toBe('tenant-guid');

    const apps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(apps.length).toBe(2);

    const principals = finding.nodes.filter(n => n.type === 'idp_principal');
    expect(principals.length).toBe(2);
    const alice = principals.find(p => p.upn === 'alice@acme.local')!;
    expect(alice.mfa_required).toBe(true);
    expect(alice.mfa_methods).toContain('PhoneAppOTP');
    const bob = principals.find(p => p.upn === 'bob@acme.local')!;
    expect(bob.enabled).toBe(false);

    const trusts = finding.edges.filter(e => e.properties.type === 'TRUSTS');
    expect(trusts.length).toBeGreaterThan(0);
  });

  it('emits MFA_REQUIRED_FOR edges from conditional access policies', () => {
    const bundle = {
      tenant: { tenantId: 'tenant-1' },
      applications: [{ appId: 'app-protected', displayName: 'Protected App' }],
      conditionalaccess: [
        {
          displayName: 'Require MFA on Protected App',
          grantControls: { builtInControls: ['mfa'] },
          conditions: { applications: { includeApplications: ['app-protected'] } },
        },
      ],
    };
    const finding = parseRoadrecon(JSON.stringify(bundle));
    const mfaEdges = finding.edges.filter(e => e.properties.type === 'MFA_REQUIRED_FOR');
    expect(mfaEdges.length).toBe(1);
  });

  it('honors excludeApplications under an `All` policy (excluded app not MFA-stamped)', () => {
    const bundle = {
      tenant: { tenantId: 'tenant-1' },
      applications: [
        { appId: 'app-in', displayName: 'Included App' },
        { appId: 'app-out', displayName: 'Excluded App' },
      ],
      conditionalaccess: [
        {
          displayName: 'MFA for all except one',
          grantControls: { builtInControls: ['mfa'] },
          conditions: { applications: { includeApplications: ['All'], excludeApplications: ['app-out'] } },
        },
      ],
    };
    const finding = parseRoadrecon(JSON.stringify(bundle));
    // `All` over 2 apps minus 1 excluded → exactly one MFA edge + one stamped app.
    const mfaEdges = finding.edges.filter(e => e.properties.type === 'MFA_REQUIRED_FOR');
    expect(mfaEdges.length).toBe(1);
    const stamped = finding.nodes.filter(n => n.type === 'idp_application' && (n as Record<string, unknown>).app_mfa_required === true);
    expect(stamped.length).toBe(1);
  });
});

// =============================================
// okta-cli
// =============================================

describe('parseOkta', () => {
  it('extracts apps from `okta apps list` JSON output', () => {
    const apps = [
      {
        id: 'app-okta-1', label: 'Salesforce', signOnMode: 'SAML_2_0', status: 'ACTIVE',
        _links: { self: { href: 'https://acme.okta.com/api/v1/apps/app-okta-1' } },
        settings: { signOn: { audience: 'https://saml.salesforce.com', ssoAcsUrl: 'https://acme.my.salesforce.com/...' } },
      },
      { id: 'app-okta-2', label: 'Slack', signOnMode: 'OPENID_CONNECT' },
    ];
    const finding = parseOkta(JSON.stringify(apps));
    const idp = finding.nodes.find(n => n.type === 'idp');
    expect(idp!.idp_kind).toBe('okta');
    expect(idp!.tenant_id).toBe('acme');
    const idpApps = finding.nodes.filter(n => n.type === 'idp_application');
    expect(idpApps.length).toBe(2);
    const sf = idpApps.find(a => a.app_name === 'Salesforce')!;
    expect(sf.audience).toBe('https://saml.salesforce.com');
  });

  it('extracts users from `okta users list` JSON output with MFA factors', () => {
    const users = [{
      id: 'user-okta-1', status: 'ACTIVE',
      profile: { login: 'alice@acme.com', email: 'alice@acme.com' },
      factors: [{ factorType: 'token:software:totp' }, { factorType: 'push' }],
      _links: { self: { href: 'https://acme.okta.com/api/v1/users/user-okta-1' } },
    }];
    const finding = parseOkta(JSON.stringify(users));
    const principal = finding.nodes.find(n => n.type === 'idp_principal')!;
    expect(principal.upn).toBe('alice@acme.com');
    expect(principal.mfa_required).toBe(true);
    expect(principal.mfa_methods).toEqual(['token:software:totp', 'push']);
    expect(principal.enabled).toBe(true);
  });
});

// =============================================
// MicroBurst — Get-AzPasswords
// =============================================

describe('parseMicroBurst', () => {
  it('extracts secrets from JSON output', () => {
    const rows = [
      { Type: 'Storage Account Key', Name: 'acmestorage', Value: 'AAAA...===', Source: 'rg-acme/acmestorage' },
      { Type: 'Key Vault Secret', Name: 'db-conn-string', Value: 'Server=...;', Source: 'kv-acme' },
      { Type: 'Service Principal Secret', Name: 'app-sp-1', Value: 'sp-secret-value', Source: 'app-sp-1' },
    ];
    const finding = parseMicroBurst(JSON.stringify(rows));
    const creds = finding.nodes.filter(n => n.type === 'credential');
    expect(creds.length).toBe(3);
    const sp = creds.find(c => c.label?.includes('Service Principal Secret'))!;
    expect(sp.cred_material_kind).toBe('oauth_client_secret');
    const storage = creds.find(c => c.label?.includes('Storage Account Key'))!;
    expect(storage.cred_material_kind).toBe('app_password');
  });
});

// =============================================
// AADInternals — Get-AADIntTenantInfo
// =============================================

describe('parseAadInternals', () => {
  it('extracts tenant + federation_mode from Get-AADIntTenantInfo JSON', () => {
    const tenant = {
      TenantId: 'tenant-aad-id',
      TenantName: 'Acme Corp',
      AuthenticationMode: 'Federated',
      Domains: ['acme.local'],
    };
    const finding = parseAadInternals(JSON.stringify(tenant));
    const idp = finding.nodes.find(n => n.type === 'idp')!;
    expect(idp.idp_kind).toBe('entra');
    expect(idp.tenant_id).toBe('tenant-aad-id');
    expect(idp.federation_mode).toBe('federated');
  });

  it('detects PHS / PTA federation modes', () => {
    const phs = parseAadInternals(JSON.stringify({ TenantId: 't', PasswordHashSync: true }));
    expect(phs.nodes.find(n => n.type === 'idp')!.federation_mode).toBe('password_hash_sync');
    const pta = parseAadInternals(JSON.stringify({ TenantId: 't', PassThroughAuth: true }));
    expect(pta.nodes.find(n => n.type === 'idp')!.federation_mode).toBe('pass_through_auth');
  });
});

// =============================================
// evilginx — AiTM session capture
// =============================================

describe('parseEvilginx', () => {
  it('extracts a session_cookie credential with cred_mfa_satisfied: true', () => {
    const session = {
      id: 1, phishlet: 'o365', username: 'alice@acme.com', password: 'Password123!',
      cookies: [
        { name: 'ESTSAUTH', value: 'ABCDEF...', domain: 'login.microsoftonline.com' },
        { name: 'ESTSAUTHPERSISTENT', value: 'GHIJKL...', domain: 'login.microsoftonline.com' },
      ],
      tokens: { access_token: 'eyJ...', id_token: 'eyJ...' },
    };
    const finding = parseEvilginx(JSON.stringify([session]));

    const cookieCred = finding.nodes.find(n => n.type === 'credential' && n.cred_material_kind === 'session_cookie');
    expect(cookieCred).toBeDefined();
    expect(cookieCred!.cred_mfa_required).toBe(true);
    expect(cookieCred!.cred_mfa_satisfied).toBe(true);

    const accessToken = finding.nodes.find(n => n.type === 'credential' && n.cred_material_kind === 'oidc_access_token');
    expect(accessToken).toBeDefined();
    expect(accessToken!.cred_mfa_satisfied).toBe(true);

    const password = finding.nodes.find(n => n.type === 'credential' && n.cred_material_kind === 'plaintext_password');
    expect(password).toBeDefined();
    // Phished password alone is MFA-required but NOT MFA-satisfied — operator
    // should pivot via the cookie, not the password.
    expect(password!.cred_mfa_required).toBe(true);
    expect(password!.cred_mfa_satisfied).toBeUndefined();

    const idp = finding.nodes.find(n => n.type === 'idp')!;
    expect(idp.idp_kind).toBe('entra'); // o365 phishlet → entra
  });

  it('retains body_tokens when tokens is a present-but-empty object', () => {
    // `tokens: {}` is present (not null), so nullish `??` used to shadow
    // body_tokens and drop the captured OAuth token entirely.
    const session = {
      id: 2, phishlet: 'o365', username: 'bob@acme.com',
      tokens: {},
      body_tokens: { access_token: 'eyJfake.body.token' },
    };
    const finding = parseEvilginx(JSON.stringify([session]));
    const accessToken = finding.nodes.find(n => n.type === 'credential' && n.cred_material_kind === 'oidc_access_token');
    expect(accessToken).toBeDefined();
  });
});
