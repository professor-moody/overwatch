// ============================================================
// Track D — token-replay response parsers.
//
// The validate_token_credential tool's refusal paths (non-token
// credential, expired credential, MFA-blocked credential, audience
// mismatch) live in the tool itself; integration testing them
// requires standing up a fake MCP server and the full instrumented
// process runner. We exercise the per-provider response parsers
// directly here — they're pure functions that consume the captured
// curl/awscli stdout and emit the expected graph mutations.
// ============================================================

import { describe, it, expect } from 'vitest';
import {
  parseTokenReplayMsGraph,
  parseTokenReplayAwsSts,
  parseTokenReplayOkta,
  parseTokenReplayGitHub,
} from '../services/parsers/index.js';

const CRED_ID = 'cred-test-1';
const APP_ID = 'idp-app-test-1';

// =============================================
// Microsoft Graph
// =============================================

describe('parseTokenReplayMsGraph', () => {
  it('200 → marks credential mfa_satisfied + emits VALID_FOR_APP edge', () => {
    const body = JSON.stringify({ id: 'user-oid-1', userPrincipalName: 'alice@acme.local', mail: 'alice@acme.local', displayName: 'Alice' });
    const output = `[STATUS:200]\n${body}`;
    const finding = parseTokenReplayMsGraph(output, 'test', { source_credential_id: CRED_ID, source_idp_application_id: APP_ID } as any);

    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.cred_mfa_satisfied).toBe(true);
    expect(cred.credential_status).toBe('active');

    const edge = finding.edges.find(e => e.properties.type === 'VALID_FOR_APP');
    expect(edge).toBeDefined();
    expect(edge!.target).toBe(APP_ID);
  });

  it('401 → marks credential expired, no VALID_FOR_APP edge', () => {
    const output = '[STATUS:401]\n{"error":{"code":"InvalidAuthenticationToken"}}';
    const finding = parseTokenReplayMsGraph(output, 'test', { source_credential_id: CRED_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.credential_status).toBe('expired');
    expect(finding.edges.filter(e => e.properties.type === 'VALID_FOR_APP')).toHaveLength(0);
  });

  it('403 → marks credential mfa_required, not satisfied', () => {
    const output = '[STATUS:403]\n{"error":{"code":"AuthenticationRequirements"}}';
    const finding = parseTokenReplayMsGraph(output, 'test', { source_credential_id: CRED_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.cred_mfa_required).toBe(true);
    expect(cred.cred_mfa_satisfied).toBe(false);
  });

  it('5xx → emits a partial result, no status flip', () => {
    const output = '[STATUS:503]\n{"error":"upstream timeout"}';
    const finding = parseTokenReplayMsGraph(output, 'test', { source_credential_id: CRED_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.partial).toBe(true);
    expect(cred.credential_status).toBeUndefined();
  });
});

// =============================================
// AWS STS (AssumeRoleWithWebIdentity)
// =============================================

describe('parseTokenReplayAwsSts', () => {
  it('successful AssumeRoleWithWebIdentity → emits new session credential + ASSUMES_ROLE edge + flips source mfa_satisfied', () => {
    const body = JSON.stringify({
      Credentials: {
        AccessKeyId: 'ASIA...',
        SecretAccessKey: 'redacted',
        SessionToken: 'redacted',
        Expiration: '2026-05-08T01:00:00Z',
      },
      AssumedRoleUser: {
        AssumedRoleId: 'AROAFAKE:overwatch-replay-abc',
        Arn: 'arn:aws:sts::111:assumed-role/PowerUser/overwatch-replay-abc',
      },
    });
    const finding = parseTokenReplayAwsSts(`[STATUS:0]\n${body}`, 'test', {
      source_credential_id: CRED_ID,
      target_role_arn: 'arn:aws:iam::111:role/PowerUser',
      target_cloud_identity_id: 'cloud-id-poweruser',
    } as any);

    const tempCred = finding.nodes.find(n => n.cred_material_kind === 'oidc_access_token' && n.id !== CRED_ID);
    expect(tempCred).toBeDefined();
    expect(tempCred!.cred_token_expires_at).toBe('2026-05-08T01:00:00Z');
    expect(tempCred!.cred_audience).toBe('arn:aws:iam::111:role/PowerUser');

    const assumeEdge = finding.edges.find(e => e.properties.type === 'ASSUMES_ROLE');
    expect(assumeEdge).toBeDefined();
    expect(assumeEdge!.source).toBe(CRED_ID);
    expect(assumeEdge!.target).toBe('cloud-id-poweruser');

    const sourceCred = finding.nodes.find(n => n.id === CRED_ID);
    expect(sourceCred?.cred_mfa_satisfied).toBe(true);
  });

  it('401/403 → marks source credential expired, no temp credential or edge', () => {
    const finding = parseTokenReplayAwsSts('[STATUS:401]\nAccessDenied', 'test', { source_credential_id: CRED_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.credential_status).toBe('expired');
    expect(finding.edges).toHaveLength(0);
    expect(finding.nodes.filter(n => n.id !== CRED_ID)).toHaveLength(0);
  });

  it('non-JSON body → marks source as inconclusive, no temp credential', () => {
    const finding = parseTokenReplayAwsSts('[STATUS:0]\nweird text', 'test', { source_credential_id: CRED_ID } as any);
    expect(finding.nodes.find(n => n.id === CRED_ID)?.partial).toBe(true);
    expect(finding.edges).toHaveLength(0);
  });
});

// =============================================
// Okta
// =============================================

describe('parseTokenReplayOkta', () => {
  it('200 /users/me → marks credential mfa_satisfied + VALID_FOR_APP edge', () => {
    const body = JSON.stringify({ id: 'okta-user-1', profile: { login: 'alice@acme.com', email: 'alice@acme.com' } });
    const finding = parseTokenReplayOkta(`[STATUS:200]\n${body}`, 'test', { source_credential_id: CRED_ID, source_idp_application_id: APP_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.cred_mfa_satisfied).toBe(true);
    expect(finding.edges.find(e => e.properties.type === 'VALID_FOR_APP')).toBeDefined();
  });

  it('200 /sessions/me with mfaActive: true → cred_mfa_satisfied true', () => {
    const body = JSON.stringify({ id: 'sess-1', userId: 'okta-user-1', status: 'ACTIVE', mfaActive: true });
    const finding = parseTokenReplayOkta(`[STATUS:200]\n${body}`, 'test', { source_credential_id: CRED_ID } as any);
    expect(finding.nodes.find(n => n.id === CRED_ID)!.cred_mfa_satisfied).toBe(true);
  });

  it('401 → marks credential expired', () => {
    const finding = parseTokenReplayOkta('[STATUS:401]\n{"errorCode":"E0000011"}', 'test', { source_credential_id: CRED_ID } as any);
    expect(finding.nodes.find(n => n.id === CRED_ID)!.credential_status).toBe('expired');
  });
});

// =============================================
// GitHub
// =============================================

describe('parseTokenReplayGitHub', () => {
  it('200 with OAuth scopes header → captures cred_scopes', () => {
    const body = JSON.stringify({ login: 'alice-h', id: 4242, email: 'alice@h.com' });
    const output = `HTTP/2 200\nX-OAuth-Scopes: repo, read:org\nContent-Type: application/json\n\n${body}`;
    const finding = parseTokenReplayGitHub(output, 'test', { source_credential_id: CRED_ID, source_idp_application_id: APP_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.cred_user).toBe('alice-h');
    expect(cred.cred_scopes).toEqual(['repo', 'read:org']);
    expect(finding.edges.find(e => e.properties.type === 'VALID_FOR_APP')).toBeDefined();
  });

  it('200 without -i headers → still updates credential, no scopes', () => {
    const finding = parseTokenReplayGitHub('[STATUS:200]\n{"login":"bob","id":7}', 'test', { source_credential_id: CRED_ID } as any);
    const cred = finding.nodes.find(n => n.id === CRED_ID)!;
    expect(cred.cred_user).toBe('bob');
    expect(cred.cred_scopes).toBeUndefined();
  });

  it('401 → marks credential expired', () => {
    const finding = parseTokenReplayGitHub('[STATUS:401]\n{"message":"Bad credentials"}', 'test', { source_credential_id: CRED_ID } as any);
    expect(finding.nodes.find(n => n.id === CRED_ID)!.credential_status).toBe('expired');
  });
});
