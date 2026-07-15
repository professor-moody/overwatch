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
import { cloudIdentityId } from '../services/parser-utils.js';

const CRED_ID = 'cred-test-1';
const APP_ID = 'idp-app-test-1';

// =============================================
// Microsoft Graph
// =============================================

describe('parseTokenReplayMsGraph', () => {
  it('parses the live curl suffix marker shape', () => {
    const body = JSON.stringify({ id: 'user-oid-live', userPrincipalName: 'live@acme.local' });
    const finding = parseTokenReplayMsGraph(`${body}\n[STATUS:200]`, 'test', {
      source_credential_id: CRED_ID,
    } as any);
    expect(finding.nodes.find(node => node.id === CRED_ID)?.cred_user).toBe('live@acme.local');
  });

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
    expect(cred.partial).toBeUndefined();
    expect(finding).toMatchObject({ partial: true, partial_reason: 'msgraph_http_503_inconclusive' });
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
        Expiration: '2099-05-08T01:00:00Z',
      },
      AssumedRoleUser: {
        AssumedRoleId: 'AROAFAKE:overwatch-replay-abc',
        Arn: 'arn:aws:sts::111122223333:assumed-role/PowerUser/overwatch-replay-abc',
      },
    });
    const finding = parseTokenReplayAwsSts(`[STATUS:0]\n${body}`, 'test', {
      source_credential_id: CRED_ID,
      target_role_arn: 'arn:aws:iam::111122223333:role/PowerUser',
      target_cloud_identity_id: cloudIdentityId('arn:aws:iam::111122223333:role/PowerUser'),
    } as any);

    const tempCred = finding.nodes.find(n => n.cred_material_kind === 'aws_session_credentials' && n.id !== CRED_ID);
    expect(tempCred).toBeDefined();
    expect(tempCred!.cred_token_expires_at).toBe('2099-05-08T01:00:00.000Z');
    expect(tempCred!.cred_usable_for_auth).toBe(true);
    expect(tempCred!.cred_audience).toBe('arn:aws:iam::111122223333:role/PowerUser');
    expect(JSON.parse(String(tempCred!.cred_value))).toEqual({
      AccessKeyId: 'ASIA...', SecretAccessKey: 'redacted', SessionToken: 'redacted',
    });

    const assumeEdge = finding.edges.find(e => e.properties.type === 'ASSUMES_ROLE');
    expect(assumeEdge).toBeDefined();
    expect(assumeEdge!.source).toBe(CRED_ID);
    expect(assumeEdge!.target).toBe(cloudIdentityId('arn:aws:iam::111122223333:role/PowerUser'));

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
    expect(finding.nodes.find(n => n.id === CRED_ID)?.partial).toBeUndefined();
    expect(finding).toMatchObject({ partial: true, partial_reason: 'aws_sts_credentials_missing' });
    expect(finding.edges).toHaveLength(0);
  });

  it.each([undefined, 'not-a-date'])(
    'missing or invalid Expiration (%s) never creates an indefinitely usable session',
    expiration => {
      const body = JSON.stringify({
        Credentials: {
          AccessKeyId: 'ASIASTALE', SecretAccessKey: 'secret', SessionToken: 'session',
          ...(expiration === undefined ? {} : { Expiration: expiration }),
        },
        AssumedRoleUser: {
          Arn: 'arn:aws:sts::111122223333:assumed-role/Observed/session', AssumedRoleId: 'AROA:session',
        },
      });
      const finding = parseTokenReplayAwsSts(body, 'test');
      const tempCred = finding.nodes.find(node => node.cred_material_kind === 'aws_session_credentials')!;
      expect(tempCred).toMatchObject({ cred_usable_for_auth: false, credential_status: 'stale' });
      expect(tempCred.cred_token_expires_at).toBeUndefined();
      expect(finding).toMatchObject({
        partial: true, partial_reason: 'aws_sts_expiration_missing_or_invalid',
      });
    },
  );

  it('retains a valid past Expiration but marks the session expired and unusable', () => {
    const body = JSON.stringify({
      Credentials: {
        AccessKeyId: 'ASIAEXPIRED', SecretAccessKey: 'secret', SessionToken: 'session',
        Expiration: '2020-01-01T00:00:00Z',
      },
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::111122223333:assumed-role/Observed/session', AssumedRoleId: 'AROA:session',
      },
    });
    const finding = parseTokenReplayAwsSts(body, 'test');
    expect(finding.nodes[0]).toMatchObject({
      cred_token_expires_at: '2020-01-01T00:00:00.000Z',
      cred_usable_for_auth: false,
      credential_status: 'expired',
    });
    expect(finding.partial).toBeUndefined();
  });

  it('reports an incomplete Credentials block as partial no-data', () => {
    const finding = parseTokenReplayAwsSts(JSON.stringify({
      Credentials: { AccessKeyId: 'ASIAONLY', Expiration: '2099-01-01T00:00:00Z' },
    }), 'test');
    expect(finding.nodes).toEqual([]);
    expect(finding).toMatchObject({ partial: true, partial_reason: 'aws_sts_credentials_incomplete' });
  });

  it('refuses to attribute successful STS credentials to a mismatched requested role', () => {
    const body = JSON.stringify({
      Credentials: {
        AccessKeyId: 'ASIAMISMATCH', SecretAccessKey: 'secret', SessionToken: 'session',
        Expiration: '2099-01-01T00:00:00Z',
      },
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::111122223333:assumed-role/Actual/session', AssumedRoleId: 'AROA:session',
      },
    });
    const finding = parseTokenReplayAwsSts(body, 'test', {
      source_credential_id: CRED_ID,
      target_role_arn: 'arn:aws:iam::111122223333:role/Requested',
      target_cloud_identity_id: cloudIdentityId('arn:aws:iam::111122223333:role/Requested'),
    });
    expect(finding.nodes).toEqual([]);
    expect(finding.edges).toEqual([]);
    expect(finding).toMatchObject({ partial: true, partial_reason: 'aws_sts_target_role_mismatch' });
  });

  it('mints from the returned role but makes no source attribution without target context', () => {
    const body = JSON.stringify({
      Credentials: {
        AccessKeyId: 'ASIANOCONTEXT', SecretAccessKey: 'secret', SessionToken: 'session',
        Expiration: '2099-01-01T00:00:00Z',
      },
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::111122223333:assumed-role/Observed/session', AssumedRoleId: 'AROA:session',
      },
    });
    const finding = parseTokenReplayAwsSts(body, 'test', { source_credential_id: CRED_ID });
    expect(finding.nodes.find(node => node.cred_material_kind === 'aws_session_credentials')?.cred_audience)
      .toBe('arn:aws:iam::111122223333:role/Observed');
    expect(finding.edges).toEqual([]);
  });

  it('matches an STS assumed-role identity to an IAM role with a path', () => {
    const targetRoleArn = 'arn:aws:iam::111122223333:role/team/platform/PowerUser';
    const body = JSON.stringify({
      Credentials: {
        AccessKeyId: 'ASIAPATH', SecretAccessKey: 'secret', SessionToken: 'session',
        Expiration: '2099-01-01T00:00:00Z',
      },
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::111122223333:assumed-role/PowerUser/session', AssumedRoleId: 'AROA:session',
      },
    });
    const finding = parseTokenReplayAwsSts(body, 'test', {
      source_credential_id: CRED_ID,
      target_role_arn: targetRoleArn,
      target_cloud_identity_id: cloudIdentityId(targetRoleArn),
    });
    expect(finding.partial).toBeUndefined();
    expect(finding.nodes.find(node => node.cred_material_kind === 'aws_session_credentials')?.cred_audience)
      .toBe(targetRoleArn);
    expect(finding.edges[0]?.target).toBe(cloudIdentityId(targetRoleArn));
  });
});

// =============================================
// Okta
// =============================================

describe('parseTokenReplayOkta', () => {
  it('parses the live curl suffix marker shape', () => {
    const body = JSON.stringify({ id: 'okta-live', profile: { login: 'live@acme.com' } });
    const finding = parseTokenReplayOkta(`${body}\n[STATUS:200]`, 'test', {
      source_credential_id: CRED_ID,
    } as any);
    expect(finding.nodes.find(node => node.id === CRED_ID)?.cred_usable_for_auth).toBe(true);
  });

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
  it('parses live -i headers plus the curl suffix marker', () => {
    const body = JSON.stringify({ login: 'live-user', id: 9001 });
    const output = `HTTP/2 200\r\nX-OAuth-Scopes: repo\r\nContent-Type: application/json\r\n\r\n${body}\n[STATUS:200]`;
    const finding = parseTokenReplayGitHub(output, 'test', {
      source_credential_id: CRED_ID,
      source_idp_application_id: APP_ID,
    } as any);
    expect(finding.nodes.find(node => node.id === CRED_ID)).toMatchObject({
      cred_user: 'live-user', cred_scopes: ['repo'],
    });
  });

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
