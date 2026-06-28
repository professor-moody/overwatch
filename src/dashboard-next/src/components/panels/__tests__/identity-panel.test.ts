import { describe, expect, it } from 'vitest';
import { identityTokenSummaries, tokenCredentials } from '../IdentityPanel';
import type { ExportedNode } from '../../../lib/types';

const nodes: ExportedNode[] = [
  {
    id: 'cred-okta-cookie',
    type: 'credential',
    label: 'jdoe:Okta session',
    confidence: 0.9,
    discovered_at: '2026-05-15T00:00:00.000Z',
    cred_material_kind: 'session_cookie',
    cred_user: 'jdoe@corp.local',
    cred_audience: 'https://benefits.corp.local',
    cred_scopes: ['openid', 'profile'],
    cred_mfa_satisfied: true,
    cred_value: 'secret-cookie-value',
  },
  {
    id: 'cred-ntlm',
    type: 'credential',
    label: 'jdoe:NTLM',
    confidence: 0.9,
    discovered_at: '2026-05-15T00:00:00.000Z',
    cred_material_kind: 'ntlm_hash',
    cred_value: 'hash-value',
  },
];

describe('identity credential derivation', () => {
  it('selects token-shaped credentials for identity context', () => {
    expect(tokenCredentials(nodes).map(node => node.id)).toEqual(['cred-okta-cookie']);
  });

  it('summarizes tokens without exposing secret material', () => {
    const summaries = identityTokenSummaries(nodes);
    expect(summaries).toEqual([expect.objectContaining({
      id: 'cred-okta-cookie',
      kind: 'session_cookie',
      status: 'MFA satisfied',
      tone: 'success',
      user: 'jdoe@corp.local',
    })]);
    expect(JSON.stringify(summaries)).not.toContain('secret-cookie-value');
  });

  it('classifies token expiry relative to now (null when no expiry)', () => {
    const now = Date.parse('2026-05-15T00:00:00.000Z');
    const withExpiry: ExportedNode[] = [{
      id: 'cred-soon',
      type: 'credential',
      label: 'expiring token',
      confidence: 0.9,
      discovered_at: '2026-05-15T00:00:00.000Z',
      cred_material_kind: 'oidc_access_token',
      cred_token_expires_at: '2026-05-15T00:30:00.000Z',
    } as ExportedNode];
    const [soon] = identityTokenSummaries(withExpiry, now);
    expect(soon.expiry?.urgency).toBe('soon');

    // The session cookie in `nodes` has no expiry timestamp → null.
    const [cookie] = identityTokenSummaries(nodes, now);
    expect(cookie.expiry).toBeNull();
  });
});
