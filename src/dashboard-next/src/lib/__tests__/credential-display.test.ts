import { describe, expect, it } from 'vitest';
import {
  getCredentialKindLabel,
  getCredentialMaterialKind,
  getEffectiveCredentialStatus,
  isCredentialReachable,
  credentialReachTargets,
  credentialExpiry,
  CREDENTIAL_EXPIRY_SOON_MS,
  isCredentialExpansionCandidate,
} from '../credential-display';
import type { ExportedEdge, ExportedNode } from '../types';

const cred = (props: Partial<ExportedNode>): ExportedNode => ({
  id: 'cred-1',
  type: 'credential',
  label: 'cred',
  confidence: 1,
  discovered_at: '2026-05-15T00:00:00Z',
  ...props,
});

describe('credential display helpers', () => {
  it('falls back from cred_material_kind to cred_type', () => {
    expect(getCredentialMaterialKind(cred({ cred_type: 'ntlm' }))).toBe('ntlm_hash');
    expect(getCredentialKindLabel(cred({ cred_type: 'plaintext' }))).toBe('Password');
    expect(getCredentialKindLabel(cred({ cred_type: 'token' }))).toBe('Token');
  });

  it('prefers explicit material kind when present', () => {
    expect(getCredentialMaterialKind(cred({
      cred_type: 'token',
      cred_material_kind: 'pat',
    }))).toBe('pat');
    expect(getCredentialKindLabel(cred({
      cred_type: 'token',
      cred_material_kind: 'pat',
    }))).toBe('PAT');
  });

  it('detects credential reachability from auth edges', () => {
    const edges: ExportedEdge[] = [
      { source: 'other', target: 'app', type: 'VALID_FOR_APP' },
      { source: 'cred-1', target: 'app', type: 'ASSUMES_ROLE' },
    ];
    expect(isCredentialReachable(cred({}), edges)).toBe(true);
    expect(isCredentialReachable(cred({ id: 'cred-2' }), edges)).toBe(false);
  });

  it('lists the target ids a credential reaches (one per reach edge)', () => {
    const edges: ExportedEdge[] = [
      { source: 'cred-1', target: 'host-a', type: 'VALID_ON' },
      { source: 'cred-1', target: 'app-b', type: 'VALID_FOR_APP' },
      { source: 'cred-1', target: 'host-c', type: 'KNOWS' }, // not a reach edge
      { source: 'other', target: 'host-d', type: 'VALID_ON' }, // different cred
    ];
    expect(credentialReachTargets(cred({}), edges).sort()).toEqual(['app-b', 'host-a']);
    expect(credentialReachTargets(cred({ id: 'cred-2' }), edges)).toEqual([]);
  });

  it('preserves non-active credential status values', () => {
    const now = Date.parse('2026-05-15T00:00:00Z');
    expect(getEffectiveCredentialStatus(cred({ credential_status: 'stale' }), now)).toBe('stale');
    expect(getEffectiveCredentialStatus(cred({ credential_status: 'rotated' }), now)).toBe('rotated');
    expect(getEffectiveCredentialStatus(cred({ credential_status: 'expired' }), now)).toBe('expired');
  });

  it('keeps active non-token and unexpired token credentials active', () => {
    const now = Date.parse('2026-05-15T00:00:00Z');
    expect(getEffectiveCredentialStatus(cred({ credential_status: 'active' }), now)).toBe('active');
    expect(getEffectiveCredentialStatus(cred({
      credential_status: 'active',
      cred_token_expires_at: '2026-05-15T01:00:00Z',
    }), now)).toBe('active');
  });

  it('treats active tokens past cred_token_expires_at as expired', () => {
    const now = Date.parse('2026-05-15T00:00:00Z');
    expect(getEffectiveCredentialStatus(cred({
      credential_status: 'active',
      cred_token_expires_at: '2026-05-14T23:59:59Z',
    }), now)).toBe('expired');
  });

  it('keeps plan-only and generic token credentials eligible for expansion', () => {
    const now = Date.parse('2026-05-15T00:00:00Z');
    expect(isCredentialExpansionCandidate(cred({
      cred_material_kind: 'token', cred_value: 'token-value', credential_status: 'active',
      recon_playbook_invoked_at: '2026-05-14T00:00:00Z',
    }), now)).toBe(true);
  });

  it('retires credentials only after confirmed provider or STS progress lands', () => {
    const now = Date.parse('2026-05-15T00:00:00Z');
    const candidate = cred({
      cred_material_kind: 'pat', cred_value: 'token-value', credential_status: 'active',
      recon_playbook_invoked_at: '2026-05-14T00:00:00Z',
    });
    expect(isCredentialExpansionCandidate(candidate, now, [{
      source: candidate.id, target: 'github-app', type: 'VALID_FOR_APP',
    }])).toBe(false);
    expect(isCredentialExpansionCandidate(candidate, now, [{
      source: 'aws-caller', target: candidate.id, type: 'OWNS_CRED',
      binding_source: 'aws_sts_get_caller_identity',
    }])).toBe(false);
    expect(isCredentialExpansionCandidate(candidate, now, [{
      source: 'owner', target: candidate.id, type: 'OWNS_CRED', binding_source: 'import',
    }])).toBe(true);
  });

  it('excludes expired, rotated, non-token, and valueless credentials from expansion', () => {
    const now = Date.parse('2026-05-15T00:00:00Z');
    expect(isCredentialExpansionCandidate(cred({
      cred_material_kind: 'pat', cred_value: 'token', credential_status: 'active',
      cred_token_expires_at: '2026-05-14T23:00:00Z',
    }), now)).toBe(false);
    expect(isCredentialExpansionCandidate(cred({
      cred_material_kind: 'pat', cred_value: 'token', credential_status: 'rotated',
    }), now)).toBe(false);
    expect(isCredentialExpansionCandidate(cred({
      cred_material_kind: 'plaintext_password', cred_value: 'password', credential_status: 'active',
    }), now)).toBe(false);
    expect(isCredentialExpansionCandidate(cred({
      cred_material_kind: 'pat', credential_status: 'active',
    }), now)).toBe(false);
  });
});

describe('credentialExpiry', () => {
  const now = Date.parse('2026-05-15T00:00:00Z');

  it('returns null when there is no (or an unparseable) expiry timestamp', () => {
    expect(credentialExpiry(cred({}), now)).toBeNull();
    expect(credentialExpiry(cred({ cred_token_expires_at: 'not-a-date' }), now)).toBeNull();
  });

  it('classifies a token well in the future as ok', () => {
    const exp = credentialExpiry(cred({ cred_token_expires_at: '2026-05-16T00:00:00Z' }), now);
    expect(exp?.urgency).toBe('ok');
    expect(exp?.ms).toBe(86_400_000);
  });

  it('classifies a token within the soon window as soon (boundary inclusive)', () => {
    const atBoundary = new Date(now + CREDENTIAL_EXPIRY_SOON_MS).toISOString();
    expect(credentialExpiry(cred({ cred_token_expires_at: atBoundary }), now)?.urgency).toBe('soon');
    const within = new Date(now + 30 * 60_000).toISOString();
    expect(credentialExpiry(cred({ cred_token_expires_at: within }), now)?.urgency).toBe('soon');
  });

  it('classifies a lapsed token as expired with a negative ms', () => {
    const exp = credentialExpiry(cred({ cred_token_expires_at: '2026-05-14T23:00:00Z' }), now);
    expect(exp?.urgency).toBe('expired');
    expect(exp?.ms).toBeLessThan(0);
  });
});
