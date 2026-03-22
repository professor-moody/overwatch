import { describe, it, expect } from 'vitest';
import {
  getCredentialMaterialKind,
  isCredentialUsableForAuth,
  isReusableDomainCredential,
  getCredentialDisplayKind,
} from '../credential-utils.js';
import type { NodeProperties } from '../../types.js';

function makeCredNode(overrides: Partial<NodeProperties> = {}): NodeProperties {
  return {
    id: 'cred-test',
    type: 'credential',
    label: 'test',
    confidence: 1.0,
    discovered_at: '2026-01-01T00:00:00Z',
    ...overrides,
  } as NodeProperties;
}

describe('Credential Utilities', () => {

  // =============================================
  // getCredentialMaterialKind
  // =============================================
  describe('getCredentialMaterialKind', () => {
    it('returns cred_material_kind when set (takes precedence)', () => {
      const node = makeCredNode({ cred_material_kind: 'ntlmv2_challenge', cred_type: 'ntlm' });
      expect(getCredentialMaterialKind(node)).toBe('ntlmv2_challenge');
    });

    it('falls back to cred_type: plaintext → plaintext_password', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'plaintext' }))).toBe('plaintext_password');
    });

    it('falls back to cred_type: ntlm → ntlm_hash', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'ntlm' }))).toBe('ntlm_hash');
    });

    it('falls back to cred_type: ntlmv2_challenge → ntlmv2_challenge', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'ntlmv2_challenge' }))).toBe('ntlmv2_challenge');
    });

    it('falls back to cred_type: aes256 → aes256_key', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'aes256' }))).toBe('aes256_key');
    });

    it('falls back to cred_type: kerberos_tgt → kerberos_tgt', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'kerberos_tgt' }))).toBe('kerberos_tgt');
    });

    it('falls back to cred_type: kerberos_tgs → kerberos_tgs', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'kerberos_tgs' }))).toBe('kerberos_tgs');
    });

    it('falls back to cred_type: certificate → certificate', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'certificate' }))).toBe('certificate');
    });

    it('falls back to cred_type: token → token', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'token' }))).toBe('token');
    });

    it('falls back to cred_type: ssh_key → ssh_key', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'ssh_key' }))).toBe('ssh_key');
    });

    it('returns undefined when neither field is set', () => {
      expect(getCredentialMaterialKind(makeCredNode())).toBeUndefined();
    });
  });

  // =============================================
  // isCredentialUsableForAuth
  // =============================================
  describe('isCredentialUsableForAuth', () => {
    it('returns explicit cred_usable_for_auth when set to true', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_usable_for_auth: true }))).toBe(true);
    });

    it('returns explicit cred_usable_for_auth when set to false', () => {
      expect(isCredentialUsableForAuth(makeCredNode({
        cred_usable_for_auth: false,
        cred_material_kind: 'plaintext_password',
      }))).toBe(false);
    });

    it('infers true for plaintext_password', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'plaintext_password' }))).toBe(true);
    });

    it('infers true for ntlm_hash', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'ntlm_hash' }))).toBe(true);
    });

    it('infers true for aes256_key', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'aes256_key' }))).toBe(true);
    });

    it('infers true for kerberos_tgt', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'kerberos_tgt' }))).toBe(true);
    });

    it('infers true for certificate', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'certificate' }))).toBe(true);
    });

    it('infers true for ssh_key', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'ssh_key' }))).toBe(true);
    });

    it('infers false for ntlmv2_challenge', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_material_kind: 'ntlmv2_challenge' }))).toBe(false);
    });

    it('infers false when no material kind is available', () => {
      expect(isCredentialUsableForAuth(makeCredNode())).toBe(false);
    });

    it('uses legacy cred_type fallback to infer usability', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_type: 'ntlm' }))).toBe(true);
    });

    it('keeps ntlmv2_challenge non-usable when inferred from legacy cred_type fallback', () => {
      expect(isCredentialUsableForAuth(makeCredNode({ cred_type: 'ntlmv2_challenge' }))).toBe(false);
    });
  });

  // =============================================
  // isReusableDomainCredential
  // =============================================
  describe('isReusableDomainCredential', () => {
    it('returns true for ntlm_hash with domain', () => {
      expect(isReusableDomainCredential(makeCredNode({
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
        cred_domain: 'acme.local',
      }))).toBe(true);
    });

    it('returns true for plaintext_password with domain', () => {
      expect(isReusableDomainCredential(makeCredNode({
        cred_material_kind: 'plaintext_password',
        cred_usable_for_auth: true,
        cred_domain: 'acme.local',
      }))).toBe(true);
    });

    it('returns false without domain', () => {
      expect(isReusableDomainCredential(makeCredNode({
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
      }))).toBe(false);
    });

    it('returns false for non-usable credential', () => {
      expect(isReusableDomainCredential(makeCredNode({
        cred_material_kind: 'ntlmv2_challenge',
        cred_usable_for_auth: false,
        cred_domain: 'acme.local',
      }))).toBe(false);
    });

    it('returns false for ssh_key even with domain', () => {
      expect(isReusableDomainCredential(makeCredNode({
        cred_material_kind: 'ssh_key',
        cred_usable_for_auth: true,
        cred_domain: 'acme.local',
      }))).toBe(false);
    });
  });

  // =============================================
  // getCredentialDisplayKind
  // =============================================
  describe('getCredentialDisplayKind', () => {
    it('returns cred_material_kind when available', () => {
      expect(getCredentialDisplayKind(makeCredNode({ cred_material_kind: 'ntlm_hash' }))).toBe('ntlm_hash');
    });

    it('falls back to cred_type', () => {
      expect(getCredentialDisplayKind(makeCredNode({ cred_type: 'plaintext' }))).toBe('plaintext_password');
    });

    it('returns unknown when neither field is set', () => {
      expect(getCredentialDisplayKind(makeCredNode())).toBe('unknown');
    });
  });
});
