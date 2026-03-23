import { describe, it, expect } from 'vitest';
import { normalizeKeyPart, domainId, userId, credentialId, hostId, caId, certTemplateId, pkiStoreId, splitQualifiedAccount } from '../parser-utils.js';

describe('Parser Utilities', () => {

  // =============================================
  // normalizeKeyPart
  // =============================================
  describe('normalizeKeyPart', () => {
    it('lowercases and replaces dots with hyphens', () => {
      expect(normalizeKeyPart('ACME.LOCAL')).toBe('acme-local');
    });

    it('replaces backslashes with hyphens', () => {
      expect(normalizeKeyPart('ACME\\jdoe')).toBe('acme-jdoe');
    });

    it('replaces forward slashes with hyphens', () => {
      expect(normalizeKeyPart('ACME/jdoe')).toBe('acme-jdoe');
    });

    it('replaces whitespace with hyphens', () => {
      expect(normalizeKeyPart('some value')).toBe('some-value');
    });

    it('collapses consecutive special chars into a single hyphen', () => {
      expect(normalizeKeyPart('a..b//c\\\\d')).toBe('a-b-c-d');
    });

    it('strips leading and trailing hyphens', () => {
      expect(normalizeKeyPart('.leading.')).toBe('leading');
    });

    it('trims whitespace', () => {
      expect(normalizeKeyPart('  padded  ')).toBe('padded');
    });

    it('returns empty string for empty input', () => {
      expect(normalizeKeyPart('')).toBe('');
    });

    it('returns empty string for only special chars', () => {
      expect(normalizeKeyPart('..//\\\\..')).toBe('');
    });

    it('strips non-alphanumeric chars besides hyphens', () => {
      expect(normalizeKeyPart('user@domain')).toBe('user-domain');
    });
  });

  // =============================================
  // domainId
  // =============================================
  describe('domainId', () => {
    it('produces canonical domain node ID', () => {
      expect(domainId('acme.local')).toBe('domain-acme-local');
    });

    it('normalizes case', () => {
      expect(domainId('ACME.LOCAL')).toBe('domain-acme-local');
    });
  });

  // =============================================
  // userId
  // =============================================
  describe('userId', () => {
    it('produces domain-qualified user ID', () => {
      expect(userId('jdoe', 'acme.local')).toBe('user-acme-local-jdoe');
    });

    it('produces plain user ID without domain', () => {
      expect(userId('jdoe')).toBe('user-jdoe');
    });

    it('normalizes case', () => {
      expect(userId('JDoe', 'ACME.LOCAL')).toBe('user-acme-local-jdoe');
    });

    it('handles undefined domain', () => {
      expect(userId('admin', undefined)).toBe('user-admin');
    });
  });

  // =============================================
  // credentialId
  // =============================================
  describe('credentialId', () => {
    it('is deterministic for the same inputs', () => {
      const a = credentialId('ntlm_hash', 'abcdef0123456789', 'jdoe', 'acme.local');
      const b = credentialId('ntlm_hash', 'abcdef0123456789', 'jdoe', 'acme.local');
      expect(a).toBe(b);
    });

    it('differs for different fingerprints', () => {
      const a = credentialId('ntlm_hash', 'hash1', 'jdoe', 'acme.local');
      const b = credentialId('ntlm_hash', 'hash2', 'jdoe', 'acme.local');
      expect(a).not.toBe(b);
    });

    it('starts with cred- prefix', () => {
      const id = credentialId('plaintext_password', 'Password1', 'jdoe', 'acme.local');
      expect(id).toMatch(/^cred-/);
    });

    it('includes material kind in ID', () => {
      const id = credentialId('ntlm_hash', 'abcdef', 'jdoe');
      expect(id).toContain('ntlm-hash');
    });

    it('works without username or domain', () => {
      const id = credentialId('plaintext_password', 'secret');
      expect(id).toMatch(/^cred-plaintext-password-[a-f0-9]+$/);
    });
  });

  // =============================================
  // hostId
  // =============================================
  describe('hostId', () => {
    it('produces canonical host ID from IP', () => {
      expect(hostId('10.10.10.5')).toBe('host-10-10-10-5');
    });

    it('replaces all dots', () => {
      expect(hostId('192.168.1.100')).toBe('host-192-168-1-100');
    });
  });

  // =============================================
  // PKI IDs
  // =============================================
  describe('pki ids', () => {
    it('produces canonical CA IDs', () => {
      expect(caId('ACME-CA')).toBe('ca-acme-ca');
    });

    it('produces canonical certificate template IDs', () => {
      expect(certTemplateId('UserTemplate')).toBe('cert-template-usertemplate');
    });

    it('produces canonical PKI store IDs', () => {
      expect(pkiStoreId('ntauth_store', 'NTAuthCertificates')).toBe('pki-store-ntauth-store-ntauthcertificates');
    });
  });

  // =============================================
  // splitQualifiedAccount
  // =============================================
  describe('splitQualifiedAccount', () => {
    it('splits backslash-delimited DOMAIN\\user', () => {
      const result = splitQualifiedAccount('ACME\\jdoe');
      expect(result).toEqual({ domain: 'ACME', username: 'jdoe' });
    });

    it('splits forward-slash-delimited DOMAIN/user', () => {
      const result = splitQualifiedAccount('ACME/jdoe');
      expect(result).toEqual({ domain: 'ACME', username: 'jdoe' });
    });

    it('returns plain username when no delimiter', () => {
      const result = splitQualifiedAccount('jdoe');
      expect(result).toEqual({ username: 'jdoe' });
    });

    it('handles multi-part domain with backslash', () => {
      const result = splitQualifiedAccount('ACME.LOCAL\\svc_sql');
      expect(result).toEqual({ domain: 'ACME.LOCAL', username: 'svc_sql' });
    });
  });
});
