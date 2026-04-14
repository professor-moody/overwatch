import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import {
  getCredentialMaterialKind,
  isCredentialUsableForAuth,
  isReusableDomainCredential,
  getCredentialDisplayKind,
  inferCredentialDomain,
} from '../credential-utils.js';
import { normalizeFindingNode } from '../finding-validation.js';
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

    it('falls back to cred_type: cleartext → plaintext_password', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'cleartext' }))).toBe('plaintext_password');
    });

    it('returns undefined when neither field is set', () => {
      expect(getCredentialMaterialKind(makeCredNode())).toBeUndefined();
    });

    it('F01: falls back to cred_type: ntlmv1_challenge → ntlmv1_challenge', () => {
      expect(getCredentialMaterialKind(makeCredNode({ cred_type: 'ntlmv1_challenge' }))).toBe('ntlmv1_challenge');
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

  // =============================================
  // normalizeFindingNode — credential property aliases
  // =============================================
  describe('normalizeFindingNode credential aliases', () => {
    it('aliases credential_type → cred_type', () => {
      const node = { id: 'cred-test', type: 'credential' as const, label: 'test', credential_type: 'cleartext' } as any;
      const result = normalizeFindingNode(node);
      expect(result.cred_type).toBe('cleartext');
    });

    it('aliases password → cred_value', () => {
      const node = { id: 'cred-test', type: 'credential' as const, label: 'test', password: 'Secret123' } as any;
      const result = normalizeFindingNode(node);
      expect(result.cred_value).toBe('Secret123');
    });

    it('aliases username → cred_user and domain → cred_domain', () => {
      const node = { id: 'cred-test', type: 'credential' as const, label: 'test', username: 'samwell.tarly', domain: 'north.sevenkingdoms.local' } as any;
      const result = normalizeFindingNode(node);
      expect(result.cred_user).toBe('samwell.tarly');
      expect(result.cred_domain).toBe('north.sevenkingdoms.local');
    });

    it('does not overwrite existing canonical properties', () => {
      const node = { id: 'cred-test', type: 'credential' as const, label: 'test', cred_type: 'plaintext' as const, credential_type: 'ntlm', cred_value: 'existing', password: 'overridden' } as any;
      const result = normalizeFindingNode(node);
      expect(result.cred_type).toBe('plaintext');
      expect(result.cred_value).toBe('existing');
    });

    it('full agent-style credential converges with all aliases', () => {
      const node = {
        id: 'cred-north-samwell.tarly-cleartext',
        type: 'credential' as const,
        label: 'samwell.tarly cleartext password',
        username: 'samwell.tarly',
        domain: 'north.sevenkingdoms.local',
        credential_type: 'cleartext',
        password: 'Heartsbane',
      } as any;
      const result = normalizeFindingNode(node);
      expect(result.cred_user).toBe('samwell.tarly');
      expect(result.cred_domain).toBe('north.sevenkingdoms.local');
      expect(result.cred_type).toBe('cleartext');
      expect(result.cred_value).toBe('Heartsbane');
      expect(result.cred_material_kind).toBe('plaintext_password');
      expect(result.cred_usable_for_auth).toBe(true);
    });

    it('does not touch non-credential nodes', () => {
      const node = { id: 'user-test', type: 'user' as const, label: 'test', username: 'admin', password: 'secret' } as any;
      const result = normalizeFindingNode(node);
      expect(result.cred_user).toBeUndefined();
      expect(result.cred_value).toBeUndefined();
    });
  });

  // =============================================
  // inferCredentialDomain
  // =============================================
  describe('inferCredentialDomain', () => {
    function makeGraph() {
      return new (Graph as any)({ type: 'directed', multi: true });
    }

    it('returns domain when single owner has single MEMBER_OF_DOMAIN', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:jdoe', cred_user: 'jdoe' });
      g.addNode('user-jdoe', { type: 'user', label: 'jdoe', username: 'jdoe' });
      g.addNode('domain-acme', { type: 'domain', label: 'acme.local', domain_name: 'acme.local' });
      g.addEdge('user-jdoe', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-jdoe', 'domain-acme', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });

      const result = inferCredentialDomain('cred-1', g);
      expect(result).toEqual({ domain: 'acme.local' });
    });

    it('returns null when owner has multiple domains', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:jdoe', cred_user: 'jdoe' });
      g.addNode('user-jdoe', { type: 'user', label: 'jdoe', username: 'jdoe' });
      g.addNode('domain-a', { type: 'domain', label: 'acme.local', domain_name: 'acme.local' });
      g.addNode('domain-b', { type: 'domain', label: 'corp.local', domain_name: 'corp.local' });
      g.addEdge('user-jdoe', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-jdoe', 'domain-a', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-jdoe', 'domain-b', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });

      expect(inferCredentialDomain('cred-1', g)).toBeNull();
    });

    it('returns null when no owner exists', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:jdoe', cred_user: 'jdoe' });
      expect(inferCredentialDomain('cred-1', g)).toBeNull();
    });

    it('returns domain when multiple owners share same domain', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:shared', cred_user: 'shared' });
      g.addNode('user-a', { type: 'user', label: 'alice', username: 'alice' });
      g.addNode('user-b', { type: 'user', label: 'bob', username: 'bob' });
      g.addNode('domain-acme', { type: 'domain', label: 'acme.local', domain_name: 'acme.local' });
      g.addEdge('user-a', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-b', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-a', 'domain-acme', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-b', 'domain-acme', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });

      expect(inferCredentialDomain('cred-1', g)).toEqual({ domain: 'acme.local' });
    });

    it('returns null when multiple owners have different domains', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:shared', cred_user: 'shared' });
      g.addNode('user-a', { type: 'user', label: 'alice', username: 'alice' });
      g.addNode('user-b', { type: 'user', label: 'bob', username: 'bob' });
      g.addNode('domain-a', { type: 'domain', label: 'acme.local', domain_name: 'acme.local' });
      g.addNode('domain-b', { type: 'domain', label: 'corp.local', domain_name: 'corp.local' });
      g.addEdge('user-a', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-b', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-a', 'domain-a', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-b', 'domain-b', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });

      expect(inferCredentialDomain('cred-1', g)).toBeNull();
    });

    it('returns null for non-existent node', () => {
      const g = makeGraph();
      expect(inferCredentialDomain('cred-nonexistent', g)).toBeNull();
    });

    it('falls back to owner domain_name property when no MEMBER_OF_DOMAIN edges', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:jdoe', cred_user: 'jdoe' });
      g.addNode('user-jdoe', { type: 'user', label: 'jdoe', username: 'jdoe', domain_name: 'north.sevenkingdoms.local' });
      g.addEdge('user-jdoe', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      // No MEMBER_OF_DOMAIN edge — should fall back to domain_name property
      expect(inferCredentialDomain('cred-1', g)).toEqual({ domain: 'north.sevenkingdoms.local' });
    });

    it('prefers MEMBER_OF_DOMAIN edge over domain_name property fallback', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:jdoe', cred_user: 'jdoe' });
      g.addNode('user-jdoe', { type: 'user', label: 'jdoe', username: 'jdoe', domain_name: 'stale.local' });
      g.addNode('domain-acme', { type: 'domain', label: 'acme.local', domain_name: 'acme.local' });
      g.addEdge('user-jdoe', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      g.addEdge('user-jdoe', 'domain-acme', { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      // Edge domain should win, not the property
      expect(inferCredentialDomain('cred-1', g)).toEqual({ domain: 'acme.local' });
    });

    it('returns null when owner has no domain_name and no MEMBER_OF_DOMAIN edges', () => {
      const g = makeGraph();
      g.addNode('cred-1', { type: 'credential', label: 'NTLM:jdoe', cred_user: 'jdoe' });
      g.addNode('user-jdoe', { type: 'user', label: 'jdoe', username: 'jdoe' });
      g.addEdge('user-jdoe', 'cred-1', { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' });
      expect(inferCredentialDomain('cred-1', g)).toBeNull();
    });
  });
});
