import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import Graph from 'graphology';
import type { NodeProperties, EdgeProperties } from '../../types.js';
import type { OverwatchGraph } from '../engine-context.js';
import {
  estimateCredentialExpiry,
  timeToExpiry,
  getCredentialProvenance,
} from '../credential-utils.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

describe('Credential Lifecycle Intelligence', () => {
  describe('estimateCredentialExpiry', () => {
    it('returns known confidence when valid_until is set', () => {
      const node = { type: 'credential', cred_type: 'plaintext', valid_until: '2026-12-31T00:00:00Z' } as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('known');
      expect(result.expires_at).toBe('2026-12-31T00:00:00Z');
      expect(result.source).toBe('valid_until');
    });

    it('estimates TGT expiry at 10 hours from discovered_at', () => {
      const node = { type: 'credential', cred_type: 'kerberos_tgt', cred_material_kind: 'kerberos_tgt', discovered_at: '2026-06-15T10:00:00Z' } as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('estimated');
      expect(result.source).toBe('default_tgt_lifetime_10h');
      expect(result.expires_at).toBe('2026-06-15T20:00:00.000Z');
    });

    it('estimates TGS expiry at 10 hours', () => {
      const node = { type: 'credential', cred_type: 'kerberos_tgs', cred_material_kind: 'kerberos_tgs', discovered_at: '2026-06-15T12:00:00Z' } as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('estimated');
      expect(result.source).toBe('default_tgs_lifetime_10h');
    });

    it('returns unknown for token without valid_until', () => {
      const node = { type: 'credential', cred_type: 'token', cred_material_kind: 'token' } as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('unknown');
      expect(result.source).toBe('token_no_expiry');
      expect(result.expires_at).toBeUndefined();
    });

    it('estimates password expiry from domain policy + pwdLastSet', () => {
      const node = { type: 'credential', cred_type: 'plaintext', cred_material_kind: 'plaintext_password', pwd_last_set: '2026-06-01T00:00:00Z' } as NodeProperties;
      const domain = { type: 'domain', password_policy: { max_pwd_age: 90 * 24 * 3600 } } as NodeProperties;
      const result = estimateCredentialExpiry(node, domain);
      expect(result.confidence).toBe('estimated');
      expect(result.source).toBe('domain_policy_max_pwd_age');
      expect(result.expires_at).toBe('2026-08-30T00:00:00.000Z');
    });

    it('returns unknown for password without domain policy', () => {
      const node = { type: 'credential', cred_type: 'plaintext', cred_material_kind: 'plaintext_password' } as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('unknown');
      expect(result.source).toBe('password_no_policy');
    });

    it('returns unknown for NTLM hash without domain policy', () => {
      const node = { type: 'credential', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash' } as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('unknown');
      expect(result.source).toBe('password_no_policy');
    });

    it('returns unknown for unrecognized credential type', () => {
      const node = { type: 'credential', cred_type: 'exotic' } as unknown as NodeProperties;
      const result = estimateCredentialExpiry(node);
      expect(result.confidence).toBe('unknown');
      expect(result.source).toBe('unknown_cred_type');
    });
  });

  describe('timeToExpiry', () => {
    let dateSpy: ReturnType<typeof vi.spyOn>;
    beforeEach(() => {
      dateSpy = vi.spyOn(Date, 'now').mockReturnValue(new Date('2026-06-15T10:00:00Z').getTime());
    });
    afterEach(() => { dateSpy.mockRestore(); });

    it('returns Infinity when no expiry info available', () => {
      const node = { type: 'credential', cred_type: 'plaintext', cred_material_kind: 'plaintext_password' } as NodeProperties;
      expect(timeToExpiry(node)).toBe(Infinity);
    });

    it('returns ms until expiry for TGT discovered 2h ago', () => {
      const node = { type: 'credential', cred_type: 'kerberos_tgt', cred_material_kind: 'kerberos_tgt', discovered_at: '2026-06-15T08:00:00Z' } as NodeProperties;
      // TGT expires at 18:00, current is 10:00 → 8h
      expect(timeToExpiry(node)).toBe(8 * 3600 * 1000);
    });

    it('returns 0 for already expired credentials', () => {
      const node = { type: 'credential', cred_type: 'kerberos_tgt', valid_until: '2026-06-15T09:00:00Z' } as NodeProperties;
      expect(timeToExpiry(node)).toBe(0);
    });

    it('uses domain policy for password expiry', () => {
      const node = { type: 'credential', cred_type: 'plaintext', cred_material_kind: 'plaintext_password', pwd_last_set: '2026-06-14T10:00:00Z' } as NodeProperties;
      const domain = { type: 'domain', password_policy: { max_pwd_age: 2 * 24 * 3600 } } as NodeProperties;
      // Expires 2026-06-16T10:00:00Z, now is 2026-06-15T10:00:00Z → 24h
      expect(timeToExpiry(node, domain)).toBe(24 * 3600 * 1000);
    });
  });

  describe('getCredentialProvenance', () => {
    it('returns single-element chain for root credential', () => {
      const graph = makeGraph();
      graph.addNode('cred-1', { type: 'credential', id: 'cred-1', label: 'cred-1' } as NodeProperties);
      expect(getCredentialProvenance('cred-1', graph)).toEqual(['cred-1']);
    });

    it('follows DERIVED_FROM chain', () => {
      const graph = makeGraph();
      graph.addNode('cred-1', { type: 'credential', id: 'cred-1', label: 'cred-1' } as NodeProperties);
      graph.addNode('cred-2', { type: 'credential', id: 'cred-2', label: 'cred-2' } as NodeProperties);
      graph.addNode('cred-3', { type: 'credential', id: 'cred-3', label: 'cred-3' } as NodeProperties);
      graph.addEdge('cred-1', 'cred-2', { type: 'DERIVED_FROM', confidence: 1.0 } as EdgeProperties);
      graph.addEdge('cred-2', 'cred-3', { type: 'DERIVED_FROM', confidence: 1.0 } as EdgeProperties);
      expect(getCredentialProvenance('cred-1', graph)).toEqual(['cred-1', 'cred-2', 'cred-3']);
    });

    it('limits depth to 10', () => {
      const graph = makeGraph();
      for (let i = 0; i < 15; i++) {
        graph.addNode(`c${i}`, { type: 'credential', id: `c${i}`, label: `c${i}` } as NodeProperties);
        if (i > 0) graph.addEdge(`c${i - 1}`, `c${i}`, { type: 'DERIVED_FROM', confidence: 1.0 } as EdgeProperties);
      }
      expect(getCredentialProvenance('c0', graph).length).toBeLessThanOrEqual(11);
    });

    it('handles cycles gracefully', () => {
      const graph = makeGraph();
      graph.addNode('a', { type: 'credential', id: 'a', label: 'a' } as NodeProperties);
      graph.addNode('b', { type: 'credential', id: 'b', label: 'b' } as NodeProperties);
      graph.addEdge('a', 'b', { type: 'DERIVED_FROM', confidence: 1.0 } as EdgeProperties);
      graph.addEdge('b', 'a', { type: 'DERIVED_FROM', confidence: 1.0 } as EdgeProperties);
      expect(getCredentialProvenance('a', graph)).toEqual(['a', 'b']);
    });
  });
});
