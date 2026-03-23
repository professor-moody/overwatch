import { describe, expect, it } from 'vitest';
import { classifyPrincipalIdentity, resolveNodeIdentity, resolveTypedRelationRef } from '../identity-resolution.js';

describe('identity resolution', () => {
  it('classifies well-known enrollment groups as group principals', () => {
    const principal = classifyPrincipalIdentity('ACME\\Domain Users');
    expect(principal.nodeType).toBe('group');
    expect(principal.id).toBe('group-acme-domain-users');
  });

  it('resolves PKI relation refs canonically without a SID map', () => {
    const resolved = resolveTypedRelationRef('CORP.LOCAL', 'Domain', new Map());
    expect(resolved).toBe('domain-corp-local');
  });

  it('marks nodes without strong identity material as unresolved', () => {
    const identity = resolveNodeIdentity({
      id: 'bh-user-s-1-5-21-x',
      type: 'user',
      label: 'mystery-user',
    });
    expect(identity.status).toBe('unresolved');
    expect(identity.id).toBe('bh-user-s-1-5-21-x');
  });
});
