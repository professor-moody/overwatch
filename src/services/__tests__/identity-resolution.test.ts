import { describe, expect, it } from 'vitest';
import { classifyPrincipalIdentity, getIdentityMarkers, resolveNodeIdentity, resolveTypedRelationRef } from '../identity-resolution.js';

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

  it('does not create canonical credential identity without a qualified domain', () => {
    const identity = resolveNodeIdentity({
      id: 'cred-administrator-ntlm',
      type: 'credential',
      label: 'administrator hash',
      cred_type: 'ntlm',
      cred_material_kind: 'ntlm_hash',
      cred_hash: '11223344556677889900aabbccddeeff',
      cred_user: 'administrator',
    });
    expect(identity.status).toBe('unresolved');
    expect(identity.id).toBe('cred-administrator-ntlm');
  });

  it('generates short hostname markers from FQDNs for host nodes', () => {
    const markers = getIdentityMarkers({
      id: 'host-10-3-10-23',
      type: 'host',
      hostname: 'braavos.essos.local',
      ip: '10.3.10.23',
    });
    expect(markers).toContain('host:ip:10-3-10-23');
    expect(markers).toContain('host:name:braavos-essos-local');
    expect(markers).toContain('host:name:braavos');
  });

  it('short hostname marker matches across FQDN and bare hostname', () => {
    const fqdnMarkers = getIdentityMarkers({
      id: 'host-10-3-10-23',
      type: 'host',
      hostname: 'braavos.essos.local',
      ip: '10.3.10.23',
    });
    const bareMarkers = getIdentityMarkers({
      id: 'host-braavos',
      type: 'host',
      hostname: 'BRAAVOS',
    });
    const overlap = fqdnMarkers.filter(m => bareMarkers.includes(m));
    expect(overlap.length).toBeGreaterThan(0);
    expect(overlap).toContain('host:name:braavos');
  });

  it('generates short-domain marker for users with FQDN domain', () => {
    const markers = getIdentityMarkers({
      id: 'user-north-sevenkingdoms-local-samwell-tarly',
      type: 'user',
      username: 'samwell.tarly',
      domain_name: 'north.sevenkingdoms.local',
    });
    expect(markers).toContain('user:acct:north-sevenkingdoms-local:samwell-tarly');
    expect(markers).toContain('user:acct:north:samwell-tarly');
  });

  it('short-domain marker enables NetBIOS↔FQDN user reconciliation', () => {
    const fqdnMarkers = getIdentityMarkers({
      id: 'user-north-sevenkingdoms-local-samwell-tarly',
      type: 'user',
      username: 'samwell.tarly',
      domain_name: 'north.sevenkingdoms.local',
    });
    const netbiosMarkers = getIdentityMarkers({
      id: 'user-north-samwell-tarly',
      type: 'user',
      username: 'samwell.tarly',
      domain_name: 'NORTH',
    });
    const overlap = fqdnMarkers.filter(m => netbiosMarkers.includes(m));
    expect(overlap.length).toBeGreaterThan(0);
    expect(overlap).toContain('user:acct:north:samwell-tarly');
  });

  it('generates short-domain marker for groups with FQDN domain', () => {
    const markers = getIdentityMarkers({
      id: 'group-north-sevenkingdoms-local-domain-admins',
      type: 'group',
      label: 'Domain Admins',
      samaccountname: 'Domain Admins',
      domain_name: 'north.sevenkingdoms.local',
    });
    expect(markers).toContain('group:acct:north-sevenkingdoms-local:domain-admins');
    expect(markers).toContain('group:acct:north:domain-admins');
  });

  it('does NOT add short-domain marker for single-label domains', () => {
    const markers = getIdentityMarkers({
      id: 'user-north-samwell-tarly',
      type: 'user',
      username: 'samwell.tarly',
      domain_name: 'NORTH',
    });
    // Should have the primary marker but NOT a short-domain duplicate
    expect(markers).toContain('user:acct:north:samwell-tarly');
    expect(markers.filter(m => m === 'user:acct:north:samwell-tarly').length).toBe(1);
  });

  it('does not treat credential material reuse as an identity marker', () => {
    const markers = getIdentityMarkers({
      id: 'cred-test',
      type: 'credential',
      label: 'admin hash',
      cred_type: 'ntlm',
      cred_material_kind: 'ntlm_hash',
      cred_hash: '11223344556677889900aabbccddeeff',
      cred_user: 'administrator',
      cred_domain: 'north.sevenkingdoms.local',
    });
    expect(markers).toContain('credential:acct:north-sevenkingdoms-local:administrator');
    expect(markers.some(marker => marker.startsWith('credential:material:'))).toBe(false);
  });
});
