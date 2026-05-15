import { describe, expect, it } from 'vitest';
import {
  getCredentialKindLabel,
  getCredentialMaterialKind,
  isCredentialReachable,
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
});
