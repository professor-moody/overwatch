// ============================================================
// Phase 1 (enterprise readiness) — IdP foundations.
//
// Pins the new identity-tier semantics:
//   - idp / idp_application / idp_principal node types accepted by the schema
//   - new edges (FEDERATES_WITH, AUTHENTICATES_VIA, ISSUES_TOKENS_FOR, etc.)
//     pass topology validation
//   - token credentials (oidc_*, saml_assertion, oauth_client_secret, pat,
//     app_password, session_cookie) flow through isCredentialUsableForAuth
//   - MFA gating: cred_mfa_required && !cred_mfa_satisfied → not usable
//   - cred_token_expires_at honored alongside valid_until
//   - credential coverage emits mfa_bypass_candidate frontier items for
//     MFA-blocked credentials so the planner still sees them
// ============================================================

import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { EdgeType, NodeProperties, EdgeProperties } from '../types.js';
import type { OverwatchGraph } from '../services/engine-context.js';
import { EngineContext } from '../services/engine-context.js';
import { createTestSandbox } from '../test-support/test-sandbox.js';

const testSandbox = createTestSandbox('identity-tier-foundations');
import {
  isCredentialUsableForAuth,
  isCredentialMfaBlocked,
  isTokenCredential,
  getCredentialMaterialKind,
} from '../services/credential-utils.js';
import { CredentialCoverageTracker } from '../services/credential-coverage.js';
import { validateEdgeEndpoints } from '../services/graph-schema.js';

const now = new Date().toISOString();

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, allowSelfLoops: true, type: 'directed' }) as OverwatchGraph;
}
function addNode(graph: OverwatchGraph, id: string, props: Partial<NodeProperties>) {
  graph.addNode(id, { id, label: id, discovered_at: now, confidence: 1.0, ...props } as NodeProperties);
}
function addEdge(graph: OverwatchGraph, src: string, tgt: string, type: string, extra: Record<string, unknown> = {}) {
  return graph.addEdge(src, tgt, { type, confidence: 1.0, discovered_at: now, ...extra } as EdgeProperties);
}
function makeConfig() {
  return {
    id: 'test-identity-tier',
    name: 'identity-tier test',
    created_at: '2026-05-07T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: ['acme.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 1 },
  } as any;
}

describe('Phase 1 — token credentials', () => {
  it('classifies oidc_access_token as a token credential', () => {
    const cred: NodeProperties = {
      id: 'cred-1', type: 'credential', label: 'access', discovered_at: now, confidence: 1,
      cred_type: 'oidc_token',
      cred_material_kind: 'oidc_access_token',
    };
    expect(isTokenCredential(cred)).toBe(true);
    expect(getCredentialMaterialKind(cred)).toBe('oidc_access_token');
    expect(isCredentialUsableForAuth(cred)).toBe(true);
  });

  it('refresh tokens are NOT directly usable (must be exchanged for an access token)', () => {
    const cred: NodeProperties = {
      id: 'cred-r', type: 'credential', label: 'refresh', discovered_at: now, confidence: 1,
      cred_material_kind: 'oidc_refresh_token',
    };
    expect(isCredentialUsableForAuth(cred)).toBe(false);
  });

  it('honors cred_token_expires_at independently of valid_until', () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const cred: NodeProperties = {
      id: 'cred-exp', type: 'credential', label: 'exp', discovered_at: now, confidence: 1,
      cred_material_kind: 'oidc_access_token',
      cred_token_expires_at: past,
    };
    expect(isCredentialUsableForAuth(cred)).toBe(false);
  });

  it('SAML assertions, PATs, app passwords, and session cookies are usable', () => {
    for (const kind of ['saml_assertion', 'pat', 'app_password', 'session_cookie'] as const) {
      const cred: NodeProperties = {
        id: `cred-${kind}`, type: 'credential', label: kind, discovered_at: now, confidence: 1,
        cred_material_kind: kind,
      };
      expect(isCredentialUsableForAuth(cred)).toBe(true);
    }
  });
});

describe('Phase 1 — MFA gating', () => {
  it('isCredentialMfaBlocked is true when required and not satisfied', () => {
    const blocked: NodeProperties = {
      id: 'cred-mfa', type: 'credential', label: 'mfa-blocked', discovered_at: now, confidence: 1,
      cred_material_kind: 'plaintext_password', cred_mfa_required: true,
    };
    expect(isCredentialMfaBlocked(blocked)).toBe(true);
    expect(isCredentialUsableForAuth(blocked)).toBe(false);
  });

  it('isCredentialMfaBlocked is false when MFA is satisfied (e.g. AiTM-captured cookie)', () => {
    const satisfied: NodeProperties = {
      id: 'cred-aitm', type: 'credential', label: 'aitm', discovered_at: now, confidence: 1,
      cred_material_kind: 'session_cookie', cred_mfa_required: true, cred_mfa_satisfied: true,
    };
    expect(isCredentialMfaBlocked(satisfied)).toBe(false);
    expect(isCredentialUsableForAuth(satisfied)).toBe(true);
  });

  it('explicit cred_usable_for_auth: true does NOT override an MFA block', () => {
    // The MFA gate fires before the explicit override — a cred you can't
    // actually use for auth must not present as usable just because the
    // parser flag says so.
    const overridden: NodeProperties = {
      id: 'cred-override', type: 'credential', label: 'override', discovered_at: now, confidence: 1,
      cred_material_kind: 'plaintext_password', cred_mfa_required: true,
      cred_usable_for_auth: true,
    };
    expect(isCredentialUsableForAuth(overridden)).toBe(false);
  });
});

describe('Phase 1 — graph schema accepts identity-tier edges', () => {
  it('FEDERATES_WITH between idp and domain validates', () => {
    const r = validateEdgeEndpoints('FEDERATES_WITH' as EdgeType, 'idp', 'domain', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(true);
  });

  it('AUTHENTICATES_VIA from webapp to idp_application validates', () => {
    const r = validateEdgeEndpoints('AUTHENTICATES_VIA' as EdgeType, 'webapp', 'idp_application', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(true);
  });

  it('ISSUES_TOKENS_FOR from idp_application to cloud_identity validates', () => {
    const r = validateEdgeEndpoints('ISSUES_TOKENS_FOR' as EdgeType, 'idp_application', 'cloud_identity', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(true);
  });

  it('MFA_REQUIRED_FOR from idp_principal to idp_application validates', () => {
    const r = validateEdgeEndpoints('MFA_REQUIRED_FOR' as EdgeType, 'idp_principal', 'idp_application', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(true);
  });

  it('VALID_FOR_APP from credential to idp_application validates', () => {
    const r = validateEdgeEndpoints('VALID_FOR_APP' as EdgeType, 'credential', 'idp_application', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(true);
  });

  it('BACKED_BY from webapp to cloud_resource validates (cross-tier)', () => {
    const r = validateEdgeEndpoints('BACKED_BY' as EdgeType, 'webapp', 'cloud_resource', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(true);
  });

  it('rejects ASSIGNED_TO_APP with a host source (wrong direction)', () => {
    const r = validateEdgeEndpoints('ASSIGNED_TO_APP' as EdgeType, 'host', 'idp_application', { source_id: 'a', target_id: 'b' });
    expect(r.valid).toBe(false);
  });
});

describe('Phase 1 — coverage filters MFA-blocked creds + emits mfa_bypass_candidate', () => {
  it('MFA-blocked credentials are excluded from the untested-pair list', () => {
    const graph = makeGraph();
    addNode(graph, 'user-1', { type: 'user', username: 'jdoe', domain_name: 'acme.local' });
    addNode(graph, 'cred-mfa', {
      type: 'credential',
      cred_type: 'plaintext',
      cred_material_kind: 'plaintext_password',
      cred_mfa_required: true,
      cred_domain: 'acme.local',
    });
    addEdge(graph, 'user-1', 'cred-mfa', 'OWNS_CRED');
    addNode(graph, 'host-1', { type: 'host', alive: true, ip: '10.10.10.5', domain_name: 'acme.local' });
    addNode(graph, 'svc-smb', { type: 'service', service_name: 'smb', port: 445 });
    addEdge(graph, 'host-1', 'svc-smb', 'RUNS');

    const ctx = new EngineContext(graph, makeConfig(), testSandbox.path('test-state-identity.json'));
    const tracker = new CredentialCoverageTracker(ctx);
    const result = tracker.compute();
    expect(result.untested_pairs.length).toBe(0);
  });

  it('MFA-blocked credentials surface as mfa_bypass_candidate frontier items', () => {
    const graph = makeGraph();
    addNode(graph, 'user-1', { type: 'user', username: 'jdoe' });
    addNode(graph, 'cred-mfa', {
      type: 'credential',
      cred_type: 'plaintext',
      cred_material_kind: 'plaintext_password',
      cred_mfa_required: true,
      cred_user: 'jdoe',
    });
    addEdge(graph, 'user-1', 'cred-mfa', 'OWNS_CRED');

    const ctx = new EngineContext(graph, makeConfig(), testSandbox.path('test-state-identity.json'));
    const tracker = new CredentialCoverageTracker(ctx);
    const items = tracker.computeFrontierItems();
    const mfaItem = items.find(i => i.type === 'mfa_bypass_candidate');
    expect(mfaItem).toBeDefined();
    expect(mfaItem!.credential_id).toBe('cred-mfa');
    expect(mfaItem!.description).toMatch(/MFA-blocked/);
  });
});
