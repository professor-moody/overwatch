// ============================================================
// B.1 — Attack Paths section in generate_report.
//
// `buildAttackPaths` decorates raw path-analyzer output (just node-id
// tuples) with edge metadata so the renderer can show confirmed vs
// inferred hops with per-edge confidence. `renderAttackPathsSection`
// produces the markdown for the report.
// ============================================================

import { describe, it, expect } from 'vitest';
import { buildAttackPaths, renderAttackPathsSection } from '../services/report-generator.js';
import type { ExportedGraph } from '../types.js';

const now = '2026-05-08T00:00:00Z';

function makeGraph(): ExportedGraph {
  return {
    nodes: [
      { id: 'host-jump', properties: { id: 'host-jump', type: 'host', label: 'jumpbox.acme', discovered_at: now, confidence: 1.0 } },
      { id: 'cred-saml', properties: { id: 'cred-saml', type: 'credential', label: 'saml-prod', discovered_at: now, confidence: 0.9 } },
      { id: 'idp-app', properties: { id: 'idp-app', type: 'idp_application', label: 'AWS Console', discovered_at: now, confidence: 1.0 } },
      { id: 'cloud-id', properties: { id: 'cloud-id', type: 'cloud_identity', label: 'arn:aws:iam::111:role/Admin', discovered_at: now, confidence: 1.0 } },
    ],
    edges: [
      { id: 'e1', source: 'host-jump', target: 'cred-saml', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now } },
      { id: 'e2', source: 'cred-saml', target: 'idp-app', properties: { type: 'VALID_FOR_APP', confidence: 0.7, discovered_at: now, inferred_by_rule: 'saml_round_trip' } },
      { id: 'e3', source: 'idp-app', target: 'cloud-id', properties: { type: 'ASSUMES_ROLE', confidence: 1.0, discovered_at: now } },
    ],
  } as ExportedGraph;
}

describe('buildAttackPaths', () => {
  it('decorates each step with label/type and per-hop edge metadata', () => {
    const raw = [{ nodes: ['host-jump', 'cred-saml', 'idp-app', 'cloud-id'], total_confidence: 0.7, total_opsec_noise: 0.3 }];
    const paths = buildAttackPaths(raw, makeGraph(), { objective_id: 'obj-1', objective_label: 'Crown jewel' });
    expect(paths).toHaveLength(1);
    const p = paths[0];
    expect(p.objective_id).toBe('obj-1');
    expect(p.steps).toHaveLength(4);
    expect(p.steps[0].label).toBe('jumpbox.acme');
    expect(p.steps[0].type).toBe('host');
    expect(p.steps[0].edge_to_next?.type).toBe('OWNS_CRED');
    expect(p.steps[0].edge_to_next?.inferred).toBe(false);
    expect(p.steps[1].edge_to_next?.type).toBe('VALID_FOR_APP');
    expect(p.steps[1].edge_to_next?.inferred).toBe(true);
    expect(p.steps[1].edge_to_next?.rule).toBe('saml_round_trip');
    expect(p.steps[3].edge_to_next).toBeUndefined();
    expect(p.contains_inferred).toBe(true);
  });

  it('dedupes paths with identical node sequences', () => {
    const raw = [
      { nodes: ['host-jump', 'cred-saml', 'idp-app', 'cloud-id'], total_confidence: 0.7, total_opsec_noise: 0.3 },
      { nodes: ['host-jump', 'cred-saml', 'idp-app', 'cloud-id'], total_confidence: 0.7, total_opsec_noise: 0.3 },
    ];
    const paths = buildAttackPaths(raw, makeGraph());
    expect(paths).toHaveLength(1);
  });

  it('handles missing edges gracefully (no crash, edge_to_next undefined)', () => {
    const graph = makeGraph();
    graph.edges = []; // strip all edges
    const raw = [{ nodes: ['host-jump', 'cred-saml'], total_confidence: 1.0, total_opsec_noise: 0 }];
    const paths = buildAttackPaths(raw, graph);
    expect(paths[0].steps[0].edge_to_next).toBeUndefined();
    expect(paths[0].contains_inferred).toBe(false);
  });
});

describe('renderAttackPathsSection', () => {
  it('returns empty string when no paths', () => {
    expect(renderAttackPathsSection([])).toBe('');
  });

  it('renders the section with grouping by objective', () => {
    const raw = [{ nodes: ['host-jump', 'cred-saml', 'idp-app', 'cloud-id'], total_confidence: 0.7, total_opsec_noise: 0.3 }];
    const paths = buildAttackPaths(raw, makeGraph(), { objective_id: 'obj-1', objective_label: 'Crown jewel' });
    const md = renderAttackPathsSection(paths);
    expect(md).toContain('## Attack Paths');
    expect(md).toContain('### Objective: Crown jewel');
    expect(md).toContain('jumpbox.acme');
    expect(md).toContain('VALID_FOR_APP');
    expect(md).toContain('inferred by `saml_round_trip`');
    expect(md).toContain('contains inferred hops');
  });

  it('omits the objective subheading when no objective_id is provided', () => {
    const raw = [{ nodes: ['host-jump', 'cred-saml'], total_confidence: 1.0, total_opsec_noise: 0 }];
    const paths = buildAttackPaths(raw, makeGraph());
    const md = renderAttackPathsSection(paths);
    expect(md).toContain('## Attack Paths');
    expect(md).not.toContain('### Objective:');
  });
});
