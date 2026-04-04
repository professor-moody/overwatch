import { describe, expect, it } from 'vitest';
import { parseLabSmokeArgs, validateProvenanceForHost } from '../lab-smoke-lib.js';
import type { ExportedGraph } from '../../types.js';

describe('lab smoke harness helpers', () => {
  it('parses only the supported CLI flags', () => {
    expect(parseLabSmokeArgs(['--keep-state', '--verbose'])).toEqual({
      keepState: true,
      verbose: true,
      profile: undefined,
    });
    expect(parseLabSmokeArgs([])).toEqual({
      keepState: false,
      verbose: false,
      profile: undefined,
    });
  });

  it('parses --profile flag', () => {
    expect(parseLabSmokeArgs(['--profile', 'network'])).toEqual({
      keepState: false,
      verbose: false,
      profile: 'network',
    });
    expect(parseLabSmokeArgs(['--keep-state', '--profile', 'cloud', '--verbose'])).toEqual({
      keepState: true,
      verbose: true,
      profile: 'cloud',
    });
  });

  it('validates provenance for a converged host', () => {
    const graph: ExportedGraph = {
      nodes: [
        {
          id: 'host-10-10-10-20',
          properties: {
            id: 'host-10-10-10-20',
            type: 'host',
            label: 'srv01.acme.local',
            discovered_at: '2026-03-22T00:00:00.000Z',
            discovered_by: 'bloodhound-ingest',
            first_seen_at: '2026-03-22T00:00:00.000Z',
            last_seen_at: '2026-03-22T00:00:02.000Z',
            confirmed_at: '2026-03-22T00:00:00.000Z',
            confidence: 1.0,
            sources: ['bloodhound-ingest', 'nmap-parser', 'nxc-parser'],
            ip: '10.10.10.20',
          },
        },
      ],
      edges: [],
    };

    const expectedSources = ['bloodhound-ingest', 'nmap-parser', 'nxc-parser'];
    const result = validateProvenanceForHost(graph, graph, 'host-10-10-10-20', expectedSources);
    expect(result.passed).toBe(true);
    expect(result.checks.sources_complete).toBe(true);
    expect(result.sources).toContain('bloodhound-ingest');
    expect(result.sources).toContain('nmap-parser');
    expect(result.sources).toContain('nxc-parser');
  });
});
