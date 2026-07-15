import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../../services/graph-engine.js';
import { recordCveResearch } from '../research-cve.js';
import { allowedToolsFor } from '../../services/headless-mcp-runner.js';
import type { EngagementConfig, Finding } from '../../types.js';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-research-cve', name: 'research test', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function seedService(engine: GraphEngine, id: string, version = '2.4.49') {
  const finding: Finding = {
    id: `seed-${id}`, agent_id: 'test', timestamp: new Date().toISOString(),
    nodes: [{ id, type: 'service', label: `http/${id}`, service_name: 'apache', version }],
    edges: [],
  };
  engine.ingestFinding(finding);
}

function hasCveFrontier(engine: GraphEngine, serviceId: string): boolean {
  return engine.computeFrontier().some(f => f.type === 'cve_research' && f.node_id === serviceId);
}

describe('allowedToolsFor (headless role profiles)', () => {
  it('research role adds web tools + research_cve, and EXCLUDES target execution', () => {
    const research = allowedToolsFor('research');
    expect(research).toContain('WebSearch');
    expect(research).toContain('WebFetch');
    expect(research).toContain('mcp__overwatch__research_cve');
    expect(research).toContain('mcp__overwatch__report_finding');
    // No target-facing tools, and not the whole-server grant.
    expect(research).not.toContain('run_bash');
    expect(research).not.toContain('run_tool');
    expect(research).not.toContain('open_session');
    expect(research).not.toContain('mcp__overwatch ');
  });
  it('default role keeps the full Overwatch surface', () => {
    expect(allowedToolsFor('default')).toBe('mcp__overwatch ToolSearch');
  });
});

describe('recordCveResearch + cve_research frontier lifecycle', () => {
  let engine: GraphEngine;
  let testDir: string;
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-research-cve-'));
    engine = new GraphEngine(makeConfig(), join(testDir, 'state.json'));
  });
  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('a versioned, uncovered service surfaces a cve_research frontier item', () => {
    seedService(engine, 'svc-1');
    expect(hasCveFrontier(engine, 'svc-1')).toBe(true);
  });

  it('ingests applicable candidates as vulnerability nodes + retires the frontier item', () => {
    seedService(engine, 'svc-1');
    const res = recordCveResearch(engine, {
      service_id: 'svc-1', agent_id: 'cve-agent', summary: 'Apache 2.4.49 path traversal',
      candidates: [
        { cve: 'CVE-2021-41773', title: 'Apache path traversal', cvss: 7.5, vuln_type: 'lfi', exploit_available: true, poc_url: 'https://example/poc', applicable: true, confidence: 0.8 },
        { cve: 'CVE-2000-0000', title: 'not relevant', applicable: false },
      ],
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.candidates_recorded).toBe(1); // only the applicable one

    const vulns = engine.getNodesByType('vulnerability');
    expect(vulns.some(v => v.cve === 'CVE-2021-41773')).toBe(true);
    // service stamped + frontier item gone
    expect(engine.getNode('svc-1')?.cve_checked_at).toBeDefined();
    expect(hasCveFrontier(engine, 'svc-1')).toBe(false);
  });

  it('terminates the loop even when NO candidates are found (empty list still stamps cve_checked_at)', () => {
    seedService(engine, 'svc-2');
    expect(hasCveFrontier(engine, 'svc-2')).toBe(true);
    const res = recordCveResearch(engine, { service_id: 'svc-2', summary: 'nothing found', candidates: [] });
    expect(res.ok).toBe(true);
    expect(engine.getNode('svc-2')?.cve_checked_at).toBeDefined();
    expect(hasCveFrontier(engine, 'svc-2')).toBe(false); // does not regenerate
  });

  it('logs a cve_research_recorded event', () => {
    seedService(engine, 'svc-3');
    const before = engine.getFullHistory().length;
    recordCveResearch(engine, { service_id: 'svc-3', summary: 's', candidates: [] });
    const after = engine.getFullHistory().slice(before);
    expect(after.some(e => (e.details as any)?.reason === 'cve_research_recorded')).toBe(true);
  });

  it('rejects an unknown / non-service node', () => {
    const res = recordCveResearch(engine, { service_id: 'nope', summary: 's', candidates: [] });
    expect(res.ok).toBe(false);
  });
});
