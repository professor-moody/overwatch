// ============================================================
// Agent-capability evals: drive an archetype end-to-end via fake-claude and
// assert it produces the graph findings it should. Regression-tests that an
// archetype is *useful*, not just correctly tool-scoped. Extensible — one
// fake-claude mode + one `it` per archetype.
// ============================================================
import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { resolve } from 'path';
import { chmodSync } from 'fs';
import { createServer } from 'net';
import { runArchetype, type ArchetypeEvalResult } from '../test-support/archetype-eval.js';

const supportsLocalListen = await new Promise<boolean>((resolveP) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); resolveP(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); resolveP(true); });
});

describe.skipIf(!supportsLocalListen)('Archetype capability evals (fake claude)', () => {
  let result: ArchetypeEvalResult | null = null;

  beforeAll(() => { chmodSync(resolve('./src/test-support/fake-claude.mjs'), 0o755); });
  afterEach(async () => { if (result) await result.cleanup(); result = null; });

  it('recon_scanner discovers host + service nodes and completes', async () => {
    result = await runArchetype({ archetype: 'recon_scanner', fakeMode: 'recon' });
    expect(result.task?.status).toBe('completed');
    // Node ids are canonicalized on ingest, so match by content (like the
    // headless e2e test does), not by the agent-supplied id.
    const hosts = result.app.engine.getNodesByType('host');
    const svcs = result.app.engine.getNodesByType('service');
    expect(hosts.some(n => JSON.stringify(n).includes('10.10.10.42'))).toBe(true);
    expect(svcs.length).toBeGreaterThan(0);
    const reported = result.app.engine.getFullHistory().some(
      e => e.event_type === 'finding_reported' || e.event_type === 'finding_ingested',
    );
    expect(reported).toBe(true);
  });

  it('web_tester records a webapp + vulnerability and completes', async () => {
    result = await runArchetype({ archetype: 'web_tester', fakeMode: 'web' });
    expect(result.task?.status).toBe('completed');
    expect(result.app.engine.getNodesByType('webapp').some(n => JSON.stringify(n).includes('10.10.10.50'))).toBe(true);
    expect(result.app.engine.getNodesByType('vulnerability').length).toBeGreaterThan(0);
  });

  it('opsec_sentinel reads OPSEC status and completes (get_opsec_status end-to-end)', async () => {
    // The agent crashes (→ interrupted) if get_opsec_status errors, so a
    // 'completed' status proves the new read-only tool works through the MCP path.
    result = await runArchetype({ archetype: 'opsec_sentinel', fakeMode: 'opsec' });
    expect(result.task?.status).toBe('completed');
  });

  it('evidence_auditor rolls up finding readiness and completes (get_finding_readiness end-to-end)', async () => {
    // Seed a public cloud_resource — the one finding-producing node that needs no
    // edges (report-generator: public resource is a finding on its own). The audit
    // mode throws (→ interrupted) if get_finding_readiness returns the wrong shape,
    // so 'completed' proves the new read-only tool works through the MCP path.
    result = await runArchetype({
      archetype: 'evidence_auditor',
      fakeMode: 'audit',
      // Flat node fields — ingestion spreads `...node` into the stored props, so
      // report-generator (which reads n.properties.public) sees them. A nested
      // `properties:{}` would be stored as an inert sub-object and yield 0 findings.
      seedNodes: [{
        id: 'cloud-res-eval', type: 'cloud_resource', label: 's3://eval-public-bucket',
        public: true, resource_type: 's3_bucket', provider: 'aws', region: 'us-east-1',
      }],
    });
    expect(result.task?.status).toBe('completed');
    // The rollup actually counted the seeded finding: the transcript summary
    // (surfaced in the agent_transcript_submitted event) reports a non-zero total.
    const audited = result.app.engine.getFullHistory().some(
      e => e.event_type === 'agent_transcript_submitted' && /audited [1-9]\d* finding/.test(e.description ?? ''),
    );
    expect(audited).toBe(true);
  });

  it('cloud_cartographer maps a cloud identity assuming a role and completes', async () => {
    result = await runArchetype({ archetype: 'cloud_cartographer', fakeMode: 'cloud' });
    expect(result.task?.status).toBe('completed');
    const identities = result.app.engine.getNodesByType('cloud_identity');
    expect(identities.some(n => JSON.stringify(n).includes('role/AdminRole'))).toBe(true);
    // The ASSUMES_ROLE edge (the cartographer's federation/role-assumption signature) landed.
    const hasAssumeEdge = result.app.engine.exportGraph().edges.some(e => e.properties.type === 'ASSUMES_ROLE');
    expect(hasAssumeEdge).toBe(true);
  });

  it('session_shepherd lists + reads a seeded session and completes (read-only session tools end-to-end)', async () => {
    // The fixture seeds one open session via a mock adapter. The shepherd crashes
    // (→ interrupted) if list_sessions/read_session error, so 'completed' proves the
    // read-only session tools work through the session_shepherd allowlist.
    result = await runArchetype({ archetype: 'session_shepherd', fakeMode: 'shepherd', seedSession: true });
    expect(result.task?.status).toBe('completed');
    // The shepherd actually saw the seeded session (non-zero count in its transcript).
    const reviewed = result.app.engine.getFullHistory().some(
      e => e.event_type === 'agent_transcript_submitted' && /reviewed [1-9]\d* session/.test(e.description ?? ''),
    );
    expect(reviewed).toBe(true);
  });
});
