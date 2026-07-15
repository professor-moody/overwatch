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

  it('cve_researcher records a CVE candidate for its assigned service and completes', async () => {
    // Seed a versioned service and scope the agent's subgraph to it — the research
    // mode reads its subgraph, finds the service, and records a candidate via
    // research_cve (web-research only; no target execution).
    result = await runArchetype({
      archetype: 'cve_researcher',
      fakeMode: 'research',
      seedNodes: [{ id: 'svc-cve-eval', type: 'service', label: 'http/2.4.49', service_name: 'http', product: 'apache', version: '2.4.49', port: 80, protocol: 'tcp' }],
      scopeSeededNodes: true,
    });
    expect(result.task?.status).toBe('completed');
    // research_cve recorded the applicable candidate as a vulnerability node.
    const vulns = result.app.engine.getNodesByType('vulnerability');
    expect(vulns.some(n => JSON.stringify(n).includes('CVE-2021-41773'))).toBe(true);
  });

  it('pathfinder proposes a confirmable plan via propose_plan and completes', async () => {
    // The planner mode submits a valid plan (a scope op needs no peer task), so
    // 'completed' + a recorded proposed plan proves the read-only propose_plan path.
    result = await runArchetype({ archetype: 'pathfinder', fakeMode: 'planner' });
    expect(result.task?.status).toBe('completed');
    expect(result.app.engine.getProposedPlanStore().getOpen().length).toBeGreaterThan(0);
  });

  it('credential_operator expands its assigned AWS credential into a recon plan and completes', async () => {
    // Seed an STS-flavored token credential and scope the agent to it; the cred mode
    // finds it and runs expand_aws_credential (plan generation, no live AWS).
    result = await runArchetype({
      archetype: 'credential_operator',
      fakeMode: 'cred',
      seedNodes: [{
        id: 'aws-cred-eval', type: 'credential', label: 'oidc-sts-token',
        cred_type: 'oidc_access_token', cred_material_kind: 'oidc_access_token',
        cred_value: 'eyJhbG.fake.sts-token', cred_user: 'svc-deploy',
        cred_audience: 'sts.amazonaws.com', cred_usable_for_auth: true, credential_status: 'active',
      }],
      scopeSeededNodes: true,
    });
    expect(result.task?.status).toBe('completed');
    // Plan generation is deliberately stateless until durable PlaybookRun state
    // lands; completing this capability must not retire the credential.
    const cred = result.app.engine.getNodesByType('credential').find(n => JSON.stringify(n).includes('svc-deploy'));
    expect(cred).toBeDefined();
    expect(cred?.recon_playbook_invoked_at).toBeUndefined();
  });

  it('post_exploit records a lateral admin-access edge and completes', async () => {
    result = await runArchetype({ archetype: 'post_exploit', fakeMode: 'postex' });
    expect(result.task?.status).toBe('completed');
    // The post-exploitation signature: an ADMIN_TO edge between a foothold and a pivot.
    const hasAdminEdge = result.app.engine.exportGraph().edges.some(e => e.properties.type === 'ADMIN_TO');
    expect(hasAdminEdge).toBe(true);
  });

  it('report_scribe drafts a report from confirmed state and completes (generate_report end-to-end)', async () => {
    // Seed a finding-producing node so the report has real content to draft.
    result = await runArchetype({
      archetype: 'report_scribe',
      fakeMode: 'scribe',
      seedNodes: [{
        id: 'cloud-res-scribe', type: 'cloud_resource', label: 's3://scribe-public-bucket',
        public: true, resource_type: 's3_bucket', provider: 'aws', region: 'us-east-1',
      }],
    });
    expect(result.task?.status).toBe('completed');
    const drafted = result.app.engine.getFullHistory().some(
      e => e.event_type === 'agent_transcript_submitted' && /drafted a \d+-char report/.test(e.description ?? ''),
    );
    expect(drafted).toBe(true);
  });

  // Orchestration-eval fidelity: the 'auto' fake mode reads its OWN archetype from
  // get_agent_context and lands type-appropriate findings (so a real primary's
  // dispatched fake children look real). This is the fake-child-fidelity crux.
  it("'auto' mode lands web findings for a web_tester child (archetype-aware)", async () => {
    result = await runArchetype({ archetype: 'web_tester', fakeMode: 'auto' });
    expect(result.task?.status).toBe('completed');
    expect(result.app.engine.getNodesByType('vulnerability').length).toBeGreaterThan(0);
    expect(result.app.engine.getNodesByType('webapp').length).toBeGreaterThan(0);
    // It did NOT land recon-shaped findings — it matched its archetype.
    expect(result.app.engine.getNodesByType('service').length).toBe(0);
  });

  it("'auto' mode lands recon findings for a recon_scanner child (archetype-aware)", async () => {
    result = await runArchetype({ archetype: 'recon_scanner', fakeMode: 'auto' });
    expect(result.task?.status).toBe('completed');
    expect(result.app.engine.getNodesByType('service').length).toBeGreaterThan(0);
    expect(result.app.engine.getNodesByType('vulnerability').length).toBe(0);
  });
});
