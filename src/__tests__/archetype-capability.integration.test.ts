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
});
