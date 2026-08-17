import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { computeEngagementScorecardForEngine } from '../engagement-quality.js';

const dirs: string[] = [];
const engines: GraphEngine[] = [];

function engineWithDaObjective(): GraphEngine {
  const dir = mkdtempSync(join(tmpdir(), 'eng-quality-'));
  dirs.push(dir);
  const config: EngagementConfig = {
    id: 'eq', name: 'eq', created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: ['lab.local'], exclusions: [] },
    objectives: [{ id: 'obj-da', description: 'DA', target_node_type: 'credential', target_criteria: { privileged: true, cred_domain: 'lab.local' }, achieved: false }],
    opsec: { name: 'test', max_noise: 1, enabled: false },
  };
  const engine = new GraphEngine(config, join(dir, 'state.json'));
  engines.push(engine);
  return engine;
}

afterEach(() => {
  for (const e of engines.splice(0)) e.dispose();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('computeEngagementScorecardForEngine — live currently_satisfied convergence', () => {
  it('drops currently_satisfied when a supporting claim decays by TIME, though stored state has not been re-evaluated', () => {
    const engine = engineWithDaObjective();
    // Set up + validate the DA credential inside the validity window, so the STORED objective
    // state is achieved + currently_satisfied = true at that instant.
    const edgeId = (engine as any).ctx.withClock('2026-07-16T00:30:00.000Z', () => {
      engine.ingestFinding({
        id: 'f', agent_id: 'nxc', action_id: 'a', timestamp: '2026-07-16T00:00:00.000Z',
        target_node_ids: ['u', 'cred-da'],
        nodes: [
          { id: 'u', type: 'user', label: 'u' },
          { id: 'cred-da', type: 'credential', label: 'admin', cred_type: 'ntlm', cred_user: 'admin', cred_domain: 'lab.local', privileged: true },
        ],
        edges: [{ source: 'u', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-07-16T00:00:00.000Z' } }],
      } as never);
      const id = engine.exportGraph().edges.find(e => e.properties.type === 'OWNS_CRED')!.id!;
      engine.promoteClaim({ edge_id: id, state: 'validated', reason: 'valid window', by_kind: 'operator', valid_until: '2026-07-16T01:00:00.000Z' });
      return id;
    });
    expect(edgeId).toBeTruthy();
    // Stored state was set while valid.
    expect(engine.getState().objectives.find(o => o.id === 'obj-da')!.currently_satisfied).toBe(true);

    const scoreAt = (nowIso: string) => (engine as any).ctx.withClock(nowIso, () => computeEngagementScorecardForEngine(engine));

    // Still within the window — achieved AND currently satisfied.
    const before = scoreAt('2026-07-16T00:45:00.000Z');
    expect(before.objectives.achieved).toBe(1);
    expect(before.objectives.currently_satisfied).toBe(1);

    // After the window elapses, with NO intervening mutation (stored currently_satisfied is still
    // true) — the live derivation drops it while the milestone stays recorded.
    const after = scoreAt('2026-07-16T09:00:00.000Z');
    expect(after.objectives.achieved).toBe(1);            // milestone recorded
    expect(after.objectives.currently_satisfied).toBe(0); // live: supporting claim decayed
    expect(engine.getState().objectives.find(o => o.id === 'obj-da')!.currently_satisfied).toBe(true); // stored NOT re-evaluated
  });
});
