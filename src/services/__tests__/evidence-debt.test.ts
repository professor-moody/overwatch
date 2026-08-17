import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../graph-engine.js';
import { computeEvidenceDebt } from '../evidence-debt.js';

const dirs: string[] = [];
const engines: GraphEngine[] = [];

function engineFixture(objectives: EngagementConfig['objectives'] = []): GraphEngine {
  const dir = mkdtempSync(join(tmpdir(), 'evidence-debt-'));
  dirs.push(dir);
  const config: EngagementConfig = {
    id: 'ed', name: 'ed', created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: ['lab.local'], exclusions: [] },
    objectives,
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

describe('computeEvidenceDebt', () => {
  it('is empty for a clean engagement', () => {
    expect(computeEvidenceDebt(engineFixture())).toEqual([]);
  });

  it('surfaces a promotion-vs-evidence contradiction, ranked first', () => {
    const engine = engineFixture();
    engine.addNode({ id: 'host-x', type: 'host', label: '10.0.0.1', ip: '10.0.0.1', discovered_at: '2026-07-16T00:00:00.000Z', confidence: 1 });
    // Refuted, but its own evidence (confidence 1.0) is positive → a contradiction.
    engine.promoteClaim({ node_id: 'host-x', state: 'refuted', reason: 'disputing confirmed host', by_kind: 'operator' });

    const debt = computeEvidenceDebt(engine);
    const contradiction = debt.find(d => d.kind === 'contradiction');
    expect(contradiction).toBeTruthy();
    expect(contradiction!.node_id).toBe('host-x');
    expect(debt[0].severity).toBe(100); // contradictions rank first
  });

  it('surfaces a lapsed objective once its supporting claim decays by time', () => {
    const engine = engineFixture([
      { id: 'obj-da', description: 'Domain Admin', target_node_type: 'credential', target_criteria: { privileged: true, cred_domain: 'lab.local' }, achieved: false },
    ]);
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

    // Within the window — the milestone is currently satisfied, so no lapsed-objective debt.
    expect((engine as any).ctx.withClock('2026-07-16T00:45:00.000Z', () => computeEvidenceDebt(engine)).some((d: any) => d.kind === 'lapsed_objective')).toBe(false);

    // After the window elapses — the objective is reached but no longer satisfied → debt.
    const lapsed = (engine as any).ctx.withClock('2026-07-16T09:00:00.000Z', () => computeEvidenceDebt(engine)).find((d: any) => d.kind === 'lapsed_objective');
    expect(lapsed).toBeTruthy();
    expect(lapsed.objective_id).toBe('obj-da');
    expect(lapsed.node_id).toBe('cred-da'); // the matching target node, so a validation agent can be dispatched
  });
});
