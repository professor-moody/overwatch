import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { assembleReport } from '../report-assembler.js';
import { SkillIndex } from '../skill-index.js';
import type { EngagementConfig } from '../../types.js';

// Cluster C / review #4b: an objective is "proof-backed" only when the ACCESS that obtained it
// is evidenced (the mature obtaining edge's creating action captured evidence), not merely that
// the target node was observed to exist.
const dirs: string[] = [];

function runObjectiveProof(evidenceUnderEdgeAction: boolean): { achieved: number; proof_ready: number } {
  const dir = mkdtempSync(join(tmpdir(), 'objproof-'));
  dirs.push(dir);
  const config = {
    id: 't', name: 't', created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: ['lab.local'], exclusions: [] },
    objectives: [{ id: 'obj-da', description: 'DA', target_node_type: 'credential', target_criteria: { privileged: true, cred_domain: 'lab.local' }, achieved: false }],
    opsec: { name: 'pentest', enabled: true, max_noise: 1.0 },
  } as EngagementConfig;
  const engine = new GraphEngine(config, join(dir, 'state.json'));
  engine.ingestFinding({
    id: 's', agent_id: 'nxc', action_id: 'a', timestamp: '2026-01-01T00:00:00Z',
    target_node_ids: ['u', 'cred-da'],
    nodes: [
      { id: 'u', type: 'user', label: 'u' },
      { id: 'cred-da', type: 'credential', label: 'admin', cred_type: 'ntlm', cred_user: 'admin', cred_domain: 'lab.local', privileged: true },
    ],
    edges: [{ source: 'u', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } }],
  } as never);
  const edgeAction = String(engine.exportGraph().edges.find(e => e.properties.type === 'OWNS_CRED')!.properties.discovered_by_action_id ?? '');
  engine.getEvidenceStore().store({
    agent_id: 'nxc', evidence_type: 'command_output', raw_output: 'owned', node_ids: ['cred-da'],
    action_id: evidenceUnderEdgeAction ? edgeAction : 'unrelated',
  } as never);
  const json = JSON.parse(assembleReport(engine, new SkillIndex('./skills'), { format: 'json', profile: 'operator' }).content) as {
    engagement_scorecard: { objectives: { achieved: number; proof_ready: number } };
  };
  return json.engagement_scorecard.objectives;
}

describe('objective proof-backing requires supporting-chain evidence', () => {
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

  it('is proof-backed when the obtaining access edge\'s action captured evidence', () => {
    const r = runObjectiveProof(true);
    expect(r.achieved).toBe(1);
    expect(r.proof_ready).toBe(1);
  });

  it('is NOT proof-backed when only unrelated (existence-style) node evidence exists', () => {
    const r = runObjectiveProof(false);
    expect(r.achieved).toBe(1);   // the objective is still achieved (mature access edge)…
    expect(r.proof_ready).toBe(0); // …but not proof-backed — the access itself isn't evidenced
  });
});
