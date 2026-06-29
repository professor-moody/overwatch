// ============================================================
// Prompt behavior-eval — scenario library
// ============================================================
// A SMALL set of focused, deterministically-seeded scenarios. Each pairs a
// seeded engagement state + archetype with: a `fakeMode` (for the deterministic
// plumbing smoke) and a rubric (expected behavior + node deltas). Kept tiny so a
// real-model run (Phase 2) stays cheap. The fakeMode aligns with the matching
// fake-claude mode so the plumbing smoke produces a deterministic graph delta.

import type { ScenarioRubric } from '../services/eval-rubric.js';

export interface EvalScenario {
  id: string;
  /** Archetype to dispatch (sets the tool surface + mission + prompt). */
  archetype: string;
  /** fake-claude mode for the deterministic plumbing smoke (Phase 2). */
  fakeMode: string;
  /** Seed nodes ingested before dispatch. */
  seedNodes?: Array<Record<string, unknown>>;
  /** Scope the agent's subgraph to the seeded nodes. */
  scopeSeededNodes?: boolean;
  /** Objective text for real-model runs (Phase 2). */
  objective: string;
  rubric: ScenarioRubric;
}

export const EVAL_SCENARIOS: EvalScenario[] = [
  {
    id: 'recon',
    archetype: 'recon_scanner',
    fakeMode: 'recon',
    seedNodes: [{ type: 'host', label: '10.10.10.10', ip: '10.10.10.10', alive: true }],
    scopeSeededNodes: true,
    objective: 'Enumerate services on the in-scope host 10.10.10.10 and record what is exposed.',
    rubric: { id: 'recon', expectedNodeTypes: ['service'] },
  },
  {
    id: 'web',
    archetype: 'web_tester',
    fakeMode: 'web',
    seedNodes: [{ type: 'webapp', label: 'http://10.10.10.20', url: 'http://10.10.10.20' }],
    scopeSeededNodes: true,
    objective: 'Test the web surface at http://10.10.10.20 for exposed endpoints and web vulnerabilities.',
    rubric: { id: 'web', expectedNodeTypes: ['vulnerability'] },
  },
  {
    id: 'cloud',
    archetype: 'cloud_cartographer',
    fakeMode: 'cloud',
    seedNodes: [{ type: 'credential', label: 'aws-access-key', cred_type: 'token', cred_material_kind: 'token' }],
    scopeSeededNodes: true,
    objective: 'Expand the captured AWS credential and map the access + roles it unlocks.',
    rubric: { id: 'cloud', expectedNodeTypes: ['cloud_identity'] },
  },
];

export function getScenario(id: string): EvalScenario | undefined {
  return EVAL_SCENARIOS.find(s => s.id === id);
}
