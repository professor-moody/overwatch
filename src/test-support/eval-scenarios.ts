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
  /** Synthetic tool fixture installed into the isolated evaluation runtime. */
  hermeticTooling?: 'nmap-recon';
  rubric: ScenarioRubric;
}

export const EVAL_SCENARIOS: EvalScenario[] = [
  {
    id: 'recon',
    archetype: 'recon_scanner',
    fakeMode: 'hermetic-recon',
    seedNodes: [{ id: 'seed-recon-host', type: 'host', label: '10.10.10.10', ip: '10.10.10.10', alive: true }],
    scopeSeededNodes: true,
    hermeticTooling: 'nmap-recon',
    objective: `Qualification mission for the in-scope synthetic host 10.10.10.10. Complete these steps in order:
1. Call get_agent_context first and use its frontier_item_id.
2. Call validate_action for nmap service enumeration with that frontier_item_id and a stable action_id you will reuse.
3. Call run_tool with binary "nmap", args ["-sV", "-oX", "-", "10.10.10.10"], target_ip "10.10.10.10", the same action_id/frontier_item_id, and parse_with "nmap". Do not use raw shell or an absolute scanner path.
4. Ensure the SSH and HTTP results are parsed into the graph; if inline parsing did not land them, use parse_output or report_finding with the same action/frontier attribution.
5. Submit your transcript, then mark the task completed.`,
    rubric: { id: 'recon', expectedNodeTypes: ['service'] },
  },
  {
    id: 'web',
    archetype: 'web_tester',
    fakeMode: 'web',
    seedNodes: [{ id: 'seed-web-app', type: 'webapp', label: 'http://10.10.10.20', url: 'http://10.10.10.20' }],
    scopeSeededNodes: true,
    objective: 'Test the web surface at http://10.10.10.20 for exposed endpoints and web vulnerabilities.',
    rubric: { id: 'web', expectedNodeTypes: ['vulnerability'] },
  },
  {
    id: 'cloud',
    archetype: 'cloud_cartographer',
    fakeMode: 'cloud',
    seedNodes: [{ id: 'seed-cloud-cred', type: 'credential', label: 'aws-access-key', cred_type: 'token', cred_material_kind: 'token' }],
    scopeSeededNodes: true,
    objective: 'Expand the captured AWS credential and map the access + roles it unlocks.',
    rubric: { id: 'cloud', expectedNodeTypes: ['cloud_identity'] },
  },
];

export function getScenario(id: string): EvalScenario | undefined {
  return EVAL_SCENARIOS.find(s => s.id === id);
}
