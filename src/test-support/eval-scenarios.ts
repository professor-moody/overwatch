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
  hermeticTooling?: 'nmap-recon' | 'nuclei-web' | 'aws-sts-cloud';
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
    fakeMode: 'hermetic-web',
    seedNodes: [{ id: 'seed-web-app', type: 'webapp', label: 'http://10.10.10.20', url: 'http://10.10.10.20' }],
    scopeSeededNodes: true,
    hermeticTooling: 'nuclei-web',
    objective: `Qualification mission for the in-scope synthetic web app http://10.10.10.20. Complete these steps in order:
1. Call get_agent_context first and use its frontier_item_id.
2. Call validate_action for a nuclei web vulnerability scan with that frontier_item_id and a stable action_id you will reuse.
3. Call run_tool with binary "nuclei", args ["-u", "http://10.10.10.20", "-jsonl"], target_url "http://10.10.10.20", the same action_id/frontier_item_id, and parse_with "nuclei". Do not use raw shell or an absolute scanner path.
4. Ensure the exposed admin vulnerability is parsed into the graph; if inline parsing did not land it, use parse_output or report_finding with the same action/frontier attribution.
5. Submit your transcript, then mark the task completed.`,
    rubric: { id: 'web', expectedNodeTypes: ['vulnerability'] },
  },
  {
    id: 'cloud',
    archetype: 'cloud_cartographer',
    fakeMode: 'hermetic-cloud',
    seedNodes: [{ id: 'seed-cloud-cred', type: 'credential', label: 'aws-access-key', cred_type: 'token', cred_material_kind: 'token' }],
    scopeSeededNodes: true,
    hermeticTooling: 'aws-sts-cloud',
    objective: `Qualification mission for the synthetic AWS credential in your scoped context. Complete these steps in order:
1. Call get_agent_context first and use its frontier_item_id and credential node ID.
2. Call validate_action for AWS caller-identity enumeration against that credential node, using technique "recon_cloud_identity", the frontier_item_id, and a stable action_id you will reuse.
3. Call run_tool with binary "aws", args ["sts", "get-caller-identity", "--output", "json"], target_node set to the credential ID, the same action_id/frontier_item_id, parse_with "aws-sts-identity", and parser_context.source_credential_id set to the credential ID. Do not use ambient credentials, raw shell, or an absolute AWS CLI path.
4. Ensure the returned AWS identity is parsed into the graph and attributed to the source credential; if inline parsing did not land it, use parse_output or report_finding with the same action/frontier attribution.
5. Submit your transcript, then mark the task completed.`,
    rubric: { id: 'cloud', expectedNodeTypes: ['cloud_identity'] },
  },
];

export function getScenario(id: string): EvalScenario | undefined {
  return EVAL_SCENARIOS.find(s => s.id === id);
}
