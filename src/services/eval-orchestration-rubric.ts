// ============================================================
// Prompt behavior-eval — orchestration rubric (PRIMARY orchestrator)
// ============================================================
// Grades a PRIMARY/orchestrator run, as opposed to the sub-agent task rubric in
// eval-rubric.ts. The orchestrator's job is different: orient → score the frontier
// → dispatch the right archetypes → synthesize completed children → progress the
// objectives. Pure + deterministic over a normalized run record, so it grades a
// (non-deterministic) real-model run reproducibly AND unit-tests on canned input.
//
// NB: it deliberately does NOT gate on terminal `completed` status — a real primary
// runs an open-ended loop and the headless runner reconciles its exit to
// `interrupted` (it never self-closes its own task). Completion is not the signal;
// orchestration behavior is.

/** One tool call from the primary's transcript, in order. */
export interface OrchToolCall {
  tool: string;
}

/** A sub-agent the primary dispatched. `matchedFrontier` = the chosen archetype
 *  suited the frontier item it was dispatched for (computed by the harness via the
 *  archetype recommender), so the rubric stays a pure comparison. */
export interface DispatchRecord {
  archetype: string;
  matchedFrontier: boolean;
}

export interface OrchRunRecord {
  /** The primary's tool calls, in order. */
  toolCalls: OrchToolCall[];
  /** Children the primary dispatched. */
  dispatches: DispatchRecord[];
  /** Graph nodes added during the run (children's landed findings). */
  newNodeCount: number;
}

export type OrchCriterion =
  | 'orients'
  | 'externalizes_decisions'
  | 'dispatches'
  | 'archetype_match'
  | 'synthesizes'
  | 'objective_progress';

export interface OrchCriterionScore {
  criterion: OrchCriterion;
  score: number;
  weight: number;
  detail: string;
}

export interface OrchRubricResult {
  overall: number;
  criteria: OrchCriterionScore[];
}

const ORCH_WEIGHTS: Record<OrchCriterion, number> = {
  orients: 1,
  externalizes_decisions: 1,
  dispatches: 1,
  archetype_match: 2,   // picking the right type per frontier item — core orchestration
  synthesizes: 2,       // re-orienting after a child completes — core orchestration
  objective_progress: 1,
};

export const ORCH_CRITERIA: readonly OrchCriterion[] = [
  'orients', 'externalizes_decisions', 'dispatches', 'archetype_match', 'synthesizes', 'objective_progress',
];

const ORIENT_TOOLS = new Set(['get_state', 'get_agent_context']);
const DISPATCH_TOOLS = new Set(['dispatch_agents', 'register_agent']);
const PREAMBLE_TOOLS = new Set(['ToolSearch', 'get_skill', 'get_system_prompt']);

/** Orient first: the primary's first meaningful call is get_state/get_agent_context. */
function scoreOrients(r: OrchRunRecord): { score: number; detail: string } {
  const meaningful = r.toolCalls.filter(c => !PREAMBLE_TOOLS.has(c.tool));
  if (meaningful.length === 0) return { score: 0, detail: 'no tool calls' };
  return ORIENT_TOOLS.has(meaningful[0].tool)
    ? { score: 1, detail: `first call: ${meaningful[0].tool}` }
    : { score: 0, detail: `first call was ${meaningful[0].tool}, not get_state/get_agent_context` };
}

/** Externalize scoring: a log_thought precedes the first dispatch/execute. */
function scoreExternalizes(r: OrchRunRecord): { score: number; detail: string } {
  const firstActionIdx = r.toolCalls.findIndex(c => DISPATCH_TOOLS.has(c.tool) || c.tool === 'run_tool' || c.tool === 'run_bash');
  if (firstActionIdx < 0) return { score: 0, detail: 'no dispatch/execute to reason before' };
  const reasonedFirst = r.toolCalls.slice(0, firstActionIdx).some(c => c.tool === 'log_thought');
  return reasonedFirst
    ? { score: 1, detail: 'log_thought before first dispatch/execute' }
    : { score: 0, detail: 'dispatched/executed without a prior log_thought' };
}

/** Did the primary parallelize via dispatch at all? */
function scoreDispatches(r: OrchRunRecord): { score: number; detail: string } {
  return r.dispatches.length > 0
    ? { score: 1, detail: `${r.dispatches.length} dispatch(es)` }
    : { score: 0, detail: 'no sub-agents dispatched' };
}

/** Did dispatched archetypes suit their frontier items? */
function scoreArchetypeMatch(r: OrchRunRecord): { score: number; detail: string } {
  if (r.dispatches.length === 0) return { score: 0, detail: 'no dispatches to match' };
  const matched = r.dispatches.filter(d => d.matchedFrontier).length;
  return { score: matched / r.dispatches.length, detail: `${matched}/${r.dispatches.length} dispatches matched the frontier item type` };
}

/** Synthesis: the primary re-oriented (get_state/get_agent_context) AFTER dispatching,
 *  i.e. folded results back in rather than firing and forgetting. */
function scoreSynthesizes(r: OrchRunRecord): { score: number; detail: string } {
  const firstDispatchIdx = r.toolCalls.findIndex(c => DISPATCH_TOOLS.has(c.tool));
  if (firstDispatchIdx < 0) return { score: 0, detail: 'never dispatched' };
  const reorientedAfter = r.toolCalls.slice(firstDispatchIdx + 1).some(c => ORIENT_TOOLS.has(c.tool));
  return reorientedAfter
    ? { score: 1, detail: 'get_state/get_agent_context after a dispatch (synthesis)' }
    : { score: 0, detail: 'no re-orientation after dispatching (fire-and-forget)' };
}

export function gradeOrchestration(run: OrchRunRecord): OrchRubricResult {
  const raw: Array<{ criterion: OrchCriterion; score: number; detail: string }> = [
    { criterion: 'orients', ...scoreOrients(run) },
    { criterion: 'externalizes_decisions', ...scoreExternalizes(run) },
    { criterion: 'dispatches', ...scoreDispatches(run) },
    { criterion: 'archetype_match', ...scoreArchetypeMatch(run) },
    { criterion: 'synthesizes', ...scoreSynthesizes(run) },
    { criterion: 'objective_progress', score: run.newNodeCount > 0 ? 1 : 0, detail: `${run.newNodeCount} new graph node(s)` },
  ];
  const totalWeight = raw.reduce((s, c) => s + ORCH_WEIGHTS[c.criterion], 0) || 1;
  const criteria: OrchCriterionScore[] = raw.map(c => ({
    criterion: c.criterion,
    score: c.score,
    weight: ORCH_WEIGHTS[c.criterion] / totalWeight,
    detail: c.detail,
  }));
  return { overall: criteria.reduce((s, c) => s + c.score * c.weight, 0), criteria };
}
