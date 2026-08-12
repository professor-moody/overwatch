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
 *  archetype recommender), so the rubric stays a pure comparison. `target` is the
 *  frontier item id it was dispatched against (for the dispatch-precision criterion;
 *  undefined for ad-hoc dispatches with no frontier item). */
export interface DispatchRecord {
  archetype: string;
  matchedFrontier: boolean;
  target?: string;
}

export interface OrchRunRecord {
  /** The primary's tool calls, in order. */
  toolCalls: OrchToolCall[];
  /** Children the primary dispatched. */
  dispatches: DispatchRecord[];
  /** Graph nodes added during the run (the engagement advanced). Coarse — creating a
   *  metadata node is not the same as making objective progress, so this only earns
   *  partial credit (see scoreObjectiveProgress). Orchestration credit comes from
   *  `dispatches`. */
  newNodeCount: number;
  /** Objectives the engagement actually achieved during the run (`objective_achieved`
   *  events) — the strongest objective-progress signal. Optional; absent → 0. */
  objectivesAchieved?: number;
  /** New access / credential / pivot edges created during the run (a shell, admin rights,
   *  a captured credential, a role assumption, a cross-tier pivot) — material offensive
   *  progress, as opposed to metadata or plain service discovery. Optional; absent → 0. */
  newAccessEdges?: number;
}

export type OrchCriterion =
  // Floor / regression-guard criteria — binary, a competent primary aces them
  // (the first real-model calibration scored all 6 at 1.0). They catch a regression
  // but can't measure an improvement.
  | 'orients'
  | 'externalizes_decisions'
  | 'dispatches'
  | 'archetype_match'
  | 'synthesizes'
  | 'objective_progress'
  // Discriminating criteria — CONTINUOUS, with headroom, so a prompt change shows a
  // fractional delta instead of a stuck-at-1.0 binary. Added after the calibration
  // run revealed the floor saturates (Move 3c finding).
  | 'dispatch_precision'    // didn't re-dispatch the same frontier item (no spam)
  | 'orient_efficiency'     // tight orientation — few meaningful calls before acting
  | 'adaptive_synthesis';   // closed the loop — re-dispatched on children's findings

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
  // Floor (8 total)
  orients: 1,
  externalizes_decisions: 1,
  dispatches: 1,
  archetype_match: 2,   // picking the right type per frontier item — core orchestration
  synthesizes: 2,       // re-orienting after a child completes — core orchestration
  objective_progress: 1,
  // Discriminating (6 total — ~43% of the score, so a prompt change moves `overall`)
  dispatch_precision: 2,
  orient_efficiency: 2,
  adaptive_synthesis: 2,
};

export const ORCH_CRITERIA: readonly OrchCriterion[] = [
  'orients', 'externalizes_decisions', 'dispatches', 'archetype_match', 'synthesizes', 'objective_progress',
  'dispatch_precision', 'orient_efficiency', 'adaptive_synthesis',
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

/** Dispatch precision: of dispatches that targeted a frontier item, the fraction that
 *  hit DISTINCT items — penalizes re-dispatching the same item (wasted agents). Neutral
 *  (1.0) when no dispatch carried a target, since there's nothing to over-spam. */
function scoreDispatchPrecision(r: OrchRunRecord): { score: number; detail: string } {
  const targeted = r.dispatches.filter(d => d.target);
  if (targeted.length === 0) return { score: 1, detail: 'no targeted dispatches to assess (neutral)' };
  const distinct = new Set(targeted.map(d => d.target)).size;
  return { score: distinct / targeted.length, detail: `${distinct}/${targeted.length} dispatches hit distinct frontier items` };
}

/** Orient efficiency: meaningful (non-preamble) tool-calls before the FIRST dispatch.
 *  Orient → reason → dispatch (~2-3) is tight; full credit up to 3, decaying to 0 by 8.
 *  Penalizes dawdling/over-orienting before acting. */
function scoreOrientEfficiency(r: OrchRunRecord): { score: number; detail: string } {
  const firstDispatchIdx = r.toolCalls.findIndex(c => DISPATCH_TOOLS.has(c.tool));
  if (firstDispatchIdx < 0) return { score: 0, detail: 'never dispatched' };
  const preamble = r.toolCalls.slice(0, firstDispatchIdx).filter(c => !PREAMBLE_TOOLS.has(c.tool)).length;
  const score = Math.max(0, Math.min(1, 1 - (preamble - 3) / 5));
  return { score, detail: `${preamble} meaningful call(s) before first dispatch` };
}

/** Adaptive synthesis: did the primary close the loop — re-orient after dispatching AND
 *  then dispatch AGAIN (adapting to what children found)? 0 = fire-and-forget; 0.5 =
 *  re-oriented but didn't act on it; 1 = re-dispatched after synthesizing. */
function scoreAdaptiveSynthesis(r: OrchRunRecord): { score: number; detail: string } {
  const firstDispatchIdx = r.toolCalls.findIndex(c => DISPATCH_TOOLS.has(c.tool));
  if (firstDispatchIdx < 0) return { score: 0, detail: 'never dispatched' };
  const afterFirst = r.toolCalls.slice(firstDispatchIdx + 1);
  const reorientIdx = afterFirst.findIndex(c => ORIENT_TOOLS.has(c.tool));
  if (reorientIdx < 0) return { score: 0, detail: 'no re-orientation after dispatching (fire-and-forget)' };
  const redispatched = afterFirst.slice(reorientIdx + 1).some(c => DISPATCH_TOOLS.has(c.tool));
  return redispatched
    ? { score: 1, detail: 're-dispatched after synthesizing (closed adaptive loop)' }
    : { score: 0.5, detail: 're-oriented after dispatch but did not adapt (no further dispatch)' };
}

/** Objective progress is graded by what actually moved the engagement forward, not by
 *  raw graph growth: an achieved objective is full credit; new access/credential/pivot
 *  edges are material progress; plain node creation (metadata, service discovery) earns
 *  only a small amount — creating a node is activity, not progress. */
function scoreObjectiveProgress(r: OrchRunRecord): { score: number; detail: string } {
  const achieved = r.objectivesAchieved ?? 0;
  const accessEdges = r.newAccessEdges ?? 0;
  if (achieved > 0) return { score: 1, detail: `${achieved} objective(s) achieved` };
  if (accessEdges > 0) return { score: 0.6, detail: `${accessEdges} new access/credential/pivot edge(s) — material progress` };
  if (r.newNodeCount > 0) return { score: 0.2, detail: `${r.newNodeCount} new node(s) — graph advanced, no access/objective progress` };
  return { score: 0, detail: 'no graph progress' };
}

export function gradeOrchestration(run: OrchRunRecord): OrchRubricResult {
  const raw: Array<{ criterion: OrchCriterion; score: number; detail: string }> = [
    { criterion: 'orients', ...scoreOrients(run) },
    { criterion: 'externalizes_decisions', ...scoreExternalizes(run) },
    { criterion: 'dispatches', ...scoreDispatches(run) },
    { criterion: 'archetype_match', ...scoreArchetypeMatch(run) },
    { criterion: 'synthesizes', ...scoreSynthesizes(run) },
    { criterion: 'objective_progress', ...scoreObjectiveProgress(run) },
    { criterion: 'dispatch_precision', ...scoreDispatchPrecision(run) },
    { criterion: 'orient_efficiency', ...scoreOrientEfficiency(run) },
    { criterion: 'adaptive_synthesis', ...scoreAdaptiveSynthesis(run) },
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

export interface OrchComparison {
  delta: number;
  regressions: Array<{ criterion: OrchCriterion; control: number; candidate: number }>;
}

/** A/B a candidate orchestration grade against control: overall delta + per-criterion
 *  regressions (candidate worse by more than `epsilon`, to ignore float noise). Mirrors
 *  the sub-agent rubric's compareGrades. */
export function compareOrchGrades(control: OrchRubricResult, candidate: OrchRubricResult, epsilon = 1e-9): OrchComparison {
  const byCriterion = new Map(control.criteria.map(c => [c.criterion, c.score]));
  const regressions = candidate.criteria
    .filter(c => { const base = byCriterion.get(c.criterion); return base != null && c.score < base - epsilon; })
    .map(c => ({ criterion: c.criterion, control: byCriterion.get(c.criterion)!, candidate: c.score }));
  return { delta: candidate.overall - control.overall, regressions };
}
