// ============================================================
// Prompt behavior-eval — deterministic rubric grader
// ============================================================
// Scores an agent run for loop-compliance: did it behave the way the operating
// instructions tell it to? Pure + deterministic given a run, so it can grade a
// (non-deterministic) real-model run reproducibly AND be unit-tested on canned
// inputs. The harness maps a real run (transcript tool calls + engine activity
// log + graph delta + task status) into a `RunRecord`; this module is the scorer.
//
// It does NOT judge offensive *quality* (that needs an LLM judge — parked). It
// measures the structural behaviors the prompt is supposed to elicit, so a
// restructured prompt that drops one shows up as a lower criterion score.

/** One tool invocation from the agent's transcript, in call order. */
export interface ToolCall {
  tool: string;
  action_id?: string;
  frontier_item_id?: string;
}

/** A relevant engine activity-log entry for the agent (side effects). */
export interface ActivityLite {
  event_type?: string;
  action_id?: string;
  frontier_item_id?: string;
}

export interface RunRecord {
  /** Transcript tool calls in order (get_agent_context, validate_action, run_tool, …). */
  toolCalls: ToolCall[];
  /** The agent's activity-log entries (for frontier_item_id threading + outcomes). */
  activity: ActivityLite[];
  /** Terminal task status. */
  taskStatus: string;
  /** Node types added to the graph during the run (delta). */
  newNodeTypes: string[];
}

export type RubricCriterion =
  | 'starts_with_context'
  | 'validate_before_execute'
  | 'threads_frontier_item_id'
  | 'lands_results'
  | 'objective_progress'
  | 'completed';

export interface ScenarioRubric {
  id: string;
  /** Node types the scenario expects the agent to discover (objective_progress). */
  expectedNodeTypes?: string[];
  /** Per-criterion weight overrides; unspecified criteria use DEFAULT_WEIGHTS. */
  weights?: Partial<Record<RubricCriterion, number>>;
}

export interface CriterionScore {
  criterion: RubricCriterion;
  score: number;   // 0..1
  weight: number;  // normalized share of the overall
  detail: string;
}

export interface RubricResult {
  overall: number; // 0..1, weighted
  criteria: CriterionScore[];
}

const DEFAULT_WEIGHTS: Record<RubricCriterion, number> = {
  starts_with_context: 1,
  validate_before_execute: 2,   // safety-load-bearing → weighted higher
  threads_frontier_item_id: 1,
  lands_results: 2,             // no-drift → weighted higher
  objective_progress: 2,
  completed: 1,
};

const CONTEXT_TOOLS = new Set(['get_state', 'get_agent_context']);
const EXECUTE_TOOLS = new Set(['run_tool', 'run_bash']);
const LAND_TOOLS = new Set(['parse_output', 'report_finding']);

/** First criterion: the agent should orient before acting — its first tool call
 *  (ignoring tool discovery) is get_state / get_agent_context. */
function scoreStartsWithContext(r: RunRecord): { score: number; detail: string } {
  const meaningful = r.toolCalls.filter(c => c.tool !== 'ToolSearch' && c.tool !== 'get_skill');
  if (meaningful.length === 0) return { score: 0, detail: 'no tool calls' };
  const first = meaningful[0].tool;
  return CONTEXT_TOOLS.has(first)
    ? { score: 1, detail: `first call: ${first}` }
    : { score: 0, detail: `first call was ${first}, not get_state/get_agent_context` };
}

/** Every execute (run_tool/run_bash) should be preceded by a validate_action for
 *  the same action_id (or, if action_ids are absent, by at least one prior
 *  validate_action). */
function scoreValidateBeforeExecute(r: RunRecord): { score: number; detail: string } {
  const executes = r.toolCalls.filter(c => EXECUTE_TOOLS.has(c.tool));
  if (executes.length === 0) return { score: 1, detail: 'no executes to gate' };
  const validatedActionIds = new Set<string>();
  let sawAnyValidate = false;
  let ok = 0;
  for (const c of r.toolCalls) {
    if (c.tool === 'validate_action') {
      sawAnyValidate = true;
      if (c.action_id) validatedActionIds.add(c.action_id);
      continue;
    }
    if (EXECUTE_TOOLS.has(c.tool)) {
      const gated = c.action_id ? validatedActionIds.has(c.action_id) : sawAnyValidate;
      if (gated) ok++;
    }
  }
  return { score: ok / executes.length, detail: `${ok}/${executes.length} executes had a prior validate_action` };
}

/** Action lifecycle events should carry frontier_item_id for retrospective
 *  attribution (mirrors retrospective.analyzeLoggingQuality). */
function scoreThreading(r: RunRecord): { score: number; detail: string } {
  const ACTION_EVENTS = new Set(['action_validated', 'action_started', 'action_completed', 'action_failed']);
  const actionEvents = r.activity.filter(e => e.event_type && ACTION_EVENTS.has(e.event_type));
  if (actionEvents.length === 0) return { score: 1, detail: 'no action events to thread' };
  const threaded = actionEvents.filter(e => !!e.frontier_item_id).length;
  return { score: threaded / actionEvents.length, detail: `${threaded}/${actionEvents.length} action events carried frontier_item_id` };
}

/** Discoveries must land in the graph (parse_output/report_finding), not be left
 *  in prose — the no-drift invariant. Scored as: did the agent land at least one
 *  result when the scenario expects discovery? */
function scoreLandsResults(r: RunRecord, scenario: ScenarioRubric): { score: number; detail: string } {
  const landed = r.toolCalls.some(c => LAND_TOOLS.has(c.tool))
    || r.activity.some(e => e.event_type === 'finding_reported' || e.event_type === 'finding_ingested' || e.event_type === 'parse_output');
  if (!scenario.expectedNodeTypes?.length) {
    return { score: landed ? 1 : 1, detail: landed ? 'landed results' : 'no discovery expected' };
  }
  return landed ? { score: 1, detail: 'landed results via parse_output/report_finding' } : { score: 0, detail: 'discovery expected but nothing landed (prose-only drift)' };
}

/** Objective progress: the run produced the node types the scenario expects. */
function scoreObjectiveProgress(r: RunRecord, scenario: ScenarioRubric): { score: number; detail: string } {
  const expected = scenario.expectedNodeTypes ?? [];
  if (expected.length === 0) return { score: 1, detail: 'no expected node types' };
  const got = new Set(r.newNodeTypes);
  const matched = expected.filter(t => got.has(t));
  return { score: matched.length / expected.length, detail: `${matched.length}/${expected.length} expected node types produced (${matched.join(', ') || 'none'})` };
}

export function gradeRun(run: RunRecord, scenario: ScenarioRubric): RubricResult {
  const raw: Array<{ criterion: RubricCriterion; score: number; detail: string }> = [
    { criterion: 'starts_with_context', ...scoreStartsWithContext(run) },
    { criterion: 'validate_before_execute', ...scoreValidateBeforeExecute(run) },
    { criterion: 'threads_frontier_item_id', ...scoreThreading(run) },
    { criterion: 'lands_results', ...scoreLandsResults(run, scenario) },
    { criterion: 'objective_progress', ...scoreObjectiveProgress(run, scenario) },
    { criterion: 'completed', score: run.taskStatus === 'completed' ? 1 : 0, detail: `status: ${run.taskStatus}` },
  ];
  const weightOf = (c: RubricCriterion) => scenario.weights?.[c] ?? DEFAULT_WEIGHTS[c];
  const totalWeight = raw.reduce((sum, c) => sum + weightOf(c.criterion), 0) || 1;
  const criteria: CriterionScore[] = raw.map(c => ({
    criterion: c.criterion,
    score: c.score,
    weight: weightOf(c.criterion) / totalWeight,
    detail: c.detail,
  }));
  const overall = criteria.reduce((sum, c) => sum + c.score * c.weight, 0);
  return { overall, criteria };
}

/** Compare a candidate run's grade against a control baseline; flags regressions. */
export interface AbComparison {
  control: number;
  candidate: number;
  delta: number;
  regressions: Array<{ criterion: RubricCriterion; control: number; candidate: number }>;
}

// ============================================================
// Tier-1 structural guard — does a generated prompt still CONTAIN the
// load-bearing affordances the rubric grades behavior against? Deterministic,
// no model. A restructured prompt that drops one fails here in CI, before any
// real-model run. Variant-agnostic (takes the prompt string), so step (b)'s
// candidate prompt is checked the same way.
// ============================================================

/** Tools a sub_agent prompt must mention so the agent can be loop-compliant.
 *  These are the STABLE workflow-section affordances (always present regardless
 *  of agent context); frontier_item_id threading is conditional prose, so it's
 *  measured behaviorally by the grader's threads_frontier_item_id criterion
 *  rather than asserted structurally here. */
export const REQUIRED_SUBAGENT_AFFORDANCES = [
  'get_agent_context',       // orient (starts_with_context)
  'validate_action',         // validate_before_execute
  'report_finding',          // lands_results
  'parse_output',            // lands_results
  'submit_agent_transcript', // clean close-out
] as const;

export function checkPromptAffordances(
  prompt: string,
  required: readonly string[] = REQUIRED_SUBAGENT_AFFORDANCES,
): { ok: boolean; missing: string[] } {
  const missing = required.filter(token => !prompt.includes(token));
  return { ok: missing.length === 0, missing };
}

export function compareGrades(control: RubricResult, candidate: RubricResult, regressionEpsilon = 0.01): AbComparison {
  const byCrit = (r: RubricResult) => new Map(r.criteria.map(c => [c.criterion, c.score]));
  const cMap = byCrit(control);
  const dMap = byCrit(candidate);
  const regressions: AbComparison['regressions'] = [];
  for (const [crit, cScore] of cMap) {
    const dScore = dMap.get(crit) ?? 0;
    if (dScore < cScore - regressionEpsilon) regressions.push({ criterion: crit, control: cScore, candidate: dScore });
  }
  return { control: control.overall, candidate: candidate.overall, delta: candidate.overall - control.overall, regressions };
}
