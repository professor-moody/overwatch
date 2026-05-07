// ============================================================
// Overwatch — Golden-Master Replay Harness (P2.2)
//
// A "tape" is a deterministic recording of an engagement's MCP-level
// inputs (config + a sequence of operations + a pinned clock per op).
// Replaying a tape against a fresh engine produces a graph; we compute
// a stable hash of that graph and assert it matches a stored "golden"
// hash. Two replays of the same tape must produce byte-identical state
// (depends on P1.2 deterministic IDs + P1.3 caller-provided timestamps).
//
// Why this exists:
//   - Catches regressions across the WHOLE pipeline (parser → ingest →
//     inference → frontier) at one integration point.
//   - Validates that the determinism work in P1.2/P1.3 holds end-to-end.
//   - Tape divergence is intentional (re-record on purpose) — silent
//     drift is impossible.
//
// Tape format intentionally tiny — operations are direct engine calls,
// not MCP wire frames. Wire-frame replay is a later refinement; this
// version exercises the same data path with less ceremony.
// ============================================================

import { createHash } from 'crypto';
import type { GraphEngine } from './graph-engine.js';
import type { EngagementConfig, ExportedGraph, Finding, NodeProperties, EdgeProperties, EdgeType } from '../types.js';

export type TapeOperation =
  | { kind: 'add_node'; now: string; props: NodeProperties }
  | { kind: 'add_edge'; now: string; source: string; target: string; props: EdgeProperties }
  | { kind: 'ingest_finding'; now: string; finding: Finding }
  | { kind: 'log_event'; now: string; description: string; event_type?: string; details?: Record<string, unknown> };

export interface GoldenTape {
  schema_version: 1;
  name: string;
  description?: string;
  config: EngagementConfig;     // must include `engagement_nonce` for determinism
  operations: TapeOperation[];
  expected_graph_hash?: string; // sha256 of canonical(exportedGraph) — set on first record
  expected_activity_digest?: string; // sha256 of canonical(activity log without volatile timestamps)
}

/**
 * Stable JSON canonicalizer: sorts object keys recursively. Two
 * structurally-equivalent objects always serialize identically.
 */
function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
  }
  return 'null';
}

export function hashGraph(graph: ExportedGraph): string {
  // Sort nodes/edges by id so traversal order doesn't perturb the hash.
  const nodes = [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id));
  const edges = [...graph.edges].sort((a, b) => a.id.localeCompare(b.id));
  const cold = graph.cold_nodes ? [...graph.cold_nodes].sort((a, b) => a.id.localeCompare(b.id)) : undefined;
  const canonical = canonicalJson({ nodes, edges, ...(cold ? { cold_nodes: cold } : {}) });
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Hash of the activity log AFTER stripping volatile fields that would
 * differ run-to-run even with deterministic IDs (e.g., wall-clock-pinned
 * timestamps that the tape doesn't pin). With proper P1.3 clock pinning
 * this is identical across replays.
 */
export function hashActivity(history: Array<{ event_id: string; event_type?: string; description: string }>): string {
  const projected = history.map(e => ({
    event_id: e.event_id,
    event_type: e.event_type,
    description: e.description,
  }));
  return createHash('sha256').update(canonicalJson(projected)).digest('hex');
}

/**
 * Apply one operation to the engine. Each op declares its `now` so the
 * engine's clock is pinned for the duration of that op's mutations.
 */
export function applyOperation(engine: GraphEngine, op: TapeOperation): void {
  switch (op.kind) {
    case 'add_node':
      engine.withClock(op.now, () => engine.addNode(op.props));
      return;
    case 'add_edge':
      engine.withClock(op.now, () => engine.addEdge(op.source, op.target, op.props));
      return;
    case 'ingest_finding':
      engine.withClock(op.now, () => engine.ingestFinding(op.finding));
      return;
    case 'log_event':
      engine.withClock(op.now, () => engine.logActionEvent({
        description: op.description,
        event_type: op.event_type as never,
        details: op.details,
      }));
      return;
  }
}

export interface ReplayResult {
  graph_hash: string;
  activity_digest: string;
  graph: ExportedGraph;
  matches_expected: boolean;
}

/**
 * Replay a tape against a (presumed-fresh) engine. Returns the resulting
 * hashes plus a `matches_expected` flag if the tape carries golden hashes.
 *
 * Caller is responsible for providing a clean engine — the harness does
 * not reset state.
 */
export function replayTape(engine: GraphEngine, tape: GoldenTape): ReplayResult {
  for (const op of tape.operations) {
    applyOperation(engine, op);
  }
  const graph = engine.exportGraph();
  const graph_hash = hashGraph(graph);
  const activity_digest = hashActivity(engine.getFullHistory());
  const matches_expected =
    (tape.expected_graph_hash === undefined || tape.expected_graph_hash === graph_hash) &&
    (tape.expected_activity_digest === undefined || tape.expected_activity_digest === activity_digest);
  return { graph_hash, activity_digest, graph, matches_expected };
}

/**
 * Convenience: re-record a tape's expected hashes from an actual run.
 * Used by tape-recording tooling and by `npm test -- --update-golden`
 * style flows. The caller is responsible for committing the updated
 * tape JSON; this function returns the new tape, doesn't write it.
 */
export function rerecordTape(tape: GoldenTape, result: ReplayResult): GoldenTape {
  return {
    ...tape,
    expected_graph_hash: result.graph_hash,
    expected_activity_digest: result.activity_digest,
  };
}
