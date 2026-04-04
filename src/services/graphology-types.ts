// ============================================================
// Overwatch — Graphology Type Wrappers
// Typed re-exports and helpers that eliminate scattered `as any`
// casts needed for CJS/ESM interop with graphology packages.
// The interop casts are centralised here.
// ============================================================

import GraphConstructor from 'graphology';
import louvainDefault from 'graphology-communities-louvain';
import type { LouvainOptions } from 'graphology-communities-louvain';
import type { AbstractGraph, Attributes, GraphOptions } from 'graphology-types';
import type { OverwatchGraph } from './engine-context.js';

// graphology publishes CJS with a default export that doesn't unwrap cleanly
// under Node16 module resolution. Resolve the actual constructor once here so
// every other module can import typed factory functions instead.
interface GraphClass {
  new (options?: GraphOptions): AbstractGraph;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Graph: GraphClass = (GraphConstructor as any).default ?? GraphConstructor;

if (typeof Graph !== 'function') {
  throw new Error('Failed to import graphology Graph constructor — check CJS/ESM interop');
}

type LouvainFn = (graph: AbstractGraph, options?: LouvainOptions) => Record<string, number>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const louvain: LouvainFn = (louvainDefault as any).default ?? louvainDefault;

/**
 * Run Louvain community detection on a graph and return node→community mapping.
 * Wraps the CJS/ESM interop so callers don't need `as any`.
 */
export function assignLouvainCommunities(
  graph: AbstractGraph,
  options?: LouvainOptions,
): Record<string, number> {
  return louvain(graph, options);
}

/**
 * Create a new directed multi-graph suitable for the Overwatch engine.
 */
export function createOverwatchGraph(): OverwatchGraph {
  return new Graph({ type: 'directed', multi: true, allowSelfLoops: false }) as OverwatchGraph;
}

/**
 * Create a new directed simple graph (used for path-analysis projections).
 */
export function createDirectedSimpleGraph(): OverwatchGraph {
  return new Graph({ type: 'directed', multi: false, allowSelfLoops: false }) as OverwatchGraph;
}

/**
 * Create a new undirected simple graph (used for community-detection projections).
 */
export function createUndirectedSimpleGraph(): AbstractGraph<Attributes, Attributes> {
  return new Graph({ type: 'undirected', multi: false, allowSelfLoops: false });
}

export type { LouvainOptions };
