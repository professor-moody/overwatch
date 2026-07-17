import { isDeepStrictEqual } from 'node:util';
import type { EdgeProperties, NodeProperties } from '../types.js';
import type { ColdNodeRecord, ColdStoreEntrySnapshot } from './cold-store.js';
import type { EngineContext, GraphUpdateDetail } from './engine-context.js';
import type {
  EngineOperation,
  EngineOperationDraftObserver,
  EngineTransactionDraft,
} from './engine-transaction.js';
import { edgeIdentityMatches } from './edge-identity.js';

export interface GraphNodeSnapshot {
  node_id: string;
  props: NodeProperties;
}

export interface GraphEdgeSnapshot {
  edge_id: string;
  source: string;
  target: string;
  props: EdgeProperties;
}

export interface EntityChange<T> {
  before: T | null;
  after: T | null;
}

export type ColdEntrySnapshot = ColdStoreEntrySnapshot;

export type GraphColdInverse =
  | { kind: 'node'; node_id: string; snapshot: GraphNodeSnapshot | null }
  | { kind: 'edge'; edge_id: string; snapshot: GraphEdgeSnapshot | null }
  | { kind: 'cold'; snapshot: ColdEntrySnapshot };

export interface FinalizedTransactionFootprint {
  node_changes: Array<{ node_id: string } & EntityChange<GraphNodeSnapshot>>;
  edge_changes: Array<{ edge_id: string } & EntityChange<GraphEdgeSnapshot>>;
  cold_changes: Array<{ id: string } & EntityChange<ColdNodeRecord>>;
  update_detail: GraphUpdateDetail;
}

function cloneValue<T>(value: T): T {
  return structuredClone(value);
}

function cloneNullable<T>(value: T | null): T | null {
  return value === null ? null : cloneValue(value);
}

function snapshotsEqual<T>(left: T | null, right: T | null): boolean {
  return left === right || isDeepStrictEqual(left, right);
}

function appendChange<T>(
  changes: Map<string, EntityChange<T>>,
  id: string,
  before: T | null,
  after: T | null,
): void {
  const existing = changes.get(id);
  changes.set(id, {
    before: existing ? existing.before : cloneNullable(before),
    after: cloneNullable(after),
  });
}

function setDetailIds(
  detail: GraphUpdateDetail,
  key: keyof Pick<
    GraphUpdateDetail,
    | 'new_nodes'
    | 'updated_nodes'
    | 'removed_nodes'
    | 'new_edges'
    | 'updated_edges'
    | 'inferred_edges'
    | 'removed_edges'
  >,
  ids: string[],
): void {
  if (ids.length > 0) detail[key] = ids;
}

/**
 * Tracks only records touched by one speculative transaction. The first
 * preimage and latest postimage are retained so finalization describes the
 * net public effect rather than the union of intermediate primitive writes.
 */
export class TransactionFootprintAccumulator {
  private readonly nodeChanges = new Map<string, EntityChange<GraphNodeSnapshot>>();
  private readonly edgeChanges = new Map<string, EntityChange<GraphEdgeSnapshot>>();
  private readonly coldChanges = new Map<string, EntityChange<ColdNodeRecord>>();
  private readonly inferredEdgeIds = new Set<string>();

  recordNode(
    nodeId: string,
    before: GraphNodeSnapshot | null,
    after: GraphNodeSnapshot | null,
  ): void {
    appendChange(this.nodeChanges, nodeId, before, after);
  }

  recordEdge(
    edgeId: string,
    before: GraphEdgeSnapshot | null,
    after: GraphEdgeSnapshot | null,
  ): void {
    appendChange(this.edgeChanges, edgeId, before, after);
  }

  recordCold(
    id: string,
    before: ColdNodeRecord | null,
    after: ColdNodeRecord | null,
  ): void {
    appendChange(this.coldChanges, id, before, after);
  }

  markInferredEdge(edgeId: string): void {
    this.inferredEdgeIds.add(edgeId);
  }

  finalize(): FinalizedTransactionFootprint {
    const newNodes: string[] = [];
    const updatedNodes: string[] = [];
    const removedNodes: string[] = [];
    const newEdges: string[] = [];
    const updatedEdges: string[] = [];
    const removedEdges: string[] = [];
    const inferredEdges: string[] = [];

    const nodeChanges = Array.from(this.nodeChanges.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .flatMap(([nodeId, change]) => {
        if (snapshotsEqual(change.before, change.after)) return [];
        if (change.before === null) newNodes.push(nodeId);
        else if (change.after === null) removedNodes.push(nodeId);
        else updatedNodes.push(nodeId);
        return [{
          node_id: nodeId,
          before: cloneNullable(change.before),
          after: cloneNullable(change.after),
        }];
      });

    const edgeChanges = Array.from(this.edgeChanges.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .flatMap(([edgeId, change]) => {
        if (snapshotsEqual(change.before, change.after)) return [];
        if (change.before === null) newEdges.push(edgeId);
        else if (change.after === null) removedEdges.push(edgeId);
        else updatedEdges.push(edgeId);
        if (change.after !== null && this.inferredEdgeIds.has(edgeId)) {
          inferredEdges.push(edgeId);
        }
        return [{
          edge_id: edgeId,
          before: cloneNullable(change.before),
          after: cloneNullable(change.after),
        }];
      });

    const coldChanges = Array.from(this.coldChanges.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .flatMap(([id, change]) => snapshotsEqual(change.before, change.after)
        ? []
        : [{
            id,
            before: cloneNullable(change.before),
            after: cloneNullable(change.after),
          }]);

    const updateDetail: GraphUpdateDetail = {};
    setDetailIds(updateDetail, 'new_nodes', newNodes);
    setDetailIds(updateDetail, 'updated_nodes', updatedNodes);
    setDetailIds(updateDetail, 'removed_nodes', removedNodes);
    setDetailIds(updateDetail, 'new_edges', newEdges);
    setDetailIds(updateDetail, 'updated_edges', updatedEdges);
    setDetailIds(updateDetail, 'inferred_edges', inferredEdges);
    setDetailIds(updateDetail, 'removed_edges', removedEdges);
    if (coldChanges.length > 0) updateDetail.cold_nodes_changed = true;

    return {
      node_changes: nodeChanges,
      edge_changes: edgeChanges,
      cold_changes: coldChanges,
      update_detail: updateDetail,
    };
  }
}

type CapturedOperation =
  | { kind: 'none' }
  | {
      kind: 'node';
      operation_type: 'add_node' | 'merge_node_attrs' | 'replace_node_attrs';
      node_id: string;
      before: GraphNodeSnapshot | null;
    }
  | {
      kind: 'edge';
      operation_type: 'add_edge' | 'drop_edge' | 'merge_edge_attrs';
      edge_ids: string[];
      before: Map<string, GraphEdgeSnapshot | null>;
      inferred: boolean;
    }
  | {
      kind: 'graph_delta';
      nodes: Map<string, GraphNodeSnapshot | null>;
      edges: Map<string, GraphEdgeSnapshot | null>;
      inferred_edge_ids: Set<string>;
    }
  | {
      kind: 'cold';
      operation_type: 'cold_add' | 'cold_promote';
      before: ColdStoreEntrySnapshot;
    };

function nodeSnapshot(ctx: EngineContext, nodeId: string): GraphNodeSnapshot | null {
  return ctx.graph.hasNode(nodeId)
    ? {
        node_id: nodeId,
        props: structuredClone(ctx.graph.getNodeAttributes(nodeId) as NodeProperties),
      }
    : null;
}

function edgeSnapshot(ctx: EngineContext, edgeId: string): GraphEdgeSnapshot | null {
  return ctx.graph.hasEdge(edgeId)
    ? {
        edge_id: edgeId,
        source: ctx.graph.source(edgeId),
        target: ctx.graph.target(edgeId),
        props: structuredClone(ctx.graph.getEdgeAttributes(edgeId) as EdgeProperties),
      }
    : null;
}

function matchingEdgeIds(
  ctx: EngineContext,
  source: unknown,
  target: unknown,
  props: unknown,
): string[] {
  if (
    typeof source !== 'string'
    || typeof target !== 'string'
    || typeof props !== 'object'
    || props === null
    || !ctx.graph.hasNode(source)
    || !ctx.graph.hasNode(target)
  ) return [];
  return ctx.graph.edges(source, target).filter(edgeId =>
    edgeIdentityMatches(ctx.graph.getEdgeAttributes(edgeId), props as EdgeProperties));
}

/**
 * Records exact preimages and postimages while an already-eligible command is
 * drafted against live memory. It makes draft rollback and proof comparison
 * proportional to touched records. Unsupported composite operations fail
 * before their effect is applied; callers select this recorder only for
 * command paths whose operation vocabulary is bounded by construction.
 */
export class BoundedTransactionFootprintCapture implements EngineOperationDraftObserver {
  private readonly inverses: GraphColdInverse[] = [];
  private readonly accumulator = new TransactionFootprintAccumulator();

  constructor(private readonly ctx: EngineContext) {}

  authorizeMutation(
    target: 'graph' | 'cold_store',
    method: string,
    args: readonly unknown[],
    token: unknown,
  ): boolean {
    const captured = Array.isArray(token) ? token as CapturedOperation[] : [];
    if (target === 'cold_store') {
      if (method !== 'add' && method !== 'promote') return false;
      const id = method === 'add'
        ? (args[0] as { id?: unknown } | undefined)?.id
        : args[0];
      return typeof id === 'string' && captured.some(operation =>
        operation.kind === 'cold'
        && operation.before.id === id
        && (
          (operation.operation_type === 'cold_add' && method === 'add')
          || (operation.operation_type === 'cold_promote' && method === 'promote')
        ));
    }

    if (
      method === 'clear'
      || method === 'import'
      || method === 'replaceAttributes'
      || method === 'mergeAttributes'
      || method === 'setAttribute'
      || method === 'updateAttribute'
      || method === 'removeAttribute'
      || method === 'updateEachNodeAttributes'
      || method === 'updateEachEdgeAttributes'
      || method === 'clearEdges'
    ) return false;

    const primitiveNodeMethods = new Set(['addNode', 'mergeNodeAttributes', 'replaceNodeAttributes']);
    const identityNodeMethods = new Set(['addNode', 'replaceNodeAttributes', 'dropNode']);
    if (primitiveNodeMethods.has(method) || identityNodeMethods.has(method)) {
      const nodeId = args[0];
      return typeof nodeId === 'string' && captured.some(operation =>
        (
          operation.kind === 'node'
          && operation.node_id === nodeId
          && primitiveNodeMethods.has(method)
        )
        || (
          operation.kind === 'graph_delta'
          && operation.nodes.has(nodeId)
          && identityNodeMethods.has(method)
        ));
    }

    const primitiveEdgeMethods = new Set(['addEdgeWithKey', 'mergeEdgeAttributes', 'dropEdge']);
    const identityEdgeMethods = new Set(['addEdgeWithKey', 'dropEdge']);
    if (primitiveEdgeMethods.has(method) || identityEdgeMethods.has(method)) {
      const edgeId = args[0];
      return typeof edgeId === 'string' && captured.some(operation =>
        (
          operation.kind === 'edge'
          && operation.edge_ids.includes(edgeId)
          && (
            (operation.operation_type === 'add_edge'
              && (method === 'addEdgeWithKey' || method === 'mergeEdgeAttributes'))
            || (operation.operation_type === 'merge_edge_attrs' && method === 'mergeEdgeAttributes')
            || (operation.operation_type === 'drop_edge' && method === 'dropEdge')
          )
        )
        || (
          operation.kind === 'graph_delta'
          && operation.edges.has(edgeId)
          && identityEdgeMethods.has(method)
        ));
    }

    // Unkeyed edge creation/update cannot be proven against an immutable
    // edge_id and is therefore never eligible for bounded drafting.
    return false;
  }

  beforeOperation(draft: EngineTransactionDraft): CapturedOperation[] {
    return draft.operations.map(operation => this.captureBefore(operation));
  }

  afterOperation(draft: EngineTransactionDraft, token: unknown): void {
    const captured = token as CapturedOperation[];
    if (!Array.isArray(captured) || captured.length !== draft.operations.length) {
      throw new Error('Bounded transaction observer received an invalid operation token.');
    }
    for (let index = 0; index < draft.operations.length; index++) {
      this.captureAfter(draft.operations[index]!, captured[index]!);
    }
  }

  markInferredEdges(edgeIds: readonly string[]): void {
    for (const edgeId of edgeIds) this.accumulator.markInferredEdge(edgeId);
  }

  finalize(): FinalizedTransactionFootprint {
    return this.accumulator.finalize();
  }

  matchesCurrentAfter(expected = this.finalize()): boolean {
    for (const change of expected.node_changes) {
      if (!snapshotsEqual(change.after, nodeSnapshot(this.ctx, change.node_id))) return false;
    }
    for (const change of expected.edge_changes) {
      if (!snapshotsEqual(change.after, edgeSnapshot(this.ctx, change.edge_id))) return false;
    }
    for (const change of expected.cold_changes) {
      const current = this.ctx.coldStore.get(change.id);
      if (!snapshotsEqual(change.after, current ? structuredClone(current) : null)) return false;
    }
    return true;
  }

  restore(): void {
    for (let index = this.inverses.length - 1; index >= 0; index--) {
      const inverse = this.inverses[index]!;
      if (inverse.kind === 'node') {
        if (inverse.snapshot === null) {
          if (this.ctx.graph.hasNode(inverse.node_id)) this.ctx.graph.dropNode(inverse.node_id);
        } else if (this.ctx.graph.hasNode(inverse.node_id)) {
          this.ctx.graph.replaceNodeAttributes(inverse.node_id, structuredClone(inverse.snapshot.props));
        } else {
          this.ctx.graph.addNode(inverse.node_id, structuredClone(inverse.snapshot.props));
        }
        continue;
      }
      if (inverse.kind === 'edge') {
        if (this.ctx.graph.hasEdge(inverse.edge_id)) this.ctx.graph.dropEdge(inverse.edge_id);
        if (inverse.snapshot !== null) {
          this.ctx.graph.addEdgeWithKey(
            inverse.edge_id,
            inverse.snapshot.source,
            inverse.snapshot.target,
            structuredClone(inverse.snapshot.props),
          );
        }
        continue;
      }
      this.ctx.coldStore.restoreEntrySnapshot(inverse.snapshot);
    }
  }

  private captureBefore(operation: EngineOperation): CapturedOperation {
    const payload = operation.payload as Record<string, unknown>;
    switch (operation.type) {
      case 'add_node':
      case 'merge_node_attrs':
      case 'replace_node_attrs': {
        const props = payload.props as Partial<NodeProperties> | undefined;
        if (!props || typeof props.id !== 'string') {
          throw new Error(`Bounded transaction cannot capture malformed ${operation.type}.`);
        }
        const before = nodeSnapshot(this.ctx, props.id);
        this.inverses.push({ kind: 'node', node_id: props.id, snapshot: before });
        return { kind: 'node', operation_type: operation.type, node_id: props.id, before };
      }
      case 'add_edge':
      case 'drop_edge':
      case 'merge_edge_attrs': {
        if (typeof payload.edge_id !== 'string') {
          throw new Error(`Bounded transaction requires an exact edge_id for ${operation.type}.`);
        }
        const edgeIds = new Set([payload.edge_id]);
        if (operation.type === 'add_edge') {
          for (const edgeId of matchingEdgeIds(this.ctx, payload.source, payload.target, payload.props)) {
            edgeIds.add(edgeId);
          }
        } else if (
          operation.type === 'drop_edge'
          && typeof payload.source === 'string'
          && typeof payload.target === 'string'
          && typeof payload.edge_type === 'string'
          && this.ctx.graph.hasNode(payload.source)
          && this.ctx.graph.hasNode(payload.target)
        ) {
          for (const edgeId of this.ctx.graph.edges(payload.source, payload.target)) {
            if (this.ctx.graph.getEdgeAttributes(edgeId).type === payload.edge_type) edgeIds.add(edgeId);
          }
        }
        const before = new Map([...edgeIds].map(edgeId => [edgeId, edgeSnapshot(this.ctx, edgeId)]));
        for (const [edgeId, snapshot] of before) {
          this.inverses.push({ kind: 'edge', edge_id: edgeId, snapshot });
        }
        return {
          kind: 'edge',
          operation_type: operation.type,
          edge_ids: [...edgeIds],
          before,
          inferred: operation.type === 'add_edge'
            && Boolean((payload.props as Partial<EdgeProperties> | undefined)?.inferred_by_rule),
        };
      }
      case 'cold_add':
      case 'cold_promote': {
        const id = operation.type === 'cold_add'
          ? (payload.record as { id?: unknown } | undefined)?.id
          : payload.id;
        if (typeof id !== 'string') {
          throw new Error(`Bounded transaction cannot capture malformed ${operation.type}.`);
        }
        const before = this.ctx.coldStore.captureEntrySnapshot(id);
        this.inverses.push({ kind: 'cold', snapshot: before });
        return { kind: 'cold', operation_type: operation.type, before };
      }
      case 'identity_rewrite': {
        const nodeChanges = Array.isArray(payload.node_changes)
          ? payload.node_changes as Array<{ node_id?: unknown }>
          : [];
        const edgeChanges = Array.isArray(payload.edge_changes)
          ? payload.edge_changes as Array<{
              edge_id?: unknown;
              after?: { props?: Partial<EdgeProperties> };
            }>
          : [];
        if (
          payload.payload_version !== 1
          || nodeChanges.some(change => typeof change.node_id !== 'string')
          || edgeChanges.some(change => typeof change.edge_id !== 'string')
        ) {
          throw new Error('Bounded transaction cannot capture malformed identity_rewrite.');
        }
        const nodes = new Map(nodeChanges.map(change => {
          const nodeId = change.node_id as string;
          return [nodeId, nodeSnapshot(this.ctx, nodeId)];
        }));
        const edges = new Map(edgeChanges.map(change => {
          const edgeId = change.edge_id as string;
          return [edgeId, edgeSnapshot(this.ctx, edgeId)];
        }));
        // Restore nodes before edges: reverse traversal visits the node
        // inverses first because edge inverses are appended first here.
        for (const [edgeId, snapshot] of edges) {
          this.inverses.push({ kind: 'edge', edge_id: edgeId, snapshot });
        }
        for (const [nodeId, snapshot] of nodes) {
          this.inverses.push({ kind: 'node', node_id: nodeId, snapshot });
        }
        return {
          kind: 'graph_delta',
          nodes,
          edges,
          inferred_edge_ids: new Set(edgeChanges
            .filter(change => Boolean(change.after?.props?.inferred_by_rule))
            .map(change => change.edge_id as string)),
        };
      }
      case 'activity_append':
        return { kind: 'none' };
      default:
        throw new Error(`Bounded transaction drafting does not support ${operation.type}.`);
    }
  }

  private captureAfter(operation: EngineOperation, captured: CapturedOperation): void {
    if (captured.kind === 'node') {
      this.accumulator.recordNode(
        captured.node_id,
        captured.before,
        nodeSnapshot(this.ctx, captured.node_id),
      );
      return;
    }
    if (captured.kind === 'edge') {
      const payload = operation.payload as Record<string, unknown>;
      const edgeIds = new Set(captured.edge_ids);
      if (operation.type === 'add_edge') {
        for (const edgeId of matchingEdgeIds(this.ctx, payload.source, payload.target, payload.props)) {
          edgeIds.add(edgeId);
        }
      }
      for (const edgeId of edgeIds) {
        this.accumulator.recordEdge(
          edgeId,
          captured.before.get(edgeId) ?? null,
          edgeSnapshot(this.ctx, edgeId),
        );
        if (captured.inferred) this.accumulator.markInferredEdge(edgeId);
      }
      return;
    }
    if (captured.kind === 'graph_delta') {
      for (const [nodeId, before] of captured.nodes) {
        this.accumulator.recordNode(nodeId, before, nodeSnapshot(this.ctx, nodeId));
      }
      for (const [edgeId, before] of captured.edges) {
        this.accumulator.recordEdge(edgeId, before, edgeSnapshot(this.ctx, edgeId));
        if (captured.inferred_edge_ids.has(edgeId)) this.accumulator.markInferredEdge(edgeId);
      }
      return;
    }
    if (captured.kind === 'cold') {
      const current = this.ctx.coldStore.get(captured.before.id);
      this.accumulator.recordCold(
        captured.before.id,
        captured.before.record,
        current ? structuredClone(current) : null,
      );
    }
  }
}
