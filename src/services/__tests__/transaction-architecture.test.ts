import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { dirname, join, relative, resolve } from 'path';
import { fileURLToPath } from 'url';
import * as ts from 'typescript';
import { GRAPH_MUTATION_METHODS } from '../graph-mutation-methods.js';
import { createOverwatchGraph } from '../graphology-types.js';

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = resolve(here, '../..');

const GRAPH_MUTATORS = new Set<string>(GRAPH_MUTATION_METHODS);

const TRANSACTION_BOUNDARIES = new Set([
  'applyJournaledMutation',
  'applyCompositeJournaledMutation',
  'applyEngineTransaction',
]);

const DURABLE_STATE_BOUNDARIES = new Set([
  'applyJournaledMutation',
  'applyCompositeJournaledMutation',
  'applyEngineTransaction',
  'transactDurableSlices',
  'transactAttachedCoordinationStore',
]);

const DURABLE_CONTEXT_FIELDS = new Set([
  'activityLog',
  'actionFrontierMap',
  'lastChainHash',
  'chainCheckpoints',
  'chainEventsSinceCheckpoint',
  'deterministicSeq',
  'agents',
  'frontierLeases',
  'campaigns',
  'agentDirectives',
  'approvalRequests',
  'inferenceRules',
  'trackedProcesses',
  'runtimeRuns',
  'playbookRuns',
  'sessionDescriptors',
  'proposedPlanStore',
  'agentQueryStore',
  'commandPlans',
  'commandOutcomes',
  'opsecTracker',
  'frontierLinkage',
  'frontierWeights',
  'recentFindingHashes',
  'dedupCount',
  'lastKnownPhaseId',
  'config',
  'artifactReferences',
]);

const COLLECTION_MUTATORS = new Set([
  'set',
  'delete',
  'clear',
  'push',
  'pop',
  'shift',
  'unshift',
  'splice',
  'sort',
  'reverse',
  'copyWithin',
  'fill',
  'restore',
  'recordNoise',
  'recordDefensiveSignal',
  'recordEmitted',
  'observe',
  'sweepDropped',
  'acquire',
  'renew',
  'releaseByTask',
  'reapExpired',
]);

/**
 * These are the deliberately small raw-mutation islands. GraphEngine appliers
 * implement frozen journal operations; StatePersistence owns restore/replay
 * and one-time normalization; IdentityReconciler is instantiated with a
 * detached planning graph in production.
 */
const ALLOWED_RAW_SCOPES = new Map<string, Set<string>>([
  ['services/graph-engine.ts', new Set([
    'applyDropNodeMutation',
    'applyIdentityRewriteMutation',
    'applyGraphCorrectedMutation',
    'applyScopeUpdatedMutation',
    'addEdgeToCorrectionDraft',
    'restoreWebChainAnnotationBaseline',
    'restoreFindingDraftBaseline',
  ])],
  ['services/state-persistence.ts', new Set([
    '_restoreFromData',
    'makeMutationApplier',
    // Exact preimage restoration for eligibility-classified primitive
    // transactions. Unsupported/composite shapes retain the full baseline.
    'restoreBounded',
    'normalizeLoadedNodeProvenance',
    'migrateDefaultCredentialFlags',
  ])],
  ['services/identity-reconciliation.ts', new Set([
    'mergeAliasIntoCanonical',
    'addEdgeToPlanningGraph',
  ])],
  ['services/transaction-footprint.ts', new Set([
    // Exact, process-local rollback for an eligibility-classified operation
    // draft; serialized writes still flow through the canonical applier.
    'restore',
  ])],
]);

/**
 * EngineContext and StatePersistence are the state container and recovery
 * applier. AgentManager, CampaignPlanner, and InferenceEngine are private
 * mutation modules whose public ownership boundary is GraphEngine; their
 * callers are covered by the GraphEngine method-level check below.
 */
const DURABLE_STATE_OWNER_FILES = new Set([
  'services/engine-context.ts',
  'services/state-persistence.ts',
  'services/agent-manager.ts',
  'services/campaign-planner.ts',
  'services/inference-engine.ts',
]);

const ALLOWED_DURABLE_SCOPES = new Map<string, Set<string>>([
  ['services/graph-engine.ts', new Set([
    'constructor',
    'applyDropNodeMutation',
    'applyIdentityRewriteMutation',
    'applyGraphCorrectedMutation',
    'applyScopeUpdatedMutation',
    'applyTrackedProcesses',
    // Bounded retention helper invoked only from runtime finalization/recovery
    // methods after their transactDurableSlices boundary is active.
    'pruneTerminalRuntimeRuns',
    'applyRuntimeConfig',
    'restoreFindingDraftBaseline',
    'applyRestoredRuntimeProjections',
  ])],
  // Legacy compatibility helpers own their complete module-level mutation and
  // synchronously persist before returning. Active GraphEngine config/scope
  // writes use EngagementConfigService and the scope transaction applier.
  ['services/config-manager.ts', new Set(['updateConfig'])],
  ['services/scope-manager.ts', new Set(['updateScope'])],
]);

type GraphOrigin = 'live' | 'scratch' | 'unknown';

interface Violation {
  file: string;
  line: number;
  column: number;
  expression: string;
  scopes: string[];
}

function productionTypeScriptFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const full = join(directory, entry.name);
    if (entry.isDirectory()) {
      // The browser keeps a separate Graphology view model; it is not durable
      // engine state and intentionally mutates for layout/interaction.
      if (
        entry.name === '__tests__'
        || entry.name === 'dashboard-next'
        || entry.name === 'test-support'
      ) continue;
      files.push(...productionTypeScriptFiles(full));
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith('.ts') || entry.name.endsWith('.test.ts')) continue;
    files.push(full);
  }
  return files;
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current)
    || ts.isAsExpression(current)
    || ts.isTypeAssertionExpression(current)
    || ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function calledName(expression: ts.LeftHandSideExpression): string | undefined {
  const unwrapped = unwrapExpression(expression);
  if (ts.isIdentifier(unwrapped)) return unwrapped.text;
  if (ts.isPropertyAccessExpression(unwrapped)) return unwrapped.name.text;
  return undefined;
}

function functionName(node: ts.Node): string | undefined {
  if (ts.isConstructorDeclaration(node)) return 'constructor';
  if (
    (ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node))
    && node.name
  ) {
    return node.name.getText();
  }
  if (!ts.isArrowFunction(node) && !ts.isFunctionExpression(node)) return undefined;
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent)) return parent.name.getText();
  if (ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent)) return parent.name.getText();
  return undefined;
}

function enclosingScopes(node: ts.Node): string[] {
  const scopes: string[] = [];
  let current: ts.Node | undefined = node.parent;
  while (current) {
    const name = functionName(current);
    if (name) scopes.push(name);
    current = current.parent;
  }
  return scopes;
}

function isInsideTransactionCallback(node: ts.Node): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) {
      const parent = current.parent;
      if (
        ts.isCallExpression(parent)
        && parent.arguments.some(argument => argument === current)
        && TRANSACTION_BOUNDARIES.has(calledName(parent.expression) ?? '')
      ) {
        return true;
      }
    }
    current = current.parent;
  }
  return false;
}

function isCallableImplementation(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node)
    || ts.isConstructorDeclaration(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node);
}

function nearestCallable(node: ts.Node): ts.FunctionLikeDeclaration | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (isCallableImplementation(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function callableContainsBoundary(
  callable: ts.FunctionLikeDeclaration,
  boundaries: ReadonlySet<string>,
): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if (
      ts.isCallExpression(node)
      && boundaries.has(calledName(node.expression) ?? '')
    ) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  if (callable.body) visit(callable.body);
  return found;
}

function isWithinCallableContainingBoundary(
  node: ts.Node,
  boundaries: ReadonlySet<string>,
): boolean {
  let current: ts.Node | undefined = node;
  while (current) {
    if (isCallableImplementation(current) && callableContainsBoundary(current, boundaries)) {
      return true;
    }
    current = current.parent;
  }
  return false;
}

function durableContextField(expression: ts.Expression): string | undefined {
  const unwrapped = unwrapExpression(expression);
  if (ts.isPropertyAccessExpression(unwrapped)) {
    if (
      DURABLE_CONTEXT_FIELDS.has(unwrapped.name.text)
      && (
        unwrapped.expression.getText() === 'ctx'
        || unwrapped.expression.getText().endsWith('.ctx')
      )
    ) {
      return unwrapped.name.text;
    }
    return durableContextField(unwrapped.expression);
  }
  if (ts.isElementAccessExpression(unwrapped)) {
    return durableContextField(unwrapped.expression);
  }
  if (ts.isCallExpression(unwrapped)) {
    return durableContextField(unwrapped.expression);
  }
  return undefined;
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment
    && kind <= ts.SyntaxKind.LastAssignment;
}

function findDurableStateViolations(file: string, source: string): Violation[] {
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const normalizedFile = relative(srcRoot, file).split('\\').join('/');
  if (DURABLE_STATE_OWNER_FILES.has(normalizedFile)) return [];
  const violations: Violation[] = [];

  const record = (node: ts.Node, field: string): void => {
    const callable = nearestCallable(node);
    const scopes = enclosingScopes(node);
    const scope = callable ? functionName(callable) : undefined;
    const allowedScope = scope !== undefined
      && (ALLOWED_DURABLE_SCOPES.get(normalizedFile)?.has(scope) ?? false);
    const behindBoundary = isWithinCallableContainingBoundary(node, DURABLE_STATE_BOUNDARIES);
    if (allowedScope || behindBoundary) return;
    const location = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    violations.push({
      file: normalizedFile,
      line: location.line + 1,
      column: location.character + 1,
      expression: `${field}: ${node.getText(sourceFile)}`,
      scopes,
    });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isBinaryExpression(node) && isAssignmentOperator(node.operatorToken.kind)) {
      const field = durableContextField(node.left);
      if (field) record(node, field);
    } else if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
      && (
        node.operator === ts.SyntaxKind.PlusPlusToken
        || node.operator === ts.SyntaxKind.MinusMinusToken
      )
    ) {
      const field = durableContextField(node.operand);
      if (field) record(node, field);
    } else if (
      ts.isCallExpression(node)
      && ts.isPropertyAccessExpression(node.expression)
      && COLLECTION_MUTATORS.has(node.expression.name.text)
    ) {
      const field = durableContextField(node.expression.expression);
      if (field) record(node, field);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return violations;
}

function directGraphOrigin(expression: ts.Expression): GraphOrigin | undefined {
  const unwrapped = unwrapExpression(expression);
  if (!ts.isPropertyAccessExpression(unwrapped) || unwrapped.name.text !== 'graph') return undefined;
  const owner = unwrapped.expression.getText();
  if (owner === 'ctx' || owner.endsWith('.ctx')) return 'live';
  if (owner === 'this') return 'unknown';
  return undefined;
}

function expressionOrigin(
  expression: ts.Expression,
  aliases: Map<string, GraphOrigin>,
): GraphOrigin | undefined {
  const initializer = unwrapExpression(expression);
  const direct = directGraphOrigin(initializer);
  if (direct) return direct;
  if (
    ts.isCallExpression(initializer)
    && ['createGraph', 'createOverwatchGraph'].includes(calledName(initializer.expression) ?? '')
  ) {
    return 'scratch';
  }
  if (ts.isIdentifier(initializer)) return aliases.get(initializer.text);
  return undefined;
}

function createsAliasScope(node: ts.Node): boolean {
  return ts.isBlock(node)
    || ts.isModuleBlock(node)
    || ts.isCatchClause(node)
    || ts.isFunctionDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node)
    || ts.isConstructorDeclaration(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node)
    || ts.isForStatement(node)
    || ts.isForInStatement(node)
    || ts.isForOfStatement(node);
}

function receiverOrigin(
  expression: ts.Expression,
  aliases: Map<string, GraphOrigin>,
): GraphOrigin | undefined {
  const direct = directGraphOrigin(expression);
  if (direct) return direct;
  const unwrapped = unwrapExpression(expression);
  if (ts.isIdentifier(unwrapped)) {
    return aliases.get(unwrapped.text) ?? (unwrapped.text === 'graph' ? 'unknown' : undefined);
  }
  return undefined;
}

function findViolations(file: string, source: string): Violation[] {
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const normalizedFile = relative(srcRoot, file).split('\\').join('/');
  const allowedScopes = ALLOWED_RAW_SCOPES.get(normalizedFile) ?? new Set<string>();
  const violations: Violation[] = [];

  const visit = (node: ts.Node, inheritedAliases: Map<string, GraphOrigin>): void => {
    const aliases = node === sourceFile || !createsAliasScope(node)
      ? inheritedAliases
      : new Map(inheritedAliases);
    if (
      ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.initializer
    ) {
      const origin = expressionOrigin(node.initializer, aliases);
      if (origin) aliases.set(node.name.text, origin);
    }
    if (
      ts.isCallExpression(node)
      && ts.isPropertyAccessExpression(node.expression)
      && GRAPH_MUTATORS.has(node.expression.name.text)
    ) {
      const origin = receiverOrigin(node.expression.expression, aliases);
      if (origin && origin !== 'scratch') {
        const scopes = enclosingScopes(node);
        const allowed = isInsideTransactionCallback(node)
          || scopes.some(scope => allowedScopes.has(scope));
        if (!allowed) {
          const location = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
          violations.push({
            file: normalizedFile,
            line: location.line + 1,
            column: location.character + 1,
            expression: node.getText(sourceFile),
            scopes,
          });
        }
      }
    }
    ts.forEachChild(node, child => visit(child, aliases));
  };
  visit(sourceFile, new Map());
  return violations;
}

describe('transaction architecture — live graph writes stay behind the applier', () => {
  it('keeps the runtime mutation inventory exhaustive for the installed Graphology API', () => {
    const graph = createOverwatchGraph();
    const methods = new Set<string>();
    for (let cursor: object | null = graph; cursor && cursor !== Object.prototype; cursor = Object.getPrototypeOf(cursor)) {
      for (const name of Object.getOwnPropertyNames(cursor)) {
        if (typeof (graph as unknown as Record<string, unknown>)[name] === 'function') methods.add(name);
      }
    }
    const eventEmitterMethods = new Set([
      'addListener',
      'removeListener',
      'removeAllListeners',
      'setMaxListeners',
    ]);
    const mutationShaped = [...methods]
      .filter(name => /^(add|merge|update|set|replace|remove|drop|clear|import)/.test(name))
      .filter(name => !eventEmitterMethods.has(name));
    expect(mutationShaped.filter(name => !GRAPH_MUTATORS.has(name))).toEqual([]);
  });

  it('has no direct production graph writes outside transaction, replay, restore, or scratch code', () => {
    const files = productionTypeScriptFiles(srcRoot);
    const violations = files.flatMap(file => findViolations(file, readFileSync(file, 'utf8')));
    const formatted = violations.map(violation =>
      `${violation.file}:${violation.line}:${violation.column} ${violation.expression}`
      + (violation.scopes.length > 0 ? ` [${violation.scopes.join(' > ')}]` : ''),
    );
    expect(
      formatted,
      'Use a durable GraphEngine mutator or add the operation to the canonical transaction applier.',
    ).toEqual([]);
  });

  it('detects a direct live alias but accepts transaction callbacks and scratch graphs', () => {
    const forbidden = findViolations(
      join(srcRoot, 'services', 'synthetic-forbidden.ts'),
      `class Example {
        scratch(): void {
          const graph = createOverwatchGraph();
          graph.setNodeAttribute('scratch', 'safe', true);
        }
        mutate(): void {
          const graph = this.ctx.graph;
          graph.setNodeAttribute('host-1', 'unsafe', true);
          graph.updateEachNodeAttributes((_id, attrs) => attrs);
          graph.setEdgeAttribute('edge-1', 'unsafe', true);
          graph.updateEachEdgeAttributes((_id, attrs) => attrs);
          graph.setAttribute('unsafe', true);
        }
      }`,
    );
    expect(forbidden).toHaveLength(5);

    const allowed = findViolations(
      join(srcRoot, 'services', 'synthetic-allowed.ts'),
      `function apply(ctx: any): void {
        ctx.applyEngineTransaction({}, () => {
          ctx.graph.addNode('host-1', {});
          ctx.graph.updateNodeAttribute('host-1', 'safe', () => true);
          ctx.graph.addDirectedEdge('host-1', 'host-2', {});
          ctx.graph.updateEdgeAttributes('edge-1', attrs => attrs);
        });
        const graph = createOverwatchGraph();
        graph.addNode('scratch', {});
        graph.setNodeAttribute('scratch', 'safe', true);
      }`,
    );
    expect(allowed).toEqual([]);

    const captureIsNotAuthority = findViolations(
      join(srcRoot, 'services', 'synthetic-capture-is-not-authority.ts'),
      `function capture(ctx: any): void {
        ctx.captureEngineOperations(() => {
          ctx.graph.setNodeAttribute('host-1', 'drafted', true);
        });
      }`,
    );
    expect(captureIsNotAuthority).toHaveLength(1);
  });

  it('keeps direct durable EngineContext writes behind a method-level transaction boundary', () => {
    const files = productionTypeScriptFiles(srcRoot);
    const violations = files.flatMap(file =>
      findDurableStateViolations(file, readFileSync(file, 'utf8')),
    );
    const formatted = violations.map(violation =>
      `${violation.file}:${violation.line}:${violation.column} ${violation.expression}`
      + (violation.scopes.length > 0 ? ` [${violation.scopes.join(' > ')}]` : ''),
    );
    expect(
      formatted,
      'Wrap durable state changes in transactDurableSlices/applyEngineTransaction or document a narrow applier/restore scope.',
    ).toEqual([]);
  });

  it('detects durable state collection and scalar writes without a boundary', () => {
    const forbidden = findDurableStateViolations(
      join(srcRoot, 'services', 'synthetic-durable-forbidden.ts'),
      `class Example {
        mutate(): void {
          this.ctx.recentFindingHashes.set('hash', 1);
          this.ctx.dedupCount++;
          this.ctx.sessionDescriptors.push({ session_id: 's' });
          this.ctx.lastKnownPhaseId = 'exploit';
        }
      }`,
    );
    expect(forbidden).toHaveLength(4);

    const speculativeOnly = findDurableStateViolations(
      join(srcRoot, 'services', 'synthetic-durable-speculative.ts'),
      `class Example {
        capture(): void {
          this.captureEngineOperations(() => {
            this.ctx.dedupCount++;
          });
        }
        draft(): void {
          this.withTransactionDraft(() => {
            this.ctx.lastKnownPhaseId = 'exploit';
          });
        }
      }`,
    );
    expect(speculativeOnly).toHaveLength(2);

    const allowed = findDurableStateViolations(
      join(srcRoot, 'services', 'synthetic-durable-allowed.ts'),
      `class Example {
        mutate(): void {
          this.transactDurableSlices('safe', ['finding_counters', 'phase'], () => {
            this.ctx.recentFindingHashes.set('hash', 1);
            this.ctx.dedupCount++;
            this.ctx.lastKnownPhaseId = 'exploit';
          });
        }
      }`,
    );
    expect(allowed).toEqual([]);
  });
});
