import { readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const workspaceRoot = resolve(process.cwd());
const sourceRoot = join(workspaceRoot, 'src');

function testFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return testFiles(path);
    return /(?:\.test\.ts|\.dom\.test\.tsx)$/u.test(entry.name) ? [path] : [];
  });
}

const persistencePathArgument = new Map([
  ['EngineContext', 2],
  ['EvidenceStore', 0],
  ['GraphEngine', 1],
  ['MutationJournal', 0],
  ['ReportArchive', 0],
]);

interface PathAnalysisContext {
  readonly assignments: ReadonlyMap<string, readonly ts.Expression[]>;
  readonly returns: ReadonlyMap<string, readonly ts.Expression[]>;
}

function collectPathAnalysisContext(source: ts.SourceFile): PathAnalysisContext {
  const assignments = new Map<string, ts.Expression[]>();
  const returns = new Map<string, ts.Expression[]>();
  const add = (target: Map<string, ts.Expression[]>, name: string, value: ts.Expression) => {
    const values = target.get(name) ?? [];
    values.push(value);
    target.set(name, values);
  };
  const returnExpressions = (body: ts.ConciseBody): ts.Expression[] => {
    if (!ts.isBlock(body)) return [body];
    const values: ts.Expression[] = [];
    const visitReturn = (node: ts.Node): void => {
      if (ts.isReturnStatement(node) && node.expression) values.push(node.expression);
      ts.forEachChild(node, visitReturn);
    };
    visitReturn(body);
    return values;
  };
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      add(assignments, node.name.text, node.initializer);
      if (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) {
        for (const value of returnExpressions(node.initializer.body)) add(returns, node.name.text, value);
      }
    } else if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(node.left)
    ) {
      add(assignments, node.left.text, node.right);
    } else if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      for (const value of returnExpressions(node.body)) add(returns, node.name.text, value);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { assignments, returns };
}

function unsafePersistencePath(
  expression: ts.Expression,
  context: PathAnalysisContext,
  seen = new Set<string>(),
): string | undefined {
  if (ts.isStringLiteralLike(expression)) {
    return isAbsolute(expression.text)
      ? `uses fixed absolute path ${JSON.stringify(expression.text)}`
      : `uses checkout-relative path ${JSON.stringify(expression.text)}`;
  }
  if (ts.isIdentifier(expression)) {
    if (seen.has(expression.text)) return undefined;
    const values = context.assignments.get(expression.text);
    if (!values) return undefined;
    const meaningfulValues = values.filter(value => !(
      ts.isStringLiteralLike(value) && value.text === ''
    ));
    const nextSeen = new Set(seen).add(expression.text);
    for (const value of meaningfulValues.length > 0 ? meaningfulValues : values) {
      const unsafe = unsafePersistencePath(value, context, nextSeen);
      if (unsafe) return `${expression.text} ${unsafe}`;
    }
    return undefined;
  }
  if (ts.isCallExpression(expression)) {
    if (ts.isPropertyAccessExpression(expression.expression) && expression.expression.name.text === 'path') {
      return undefined;
    }
    if (ts.isIdentifier(expression.expression)) {
      const name = expression.expression.text;
      if (name === 'mkdtempSync') return undefined;
      if (name === 'tmpdir') return 'uses the shared OS temporary root directly';
      if (name === 'join' || name === 'resolve') {
        const root = expression.arguments[0];
        return root
          ? unsafePersistencePath(root, context, seen)
          : `${name}() has no owned root`;
      }
      for (const value of context.returns.get(name) ?? []) {
        const unsafe = unsafePersistencePath(value, context, new Set(seen).add(name));
        if (unsafe) return `${name}() ${unsafe}`;
      }
    }
    return undefined;
  }
  if (ts.isTemplateExpression(expression)) {
    if (expression.head.text) {
      return isAbsolute(expression.head.text)
        ? `uses fixed absolute template path ${JSON.stringify(expression.head.text)}`
        : `uses checkout-relative template path ${JSON.stringify(expression.head.text)}`;
    }
    return expression.templateSpans.length > 0
      ? unsafePersistencePath(expression.templateSpans[0].expression, context, seen)
      : 'uses an unowned template path';
  }
  if (ts.isConditionalExpression(expression)) {
    return unsafePersistencePath(expression.whenTrue, context, seen)
      ?? unsafePersistencePath(expression.whenFalse, context, seen);
  }
  if (ts.isParenthesizedExpression(expression)) {
    return unsafePersistencePath(expression.expression, context, seen);
  }
  if (ts.isBinaryExpression(expression)) {
    return unsafePersistencePath(expression.left, context, seen)
      ?? unsafePersistencePath(expression.right, context, seen);
  }
  return undefined;
}

describe('test hermeticity architecture', () => {
  it('forbids missing, indirect fixed, and checkout-relative persistence paths', () => {
    const violations: string[] = [];
    for (const file of testFiles(sourceRoot)) {
      const sourceText = readFileSync(file, 'utf8');
      const source = ts.createSourceFile(
        file,
        sourceText,
        ts.ScriptTarget.Latest,
        true,
        file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
      );
      const context = collectPathAnalysisContext(source);
      const visit = (node: ts.Node): void => {
        if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
          const argumentIndex = persistencePathArgument.get(node.expression.text);
          const argument = argumentIndex === undefined ? undefined : node.arguments?.[argumentIndex];
          const hasSpreadArguments = node.arguments?.some(ts.isSpreadElement) ?? false;
          const reason = argument ? unsafePersistencePath(argument, context) : undefined;
          if (argumentIndex !== undefined && !argument && !hasSpreadArguments) {
            const position = source.getLineAndCharacterOfPosition(node.getStart(source));
            violations.push(
              `${relative(workspaceRoot, file)}:${position.line + 1} constructs ${node.expression.text} without an explicit persistence path`,
            );
          } else if (argument && reason) {
            const position = source.getLineAndCharacterOfPosition(argument.getStart(source));
            violations.push(
              `${relative(workspaceRoot, file)}:${position.line + 1} constructs ${node.expression.text}: ${reason}`,
            );
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(source);
    }
    expect(violations).toEqual([]);
  });

  it('keeps every Vitest surface behind the same cleanup and artifact sentinels', () => {
    const configs = [
      'vitest.config.ts',
      'vitest.dashboard-dom.config.ts',
      'vitest.integration-http.config.ts',
      'vitest.integration-stdio.config.ts',
      'vitest.journeys.config.ts',
    ];
    for (const config of configs) {
      const source = readFileSync(join(workspaceRoot, config), 'utf8');
      expect(source, config).toContain('setup-hermetic.ts');
      expect(source, config).toContain('artifact-hygiene-global.ts');
      expect(source, config).toContain("hooks: 'stack'");
      expect(source, config).toContain("setupFiles: 'list'");
    }
  });
});
