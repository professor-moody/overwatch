#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const docsRoot = join(root, 'docs');
const mkdocsPath = join(root, 'mkdocs.yml');
const packagePath = join(root, 'package.json');
const dashboardManifestPath = join(
  root,
  'src',
  'contracts',
  'dashboard-api-v1.manifest.json',
);

const failures = [];

function fail(file, message) {
  failures.push(`${relative(root, file)}: ${message}`);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function activeMarkdownFiles() {
  const mkdocs = readFileSync(mkdocsPath, 'utf8');
  const navOffset = mkdocs.search(/^nav:\s*$/m);
  if (navOffset < 0) {
    fail(mkdocsPath, 'missing the active MkDocs nav');
    return [join(root, 'README.md')];
  }

  const nav = mkdocs.slice(navOffset);
  const files = new Set([join(root, 'README.md')]);
  for (const match of nav.matchAll(/(?:^|\s)([A-Za-z0-9_./-]+\.md)\s*$/gm)) {
    const path = join(docsRoot, match[1]);
    files.add(path);
    if (!existsSync(path)) fail(mkdocsPath, `nav target does not exist: docs/${match[1]}`);
  }
  return [...files];
}

function stripTargetDecorations(target) {
  let cleaned = target.trim();
  if (cleaned.startsWith('<') && cleaned.endsWith('>')) {
    cleaned = cleaned.slice(1, -1);
  } else {
    cleaned = cleaned.split(/\s+["']/u, 1)[0];
  }
  const hash = cleaned.indexOf('#');
  if (hash >= 0) cleaned = cleaned.slice(0, hash);
  const query = cleaned.indexOf('?');
  if (query >= 0) cleaned = cleaned.slice(0, query);
  try {
    return decodeURIComponent(cleaned);
  } catch {
    return cleaned;
  }
}

function linkCandidates(source, target) {
  const base = target.startsWith('/')
    ? join(docsRoot, target.replace(/^\/+/, ''))
    : resolve(dirname(source), target);
  const candidates = [base];
  if (!extname(base)) {
    candidates.push(`${base}.md`, join(base, 'index.md'));
  }
  return candidates;
}

function checkInternalLinks(file, text) {
  for (const match of text.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    const raw = match[1].trim();
    if (
      raw === ''
      || raw.startsWith('#')
      || /^(?:https?:|mailto:|data:|javascript:)/i.test(raw)
    ) continue;
    const target = stripTargetDecorations(raw);
    if (target === '') continue;
    if (!linkCandidates(file, target).some(candidate => existsSync(candidate))) {
      fail(file, `internal link target does not exist: ${raw}`);
    }
  }
}

function checkNpmScripts(file, text, scripts) {
  for (const match of text.matchAll(/\bnpm\s+run\s+([A-Za-z0-9:_-]+)/g)) {
    if (!Object.hasOwn(scripts, match[1])) {
      fail(file, `documents missing package script: npm run ${match[1]}`);
    }
  }
}

function checkPackageBinaries(file, text, packageBinaries) {
  const invoked = new Set();
  for (const match of text.matchAll(/\bnpx\s+(overwatch(?:-[a-z0-9-]+)?)(?=\s|$)/gm)) {
    invoked.add(match[1]);
  }
  for (const block of text.matchAll(/```(?:bash|sh|shell|console)?\s*\n([\s\S]*?)```/gi)) {
    for (const line of block[1].split('\n')) {
      const match = line.match(/^\s*(?:\$\s*)?(overwatch(?:-[a-z0-9-]+)?)(?=\s|$)/);
      if (match) invoked.add(match[1]);
    }
  }
  for (const binary of invoked) {
    if (!packageBinaries.has(binary)) {
      fail(file, `invokes a package binary that is not shipped: ${binary}`);
    }
  }
}

function negativeInstruction(line) {
  return /\b(?:do not|don't|never|must not|does not|doesn't|without|unsupported)\b/i.test(line);
}

function checkObsoleteInstructions(file, text) {
  const relativePath = relative(root, file);
  const allowIsolatedDirectRuntime = relativePath === 'docs/smoke-test.md';

  for (const [index, line] of text.split('\n').entries()) {
    const lineNumber = index + 1;
    if (/\bnpx\s+overwatch-mcp(?=\s|$)/i.test(line)) {
      fail(file, `line ${lineNumber} invokes the removed npx overwatch-mcp command`);
    }
    if (
      /\bnode\s+(?:\.\/)?dist\/index\.js\b/i.test(line)
      && !allowIsolatedDirectRuntime
      && !negativeInstruction(line)
    ) {
      fail(file, `line ${lineNumber} presents direct dist/index.js startup as an active workflow`);
    }
    if (
      /\bcreat(?:e|es|ed|ing)\b.*\bengagement\b.*\b(?:switch(?:es|ed|ing)?|activat(?:e|es|ed|ing))\b/i.test(line)
      && !negativeInstruction(line)
    ) {
      fail(file, `line ${lineNumber} claims engagement creation switches or activates the daemon`);
    }
    if (
      /\b(?:all|every|each)\s+actions?\b.*\b(?:always\s+)?(?:requires?|needs?|must)\b.*\b(?:manual|click|explicit approval)\b/i.test(line)
      && !negativeInstruction(line)
    ) {
      fail(file, `line ${lineNumber} claims every action always needs manual approval`);
    }
  }

  if (!allowIsolatedDirectRuntime) {
    for (const block of text.matchAll(/```(?:bash|sh|shell|console)?\s*\n([\s\S]*?)```/gi)) {
      if (
        /OVERWATCH_STATE_FILE\s*=/.test(block[1])
        && /npm\s+run\s+(?:daemon:start|start(?::daemon)?)/.test(block[1])
      ) {
        fail(file, 'presents transient OVERWATCH_STATE_FILE selection as normal managed startup');
      }
    }
  }
}

function normalizeDocumentedPath(raw) {
  return raw
    .replace(/[),.;]+$/g, '')
    .split(/[?#]/, 1)[0]
    .replace(/<([A-Za-z0-9_-]+)>/g, '{$1}')
    .replace(/:([A-Za-z][A-Za-z0-9_-]*)/g, '{$1}')
    .replace(/\/+/g, '/');
}

function routePattern(path) {
  const escaped = path
    .split(/(\{[A-Za-z0-9_-]+\})/g)
    .map(part => /^\{[A-Za-z0-9_-]+\}$/.test(part)
      ? '[^/]+'
      : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('');
  return new RegExp(`^${escaped}$`);
}

function checkDashboardReferences(file, text, manifest) {
  const routes = manifest.routes.map(route => ({
    method: route.method,
    path: route.path,
    pattern: routePattern(route.path),
  }));
  const sockets = Object.values(manifest.websockets).map(socket => ({
    path: socket.path,
    pattern: routePattern(socket.path),
  }));
  const nonDashboardExamples = new Set([
    // Graph data may describe a target application's own endpoint. This is not
    // an Overwatch dashboard route and is intentionally the only active-doc
    // path excluded from dashboard registry validation.
    'docs/graph-model.md:/api/users',
  ]);

  for (const match of text.matchAll(/\/api\/[A-Za-z0-9_{}<>:./?=&%*-]+/g)) {
    const path = normalizeDocumentedPath(match[0]);
    if (path === '/api/*') continue;
    if (nonDashboardExamples.has(`${relative(root, file)}:${path}`)) continue;
    if (!routes.some(route => route.pattern.test(path))) {
      fail(file, `documents an unregistered dashboard endpoint path: ${path}`);
    }
  }

  for (const match of text.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+(\/api\/[A-Za-z0-9_{}<>:./?=&%*-]+)/g)) {
    const method = match[1];
    const path = normalizeDocumentedPath(match[2]);
    if (path === '/api/*') continue;
    if (!routes.some(route => route.method === method && route.pattern.test(path))) {
      fail(file, `documents unregistered dashboard endpoint: ${method} ${path}`);
    }
  }

  for (const match of text.matchAll(/\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`?(\/api\/[A-Za-z0-9_{}<>:./?=&%*-]+)/g)) {
    const method = match[1];
    const path = normalizeDocumentedPath(match[2]);
    if (!routes.some(route => route.method === method && route.pattern.test(path))) {
      fail(file, `documents unregistered dashboard endpoint: ${method} ${path}`);
    }
  }

  for (const match of text.matchAll(/\/ws(?:\/[A-Za-z0-9_{}<>:./-]+)?(?:\?[^\s)`"]+)?/g)) {
    const path = normalizeDocumentedPath(match[0]);
    if (!sockets.some(socket => socket.pattern.test(path))) {
      fail(file, `documents unregistered dashboard WebSocket path: ${path}`);
    }
  }
}

const activeFiles = activeMarkdownFiles();
const packageJson = readJson(packagePath);
const packageBinaries = new Set(Object.keys(packageJson.bin ?? {}));
const manifest = readJson(dashboardManifestPath);

for (const file of activeFiles) {
  if (!existsSync(file)) continue;
  const text = readFileSync(file, 'utf8');
  checkInternalLinks(file, text);
  checkNpmScripts(file, text, packageJson.scripts ?? {});
  checkPackageBinaries(file, text, packageBinaries);
  checkObsoleteInstructions(file, text);
  checkDashboardReferences(file, text, manifest);
}

const cliAdapter = join(docsRoot, 'playbook', 'cli-adapter.md');
const mkdocs = readFileSync(mkdocsPath, 'utf8');
if (mkdocs.includes('playbook/cli-adapter.md')) {
  fail(mkdocsPath, 'the unimplemented CLI Adapter design must not be active in navigation');
}
if (
  existsSync(cliAdapter)
  && !readFileSync(cliAdapter, 'utf8').includes('DOCS_STATUS: archived-unimplemented-design')
) {
  fail(cliAdapter, 'retained CLI Adapter design is missing its archive marker');
}

if (failures.length > 0) {
  console.error(`Documentation semantic checks failed (${failures.length}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Documentation semantic checks passed (${activeFiles.length} active Markdown files, `
  + `${manifest.routes.length} dashboard routes, ${Object.keys(manifest.websockets).length} WebSocket channels).`,
);
