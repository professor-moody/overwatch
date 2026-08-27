#!/usr/bin/env node

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dashboardRoot = join(root, 'src', 'dashboard-next', 'src');

export const LEGACY_DESTINATIONS = [
  'overview', 'agents', 'frontier', 'actions', 'campaigns', 'sessions',
  'activity', 'analysis', 'graph', 'recon', 'identity', 'credentials',
  'paths', 'findings', 'evidence', 'engagements', 'settings', 'smoke',
];

const compatibilityBoundaries = new Set([
  'App.tsx',
  'lib/legacy-navigation.ts',
  'lib/workspace-navigation.ts',
]);

const retiredRuntimeFiles = [
  'components/layout/Breadcrumb.tsx',
  'components/layout/OperatorLayout.tsx',
  'components/layout/Sidebar.tsx',
  'components/layout/Toolbar.tsx',
  'hooks/useKeyboardShortcuts.ts',
  'hooks/useNavigation.ts',
  ...[
    'ActionsPanel', 'ActivityPanel', 'AddTargetsModal', 'AgentThread',
    'AgentsPanel', 'AnalysisPanel', 'AttackPathsPanel', 'CredentialsPanel',
    'DeployModal', 'DeploySelectedModal', 'EngagementQualityCard',
    'EngagementsPanel', 'EvidencePanel', 'FindingsPanel', 'FrontierPanel',
    'IdentityPanel', 'MissionCard', 'OverviewPanel', 'ReconPanel',
    'SessionsPanel', 'SettingsPanel', 'SmokePanel', 'TelemetrySection',
  ].map(name => `components/panels/${name}.tsx`),
];

function walk(directory) {
  const files = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) files.push(...walk(path));
    else if (/\.(?:ts|tsx)$/u.test(entry)) files.push(path);
  }
  return files;
}

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//gu, '')
    .replace(/^\s*\/\/.*$/gmu, '');
}

function lineNumber(source, offset) {
  return source.slice(0, offset).split('\n').length;
}

/** Audit active dashboard source. Compatibility adapters are explicit
 * exceptions because they consume legacy URLs; runtime producers must use the
 * typed canonical workspace navigation helpers. */
export function auditDashboardSources(sources) {
  const failures = [];
  const legacyLiteral = new RegExp(
    `(['"\\x60])\\/(?:${LEGACY_DESTINATIONS.join('|')})(?=[/?#'"\\x60])`,
    'gu',
  );
  const oldGrammar = /\b(?:PageHeader|PanelSection)\b/gu;
  const retiredImport = /(?:layout\/(?:Breadcrumb|OperatorLayout|Sidebar|Toolbar)|hooks\/(?:useKeyboardShortcuts|useNavigation)|panels\/(?:ActionsPanel|ActivityPanel|AddTargetsModal|AgentThread|AgentsPanel|AnalysisPanel|AttackPathsPanel|CredentialsPanel|DeployModal|DeploySelectedModal|EngagementQualityCard|EngagementsPanel|EvidencePanel|FindingsPanel|FrontierPanel|IdentityPanel|MissionCard|OverviewPanel|ReconPanel|SessionsPanel|SettingsPanel|SmokePanel|TelemetrySection))/gu;

  for (const [path, rawSource] of Object.entries(sources)) {
    const normalized = path.replaceAll('\\', '/');
    if (normalized.includes('/__tests__/') || normalized.endsWith('.test.ts') || normalized.endsWith('.test.tsx')) continue;
    const source = stripComments(rawSource);

    if (!compatibilityBoundaries.has(normalized)) {
      for (const match of source.matchAll(legacyLiteral)) {
        failures.push(`${normalized}:${lineNumber(source, match.index)} emits legacy dashboard route ${match[0].slice(1)}`);
      }
    }

    for (const match of source.matchAll(retiredImport)) {
      failures.push(`${normalized}:${lineNumber(source, match.index)} imports retired dashboard runtime ${match[0]}`);
    }

    if (normalized.startsWith('components/workspaces/') || normalized.startsWith('components/drawer/')) {
      for (const match of source.matchAll(oldGrammar)) {
        failures.push(`${normalized}:${lineNumber(source, match.index)} uses retired page grammar ${match[0]}`);
      }
    }
  }
  return failures;
}

export function auditDashboardTree() {
  const sources = Object.fromEntries(walk(dashboardRoot).map(path => [
    relative(dashboardRoot, path).replaceAll('\\', '/'),
    readFileSync(path, 'utf8'),
  ]));
  const failures = auditDashboardSources(sources);
  for (const retired of retiredRuntimeFiles) {
    if (existsSync(join(dashboardRoot, retired))) failures.push(`${retired}: retired dashboard runtime file was reintroduced`);
  }
  return failures;
}

function main() {
  const failures = auditDashboardTree();
  if (failures.length > 0) {
    console.error(`Dashboard navigation guard failed:\n${failures.map(failure => `- ${failure}`).join('\n')}`);
    process.exitCode = 1;
    return;
  }
  console.log('dashboard navigation guard ok (canonical producers; legacy adapters isolated)');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
