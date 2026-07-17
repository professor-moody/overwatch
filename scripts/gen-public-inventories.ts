#!/usr/bin/env node
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import {
  createOverwatchApp,
  shutdownOverwatchApp,
} from '../src/app.js';
import {
  buildToolRegistryManifest,
  type ToolDescriptor,
} from '../src/services/tool-descriptor-registry.js';
import {
  generateOperatorCockpitArchetypeTable,
  generateSubAgentArchetypeReference,
  listArchetypes,
} from '../src/services/agent-archetypes.js';
import { getSupportedParsers } from '../src/services/parsers/index.js';
import { BUILTIN_RULES } from '../src/services/builtin-inference-rules.js';
import { EDGE_TYPES, NODE_TYPES } from '../src/types.js';

const CHECK = process.argv.includes('--check');
const ROOT = resolve('.');
const changed: string[] = [];

function replaceBetween(
  text: string,
  begin: string,
  end: string,
  body: string,
  path: string,
): string {
  const start = text.indexOf(begin);
  const finish = text.indexOf(end);
  if (start < 0 || finish < 0 || finish < start) {
    throw new Error(`markers ${begin}/${end} not found in ${path}`);
  }
  return `${text.slice(0, start + begin.length)}\n${body}\n${text.slice(finish)}`;
}

function updateMarkedFile(
  relativePath: string,
  begin: string,
  end: string,
  body: string,
): void {
  const path = resolve(ROOT, relativePath);
  const current = readFileSync(path, 'utf8');
  const expected = replaceBetween(current, begin, end, body, relativePath);
  writeOrCheck(relativePath, expected, current);
}

function writeOrCheck(relativePath: string, expected: string, current?: string): void {
  const path = resolve(ROOT, relativePath);
  const observed = current ?? (() => {
    try { return readFileSync(path, 'utf8'); } catch { return ''; }
  })();
  if (observed === expected) return;
  changed.push(relativePath);
  if (!CHECK) writeFileSync(path, expected);
}

function escapeCell(value: string): string {
  return value.replaceAll('|', '\\|').replace(/\s+/g, ' ').trim();
}

function compactPurpose(tool: ToolDescriptor): string {
  const purpose = tool.documentation.purpose;
  const sentence = purpose.match(/^.*?[.!?](?:\s|$)/)?.[0]?.trim() ?? purpose;
  return escapeCell(sentence.length > 220 ? `${sentence.slice(0, 217)}…` : sentence);
}

function accessLabel(tool: ToolDescriptor): string {
  if (tool.persistence.mode === 'conditional') return 'Conditional';
  return tool.persistence.mode === 'read' ? 'Read-only' : 'Mutating';
}

function toolTable(tools: ToolDescriptor[], fromAgents: boolean): string {
  const rows = [...tools]
    .sort((left, right) => left.category_order - right.category_order
      || left.name.localeCompare(right.name))
    .map(tool => {
      const path = fromAgents
        ? `docs/${tool.documentation.path}`
        : basename(tool.documentation.path);
      return `| [\`${tool.name}\`](${path}) | ${compactPurpose(tool)} | ${tool.category_label} | ${accessLabel(tool)} |`;
    });
  return [
    '| Tool | Purpose | Category | Persistence |',
    '|------|---------|----------|-------------|',
    ...rows,
  ].join('\n');
}

function capabilityTable(capabilities: CapabilityCounts): string {
  return [
    '| Capability | Count | Capability | Count |',
    '|------------|------:|------------|------:|',
    `| MCP tools | **${capabilities.mcp_tools}** | Offensive skills | **${capabilities.skills}** |`,
    `| Parser aliases | **${capabilities.parser_aliases}** | Built-in inference rules | **${capabilities.inference_rules}** |`,
    `| Node types | **${capabilities.node_types}** | Edge types | **${capabilities.edge_types}** |`,
    `| Agent archetypes | **${capabilities.agent_archetypes}** | Tool categories | **${capabilities.tool_categories}** |`,
  ].join('\n');
}

interface CapabilityCounts {
  mcp_tools: number;
  skills: number;
  parser_aliases: number;
  inference_rules: number;
  node_types: number;
  edge_types: number;
  agent_archetypes: number;
  tool_categories: number;
}

const temp = mkdtempSync(join(tmpdir(), 'overwatch-public-inventory-'));
const configPath = join(temp, 'engagement.json');
const statePath = join(temp, 'state-tool-registry.json');
const example = JSON.parse(readFileSync(resolve(ROOT, 'engagement.example.json'), 'utf8')) as Record<string, unknown>;
writeFileSync(configPath, JSON.stringify({
  ...example,
  id: 'tool-registry-generation',
  name: 'Tool registry generation',
}));

const app = createOverwatchApp({
  configPath,
  stateFilePath: statePath,
  skillDir: resolve(ROOT, 'skills'),
  dashboardPort: 0,
});

try {
  const registry = buildToolRegistryManifest(app.registeredTools);
  const archetypeIds = new Set(listArchetypes().map(archetype => archetype.id));
  const registeredToolNames = new Set(registry.tools.map(tool => tool.name));
  for (const archetype of listArchetypes()) {
    if (archetype.tools.full) continue;
    for (const toolName of archetype.tools.overwatch) {
      if (!registeredToolNames.has(toolName)) {
        throw new Error(`Archetype ${archetype.id} references unregistered tool ${toolName}`);
      }
    }
  }
  for (const tool of registry.tools) {
    const documentationPath = resolve(ROOT, 'docs', tool.documentation.path);
    if (!existsSync(documentationPath)) {
      throw new Error(`Tool ${tool.name} references missing documentation: ${tool.documentation.path}`);
    }
    if (tool.archetype_exposure.length === 0) {
      throw new Error(`Tool ${tool.name} is not exposed by any agent archetype`);
    }
    for (const archetype of tool.archetype_exposure) {
      if (!archetypeIds.has(archetype)) {
        throw new Error(`Tool ${tool.name} references unknown archetype ${archetype}`);
      }
    }
  }
  const capabilities: CapabilityCounts = {
    mcp_tools: registry.tool_count,
    skills: app.skills.count,
    parser_aliases: getSupportedParsers().length,
    inference_rules: BUILTIN_RULES.length,
    node_types: NODE_TYPES.length,
    edge_types: EDGE_TYPES.length,
    agent_archetypes: listArchetypes().length,
    tool_categories: registry.categories.length,
  };
  const publicManifest = {
    ...registry,
    capabilities,
  };

  updateMarkedFile(
    'AGENTS.md',
    '<!-- BEGIN:archetypes -->',
    '<!-- END:archetypes -->',
    generateSubAgentArchetypeReference(),
  );
  updateMarkedFile(
    'AGENTS.md',
    '<!-- BEGIN:tool-inventory -->',
    '<!-- END:tool-inventory -->',
    toolTable(registry.tools, true),
  );
  updateMarkedFile(
    'docs/tools/index.md',
    '<!-- BEGIN:tool-inventory -->',
    '<!-- END:tool-inventory -->',
    toolTable(registry.tools, false),
  );
  updateMarkedFile(
    'docs/index.md',
    '<!-- BEGIN:capability-counts -->',
    '<!-- END:capability-counts -->',
    capabilityTable(capabilities),
  );
  updateMarkedFile(
    'docs/operator-cockpit.md',
    '<!-- BEGIN:archetype-table -->',
    '<!-- END:archetype-table -->',
    generateOperatorCockpitArchetypeTable(),
  );

  writeOrCheck(
    'docs/reference/tool-schema-manifest.json',
    `${JSON.stringify(publicManifest, null, 2)}\n`,
  );

  const categoryCounts = Object.fromEntries(
    registry.categories.map(category => [
      category.id,
      registry.tools.filter(tool => tool.category === category.id).length,
    ]),
  );
  const generatedCategories = `// Generated by scripts/gen-public-inventories.ts. Do not edit.\n`
    + `export const TOOL_REGISTRY_SHA256 = ${JSON.stringify(registry.registry_sha256)};\n`
    + `export const TOOL_CATEGORIES = ${JSON.stringify(registry.categories.map(category => ({
      ...category,
      count: categoryCounts[category.id],
    })), null, 2)} as const;\n`;
  writeOrCheck(
    'src/dashboard-next/src/lib/tool-categories.generated.ts',
    generatedCategories,
  );
} finally {
  await shutdownOverwatchApp(app);
  rmSync(temp, { recursive: true, force: true });
}

if (changed.length > 0) {
  if (CHECK) {
    console.error(`Generated public inventories are stale: ${changed.join(', ')}`);
    console.error('Run `npm run gen:docs`.');
    process.exitCode = 1;
  } else {
    console.log(`Updated ${changed.join(', ')}`);
  }
} else {
  console.log('Public inventories are up to date.');
}
