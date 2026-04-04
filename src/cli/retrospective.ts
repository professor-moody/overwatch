#!/usr/bin/env node
// ============================================================
// Overwatch — Retrospective CLI
// Usage: npm run retrospective [-- --config path --output dir --state path]
// ============================================================

import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { GraphEngine } from '../services/graph-engine.js';
import { SkillIndex } from '../services/skill-index.js';
import { runRetrospective } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import type { EngagementConfig } from '../types.js';
import { formatConfigError, loadEngagementConfigFile } from '../config.js';

// --- Help ---
if (process.argv.includes('--help')) {
  console.log(`Usage: npm run retrospective [-- OPTIONS]

Options:
  --config <path>   Path to engagement config file (default: $OVERWATCH_CONFIG or ./engagement.json)
  --skills <path>   Path to skill library directory (default: $OVERWATCH_SKILLS or ./skills)
  --output <dir>    Output directory for retrospective results (default: ./retrospective)
  --state <path>    Path to state file (default: ./state-<config.id>.json)
  --help            Show this help message`);
  process.exit(0);
}

// --- Parse args ---
export function parseRetrospectiveArgs(args: string[]): {
  configPath: string;
  skillDir: string;
  outputDir: string;
  statePath: string | undefined;
} {
  function getArg(name: string, defaultValue: string): string {
    const idx = args.indexOf(`--${name}`);
    if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
    return defaultValue;
  }
  const stateIdx = args.indexOf('--state');
  return {
    configPath: getArg('config', process.env.OVERWATCH_CONFIG || './engagement.json'),
    skillDir: getArg('skills', process.env.OVERWATCH_SKILLS || './skills'),
    outputDir: getArg('output', './retrospective'),
    statePath: stateIdx >= 0 && stateIdx + 1 < args.length ? args[stateIdx + 1] : undefined,
  };
}

const parsedArgs = parseRetrospectiveArgs(process.argv.slice(2));
const configPath = parsedArgs.configPath;
const skillDir = parsedArgs.skillDir;
const outputDir = parsedArgs.outputDir;

// --- Load config ---
if (!existsSync(configPath)) {
  console.error(`Config not found: ${configPath}`);
  process.exit(1);
}

let config: EngagementConfig;
try {
  config = loadEngagementConfigFile(configPath);
} catch (error) {
  console.error(formatConfigError(error, configPath));
  process.exit(1);
}
console.log(`Loading engagement: ${config.name} (${config.id})`);

// --- Load engine (reads persisted state) ---
const stateFile = parsedArgs.statePath ?? `./state-${config.id}.json`;
if (!existsSync(stateFile)) {
  console.error(`State file not found: ${stateFile} — has the engagement been started?`);
  process.exit(1);
}

const engine = new GraphEngine(config, stateFile);
const skills = new SkillIndex(skillDir);

// --- Build input ---
const allSkills = skills.listSkills();
const input: RetrospectiveInput = {
  config: engine.getConfig(),
  graph: engine.exportGraph(),
  history: engine.getFullHistory(),
  inferenceRules: engine.getInferenceRules(),
  agents: engine.getAllAgents(),
  skillNames: allSkills.map(s => s.name),
  skillTags: allSkills.flatMap(s => s.tags),
};

console.log(`Graph: ${input.graph.nodes.length} nodes, ${input.graph.edges.length} edges`);
console.log(`History: ${input.history.length} entries`);
console.log(`Skills: ${input.skillNames.length} loaded`);
console.log('');

// --- Run analysis ---
console.log('Running retrospective analysis...');
const result = runRetrospective(input);

// --- Write outputs ---
const dir = join(outputDir, config.id);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

writeFileSync(join(dir, 'report.md'), result.report_markdown);
writeFileSync(join(dir, 'inference-suggestions.json'), JSON.stringify(result.inference_suggestions, null, 2));
writeFileSync(join(dir, 'skill-gaps.json'), JSON.stringify(result.skill_gaps, null, 2));
writeFileSync(join(dir, 'context-improvements.json'), JSON.stringify(result.context_improvements, null, 2));
writeFileSync(join(dir, 'training-traces.json'), JSON.stringify(result.training_traces, null, 2));
writeFileSync(join(dir, 'trace-quality.json'), JSON.stringify(result.trace_quality, null, 2));
writeFileSync(join(dir, 'summary.txt'), result.summary);

console.log(`Output written to ${dir}/`);
console.log('');
console.log('Files:');
console.log(`  report.md                    — attack path report`);
console.log(`  inference-suggestions.json   — ${result.inference_suggestions.length} rule suggestions`);
console.log(`  skill-gaps.json              — ${result.skill_gaps.missing_skills.length} missing, ${result.skill_gaps.unused_skills.length} unused`);
console.log(`  context-improvements.json    — ${result.context_improvements.recommendations.length} recommendations`);
console.log(`  training-traces.json         — ${result.training_traces.length} heuristic RLVR traces`);
console.log(`  trace-quality.json           — ${result.trace_quality.status} trace quality`);
console.log(`  summary.txt                  — overview`);
console.log('');
console.log('=== Summary ===');
console.log(result.summary);
