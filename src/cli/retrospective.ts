#!/usr/bin/env node
// ============================================================
// Overwatch — Retrospective CLI
// Usage: npm run retrospective [-- --config path --output dir]
// ============================================================

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { GraphEngine } from '../services/graph-engine.js';
import { SkillIndex } from '../services/skill-index.js';
import { runRetrospective } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import type { EngagementConfig } from '../types.js';

// --- Parse args ---
const args = process.argv.slice(2);
function getArg(name: string, defaultValue: string): string {
  const idx = args.indexOf(`--${name}`);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return defaultValue;
}

const configPath = getArg('config', process.env.OVERWATCH_CONFIG || './engagement.json');
const skillDir = getArg('skills', process.env.OVERWATCH_SKILLS || './skills');
const outputDir = getArg('output', './retrospective');

// --- Load config ---
if (!existsSync(configPath)) {
  console.error(`Config not found: ${configPath}`);
  process.exit(1);
}

const config: EngagementConfig = JSON.parse(readFileSync(configPath, 'utf-8'));
console.log(`Loading engagement: ${config.name} (${config.id})`);

// --- Load engine (reads persisted state) ---
const stateFile = `./state-${config.id}.json`;
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
writeFileSync(join(dir, 'scoring-recommendations.json'), JSON.stringify(result.scoring, null, 2));
writeFileSync(join(dir, 'training-traces.json'), JSON.stringify(result.training_traces, null, 2));
writeFileSync(join(dir, 'summary.txt'), result.summary);

console.log(`Output written to ${dir}/`);
console.log('');
console.log('Files:');
console.log(`  report.md                    — attack path report`);
console.log(`  inference-suggestions.json   — ${result.inference_suggestions.length} rule suggestions`);
console.log(`  skill-gaps.json              — ${result.skill_gaps.missing_skills.length} missing, ${result.skill_gaps.unused_skills.length} unused`);
console.log(`  scoring-recommendations.json — ${result.scoring.rationale.length} recommendations`);
console.log(`  training-traces.json         — ${result.training_traces.length} RLVR traces`);
console.log(`  summary.txt                  — overview`);
console.log('');
console.log('=== Summary ===');
console.log(result.summary);
