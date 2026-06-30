#!/usr/bin/env node
// Regenerates the registry-derived sections of AGENTS.md in place (between the
// `<!-- BEGIN:archetypes -->` / `<!-- END:archetypes -->` markers). The
// agents-md-drift test asserts the checked-in content matches; run this after
// changing the archetype registry. Usage: `npm run gen:docs`.
import { readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import { generateSubAgentArchetypeReference } from '../src/services/agent-archetypes.js';

const AGENTS_MD = resolve('./AGENTS.md');
const BEGIN = '<!-- BEGIN:archetypes -->';
const END = '<!-- END:archetypes -->';

function replaceBetween(text: string, begin: string, end: string, body: string): string {
  const i = text.indexOf(begin);
  const j = text.indexOf(end);
  if (i < 0 || j < 0 || j < i) throw new Error(`markers ${begin}/${end} not found (in order) in AGENTS.md`);
  return text.slice(0, i + begin.length) + '\n' + body + '\n' + text.slice(j);
}

const current = readFileSync(AGENTS_MD, 'utf-8');
const updated = replaceBetween(current, BEGIN, END, generateSubAgentArchetypeReference());
if (updated !== current) {
  writeFileSync(AGENTS_MD, updated);
  console.log('AGENTS.md archetype section regenerated.');
} else {
  console.log('AGENTS.md already up to date.');
}
