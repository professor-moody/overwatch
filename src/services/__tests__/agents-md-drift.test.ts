import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { generateSubAgentArchetypeReference } from '../agent-archetypes.js';

// Keeps the offline-fallback AGENTS.md archetype catalog in lockstep with the
// registry (the CLAUDE.md prompt-generator↔AGENTS.md alignment rule). If the
// registry's archetypes / descriptions / done-tests change, regenerate with
// `npm run gen:docs` — this test fails until they match.
describe('AGENTS.md archetype section drift-check', () => {
  it('the checked-in archetype section equals the registry-generated one', () => {
    const md = readFileSync(resolve('./AGENTS.md'), 'utf-8');
    const BEGIN = '<!-- BEGIN:archetypes -->';
    const END = '<!-- END:archetypes -->';
    const i = md.indexOf(BEGIN);
    const j = md.indexOf(END);
    expect(i, 'BEGIN:archetypes marker present').toBeGreaterThanOrEqual(0);
    expect(j, 'END:archetypes marker after BEGIN').toBeGreaterThan(i);
    const section = md.slice(i + BEGIN.length, j).trim();
    expect(section, 'run `npm run gen:docs` to regenerate').toBe(generateSubAgentArchetypeReference());
  });
});
