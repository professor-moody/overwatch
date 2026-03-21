import { describe, it, expect } from 'vitest';
import { SkillIndex } from '../skill-index.js';

const skills = new SkillIndex('./skills');

describe('SkillIndex', () => {
  it('loads skills from directory', () => {
    expect(skills.count).toBe(29);
  });

  it('listSkills returns all skills with names and tags', () => {
    const list = skills.listSkills();
    expect(list.length).toBe(29);
    expect(list[0]).toHaveProperty('id');
    expect(list[0]).toHaveProperty('name');
    expect(list[0]).toHaveProperty('tags');
  });

  it('search finds relevant skills by keyword', () => {
    const results = skills.search('nmap port scan');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toContain('network');
  });

  it('search ranks tagged skills higher', () => {
    const results = skills.search('smb relay');
    expect(results.length).toBeGreaterThan(0);
    // smb-relay.md has 'smb' and 'relay' as tags — should rank high
    expect(results[0].name.toLowerCase()).toMatch(/smb|relay/);
  });

  it('search ranks name matches higher', () => {
    const results = skills.search('active directory');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toMatch(/active directory/);
  });

  it('getSkillContent returns full markdown', () => {
    const list = skills.listSkills();
    const content = skills.getSkillContent(list[0].id);
    expect(content).toBeTruthy();
    expect(content).toContain('#');
  });

  it('getSkillContent returns null for unknown skill', () => {
    const content = skills.getSkillContent('nonexistent-skill');
    expect(content).toBeNull();
  });

  it('search with empty query returns results', () => {
    const results = skills.search('');
    // Should still return skills (or empty gracefully)
    expect(Array.isArray(results)).toBe(true);
  });

  it('search for specific technique returns relevant skill', () => {
    const results = skills.search('kerberoasting');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toMatch(/kerber/);
  });

  it('search for lateral movement returns relevant skill', () => {
    const results = skills.search('lateral movement psexec');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toMatch(/lateral/);
  });
});
