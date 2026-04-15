import { describe, it, expect } from 'vitest';
import { readdirSync } from 'fs';
import { SkillIndex } from '../skill-index.js';

const skills = new SkillIndex('./skills');
const expectedSkillCount = readdirSync('./skills').filter(file => file.endsWith('.md')).length;

describe('SkillIndex', () => {
  it('loads skills from directory', () => {
    expect(skills.count).toBe(expectedSkillCount);
  });

  it('listSkills returns all skills with names and tags', () => {
    const list = skills.listSkills();
    expect(list.length).toBe(expectedSkillCount);
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

  it('stemmer handles security terms correctly', () => {
    // Access the private stem method for direct testing
    const stem = (word: string) => (skills as any).stem(word);

    // sses$ → ss (addresses, processes)
    expect(stem('addresses')).toBe('address');
    expect(stem('processes')).toBe('process');

    // ies$ → y
    expect(stem('vulnerabilities')).toBe('vulnerability');
    expect(stem('policies')).toBe('policy');

    // ation$ → ate
    expect(stem('enumeration')).toBe('enumerate');

    // ing/ed removal
    expect(stem('scanning')).toBe('scann');
    expect(stem('discovered')).toBe('discover');

    // s$ guarded — should not turn 'ss' into 's'
    expect(stem('access')).toBe('access');
    expect(stem('lass')).toBe('lass');

    // Normal s$ stripping
    expect(stem('hosts')).toBe('host');
    expect(stem('ports')).toBe('port');
  });

  it('stemmer preserves stop-list terms', () => {
    const stem = (word: string) => (skills as any).stem(word);

    expect(stem('kerberos')).toBe('kerberos');
    expect(stem('mimikatz')).toBe('mimikatz');
    expect(stem('rubeus')).toBe('rubeus');
    expect(stem('bloodhound')).toBe('bloodhound');
    expect(stem('nmap')).toBe('nmap');
    expect(stem('impacket')).toBe('impacket');
    expect(stem('certipy')).toBe('certipy');
  });

  it('IDF is positive even when a term appears in all documents', () => {
    const idfMap = (skills as any).idf as Map<string, number>;
    for (const [, value] of idfMap) {
      expect(value).toBeGreaterThan(0);
    }
  });

  it('constructor with non-existent custom path does not throw and produces empty results', () => {
    const idx = new SkillIndex('/tmp/overwatch-nonexistent-skills-dir-test-' + Date.now());
    expect(idx.count).toBe(0);
    expect(idx.listSkills()).toEqual([]);
    expect(idx.search('nmap')).toEqual([]);
  });

  it('excerpt matching works with stemmed terms', () => {
    const getExcerpt = (content: string, queryTokens: string[]) =>
      (skills as any).getExcerpt(content, queryTokens);

    const content = 'Short\nThis line discusses scanning vulnerabilities in the network infrastructure\nAnother line here';
    // "scanning" stems to "scann", "vulnerabilities" stems to "vulnerability"
    const stemmedTokens = [(skills as any).stem('scanning')];
    const excerpt = getExcerpt(content, stemmedTokens);
    expect(excerpt).toContain('scanning');

    // Also verify that the inflected form "vulnerabilities" matches the stemmed query "vulnerability"
    const excerpt2 = getExcerpt(content, [(skills as any).stem('vulnerabilities')]);
    expect(excerpt2).toContain('vulnerabilities');
  });

  // ---- Phase 3: Tag discoverability & netexec skill ----

  it('search for netexec returns the netexec skill first', () => {
    const results = skills.search('netexec');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toMatch(/netexec|nxc/);
  });

  it('search for crackmapexec alias finds netexec skill', () => {
    const results = skills.search('crackmapexec');
    expect(results.length).toBeGreaterThan(0);
    expect(results.some(r => r.name.toLowerCase().includes('netexec'))).toBe(true);
  });

  it('search for bloodhound returns ad-discovery skill', () => {
    const results = skills.search('bloodhound');
    expect(results.length).toBeGreaterThan(0);
    // Verify the top result has bloodhound in its name or is ad-discovery
    expect(results[0].name.toLowerCase()).toMatch(/active directory|ad|bloodhound/);
  });

  it('search for password spray returns password-spraying skill', () => {
    const results = skills.search('password spray');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toMatch(/password|spray/);
  });

  it('search for ntlm relay returns smb-relay skill', () => {
    const results = skills.search('ntlm relay');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name.toLowerCase()).toMatch(/smb|relay|ntlm/);
  });
});
