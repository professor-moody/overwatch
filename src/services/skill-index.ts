// ============================================================
// Overwatch — Skill Index (RAG)
// Simple TF-IDF search over markdown skill files.
// No external vector DB dependency — runs locally.
// ============================================================

import { readFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, basename } from 'path';

interface SkillEntry {
  id: string;
  name: string;
  filename: string;
  content: string;
  tags: string[];
  tokens: string[];       // lowercased word tokens
  tf: Map<string, number>; // term frequency
}

interface SkillMatch {
  id: string;
  name: string;
  score: number;
  excerpt: string;
  filename: string;
}

export class SkillIndex {
  private skills: SkillEntry[] = [];
  private idf: Map<string, number> = new Map();
  private skillDir: string;

  constructor(skillDir?: string) {
    this.skillDir = skillDir || './skills';
    if (!existsSync(this.skillDir)) {
      mkdirSync(this.skillDir, { recursive: true });
    }
    this.loadSkills();
    this.computeIDF();
  }

  // =============================================
  // Loading
  // =============================================

  private loadSkills(): void {
    if (!existsSync(this.skillDir)) return;

    const files = readdirSync(this.skillDir).filter(f => f.endsWith('.md'));
    for (const file of files) {
      const filepath = join(this.skillDir, file);
      const content = readFileSync(filepath, 'utf-8');
      const name = this.extractName(content, file);
      const tags = this.extractTags(content);
      const tokens = this.tokenize(content);
      const tf = this.computeTF(tokens);

      this.skills.push({
        id: basename(file, '.md'),
        name,
        filename: file,
        content,
        tags,
        tokens,
        tf
      });
    }
  }

  private extractName(content: string, fallback: string): string {
    const match = content.match(/^#\s+(.+)$/m);
    return match ? match[1].trim() : basename(fallback, '.md');
  }

  private extractTags(content: string): string[] {
    // Look for a tags line like: tags: smb, relay, ntlm, lateral-movement
    const match = content.match(/^tags:\s*(.+)$/mi);
    if (match) {
      return match[1].split(',').map(t => t.trim().toLowerCase());
    }
    return [];
  }

  // =============================================
  // TF-IDF Search
  // =============================================

  private tokenize(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^a-z0-9\-_.]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 2);
  }

  private computeTF(tokens: string[]): Map<string, number> {
    const tf = new Map<string, number>();
    const total = tokens.length || 1;
    for (const t of tokens) {
      tf.set(t, (tf.get(t) || 0) + 1);
    }
    // Normalize
    for (const [k, v] of tf) {
      tf.set(k, v / total);
    }
    return tf;
  }

  private computeIDF(): void {
    const docCount = this.skills.length || 1;
    const docFreq = new Map<string, number>();

    for (const skill of this.skills) {
      const uniqueTokens = new Set(skill.tokens);
      for (const t of uniqueTokens) {
        docFreq.set(t, (docFreq.get(t) || 0) + 1);
      }
    }

    for (const [term, freq] of docFreq) {
      this.idf.set(term, Math.log(docCount / freq));
    }
  }

  search(query: string, maxResults: number = 5): SkillMatch[] {
    const queryTokens = this.tokenize(query);
    if (queryTokens.length === 0) return [];

    const scores: Array<{ skill: SkillEntry; score: number }> = [];

    for (const skill of this.skills) {
      let score = 0;

      // TF-IDF score
      for (const qt of queryTokens) {
        const tf = skill.tf.get(qt) || 0;
        const idf = this.idf.get(qt) || 0;
        score += tf * idf;
      }

      // Tag bonus — exact tag matches get a strong boost
      for (const qt of queryTokens) {
        if (skill.tags.includes(qt)) {
          score += 0.5;
        }
      }

      // Name bonus — query terms in the skill name
      const nameLower = skill.name.toLowerCase();
      for (const qt of queryTokens) {
        if (nameLower.includes(qt)) {
          score += 0.3;
        }
      }

      if (score > 0) {
        scores.push({ skill, score });
      }
    }

    return scores
      .sort((a, b) => b.score - a.score)
      .slice(0, maxResults)
      .map(({ skill, score }) => ({
        id: skill.id,
        name: skill.name,
        score: Math.round(score * 100) / 100,
        excerpt: this.getExcerpt(skill.content, queryTokens),
        filename: skill.filename
      }));
  }

  getSkillContent(id: string): string | null {
    const skill = this.skills.find(s => s.id === id);
    return skill ? skill.content : null;
  }

  listSkills(): Array<{ id: string; name: string; tags: string[] }> {
    return this.skills.map(s => ({ id: s.id, name: s.name, tags: s.tags }));
  }

  private getExcerpt(content: string, queryTokens: string[]): string {
    const lines = content.split('\n');
    // Find the first line containing a query token
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (queryTokens.some(t => lower.includes(t)) && line.trim().length > 10) {
        return line.trim().substring(0, 200);
      }
    }
    // Fallback: first non-header, non-empty line
    for (const line of lines) {
      if (line.trim() && !line.startsWith('#') && !line.startsWith('tags:')) {
        return line.trim().substring(0, 200);
      }
    }
    return '';
  }

  // =============================================
  // Skill count for health checks
  // =============================================

  get count(): number {
    return this.skills.length;
  }
}
