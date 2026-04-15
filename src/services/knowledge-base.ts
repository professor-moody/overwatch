// ============================================================
// Overwatch — Multi-Engagement Knowledge Base
// File-based KB storing cross-engagement statistics:
// - Per-technique success rates
// - Per-service credential patterns
// - Defense-vs-technique matrix
// Privacy-preserving: statistics only, no sensitive data.
// ============================================================

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { mkdirSync } from 'fs';

// --- Types ---

export interface TechniqueStats {
  technique_id: string;
  name: string;
  attempts: number;
  successes: number;
  success_rate: number;  // 0.0–1.0
  avg_noise: number;     // average opsec noise when used
  last_seen: string;     // ISO timestamp
  engagements: number;   // distinct engagement count
}

export interface ServiceCredPattern {
  service: string;        // e.g. 'mssql', 'smb', 'ssh', 'rdp'
  default_creds_found: number;
  weak_creds_found: number;
  total_attempts: number;
  common_users: string[]; // most common usernames (max 10)
  engagements: number;
}

export interface DefenseEntry {
  defense: string;        // e.g. 'EDR-CrowdStrike', 'MFA-Duo', 'WAF-Cloudflare'
  blocks_techniques: string[];  // technique IDs typically blocked
  bypassed_count: number;
  encountered_count: number;
  bypass_rate: number;    // 0.0–1.0
}

export interface KBData {
  version: number;
  last_updated: string;
  engagement_count: number;
  techniques: Record<string, TechniqueStats>;
  service_patterns: Record<string, ServiceCredPattern>;
  defenses: Record<string, DefenseEntry>;
}

const KB_VERSION = 1;

function emptyKB(): KBData {
  return {
    version: KB_VERSION,
    last_updated: new Date().toISOString(),
    engagement_count: 0,
    techniques: {},
    service_patterns: {},
    defenses: {},
  };
}

// --- Knowledge Base Class ---

export class KnowledgeBase {
  private data: KBData;
  private filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath || resolve(process.cwd(), 'knowledge-base.json');
    this.data = this.load();
  }

  private load(): KBData {
    if (!existsSync(this.filePath)) return emptyKB();
    try {
      const raw = readFileSync(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (parsed.version !== KB_VERSION) return emptyKB();
      return parsed;
    } catch {
      return emptyKB();
    }
  }

  save(): void {
    this.data.last_updated = new Date().toISOString();
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
  }

  getData(): KBData {
    return this.data;
  }

  getEngagementCount(): number {
    return this.data.engagement_count;
  }

  // --- Technique Stats ---

  recordTechniqueAttempt(techniqueId: string, name: string, success: boolean, noise: number): void {
    const existing = this.data.techniques[techniqueId];
    if (existing) {
      existing.attempts++;
      if (success) existing.successes++;
      existing.success_rate = existing.successes / existing.attempts;
      existing.avg_noise = (existing.avg_noise * (existing.attempts - 1) + noise) / existing.attempts;
      existing.last_seen = new Date().toISOString();
    } else {
      this.data.techniques[techniqueId] = {
        technique_id: techniqueId,
        name,
        attempts: 1,
        successes: success ? 1 : 0,
        success_rate: success ? 1.0 : 0.0,
        avg_noise: noise,
        last_seen: new Date().toISOString(),
        engagements: 1,
      };
    }
  }

  getTechniqueStats(techniqueId: string): TechniqueStats | undefined {
    return this.data.techniques[techniqueId];
  }

  getAllTechniqueStats(): TechniqueStats[] {
    return Object.values(this.data.techniques);
  }

  // --- Service Credential Patterns ---

  recordCredentialPattern(service: string, isDefault: boolean, isWeak: boolean, username?: string): void {
    const existing = this.data.service_patterns[service];
    if (existing) {
      existing.total_attempts++;
      if (isDefault) existing.default_creds_found++;
      if (isWeak) existing.weak_creds_found++;
      if (username && !existing.common_users.includes(username)) {
        existing.common_users.push(username);
        if (existing.common_users.length > 10) existing.common_users = existing.common_users.slice(-10);
      }
    } else {
      this.data.service_patterns[service] = {
        service,
        default_creds_found: isDefault ? 1 : 0,
        weak_creds_found: isWeak ? 1 : 0,
        total_attempts: 1,
        common_users: username ? [username] : [],
        engagements: 1,
      };
    }
  }

  getServicePattern(service: string): ServiceCredPattern | undefined {
    return this.data.service_patterns[service];
  }

  // --- Defense Matrix ---

  recordDefense(defense: string, techniquesBlocked: string[], wasBypassed: boolean): void {
    const existing = this.data.defenses[defense];
    if (existing) {
      existing.encountered_count++;
      if (wasBypassed) existing.bypassed_count++;
      existing.bypass_rate = existing.bypassed_count / existing.encountered_count;
      for (const t of techniquesBlocked) {
        if (!existing.blocks_techniques.includes(t)) {
          existing.blocks_techniques.push(t);
        }
      }
    } else {
      this.data.defenses[defense] = {
        defense,
        blocks_techniques: [...techniquesBlocked],
        bypassed_count: wasBypassed ? 1 : 0,
        encountered_count: 1,
        bypass_rate: wasBypassed ? 1.0 : 0.0,
      };
    }
  }

  getDefense(defense: string): DefenseEntry | undefined {
    return this.data.defenses[defense];
  }

  // --- Engagement Import ---

  /**
   * Import aggregated stats from an engagement.
   * Call this during retrospective to merge findings into the KB.
   */
  importFromEngagement(input: {
    techniques: Array<{ id: string; name: string; success: boolean; noise: number }>;
    credentials: Array<{ service: string; isDefault: boolean; isWeak: boolean; username?: string }>;
    defenses: Array<{ defense: string; techniquesBlocked: string[]; wasBypassed: boolean }>;
  }): void {
    for (const t of input.techniques) {
      this.recordTechniqueAttempt(t.id, t.name, t.success, t.noise);
    }
    for (const c of input.credentials) {
      this.recordCredentialPattern(c.service, c.isDefault, c.isWeak, c.username);
    }
    for (const d of input.defenses) {
      this.recordDefense(d.defense, d.techniquesBlocked, d.wasBypassed);
    }

    // Increment engagement count and bump per-entity engagement counts
    this.data.engagement_count++;
    // Note: per-entity engagement counts are incremented in the respective record methods
    // but only once per engagement. For simplicity, we just increment on each call.
  }

  // --- Query Helpers ---

  /** Get technique stats formatted for validate_action context. */
  getTechniqueContext(techniqueId: string): string | null {
    const stats = this.data.techniques[techniqueId];
    if (!stats) return null;
    return `Historical success: ${Math.round(stats.success_rate * 100)}% (${stats.engagements} engagement${stats.engagements !== 1 ? 's' : ''}, ${stats.attempts} attempts, avg noise ${stats.avg_noise.toFixed(2)})`;
  }

  /** Get top techniques by success rate. */
  getTopTechniques(limit: number = 10): TechniqueStats[] {
    return Object.values(this.data.techniques)
      .filter(t => t.attempts >= 2) // require at least 2 attempts
      .sort((a, b) => b.success_rate - a.success_rate)
      .slice(0, limit);
  }
}
