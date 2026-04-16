// ============================================================
// Overwatch — Engagement Manager
// Manages multiple engagement configs on disk in engagements/
// ============================================================

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

export interface EngagementSummary {
  id: string;
  name: string;
  profile?: string;
  created_at?: string;
  scope_cidrs: string[];
  scope_domains: string[];
  objectives_count: number;
  phases_count: number;
  config_path: string;
  is_active: boolean;
}

export interface CreateEngagementInput {
  name: string;
  profile?: string;
  cidrs?: string[];
  domains?: string[];
  exclusions?: string[];
  opsec_profile?: string;
  objectives?: Array<{ id: string; description: string }>;
}

const OPSEC_PROFILES: Record<string, { name: string; max_noise: number }> = {
  stealth: { name: 'stealth', max_noise: 0.2 },
  normal:  { name: 'normal',  max_noise: 0.5 },
  pentest: { name: 'pentest', max_noise: 0.7 },
  loud:    { name: 'loud',    max_noise: 1.0 },
};

export class EngagementManager {
  readonly engagementsDir: string;

  constructor(private readonly activeConfigPath: string) {
    this.engagementsDir = join(dirname(activeConfigPath), 'engagements');
    if (!existsSync(this.engagementsDir)) {
      mkdirSync(this.engagementsDir, { recursive: true });
    }
    this.mirrorActiveIfNeeded();
  }

  /** Copy the active engagement config into engagements/ on first run. */
  private mirrorActiveIfNeeded(): void {
    if (!existsSync(this.activeConfigPath)) return;
    try {
      const raw = JSON.parse(readFileSync(this.activeConfigPath, 'utf-8'));
      if (!raw.id) return;
      const mirrorPath = join(this.engagementsDir, `${raw.id}.json`);
      if (!existsSync(mirrorPath)) {
        writeFileSync(mirrorPath, JSON.stringify(raw, null, 2));
      }
    } catch {
      // non-fatal
    }
  }

  /** Return id of the currently-running engagement. */
  getActiveId(): string | null {
    if (!existsSync(this.activeConfigPath)) return null;
    try {
      return JSON.parse(readFileSync(this.activeConfigPath, 'utf-8')).id ?? null;
    } catch { return null; }
  }

  listEngagements(): EngagementSummary[] {
    const results: EngagementSummary[] = [];
    const activeId = this.getActiveId();
    const seen = new Set<string>();

    if (!existsSync(this.engagementsDir)) return results;

    const files = readdirSync(this.engagementsDir)
      .filter(f => f.endsWith('.json'))
      .sort();

    for (const file of files) {
      const filePath = join(this.engagementsDir, file);
      try {
        const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
        if (!raw.id) continue;
        seen.add(raw.id);
        results.push(this.toSummary(raw, filePath, raw.id === activeId));
      } catch { /* skip corrupt files */ }
    }

    // If the active engagement isn't mirrored yet, prepend it directly
    if (activeId && !seen.has(activeId) && existsSync(this.activeConfigPath)) {
      try {
        const raw = JSON.parse(readFileSync(this.activeConfigPath, 'utf-8'));
        results.unshift(this.toSummary(raw, this.activeConfigPath, true));
      } catch { /* ignore */ }
    }

    return results;
  }

  createEngagement(input: CreateEngagementInput): EngagementSummary {
    const slug = input.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 40);
    const id = `${slug}-${Date.now().toString(36)}`;

    const config = {
      id,
      name: input.name,
      created_at: new Date().toISOString(),
      profile: input.profile || 'network',
      scope: {
        cidrs: input.cidrs || [],
        domains: input.domains || [],
        exclusions: input.exclusions || [],
      },
      objectives: (input.objectives || []).map((o, i) => ({
        id: o.id || `obj-${i + 1}`,
        description: o.description,
        achieved: false,
      })),
      opsec: OPSEC_PROFILES[input.opsec_profile || 'pentest'] ?? OPSEC_PROFILES.pentest,
      phases: [],
    };

    const filePath = join(this.engagementsDir, `${id}.json`);
    writeFileSync(filePath, JSON.stringify(config, null, 2));
    return this.toSummary(config, filePath, false);
  }

  private toSummary(raw: any, configPath: string, isActive: boolean): EngagementSummary {
    return {
      id: raw.id,
      name: raw.name,
      profile: raw.profile,
      created_at: raw.created_at,
      scope_cidrs: raw.scope?.cidrs ?? [],
      scope_domains: raw.scope?.domains ?? [],
      objectives_count: (raw.objectives ?? []).length,
      phases_count: (raw.phases ?? []).length,
      config_path: configPath,
      is_active: isActive,
    };
  }
}
