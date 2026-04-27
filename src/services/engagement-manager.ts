// ============================================================
// Overwatch — Engagement Manager
// Manages multiple engagement configs on disk in engagements/
// ============================================================

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { loadTemplate, mergeTemplateWithConfig } from '../config.js';

export interface EngagementSummary {
  id: string;
  name: string;
  profile?: string;
  created_at?: string;
  scope_cidrs: string[];
  scope_domains: string[];
  exclusions_count: number;
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
  hosts?: string[];
  url_patterns?: string[];
  aws_accounts?: string[];
  azure_subscriptions?: string[];
  gcp_projects?: string[];
  opsec_profile?: string;
  opsec?: {
    max_noise?: number;
    approval_mode?: string;
    approval_timeout_ms?: number;
    time_window?: { start_hour: number; end_hour: number } | null;
    blacklisted_techniques?: string[];
  };
  objectives?: Array<{ id: string; description: string }>;
  failure_patterns?: Array<{ technique: string; target_pattern?: string; warning: string }>;
  phases?: Array<{ id: string; name: string; order: number; strategies?: string[]; entry_criteria?: unknown[]; exit_criteria?: unknown[] }>;
  template_id?: string;
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
    const created_at = new Date().toISOString();

    let config: Record<string, unknown>;

    if (input.template_id) {
      const template = loadTemplate(input.template_id);
      if (!template) {
        throw new Error(`Template not found: ${input.template_id}`);
      }
      const opsecOverride = input.opsec_profile
        ? OPSEC_PROFILES[input.opsec_profile] ?? OPSEC_PROFILES.pentest
        : undefined;
      const mergedObjectives = input.objectives && input.objectives.length > 0
        ? input.objectives.map((o, i) => ({ id: o.id || `obj-${i + 1}`, description: o.description, achieved: false }))
        : undefined;
      const overrides: any = {
        id,
        name: input.name,
        created_at,
        scope: this.buildScope(input),
      };
      if (input.profile) overrides.profile = input.profile;
      if (opsecOverride) overrides.opsec = { ...opsecOverride, ...this.buildOpsecOverrides(input) };
      else if (input.opsec) overrides.opsec = this.buildOpsecOverrides(input);
      if (mergedObjectives) overrides.objectives = mergedObjectives;
      if (input.failure_patterns?.length) overrides.failure_patterns = input.failure_patterns;
      if (input.phases?.length) overrides.phases = input.phases;
      config = mergeTemplateWithConfig(template, overrides) as unknown as Record<string, unknown>;
    } else {
      const baseOpsec = OPSEC_PROFILES[input.opsec_profile || 'pentest'] ?? OPSEC_PROFILES.pentest;
      config = {
        id,
        name: input.name,
        created_at,
        profile: input.profile || 'network',
        scope: this.buildScope(input),
        objectives: (input.objectives || []).map((o, i) => ({
          id: o.id || `obj-${i + 1}`,
          description: o.description,
          achieved: false,
        })),
        opsec: { ...baseOpsec, ...this.buildOpsecOverrides(input) },
        failure_patterns: input.failure_patterns || [],
        phases: input.phases || [],
      };
    }

    const filePath = join(this.engagementsDir, `${id}.json`);
    writeFileSync(filePath, JSON.stringify(config, null, 2));
    return this.toSummary(config, filePath, false);
  }

  getEngagement(id: string): Record<string, unknown> | null {
    const activeId = this.getActiveId();
    // If requesting active engagement, read from active config (has live state)
    if (id === activeId && existsSync(this.activeConfigPath)) {
      try {
        const raw = JSON.parse(readFileSync(this.activeConfigPath, 'utf-8'));
        return { ...raw, is_active: true, config_path: this.activeConfigPath };
      } catch { /* fall through to disk */ }
    }
    const filePath = join(this.engagementsDir, `${id}.json`);
    if (!existsSync(filePath)) return null;
    try {
      const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
      return { ...raw, is_active: id === activeId, config_path: filePath };
    } catch { return null; }
  }

  updateEngagement(id: string, partial: Record<string, unknown>): Record<string, unknown> | null {
    const filePath = join(this.engagementsDir, `${id}.json`);
    if (!existsSync(filePath)) return null;
    try {
      const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
      // Merge top-level scalars
      if (typeof partial.name === 'string') raw.name = partial.name;
      if (typeof partial.profile === 'string') raw.profile = partial.profile;
      // Merge scope (partial)
      if (partial.scope && typeof partial.scope === 'object') {
        raw.scope = { ...(raw.scope || {}), ...(partial.scope as Record<string, unknown>) };
      }
      // Merge opsec (partial)
      if (partial.opsec && typeof partial.opsec === 'object') {
        raw.opsec = { ...(raw.opsec || {}), ...(partial.opsec as Record<string, unknown>) };
      }
      // Full replace for arrays
      if (Array.isArray(partial.objectives)) raw.objectives = partial.objectives;
      if (Array.isArray(partial.failure_patterns)) raw.failure_patterns = partial.failure_patterns;
      if (Array.isArray(partial.phases)) raw.phases = partial.phases;
      writeFileSync(filePath, JSON.stringify(raw, null, 2));
      return raw;
    } catch { return null; }
  }

  private buildScope(input: CreateEngagementInput): Record<string, unknown> {
    const scope: Record<string, unknown> = {
      cidrs: input.cidrs || [],
      domains: input.domains || [],
      exclusions: input.exclusions || [],
    };
    if (input.hosts?.length) scope.hosts = input.hosts;
    if (input.url_patterns?.length) scope.url_patterns = input.url_patterns;
    if (input.aws_accounts?.length) scope.aws_accounts = input.aws_accounts;
    if (input.azure_subscriptions?.length) scope.azure_subscriptions = input.azure_subscriptions;
    if (input.gcp_projects?.length) scope.gcp_projects = input.gcp_projects;
    return scope;
  }

  private buildOpsecOverrides(input: CreateEngagementInput): Record<string, unknown> {
    const o: Record<string, unknown> = {};
    if (!input.opsec) return o;
    if (input.opsec.max_noise != null) o.max_noise = input.opsec.max_noise;
    if (input.opsec.approval_mode) o.approval_mode = input.opsec.approval_mode;
    if (input.opsec.approval_timeout_ms != null) o.approval_timeout_ms = input.opsec.approval_timeout_ms;
    if (input.opsec.time_window !== undefined) {
      o.time_window = input.opsec.time_window;
    }
    if (input.opsec.blacklisted_techniques?.length) o.blacklisted_techniques = input.opsec.blacklisted_techniques;
    return o;
  }

  private toSummary(raw: any, configPath: string, isActive: boolean): EngagementSummary {
    return {
      id: raw.id,
      name: raw.name,
      profile: raw.profile,
      created_at: raw.created_at,
      scope_cidrs: raw.scope?.cidrs ?? [],
      scope_domains: raw.scope?.domains ?? [],
      exclusions_count: (raw.scope?.exclusions ?? []).length,
      objectives_count: (raw.objectives ?? []).length,
      phases_count: (raw.phases ?? []).length,
      config_path: configPath,
      is_active: isActive,
    };
  }
}
