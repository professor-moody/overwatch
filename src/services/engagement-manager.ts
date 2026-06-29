// ============================================================
// Overwatch — Engagement Manager
// Manages multiple engagement configs on disk in engagements/
// ============================================================

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { randomBytes } from 'crypto';
import { buildEngagementConfig } from './engagement-builder.js';
import type { EngagementConfig } from '../types.js';

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
  state_path: string;
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

/**
 * Engagement IDs become filesystem path components (`engagements/<id>.json`).
 * Reject anything that could escape the directory (`..`, slashes, NUL,
 * leading dot, control chars) or that is otherwise unreasonable as a slug.
 * Mirrors the shape produced by `createEngagement` (lowercased slug + base36
 * timestamp) but is tolerant of legacy IDs that may use uppercase / digits /
 * hyphens / underscores / dots-in-the-middle.
 */
function isSafeEngagementId(id: unknown): id is string {
  if (typeof id !== 'string') return false;
  if (id.length === 0 || id.length > 200) return false;
  if (id === '.' || id === '..') return false;
  if (id.startsWith('.')) return false;
  // Disallow path separators, NUL, and any control chars.
  // eslint-disable-next-line no-control-regex
  if (/[\\/\x00-\x1f]/.test(id)) return false;
  // Whitelist: alphanum, hyphen, underscore, dot.
  if (!/^[A-Za-z0-9._-]+$/.test(id)) return false;
  return true;
}

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
    // Build + validate via the shared builder (single source of truth for
    // id/nonce/profile/template logic); this manager owns only persistence.
    const parsedConfig = buildEngagementConfig(input);
    return this.persistConfig(parsedConfig);
  }

  /** Persist an already-built + validated config to engagements/<id>.json.
   *  The single write gateway (createEngagement + the dashboard from-template
   *  endpoint both route through here), so it enforces the persistence
   *  invariants for every path:
   *   - the id must be filesystem-safe (no path traversal — from-template
   *     accepts a caller-supplied id that the schema only checks is non-empty),
   *   - every persisted engagement carries a 64-hex nonce (P1.2), even on the
   *     from-template path which builds via mergeTemplateWithConfig (no minting),
   *   - never silently overwrite an existing engagement on an id collision. */
  persistConfig(config: EngagementConfig): EngagementSummary {
    if (!isSafeEngagementId(config.id)) {
      throw new Error(`Refusing to persist engagement with unsafe id: ${JSON.stringify(config.id)}`);
    }
    if (typeof (config as { engagement_nonce?: string }).engagement_nonce !== 'string') {
      (config as { engagement_nonce?: string }).engagement_nonce = randomBytes(32).toString('hex');
    }
    const filePath = join(this.engagementsDir, `${config.id}.json`);
    if (existsSync(filePath)) {
      throw new Error(`Engagement already exists: ${config.id}`);
    }
    writeFileSync(filePath, JSON.stringify(config, null, 2));
    return this.toSummary(config, filePath, false);
  }

  getEngagement(id: string): Record<string, unknown> | null {
    if (!isSafeEngagementId(id)) return null;
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
    if (!isSafeEngagementId(id)) return null;
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
      state_path: join(dirname(configPath), `state-${raw.id}.json`),
      is_active: isActive,
    };
  }
}
