// ============================================================
// Overwatch — Engagement Manager
// Manages multiple engagement configs on disk in engagements/
// ============================================================

import { readFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { createHash, randomBytes } from 'crypto';
import { z } from 'zod';
import { buildEngagementConfig } from './engagement-builder.js';
import type { EngagementConfig } from '../types.js';
import {
  engagementConfigSchema,
  engagementObjectiveSchema,
  nodeTypeSchema,
  operatorPolicyUpdateSchema,
} from '../types.js';
import { mergeConfig } from './config-manager.js';
import {
  configsSemanticallyEqual,
  withConfigMetadata,
  writeJsonAtomicDurable,
} from './engagement-config-service.js';

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

export type EngagementManagerErrorCode =
  | 'ENGAGEMENT_NOT_FOUND'
  | 'ENGAGEMENT_VALIDATION_FAILED'
  | 'ENGAGEMENT_CONFLICT'
  | 'ENGAGEMENT_PERSISTENCE_FAILED';

/**
 * Stable failure classification for the inactive-engagement file store.
 * Dashboard adapters use the code to distinguish operator input/conflicts
 * from a durable write that did not land.
 */
export class EngagementManagerError extends Error {
  constructor(
    readonly code: EngagementManagerErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'EngagementManagerError';
  }
}

type DurableConfigWriter = (
  path: string,
  value: unknown,
  assertCurrent?: (capturedPath?: string) => void,
) => void;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function managerError(
  code: EngagementManagerErrorCode,
  message: string,
  cause?: unknown,
): EngagementManagerError {
  return new EngagementManagerError(
    code,
    cause === undefined ? message : `${message}: ${errorMessage(cause)}`,
  );
}

const stringArraySchema = z.array(z.string());
const crossTierLinkUpdateSchema = z.object({
  url_pattern: z.string().optional(),
  aws_account: z.string().optional(),
  azure_subscription: z.string().optional(),
  gcp_project: z.string().optional(),
  cloud_resource_prefix: z.string().optional(),
  idp_kind: z.enum([
    'okta',
    'entra',
    'auth0',
    'ping',
    'generic_oidc',
    'generic_saml',
    'ci_github_actions',
    'ci_gitlab',
    'ci_circleci',
  ]).optional(),
  tenant_id: z.string().optional(),
  notes: z.string().optional(),
}).strict();

const scopeUpdateSchema = z.object({
  cidrs: stringArraySchema.optional(),
  domains: stringArraySchema.optional(),
  exclusions: stringArraySchema.optional(),
  hosts: stringArraySchema.optional(),
  aws_accounts: stringArraySchema.optional(),
  azure_subscriptions: stringArraySchema.optional(),
  gcp_projects: stringArraySchema.optional(),
  url_patterns: stringArraySchema.optional(),
  cross_tier_links: z.array(crossTierLinkUpdateSchema).optional(),
}).strict();

const timeWindowUpdateSchema = z.object({
  start_hour: z.number().int().min(0).max(23),
  end_hour: z.number().int().min(0).max(23),
}).strict();

const opsecUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  enabled: z.boolean().optional(),
  max_noise: z.number().min(0).max(1).optional(),
  time_window: timeWindowUpdateSchema.nullable().optional(),
  blacklisted_techniques: stringArraySchema.optional(),
  notes: z.string().optional(),
  approval_mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional(),
  approval_timeout_ms: z.number().int().min(1000).optional(),
}).strict();

const phaseCriterionUpdateSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('always') }).strict(),
  z.object({ type: z.literal('phase_completed'), phase_id: z.string().min(1) }).strict(),
  z.object({ type: z.literal('objective_achieved'), objective_id: z.string().min(1) }).strict(),
  z.object({
    type: z.literal('node_count'),
    node_type: nodeTypeSchema,
    min: z.number().int().min(1),
  }).strict(),
  z.object({
    type: z.literal('access_level'),
    min_level: z.enum(['user', 'local_admin', 'domain_admin']),
  }).strict(),
]);

const phaseUpdateSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  order: z.number().int().min(0),
  strategies: z.array(z.enum([
    'credential_spray',
    'enumeration',
    'post_exploitation',
    'network_discovery',
    'custom',
  ])).optional(),
  entry_criteria: z.array(phaseCriterionUpdateSchema).optional(),
  exit_criteria: z.array(phaseCriterionUpdateSchema).optional(),
  opsec_overrides: opsecUpdateSchema.optional(),
  approval_overrides: z.object({
    mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional(),
    blacklisted_techniques: stringArraySchema.optional(),
  }).strict().optional(),
}).strict();

/** Strict schema for the fields mergeConfig intentionally supports. */
export const engagementUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  profile: z.enum(['goad_ad', 'single_host', 'network', 'web_app', 'cloud', 'hybrid']).optional(),
  community_resolution: z.number().min(0.1).max(10).optional(),
  max_prompt_tokens: z.number().int().min(1000).max(100000).optional(),
  iam_assume_depth: z.number().int().min(0).max(20).optional(),
  hash_chain_enabled: z.boolean().optional(),
  engagement_signing_key_id: z.string().nullable().optional(),
  subagent_isolation: z.enum(['in_process', 'process']).optional(),
  available_models: stringArraySchema.optional(),
  default_agent_model: z.string().nullable().optional(),
  orchestrator: z.object({ enabled: z.boolean().optional() }).strict().nullable().optional(),
  cve_research: z.object({ enabled: z.boolean().optional() }).strict().nullable().optional(),
  postgres_dsn: z.string().nullable().optional(),
  tape: z.object({
    enabled: z.boolean().optional(),
    dir: z.string().optional(),
    file: z.string().optional(),
  }).strict().nullable().optional(),
  scope: scopeUpdateSchema.optional(),
  opsec: opsecUpdateSchema.optional(),
  failure_patterns: z.array(z.object({
    technique: z.string(),
    target_pattern: z.string().optional(),
    warning: z.string(),
  }).strict()).optional(),
  objectives: z.array(engagementObjectiveSchema.strict()).optional(),
  phases: z.array(phaseUpdateSchema).optional(),
  operator_policy: operatorPolicyUpdateSchema.nullable().optional(),
}).strict().refine(value => Object.keys(value).length > 0, {
  message: 'At least one supported engagement field is required',
});

export type EngagementUpdate = z.infer<typeof engagementUpdateSchema>;

/**
 * Parse the shared engagement PATCH payload before selecting the active or
 * inactive storage path. Keeping the stable manager error here gives every
 * adapter the same validation envelope instead of letting mergeConfig silently
 * ignore malformed values on the active path.
 */
export function parseEngagementUpdate(
  partial: unknown,
  engagementId?: string,
): EngagementUpdate {
  const parsed = engagementUpdateSchema.safeParse(partial);
  if (parsed.success) return parsed.data;
  throw managerError(
    'ENGAGEMENT_VALIDATION_FAILED',
    engagementId
      ? `Engagement update for ${engagementId} is invalid`
      : 'Engagement update is invalid',
    parsed.error,
  );
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
  private readOnly: boolean;
  private readonly writableProbe?: () => boolean;

  constructor(
    private readonly activeConfigPath: string,
    private readonly writeConfig: DurableConfigWriter = writeJsonAtomicDurable,
    options: { readOnly?: boolean; isWritable?: () => boolean } = {},
  ) {
    this.engagementsDir = join(dirname(activeConfigPath), 'engagements');
    this.readOnly = options.readOnly === true;
    this.writableProbe = options.isWritable;
    if (this.readOnly) return;
    if (!existsSync(this.engagementsDir)) {
      mkdirSync(this.engagementsDir, { recursive: true });
    }
    this.mirrorActiveIfNeeded();
  }

  isReadOnly(): boolean {
    if (!this.writableProbe) return this.readOnly;
    try {
      return this.readOnly || !this.writableProbe();
    } catch {
      return true;
    }
  }

  /**
   * Re-open engagement storage after in-process recovery/config reconciliation.
   * Initialization is idempotent so both MCP and dashboard owners can enable
   * their independently constructed managers safely.
   */
  enableWrites(): void {
    if (!this.readOnly) return;
    if (this.writableProbe) {
      let writable = false;
      try {
        writable = this.writableProbe();
      } catch {
        writable = false;
      }
      if (!writable) {
        throw new EngagementManagerError(
          'ENGAGEMENT_PERSISTENCE_FAILED',
          'Engagement storage is read-only while durable recovery is incomplete.',
        );
      }
    }
    if (!existsSync(this.engagementsDir)) {
      mkdirSync(this.engagementsDir, { recursive: true });
    }
    this.readOnly = false;
    this.mirrorActiveIfNeeded();
  }

  private assertWritable(): void {
    if (this.writableProbe) {
      let writable = false;
      try {
        writable = this.writableProbe();
      } catch {
        writable = false;
      }
      if (!writable) {
        throw new EngagementManagerError(
          'ENGAGEMENT_PERSISTENCE_FAILED',
          'Engagement storage is read-only while durable recovery is incomplete.',
        );
      }
      if (this.readOnly) this.enableWrites();
    }
    if (this.readOnly) {
      throw new EngagementManagerError(
        'ENGAGEMENT_PERSISTENCE_FAILED',
        'Engagement storage is read-only while durable recovery is incomplete.',
      );
    }
  }

  /** Copy the active engagement config into engagements/ on first run. */
  private mirrorActiveIfNeeded(): void {
    if (!existsSync(this.activeConfigPath)) return;
    try {
      const raw = JSON.parse(readFileSync(this.activeConfigPath, 'utf-8'));
      if (!raw.id) return;
      const mirrorPath = join(this.engagementsDir, `${raw.id}.json`);
      if (!existsSync(mirrorPath)) {
        this.writeConfig(mirrorPath, raw);
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

    const files = existsSync(this.engagementsDir)
      ? readdirSync(this.engagementsDir)
          .filter(f => f.endsWith('.json'))
          .sort()
      : [];

    for (const file of files) {
      const filePath = join(this.engagementsDir, file);
      try {
        const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
        if (!raw.id) continue;
        if (raw.id === activeId && existsSync(this.activeConfigPath)) {
          const active = JSON.parse(readFileSync(this.activeConfigPath, 'utf-8'));
          seen.add(active.id);
          results.push(this.toSummary(active, this.activeConfigPath, true));
        } else {
          seen.add(raw.id);
          results.push(this.toSummary(raw, filePath, false));
        }
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
    this.assertWritable();
    // Build + validate via the shared builder (single source of truth for
    // id/nonce/profile/template logic); this manager owns only persistence.
    let parsedConfig: EngagementConfig;
    try {
      parsedConfig = buildEngagementConfig(input);
    } catch (error) {
      throw managerError(
        'ENGAGEMENT_VALIDATION_FAILED',
        'Engagement configuration is invalid',
        error,
      );
    }
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
    this.assertWritable();
    if (!isSafeEngagementId(config.id)) {
      throw new EngagementManagerError(
        'ENGAGEMENT_VALIDATION_FAILED',
        `Refusing to persist engagement with unsafe id: ${JSON.stringify(config.id)}`,
      );
    }
    if (typeof (config as { engagement_nonce?: string }).engagement_nonce !== 'string') {
      (config as { engagement_nonce?: string }).engagement_nonce = randomBytes(32).toString('hex');
    }
    const filePath = join(this.engagementsDir, `${config.id}.json`);
    if (existsSync(filePath)) {
      throw new EngagementManagerError(
        'ENGAGEMENT_CONFLICT',
        `Engagement already exists: ${config.id}`,
      );
    }
    const revision = Math.max(config.config_revision ?? 1, 1);
    let stamped: EngagementConfig;
    try {
      stamped = withConfigMetadata(config, revision);
    } catch (error) {
      throw managerError(
        'ENGAGEMENT_VALIDATION_FAILED',
        'Engagement configuration is invalid',
        error,
      );
    }
    try {
      this.writeConfig(filePath, stamped);
    } catch (error) {
      throw managerError(
        'ENGAGEMENT_PERSISTENCE_FAILED',
        `Engagement ${config.id} was not durably persisted`,
        error,
      );
    }
    return this.toSummary(stamped, filePath, false);
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

  updateEngagement(id: string, partial: Record<string, unknown>): EngagementConfig {
    this.assertWritable();
    if (!isSafeEngagementId(id)) {
      throw new EngagementManagerError(
        'ENGAGEMENT_VALIDATION_FAILED',
        `Invalid engagement id: ${JSON.stringify(id)}`,
      );
    }
    // Edit the SAME file getEngagement reads. For the ACTIVE engagement that's the live
    // active config, not the (stale) engagementsDir mirror — writing the mirror left the
    // active config and every subsequent read/reload unchanged, so the edit vanished.
    const activeId = this.getActiveId();
    const filePath = (id === activeId && existsSync(this.activeConfigPath))
      ? this.activeConfigPath
      : join(this.engagementsDir, `${id}.json`);
    if (!existsSync(filePath)) {
      throw new EngagementManagerError(
        'ENGAGEMENT_NOT_FOUND',
        `Engagement not found: ${id}`,
      );
    }

    let serialized: string;
    try {
      serialized = readFileSync(filePath, 'utf-8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException | null)?.code === 'ENOENT') {
        throw new EngagementManagerError(
          'ENGAGEMENT_NOT_FOUND',
          `Engagement not found: ${id}`,
        );
      }
      throw managerError(
        'ENGAGEMENT_PERSISTENCE_FAILED',
        `Engagement ${id} could not be read from durable storage`,
        error,
      );
    }

    let raw: unknown;
    try {
      raw = JSON.parse(serialized);
    } catch (error) {
      throw managerError(
        'ENGAGEMENT_CONFLICT',
        `Stored engagement ${id} is invalid and cannot be updated`,
        error,
      );
    }

    const parsed = engagementConfigSchema.safeParse(raw);
    if (!parsed.success) {
      throw managerError(
        'ENGAGEMENT_CONFLICT',
        `Stored engagement ${id} is invalid and cannot be updated`,
        parsed.error,
      );
    }

    const update = parseEngagementUpdate(partial, id);
    let next: EngagementConfig;
    try {
      const merged = mergeConfig(parsed.data, update);
      if (configsSemanticallyEqual(parsed.data, merged)) return parsed.data;
      next = withConfigMetadata(merged, (parsed.data.config_revision ?? 0) + 1);
    } catch (error) {
      throw managerError(
        'ENGAGEMENT_VALIDATION_FAILED',
        `Engagement update for ${id} is invalid`,
        error,
      );
    }

    try {
      const expectedRawHash = createHash('sha256').update(serialized).digest('hex');
      this.writeConfig(filePath, next, capturedPath => {
        if (!capturedPath) {
          throw new EngagementManagerError(
            'ENGAGEMENT_CONFLICT',
            `Engagement ${id} changed after it was inspected`,
          );
        }
        const observedRawHash = createHash('sha256').update(readFileSync(capturedPath)).digest('hex');
        if (observedRawHash !== expectedRawHash) {
          throw new EngagementManagerError(
            'ENGAGEMENT_CONFLICT',
            `Engagement ${id} changed after it was inspected`,
          );
        }
      });
    } catch (error) {
      if (error instanceof EngagementManagerError) throw error;
      throw managerError(
        'ENGAGEMENT_PERSISTENCE_FAILED',
        `Engagement ${id} update was not durably persisted`,
        error,
      );
    }
    return next;
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
