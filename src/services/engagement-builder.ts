// ============================================================
// Overwatch — Engagement config builder
// ============================================================
// Single source of truth for turning a CreateEngagementInput into a complete,
// validated EngagementConfig WITHOUT persisting it. Shared by
// EngagementManager.createEngagement (which writes it), the dashboard
// from-template endpoint, and the create_engagement MCP tool — so id/nonce/
// profile/template/validation logic lives in exactly one place.

import { randomBytes } from 'crypto';
import { loadTemplate, mergeTemplateWithConfig } from '../config.js';
import { engagementConfigSchema, type EngagementConfig } from '../types.js';
import type { CreateEngagementInput } from './engagement-manager.js';

/** Named OPSEC profiles (name + max_noise). `quiet` is an alias for `stealth`.
 *  approval_mode / time_window are intentionally left to the schema defaults +
 *  per-engagement overrides — enriching these is a separate maintainer decision. */
export const OPSEC_PROFILES: Record<string, { name: string; max_noise: number }> = {
  quiet:   { name: 'quiet',   max_noise: 0.2 },
  stealth: { name: 'stealth', max_noise: 0.2 },
  normal:  { name: 'normal',  max_noise: 0.5 },
  pentest: { name: 'pentest', max_noise: 0.7 },
  loud:    { name: 'loud',    max_noise: 1.0 },
};

/** Slugify a name into the id prefix (lowercase, hyphenated, ≤40 chars). */
export function slugifyName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
}

export function buildScope(input: CreateEngagementInput): Record<string, unknown> {
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

export function buildOpsecOverrides(input: CreateEngagementInput): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  if (!input.opsec) return o;
  if (input.opsec.max_noise != null) o.max_noise = input.opsec.max_noise;
  if (input.opsec.approval_mode) o.approval_mode = input.opsec.approval_mode;
  if (input.opsec.approval_timeout_ms != null) o.approval_timeout_ms = input.opsec.approval_timeout_ms;
  // Only persist a real time_window object; the UI sends `null` for "no window",
  // which the schema (optional object) would reject.
  if (input.opsec.time_window) o.time_window = input.opsec.time_window;
  if (input.opsec.blacklisted_techniques?.length) o.blacklisted_techniques = input.opsec.blacklisted_techniques;
  return o;
}

/**
 * Build + validate a complete EngagementConfig (id + created_at + engagement_nonce
 * minted here). Does NOT write to disk — callers persist. Throws on an unknown
 * template or on schema validation failure.
 */
export function buildEngagementConfig(input: CreateEngagementInput): EngagementConfig {
  // Fall back to a literal slug when the name is all non-alphanumeric, so the id
  // is never a bare `-<base36>` (leading hyphen).
  const slug = slugifyName(input.name) || 'engagement';
  const id = `${slug}-${Date.now().toString(36)}`;
  const created_at = new Date().toISOString();

  let config: Record<string, unknown>;

  if (input.template_id) {
    const template = loadTemplate(input.template_id);
    if (!template) throw new Error(`Template not found: ${input.template_id}`);
    const opsecOverride = input.opsec_profile
      ? OPSEC_PROFILES[input.opsec_profile] ?? OPSEC_PROFILES.pentest
      : undefined;
    const mergedObjectives = input.objectives && input.objectives.length > 0
      ? input.objectives.map((o, i) => ({ id: o.id || `obj-${i + 1}`, description: o.description, achieved: false }))
      : undefined;
    const overrides: Record<string, unknown> = { id, name: input.name, created_at, scope: buildScope(input) };
    if (input.profile) overrides.profile = input.profile;
    if (opsecOverride) overrides.opsec = { ...opsecOverride, ...buildOpsecOverrides(input) };
    else if (input.opsec) overrides.opsec = buildOpsecOverrides(input);
    if (mergedObjectives) overrides.objectives = mergedObjectives;
    if (input.failure_patterns?.length) overrides.failure_patterns = input.failure_patterns;
    if (input.phases?.length) overrides.phases = input.phases;
    config = mergeTemplateWithConfig(template, overrides as unknown as Parameters<typeof mergeTemplateWithConfig>[1]) as unknown as Record<string, unknown>;
  } else {
    const baseOpsec = OPSEC_PROFILES[input.opsec_profile || 'pentest'] ?? OPSEC_PROFILES.pentest;
    config = {
      id,
      name: input.name,
      created_at,
      profile: input.profile || 'network',
      scope: buildScope(input),
      objectives: (input.objectives || []).map((o, i) => ({
        id: o.id || `obj-${i + 1}`,
        description: o.description,
        achieved: false,
      })),
      opsec: { ...baseOpsec, ...buildOpsecOverrides(input) },
      failure_patterns: input.failure_patterns || [],
      phases: input.phases || [],
    };
  }

  // P1.2: every NEW engagement gets a deterministic-id nonce. A template that
  // already ships a nonce keeps it; otherwise mint a fresh one (64 hex chars).
  if (typeof (config as { engagement_nonce?: string }).engagement_nonce !== 'string') {
    (config as { engagement_nonce?: string }).engagement_nonce = randomBytes(32).toString('hex');
  }

  return engagementConfigSchema.parse(config);
}
