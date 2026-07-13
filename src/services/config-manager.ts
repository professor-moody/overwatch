// ============================================================
// Config Manager
// Engagement configuration CRUD and graph seeding logic
// extracted from GraphEngine.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, EngagementConfig } from '../types.js';
import { engagementConfigSchema } from '../types.js';
import { isValidCidr } from './cidr.js';
import { isValidDomain } from './scope-manager.js';

export interface ConfigManagerHost {
  ctx: EngineContext;
  addNode(props: NodeProperties): string;
  persist(detail?: Record<string, unknown>): void;
}

/**
 * Seed initial graph nodes from engagement config (called once on fresh init).
 *
 * P1.3 / P2.2: prefer the engagement's persisted `created_at` for seed
 * timestamps over wall-clock. Engagement creation is when these nodes
 * conceptually came into existence; using a stable, persisted timestamp
 * makes graph state byte-reproducible across engine restarts and tape
 * replays. Falls back to `ctx.nowIso()` (which honors `withClock`) when
 * `created_at` is missing.
 */
export function seedFromConfig(host: ConfigManagerHost): void {
  const now = host.ctx.config.created_at || host.ctx.nowIso();

  // CIDRs are used for scope validation only — hosts are created when tools discover them

  // Create host nodes from explicit hosts
  if (host.ctx.config.scope.hosts) {
    for (const h of host.ctx.config.scope.hosts) {
      const id = `host-${h.replace(/[.\s]/g, '-')}`;
      if (!host.ctx.graph.hasNode(id)) {
        host.addNode({
          id,
          type: 'host',
          label: h,
          hostname: h,
          discovered_at: now,
          first_seen_at: now,
          last_seen_at: now,
          confidence: 1.0
        });
      }
    }
  }

  // Create domain nodes
  for (const domain of host.ctx.config.scope.domains) {
    host.addNode({
      id: `domain-${domain.replace(/\./g, '-')}`,
      type: 'domain',
      label: domain,
      domain_name: domain,
      discovered_at: now,
      first_seen_at: now,
      last_seen_at: now,
      confidence: 1.0
    });
  }

  // Create subnet nodes from scoped CIDRs
  for (const cidr of host.ctx.config.scope.cidrs) {
    const subnetId = `subnet-${cidr.replace(/[./]/g, '-')}`;
    if (!host.ctx.graph.hasNode(subnetId)) {
      host.addNode({
        id: subnetId,
        type: 'subnet',
        label: cidr,
        subnet_cidr: cidr,
        discovered_at: now,
        first_seen_at: now,
        last_seen_at: now,
        confidence: 1.0
      });
    }
  }

  // Create objective nodes
  for (const obj of host.ctx.config.objectives) {
    host.addNode({
      id: `obj-${obj.id}`,
      type: 'objective',
      label: obj.description,
      objective_description: obj.description,
      objective_achieved: obj.achieved,
      objective_achieved_at: obj.achieved_at,
      discovered_at: now,
      first_seen_at: now,
      last_seen_at: now,
      confidence: 1.0
    });
  }

  host.persist();
}

/**
 * Merge partial config updates into current config atomically.
 * Applies changes to a deep clone, validates the result, then commits.
 * If validation fails the live runtime config is never touched.
 */
export function updateConfig(host: ConfigManagerHost, partial: Record<string, unknown>): EngagementConfig {
  // Work on a deep clone so a validation failure cannot leave the live
  // config in a half-mutated state (P1 atomicity fix).
  const draft = JSON.parse(JSON.stringify(host.ctx.config)) as EngagementConfig;

  // Merge top-level scalars
  if (typeof partial.name === 'string' && partial.name.length > 0) draft.name = partial.name;
  if (typeof partial.profile === 'string') draft.profile = partial.profile as EngagementConfig['profile'];
  if (typeof partial.community_resolution === 'number') draft.community_resolution = partial.community_resolution;
  // Agent model knobs (settable via a config PATCH, not only file edit).
  if (Array.isArray(partial.available_models)) draft.available_models = (partial.available_models as unknown[]).filter(m => typeof m === 'string') as string[];
  if (typeof partial.default_agent_model === 'string') draft.default_agent_model = partial.default_agent_model;

  // Merge scope (partial merge — only overwrite provided keys)
  if (partial.scope && typeof partial.scope === 'object') {
    const s = partial.scope as Record<string, unknown>;
    const scopeErrors: string[] = [];
    for (const key of ['cidrs', 'exclusions'] as const) {
      if (Array.isArray(s[key])) {
        for (const cidr of s[key] as string[]) {
          if (!isValidCidr(cidr)) scopeErrors.push(`Invalid CIDR in scope.${key}: ${cidr}`);
        }
      }
    }
    if (Array.isArray(s.domains)) {
      for (const domain of s.domains as string[]) {
        if (!isValidDomain(domain)) scopeErrors.push(`Invalid domain in scope.domains: ${domain}`);
      }
    }
    if (scopeErrors.length > 0) {
      throw new Error(`Scope validation failed: ${scopeErrors.join('; ')}`);
    }
    if (Array.isArray(s.cidrs)) draft.scope.cidrs = s.cidrs;
    if (Array.isArray(s.domains)) draft.scope.domains = s.domains;
    if (Array.isArray(s.exclusions)) draft.scope.exclusions = s.exclusions;
    if (Array.isArray(s.hosts)) draft.scope.hosts = s.hosts;
    if (Array.isArray(s.aws_accounts)) draft.scope.aws_accounts = s.aws_accounts;
    if (Array.isArray(s.azure_subscriptions)) draft.scope.azure_subscriptions = s.azure_subscriptions;
    if (Array.isArray(s.gcp_projects)) draft.scope.gcp_projects = s.gcp_projects;
    if (Array.isArray(s.url_patterns)) draft.scope.url_patterns = s.url_patterns;
  }

  // Merge opsec
  if (partial.opsec && typeof partial.opsec === 'object') {
    const o = partial.opsec as Record<string, unknown>;
    if (typeof o.name === 'string') draft.opsec.name = o.name;
    if (typeof o.enabled === 'boolean') draft.opsec.enabled = o.enabled;
    if (typeof o.max_noise === 'number') draft.opsec.max_noise = o.max_noise;
    if (typeof o.approval_mode === 'string') draft.opsec.approval_mode = o.approval_mode as EngagementConfig['opsec']['approval_mode'];
    if (typeof o.approval_timeout_ms === 'number') draft.opsec.approval_timeout_ms = o.approval_timeout_ms;
    if (Array.isArray(o.blacklisted_techniques)) draft.opsec.blacklisted_techniques = o.blacklisted_techniques;
    if (o.time_window === null) draft.opsec.time_window = undefined;
    else if (o.time_window && typeof o.time_window === 'object') {
      const tw = o.time_window as Record<string, unknown>;
      if (typeof tw.start_hour === 'number' && typeof tw.end_hour === 'number') {
        draft.opsec.time_window = { start_hour: tw.start_hour, end_hour: tw.end_hour };
      }
    }
    if (typeof o.notes === 'string') draft.opsec.notes = o.notes;
  }

  // Merge failure_patterns (full replace)
  if (Array.isArray(partial.failure_patterns)) {
    draft.failure_patterns = partial.failure_patterns as EngagementConfig['failure_patterns'];
  }

  // Merge objectives (full replace if provided)
  if (Array.isArray(partial.objectives)) {
    draft.objectives = partial.objectives as EngagementConfig['objectives'];
  }

  // Merge operator_policy (full replace; null clears it). The dashboard validates the
  // whole policy strictly at the route, and the merged draft is validated again below.
  // Without this the route accepted the policy and reported success but the value was
  // silently dropped here — so approval rules / dispatch caps never took effect.
  if (partial.operator_policy === null) {
    draft.operator_policy = undefined;
  } else if (partial.operator_policy && typeof partial.operator_policy === 'object') {
    draft.operator_policy = partial.operator_policy as EngagementConfig['operator_policy'];
  }

  // Validate the fully-merged draft before committing to live config.
  const parsed = engagementConfigSchema.safeParse(draft);
  if (!parsed.success) {
    const issues = parsed.error.issues.map(i =>
      `${i.path.join('.') || '<root>'}: ${i.message}`,
    );
    throw new Error(`Config validation failed: ${issues.join('; ')}`);
  }

  // Commit: only now does the live config change.
  host.ctx.config = parsed.data;
  host.persist();
  return host.ctx.config;
}
