// ============================================================
// Scope Manager
// Runtime scope expansion/contraction logic extracted from GraphEngine.
// ============================================================

import type { EngineContext, ActivityLogEntry } from './engine-context.js';
import type { NodeProperties, NodeType, EngagementConfig, ScopeSuggestion } from '../types.js';
import { isIpInScope, isValidCidr, isIPv6 } from './cidr.js';

export interface ScopeManagerHost {
  ctx: EngineContext;
  addNode(props: NodeProperties): string;
  logActionEvent(entry: Partial<ActivityLogEntry>): void;
  persist(): void;
  invalidateFrontierCache(): void;
  invalidateHealthReport(): void;
  runInferenceRules(nodeId: string): string[];
}

export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (/\s/.test(domain)) return false;
  if (domain.includes('/') || domain.includes('\\')) return false;
  if (!domain.includes('.')) return false;
  const labels = domain.split('.');
  return labels.every(l => l.length > 0 && l.length <= 63 && /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(l));
}

export function updateScope(
  host: ScopeManagerHost,
  changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
    reason: string;
  },
): { applied: boolean; errors: string[]; before: EngagementConfig['scope']; after: EngagementConfig['scope']; affected_node_count: number } {
  const errors: string[] = [];

  for (const cidr of changes.add_cidrs || []) {
    if (isIPv6(cidr)) { errors.push(`IPv6 CIDRs are not supported (scope is IPv4-only): ${cidr}`); }
    else if (!isValidCidr(cidr)) errors.push(`Invalid CIDR: ${cidr}`);
  }
  for (const cidr of changes.remove_cidrs || []) {
    if (isIPv6(cidr)) { errors.push(`IPv6 CIDRs are not supported (scope is IPv4-only): ${cidr}`); }
    else if (!isValidCidr(cidr)) errors.push(`Invalid CIDR to remove: ${cidr}`);
  }
  for (const domain of changes.add_domains || []) {
    if (!isValidDomain(domain)) errors.push(`Invalid domain format: ${domain}`);
  }
  for (const cidr of changes.add_exclusions || []) {
    if (isIPv6(cidr)) { errors.push(`IPv6 exclusions are not supported (scope is IPv4-only): ${cidr}`); }
    else if (!isValidCidr(cidr)) errors.push(`Invalid exclusion: ${cidr}`);
  }
  for (const cidr of changes.remove_exclusions || []) {
    if (isIPv6(cidr)) { errors.push(`IPv6 exclusions are not supported (scope is IPv4-only): ${cidr}`); }
    else if (!isValidCidr(cidr)) errors.push(`Invalid exclusion to remove: ${cidr}`);
  }

  if (errors.length > 0) {
    return { applied: false, errors, before: { ...host.ctx.config.scope }, after: { ...host.ctx.config.scope }, affected_node_count: 0 };
  }

  const before = {
    cidrs: [...host.ctx.config.scope.cidrs],
    domains: [...host.ctx.config.scope.domains],
    exclusions: [...host.ctx.config.scope.exclusions],
  };

  if (changes.add_cidrs) {
    for (const cidr of changes.add_cidrs) {
      if (!host.ctx.config.scope.cidrs.includes(cidr)) {
        host.ctx.config.scope.cidrs.push(cidr);
      }
    }
  }
  if (changes.remove_cidrs) {
    host.ctx.config.scope.cidrs = host.ctx.config.scope.cidrs.filter(c => !changes.remove_cidrs!.includes(c));
  }
  if (changes.add_domains) {
    for (const domain of changes.add_domains) {
      if (!host.ctx.config.scope.domains.includes(domain)) {
        host.ctx.config.scope.domains.push(domain);
      }
    }
  }
  if (changes.remove_domains) {
    host.ctx.config.scope.domains = host.ctx.config.scope.domains.filter(d => !changes.remove_domains!.includes(d));
  }
  if (changes.add_exclusions) {
    for (const excl of changes.add_exclusions) {
      if (!host.ctx.config.scope.exclusions.includes(excl)) {
        host.ctx.config.scope.exclusions.push(excl);
      }
    }
  }
  if (changes.remove_exclusions) {
    host.ctx.config.scope.exclusions = host.ctx.config.scope.exclusions.filter(e => !changes.remove_exclusions!.includes(e));
  }

  const after = {
    cidrs: [...host.ctx.config.scope.cidrs],
    domains: [...host.ctx.config.scope.domains],
    exclusions: [...host.ctx.config.scope.exclusions],
  };

  let affectedNodeCount = 0;
  host.ctx.graph.forEachNode((_id, attrs) => {
    if (attrs.type !== 'host') return;
    const ip = attrs.ip;
    if (!ip) return;
    const wasInScope = isIpInScope(ip, before.cidrs, before.exclusions);
    const nowInScope = isIpInScope(ip, after.cidrs, after.exclusions);
    if (!wasInScope && nowInScope) affectedNodeCount++;
  });

  const coldToPromote: string[] = [];
  host.ctx.coldStore.forEach((record) => {
    if (!record.ip) return;
    const wasInScope = isIpInScope(record.ip, before.cidrs, before.exclusions);
    const nowInScope = isIpInScope(record.ip, after.cidrs, after.exclusions);
    if (!wasInScope && nowInScope) coldToPromote.push(record.id);
  });
  const promotedIds: string[] = [];
  for (const id of coldToPromote) {
    const coldRecord = host.ctx.coldStore.promote(id);
    if (coldRecord) {
      host.addNode({
        id: coldRecord.id,
        type: coldRecord.type as NodeType,
        label: coldRecord.label,
        ip: coldRecord.ip,
        hostname: coldRecord.hostname,
        discovered_at: coldRecord.discovered_at,
        last_seen_at: coldRecord.last_seen_at,
        alive: coldRecord.alive,
        discovered_by: coldRecord.provenance,
        confidence: coldRecord.confidence ?? 1.0,
      });
      promotedIds.push(coldRecord.id);
      affectedNodeCount++;
    }
  }

  for (const promotedId of promotedIds) {
    host.runInferenceRules(promotedId);
  }

  host.invalidateFrontierCache();
  host.invalidateHealthReport();

  host.logActionEvent({
    description: `Scope updated: ${changes.reason}`,
    event_type: 'scope_updated',
    category: 'system',
    result_classification: 'success',
    details: {
      reason: changes.reason,
      before,
      after,
      affected_node_count: affectedNodeCount,
    },
  });

  host.persist();

  return { applied: true, errors: [], before, after, affected_node_count: affectedNodeCount };
}

export function collectScopeSuggestions(host: ScopeManagerHost): ScopeSuggestion[] {
  const outOfScopeIps = new Map<string, { ips: Set<string>; nodeIds: Set<string>; firstSeen: string; sources: Set<string> }>();

  host.ctx.graph.forEachNode((id, attrs) => {
    if (attrs.type !== 'host' || !attrs.ip) return;
    if (isIpInScope(attrs.ip, host.ctx.config.scope.cidrs, host.ctx.config.scope.exclusions)) return;

    const parts = attrs.ip.split('.');
    if (parts.length !== 4) return;
    const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
    const suggestedCidr = `${prefix}.0/24`;

    if (!outOfScopeIps.has(suggestedCidr)) {
      outOfScopeIps.set(suggestedCidr, { ips: new Set(), nodeIds: new Set(), firstSeen: attrs.discovered_at, sources: new Set() });
    }
    const entry = outOfScopeIps.get(suggestedCidr)!;
    entry.ips.add(attrs.ip);
    entry.nodeIds.add(id);
    if (attrs.discovered_at < entry.firstSeen) entry.firstSeen = attrs.discovered_at;
    if (attrs.discovered_by) entry.sources.add(attrs.discovered_by);
  });

  return Array.from(outOfScopeIps.entries()).map(([cidr, data]) => ({
    suggested_cidr: cidr,
    out_of_scope_ips: Array.from(data.ips).sort(),
    node_ids: Array.from(data.nodeIds),
    first_seen_at: data.firstSeen,
    source_descriptions: Array.from(data.sources),
  }));
}

export function previewScopeChange(
  host: ScopeManagerHost,
  changes: {
    add_cidrs?: string[];
    remove_cidrs?: string[];
    add_domains?: string[];
    remove_domains?: string[];
    add_exclusions?: string[];
    remove_exclusions?: string[];
  },
): { before: EngagementConfig['scope']; after: EngagementConfig['scope']; nodes_entering_scope: number; nodes_leaving_scope: number; pending_suggestions_resolved: string[] } {
  const before = {
    cidrs: [...host.ctx.config.scope.cidrs],
    domains: [...host.ctx.config.scope.domains],
    exclusions: [...host.ctx.config.scope.exclusions],
  };

  const afterCidrs = [...before.cidrs];
  for (const cidr of changes.add_cidrs || []) {
    if (!afterCidrs.includes(cidr)) afterCidrs.push(cidr);
  }
  for (const cidr of changes.remove_cidrs || []) {
    const idx = afterCidrs.indexOf(cidr);
    if (idx >= 0) afterCidrs.splice(idx, 1);
  }
  const afterDomains = [...before.domains];
  for (const d of changes.add_domains || []) {
    if (!afterDomains.includes(d)) afterDomains.push(d);
  }
  for (const d of changes.remove_domains || []) {
    const idx = afterDomains.indexOf(d);
    if (idx >= 0) afterDomains.splice(idx, 1);
  }
  const afterExclusions = [...before.exclusions];
  for (const e of changes.add_exclusions || []) {
    if (!afterExclusions.includes(e)) afterExclusions.push(e);
  }
  for (const e of changes.remove_exclusions || []) {
    const idx = afterExclusions.indexOf(e);
    if (idx >= 0) afterExclusions.splice(idx, 1);
  }

  const after = { cidrs: afterCidrs, domains: afterDomains, exclusions: afterExclusions };

  let entering = 0;
  let leaving = 0;
  host.ctx.graph.forEachNode((_id, attrs) => {
    if (attrs.type !== 'host' || !attrs.ip) return;
    const wasIn = isIpInScope(attrs.ip, before.cidrs, before.exclusions);
    const nowIn = isIpInScope(attrs.ip, after.cidrs, after.exclusions);
    if (!wasIn && nowIn) entering++;
    if (wasIn && !nowIn) leaving++;
  });

  const suggestions = collectScopeSuggestions(host);
  const resolved: string[] = [];
  for (const s of suggestions) {
    for (const ip of s.out_of_scope_ips) {
      if (isIpInScope(ip, after.cidrs, after.exclusions)) {
        resolved.push(s.suggested_cidr);
        break;
      }
    }
  }

  return { before, after, nodes_entering_scope: entering, nodes_leaving_scope: leaving, pending_suggestions_resolved: [...new Set(resolved)] };
}
