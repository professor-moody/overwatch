// ============================================================
// Overwatch — Credential Coverage Matrix
// Tracks which credentials have been tested against which targets,
// surfaces untested pairs, and computes coverage statistics.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { NodeProperties, CredentialCoverage, FrontierItem } from '../types.js';
import { isCredentialUsableForAuth, isCredentialStaleOrExpired, getCredentialDisplayKind, getCredentialMaterialKind } from './credential-utils.js';

// Services that accept credential authentication
const AUTH_SERVICES = new Set([
  'smb', 'rdp', 'ssh', 'winrm', 'mssql', 'http', 'https',
  'ldap', 'kerberos', 'ftp', 'vnc', 'telnet', 'postgresql', 'mysql',
]);

// Priority weights for credential material types (higher = more valuable to test)
const CRED_TYPE_WEIGHT: Record<string, number> = {
  plaintext_password: 1.0,
  ntlm_hash: 0.9,
  aes256_key: 0.85,
  kerberos_tgt: 0.8,
  ssh_key: 0.8,
  token: 0.7,
  certificate: 0.7,
};

// Priority weights for target service types
const SERVICE_WEIGHT: Record<string, number> = {
  smb: 0.9,
  rdp: 0.85,
  ssh: 0.8,
  winrm: 0.8,
  mssql: 0.7,
  ldap: 0.7,
  kerberos: 0.6,
  http: 0.5,
  https: 0.5,
};

export interface UntestedPair {
  credential_id: string;
  credential_label: string;
  target_id: string;
  target_label: string;
  service_name?: string;
  priority: number;
}

export class CredentialCoverageTracker {
  constructor(private ctx: EngineContext) {}

  /**
   * Compute the full credential coverage matrix from the current graph state.
   */
  compute(hopsToObjective?: (nodeId: string) => number | null): CredentialCoverage & { untested_pairs: UntestedPair[] } {
    const credentials = this.collectUsableCredentials();
    const targets = this.collectAuthTargets();

    if (credentials.length === 0 || targets.length === 0) {
      return {
        total_credentials: credentials.length,
        total_targets: targets.length,
        tested_pairs: 0,
        total_pairs: 0,
        coverage_pct: 0,
        top_untested: [],
        untested_pairs: [],
      };
    }

    // Build tested-pair set from graph edges
    const testedSet = this.buildTestedSet();

    const totalPairs = credentials.length * targets.length;
    let testedCount = 0;
    const untested: UntestedPair[] = [];

    for (const cred of credentials) {
      for (const target of targets) {
        const key = `${cred.id}::${target.id}`;
        if (testedSet.has(key)) {
          testedCount++;
          continue;
        }

        // Skip if credential's domain doesn't match target's domain (cross-domain noise)
        if (cred.domain && target.domain && cred.domain !== target.domain) continue;

        const credWeight = CRED_TYPE_WEIGHT[getCredentialMaterialKind(cred.node) || ''] ?? 0.5;
        const svcWeight = SERVICE_WEIGHT[target.service_name || ''] ?? 0.5;
        const hops = hopsToObjective ? (hopsToObjective(target.id) ?? 10) : 10;
        const hopsFactor = Math.max(0.1, 1 - (hops / 20));
        const domainBoost = cred.domain && cred.domain === target.domain ? 1.3 : 1.0;

        const priority = parseFloat(
          (credWeight * svcWeight * hopsFactor * domainBoost * 10).toFixed(2)
        );

        untested.push({
          credential_id: cred.id,
          credential_label: cred.label,
          target_id: target.id,
          target_label: target.label,
          service_name: target.service_name,
          priority,
        });
      }
    }

    // Sort by priority descending
    untested.sort((a, b) => b.priority - a.priority);

    const coveragePct = totalPairs > 0 ? parseFloat(((testedCount / totalPairs) * 100).toFixed(1)) : 0;

    return {
      total_credentials: credentials.length,
      total_targets: targets.length,
      tested_pairs: testedCount,
      total_pairs: totalPairs,
      coverage_pct: coveragePct,
      top_untested: untested.slice(0, 10).map(p => ({
        credential: p.credential_label,
        target: p.target_label,
        priority: p.priority,
        service: p.service_name,
      })),
      untested_pairs: untested,
    };
  }

  /**
   * Generate frontier items for the top-N untested credential/target pairs.
   */
  computeFrontierItems(maxItems: number = 20, hopsToObjective?: (nodeId: string) => number | null): FrontierItem[] {
    const result = this.compute(hopsToObjective);
    const items: FrontierItem[] = [];

    for (const pair of result.untested_pairs.slice(0, maxItems)) {
      items.push({
        id: `frontier-credtest-${pair.credential_id}-${pair.target_id}`,
        type: 'credential_test',
        node_id: pair.target_id,
        credential_id: pair.credential_id,
        description: `Test "${pair.credential_label}" against ${pair.target_label}${pair.service_name ? ` (${pair.service_name})` : ''}`,
        graph_metrics: {
          hops_to_objective: hopsToObjective ? (hopsToObjective(pair.target_id) ?? null) : null,
          fan_out_estimate: 3,
          node_degree: this.ctx.graph.hasNode(pair.target_id) ? this.ctx.graph.degree(pair.target_id) : 0,
          confidence: 0.5,
        },
        opsec_noise: 0.3,
        staleness_seconds: 0,
      });
    }

    return items;
  }

  // --- Private helpers ---

  private collectUsableCredentials(): Array<{
    id: string;
    label: string;
    node: NodeProperties;
    domain?: string;
    owner_id?: string;
  }> {
    const creds: Array<{ id: string; label: string; node: NodeProperties; domain?: string; owner_id?: string }> = [];

    this.ctx.graph.forEachNode((id: string, attrs) => {
      if (attrs.type !== 'credential') return;
      if (attrs.identity_status === 'superseded') return;
      if (!isCredentialUsableForAuth(attrs)) return;
      if (isCredentialStaleOrExpired(attrs)) return;

      // Find the owning user to get domain info. F3: parsers populate
      // `domain_name` on user nodes (sometimes legacy `domain`); credentials
      // separately carry `cred_domain`. Read all three so the same-domain
      // boost actually fires on real ingests instead of always falling
      // through to the cross-domain skip.
      let domain: string | undefined;
      let ownerId: string | undefined;
      for (const edge of this.ctx.graph.inEdges(id) as string[]) {
        const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
        if (eAttrs.type === 'OWNS_CRED') {
          const owner = this.ctx.graph.getNodeAttributes(this.ctx.graph.source(edge));
          domain = (owner.domain_name as string | undefined) ?? (owner.domain as string | undefined);
          ownerId = this.ctx.graph.source(edge);
          break;
        }
      }
      // F3: when no owner edge exists, fall back to the credential's own
      // `cred_domain` (set by every Kerberos/NTLM parser) so domain
      // filtering still works for orphaned credentials.
      if (!domain) {
        domain = (attrs.cred_domain as string | undefined);
      }

      creds.push({
        id,
        label: `${attrs.cred_user || attrs.label || id}:${getCredentialDisplayKind(attrs)}`,
        node: attrs,
        domain,
        owner_id: ownerId,
      });
    });

    return creds;
  }

  private collectAuthTargets(): Array<{
    id: string;
    label: string;
    host_id: string;
    service_name?: string;
    domain?: string;
  }> {
    // F2: coverage is now per-(host, service), not per-host. Previously
    // collectAuthTargets picked one bestService per host and deduped on
    // host id, so testing one credential against SMB silently marked the
    // host fully covered for SSH/RDP/WinRM. Each AUTH_SERVICES entry on a
    // host is now its own target; the outer iteration in `compute` then
    // produces (cred, service) pairs.
    const targets: Array<{ id: string; label: string; host_id: string; service_name?: string; domain?: string }> = [];
    const seen = new Set<string>();

    this.ctx.graph.forEachNode((id: string, attrs) => {
      if (attrs.identity_status === 'superseded') return;

      if (attrs.type === 'host' && attrs.alive !== false) {
        // F3: parsers populate `domain_name`; legacy ingests may still
        // carry `domain`. Read both so the same-domain boost fires.
        const hostDomain = (attrs.domain_name as string | undefined) ?? (attrs.domain as string | undefined);
        const hostLabel = attrs.label || attrs.hostname || id;

        // Walk every RUNS edge and create one target per auth-accepting
        // service. The target id is the service node id, so the
        // `(cred, target)` keying in buildTestedSet preserves service
        // granularity. Hosts with no auth-accepting services are not
        // coverage targets — there's nothing to test against.
        for (const edge of this.ctx.graph.outEdges(id) as string[]) {
          const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
          if (eAttrs.type !== 'RUNS') continue;
          const svcId = this.ctx.graph.target(edge);
          const svcNode = this.ctx.graph.getNodeAttributes(svcId);
          const svcName = svcNode.service_name as string | undefined;
          if (svcName && AUTH_SERVICES.has(svcName)) {
            const targetId = svcId;
            if (seen.has(targetId)) continue;
            seen.add(targetId);
            targets.push({
              id: targetId,
              label: hostLabel,
              host_id: id,
              service_name: svcName,
              domain: hostDomain,
            });
          }
        }
      }
    });

    return targets;
  }

  private buildTestedSet(): Set<string> {
    const tested = new Set<string>();

    // Edge types that indicate a credential was tested against a target
    const TESTED_EDGE_TYPES = new Set(['TESTED_CRED', 'VALID_ON', 'HAS_SESSION', 'ADMIN_TO']);

    // F2: record `(cred, edge_target)` directly so per-service granularity
    // is preserved. When the edge points at a service, ALSO record a
    // host-level fallback so per-host targets (used when a host has no
    // RUNS edges in the graph) still register as tested. This avoids the
    // bug where one cred-vs-SMB test silently marked the entire host
    // covered for SSH/RDP/WinRM.
    this.ctx.graph.forEachEdge((_edgeId: string, attrs, source: string, target: string) => {
      if (!TESTED_EDGE_TYPES.has(attrs.type)) return;

      const srcNode = this.ctx.graph.getNodeAttributes(source);
      const tgtNode = this.ctx.graph.getNodeAttributes(target);

      const credIds: string[] =
        srcNode.type === 'credential'
          ? [source]
          : srcNode.type === 'user'
            ? this.getCredentialsForUser(source)
            : [];
      if (credIds.length === 0) return;

      if (tgtNode.type === 'service') {
        // Service-targeted edge: record (cred, service) only. Other
        // services on the same host stay untested — that's the F2
        // intent. Also record (cred, host) so host-level frontier
        // suggestions still see the test.
        const hostId = this.findHostForService(target);
        for (const credId of credIds) {
          tested.add(`${credId}::${target}`);
          if (hostId) tested.add(`${credId}::${hostId}`);
        }
      } else if (tgtNode.type === 'host') {
        // Host-targeted edge: parsers like nxc emit cred→host edges with
        // a `tested_service` hint that names which protocol the test ran
        // against. When the hint is present, mark only that service's
        // pair tested. Without the hint, the parser doesn't tell us
        // which service was tested — fall back to host-rollup (mark all
        // services on the host) so legacy emissions don't flood the
        // frontier with retests. Real F2 granularity activates once the
        // parser populates the hint.
        const hint = (attrs as { tested_service?: string }).tested_service;
        for (const credId of credIds) {
          tested.add(`${credId}::${target}`);
        }
        for (const e of this.ctx.graph.outEdges(target) as string[]) {
          const ea = this.ctx.graph.getEdgeAttributes(e);
          if (ea.type !== 'RUNS') continue;
          const svcId = this.ctx.graph.target(e);
          const svcAttrs = this.ctx.graph.getNodeAttributes(svcId);
          const svcName = svcAttrs.service_name as string | undefined;
          if (hint && svcName !== hint) continue;
          for (const credId of credIds) {
            tested.add(`${credId}::${svcId}`);
          }
        }
      }
    });

    return tested;
  }

  private findHostForService(serviceId: string): string | undefined {
    for (const edge of this.ctx.graph.inEdges(serviceId) as string[]) {
      const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
      if (eAttrs.type === 'RUNS') {
        return this.ctx.graph.source(edge);
      }
    }
    return undefined;
  }

  private getCredentialsForUser(userId: string): string[] {
    const creds: string[] = [];
    for (const edge of this.ctx.graph.outEdges(userId) as string[]) {
      const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
      if (eAttrs.type === 'OWNS_CRED') {
        creds.push(this.ctx.graph.target(edge));
      }
    }
    return creds;
  }
}
