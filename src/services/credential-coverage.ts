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

      // Find the owning user to get domain info
      let domain: string | undefined;
      let ownerId: string | undefined;
      for (const edge of this.ctx.graph.inEdges(id) as string[]) {
        const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
        if (eAttrs.type === 'OWNS_CRED') {
          const owner = this.ctx.graph.getNodeAttributes(this.ctx.graph.source(edge));
          domain = owner.domain as string | undefined;
          ownerId = this.ctx.graph.source(edge);
          break;
        }
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
    service_name?: string;
    domain?: string;
  }> {
    const targets: Array<{ id: string; label: string; service_name?: string; domain?: string }> = [];
    const seen = new Set<string>();

    this.ctx.graph.forEachNode((id: string, attrs) => {
      if (attrs.identity_status === 'superseded') return;

      if (attrs.type === 'host' && attrs.alive !== false) {
        // Check if host runs any auth-accepting service
        let bestService: string | undefined;
        let bestWeight = -1;
        for (const edge of this.ctx.graph.outEdges(id) as string[]) {
          const eAttrs = this.ctx.graph.getEdgeAttributes(edge);
          if (eAttrs.type !== 'RUNS') continue;
          const svcNode = this.ctx.graph.getNodeAttributes(this.ctx.graph.target(edge));
          const svcName = svcNode.service_name as string | undefined;
          if (svcName && AUTH_SERVICES.has(svcName)) {
            const w = SERVICE_WEIGHT[svcName] ?? 0.5;
            if (w > bestWeight) {
              bestWeight = w;
              bestService = svcName;
            }
          }
        }

        if (bestService && !seen.has(id)) {
          seen.add(id);
          targets.push({
            id,
            label: attrs.label || attrs.hostname || id,
            service_name: bestService,
            domain: attrs.domain as string | undefined,
          });
        }
      }
    });

    return targets;
  }

  private buildTestedSet(): Set<string> {
    const tested = new Set<string>();

    // Edge types that indicate a credential was tested against a target
    const TESTED_EDGE_TYPES = new Set(['TESTED_CRED', 'VALID_ON', 'HAS_SESSION', 'ADMIN_TO']);

    this.ctx.graph.forEachEdge((_edgeId: string, attrs, source: string, target: string) => {
      if (!TESTED_EDGE_TYPES.has(attrs.type)) return;

      const srcNode = this.ctx.graph.getNodeAttributes(source);
      const tgtNode = this.ctx.graph.getNodeAttributes(target);

      if (srcNode.type === 'credential' && (tgtNode.type === 'host' || tgtNode.type === 'service')) {
        // Direct: credential → host/service
        const hostId = tgtNode.type === 'service' ? this.findHostForService(target) : target;
        if (hostId) tested.add(`${source}::${hostId}`);
      } else if (srcNode.type === 'user' && (tgtNode.type === 'host' || tgtNode.type === 'service')) {
        // Indirect: user → host, resolve user's credentials
        const credIds = this.getCredentialsForUser(source);
        const hostId = tgtNode.type === 'service' ? this.findHostForService(target) : target;
        if (hostId) {
          for (const credId of credIds) {
            tested.add(`${credId}::${hostId}`);
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
