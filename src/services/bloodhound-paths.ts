// ============================================================
// Overwatch — BloodHound Path Enricher
// Post-ingest HVT identification, named attack path templates,
// and pre-computed attack paths for the frontier.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { EdgeType, NodeProperties } from '../types.js';
import type { PathAnalyzer, PathResult, PathOptimize } from './path-analyzer.js';

// --- High-Value Target Identification ---

/** Tier-0 group names / patterns that indicate high-value targets. */
const TIER_0_GROUP_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /^domain admins$/i, reason: 'Domain Admins member' },
  { pattern: /^enterprise admins$/i, reason: 'Enterprise Admins member' },
  { pattern: /^schema admins$/i, reason: 'Schema Admins member' },
  { pattern: /^administrators$/i, reason: 'Builtin Administrators member' },
  { pattern: /^backup operators$/i, reason: 'Backup Operators member' },
  { pattern: /^account operators$/i, reason: 'Account Operators member' },
  { pattern: /^server operators$/i, reason: 'Server Operators member' },
  { pattern: /^print operators$/i, reason: 'Print Operators member' },
  { pattern: /^key admins$/i, reason: 'Key Admins member' },
  { pattern: /^enterprise key admins$/i, reason: 'Enterprise Key Admins member' },
];

/** Well-known SID suffixes for Tier-0 groups. */
const TIER_0_SID_SUFFIXES: Array<{ suffix: string; reason: string }> = [
  { suffix: '-512', reason: 'Domain Admins (SID -512)' },
  { suffix: '-519', reason: 'Enterprise Admins (SID -519)' },
  { suffix: '-518', reason: 'Schema Admins (SID -518)' },
  { suffix: '-544', reason: 'Builtin Administrators (SID -544)' },
  { suffix: '-551', reason: 'Backup Operators (SID -551)' },
];

/** Azure role names that constitute HVT. */
const AZURE_HVT_ROLES = new Set([
  'global administrator',
  'privileged role administrator',
  'privileged authentication administrator',
  'application administrator',
  'cloud application administrator',
  'exchange administrator',
  'partner tier2 support',
]);

/** Edge types that confer DCSync capability. */
const DCSYNC_EDGE: EdgeType = 'CAN_DCSYNC';

// --- Named Attack Path Templates (B2) ---

export interface AttackPathTemplate {
  id: string;
  name: string;
  description: string;
  /** Ordered edge type sequence that constitutes the attack chain. */
  edge_sequence: EdgeType[];
  /** Multiplier applied to path confidence when this template matches. */
  confidence_modifier: number;
}

export const ATTACK_PATH_TEMPLATES: AttackPathTemplate[] = [
  {
    id: 'acl-takeover',
    name: 'ACL Takeover',
    description: 'WriteOwner → WriteDacl → GenericAll → ForceChangePassword chain',
    edge_sequence: ['WRITE_OWNER', 'WRITE_DACL', 'GENERIC_ALL', 'FORCE_CHANGE_PASSWORD'],
    confidence_modifier: 0.9,
  },
  {
    id: 'group-escalation',
    name: 'Group Escalation',
    description: 'AddMember on privileged group → inherited rights',
    edge_sequence: ['ADD_MEMBER', 'MEMBER_OF', 'GENERIC_ALL'],
    confidence_modifier: 0.85,
  },
  {
    id: 'delegation-abuse',
    name: 'Delegation Abuse',
    description: 'Constrained delegation → S4U2Self → target service',
    edge_sequence: ['DELEGATES_TO', 'CAN_DELEGATE_TO'],
    confidence_modifier: 0.8,
  },
  {
    id: 'rbcd-abuse',
    name: 'Resource-Based Constrained Delegation',
    description: 'Writeable msDS-AllowedToActOnBehalfOfOtherIdentity → impersonation',
    edge_sequence: ['GENERIC_WRITE', 'ALLOWED_TO_ACT'],
    confidence_modifier: 0.85,
  },
  {
    id: 'adcs-esc1',
    name: 'ADCS ESC1 Chain',
    description: 'Certificate enrollment → ESC1 → authenticate as target',
    edge_sequence: ['CAN_ENROLL', 'ESC1', 'AUTHENTICATED_AS'],
    confidence_modifier: 0.9,
  },
  {
    id: 'adcs-esc4',
    name: 'ADCS ESC4 Chain',
    description: 'Template misconfiguration → ESC4 → certificate impersonation',
    edge_sequence: ['CAN_ENROLL', 'ESC4', 'AUTHENTICATED_AS'],
    confidence_modifier: 0.85,
  },
  {
    id: 'dcsync-path',
    name: 'DCSync Path',
    description: 'DACL chain → CAN_DCSYNC → domain credential dump',
    edge_sequence: ['GENERIC_ALL', 'CAN_DCSYNC'],
    confidence_modifier: 0.95,
  },
  {
    id: 'cross-trust',
    name: 'Cross-Trust Pivot',
    description: 'Domain trust traversal with SID filtering check',
    edge_sequence: ['TRUSTS'],
    confidence_modifier: 0.6,
  },
];

// --- BloodHound Path Enricher ---

export interface HVTResult {
  node_id: string;
  reason: string;
}

export interface PreComputedPath {
  from: string;
  to: string;
  path: PathResult;
  matched_template?: string;
}

export class BloodHoundPathEnricher {
  private ctx: EngineContext;

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  /**
   * Scan the graph for High-Value Targets and tag them with hvt=true/hvt_reason.
   * Returns the list of identified HVTs.
   */
  computeHighValueTargets(): HVTResult[] {
    const hvts: HVTResult[] = [];
    const taggedIds = new Set<string>();

    this.ctx.graph.forEachNode((id: string, attrs: NodeProperties) => {
      const reasons: string[] = [];

      // 1. Domain Controllers
      if (attrs.type === 'host' && attrs.domain_joined) {
        const label = (attrs.label || attrs.hostname || '').toLowerCase();
        if (label.includes('dc') || attrs.service_name === 'ldap') {
          // Check if it has LDAP/Kerberos services — likely a DC
          const hasLdap = this.ctx.graph.edges(id).some((e: string) => {
            try {
              const target = this.ctx.graph.target(e);
              const tAttrs = this.ctx.graph.getNodeAttributes(target) as NodeProperties;
              return tAttrs.service_name === 'ldap' || tAttrs.service_name === 'kerberos';
            } catch { return false; }
          });
          if (hasLdap) reasons.push('Domain Controller');
        }
      }

      // 2. Tier-0 group membership (check groups by label and SID)
      if (attrs.type === 'group') {
        const label = (attrs.label || '').trim();
        const sid = attrs.sid || '';
        for (const g of TIER_0_GROUP_PATTERNS) {
          if (g.pattern.test(label)) {
            // The group itself is HVT, and so are its members
            reasons.push(g.reason + ' (group)');
            break;
          }
        }
        for (const s of TIER_0_SID_SUFFIXES) {
          if (sid.endsWith(s.suffix)) {
            reasons.push(s.reason);
            break;
          }
        }
      }

      // 3. Users with DCSync capability
      if (attrs.type === 'user' || attrs.type === 'group') {
        const hasDcsync = this.ctx.graph.edges(id).some((e: string) => {
          try {
            const ep = this.ctx.graph.getEdgeAttributes(e);
            return ep.type === DCSYNC_EDGE;
          } catch { return false; }
        });
        if (hasDcsync) reasons.push('Has DCSync rights');
      }

      // 4. Unconstrained delegation hosts
      if (attrs.type === 'host') {
        const hasUnconstrainedDeleg = this.ctx.graph.edges(id).some((e: string) => {
          try {
            const ep = this.ctx.graph.getEdgeAttributes(e);
            return ep.type === 'DELEGATES_TO' && !ep.constrained;
          } catch { return false; }
        });
        if (hasUnconstrainedDeleg) reasons.push('Unconstrained delegation');
      }

      // 5. Certificate Authority servers
      if (attrs.type === 'host' && attrs.ca_kind === 'enterprise_ca') {
        reasons.push('Enterprise CA server');
      }
      if (attrs.type === 'certificate' && attrs.ca_kind) {
        reasons.push(`Certificate Authority (${attrs.ca_kind})`);
      }

      // 6. Privileged user flag (from BloodHound)
      if (attrs.type === 'user' && attrs.privileged) {
        reasons.push('Marked as privileged');
      }

      // 7. Azure HVT: Global Admin, PIM roles
      if (attrs.type === 'cloud_identity') {
        const roleName = ((attrs.role_name as string) || '').toLowerCase();
        if (AZURE_HVT_ROLES.has(roleName)) {
          reasons.push(`Azure ${attrs.role_name}`);
        }
      }

      if (reasons.length > 0) {
        const reason = reasons.join('; ');
        this.ctx.graph.mergeNodeAttributes(id, { hvt: true, hvt_reason: reason });
        hvts.push({ node_id: id, reason });
        taggedIds.add(id);
      }
    });

    // Second pass: tag members of HVT groups
    for (const hvt of [...hvts]) {
      const attrs = this.ctx.graph.getNodeAttributes(hvt.node_id) as NodeProperties;
      if (attrs.type !== 'group') continue;

      this.ctx.graph.forEachInEdge(hvt.node_id, (e: string, _ea, source: string) => {
        try {
          const ep = this.ctx.graph.getEdgeAttributes(e);
          if (ep.type === 'MEMBER_OF' && !taggedIds.has(source)) {
            const memberReason = `Member of ${attrs.label || hvt.node_id}`;
            this.ctx.graph.mergeNodeAttributes(source, { hvt: true, hvt_reason: memberReason });
            hvts.push({ node_id: source, reason: memberReason });
            taggedIds.add(source);
          }
        } catch { /* skip */ }
      });
    }

    return hvts;
  }

  /**
   * Get all node IDs currently tagged as HVT in the graph.
   */
  getHighValueTargets(): string[] {
    const hvtIds: string[] = [];
    this.ctx.graph.forEachNode((id: string, attrs: NodeProperties) => {
      if (attrs.hvt) hvtIds.push(id);
    });
    return hvtIds;
  }

  /**
   * Get all node IDs currently marked as "owned" (have confirmed access).
   */
  getOwnedNodes(): string[] {
    const owned: string[] = [];
    this.ctx.graph.forEachNode((id: string, attrs: NodeProperties) => {
      if (attrs.type === 'host' || attrs.type === 'user') {
        const hasAccess = this.ctx.graph.edges(id).some((e: string) => {
          try {
            const ep = this.ctx.graph.getEdgeAttributes(e);
            return (ep.type === 'HAS_SESSION' || ep.type === 'ADMIN_TO' || ep.type === 'OWNS_CRED') && ep.confidence >= 0.9;
          } catch { return false; }
        });
        if (hasAccess) owned.push(id);
      }
    });
    return owned;
  }

  /**
   * Match a path's edge sequence against named attack path templates.
   * Returns the first matching template ID or undefined.
   */
  matchPathTemplate(path: string[]): AttackPathTemplate | undefined {
    if (path.length < 2) return undefined;

    // Extract the edge type sequence from the path
    const edgeTypes: EdgeType[] = [];
    for (let i = 0; i < path.length - 1; i++) {
      const edges = this.ctx.graph.edges(path[i], path[i + 1]);
      if (edges.length === 0) {
        // Try reverse direction
        const revEdges = this.ctx.graph.edges(path[i + 1], path[i]);
        if (revEdges.length > 0) {
          edgeTypes.push((this.ctx.graph.getEdgeAttributes(revEdges[0]) as any).type);
        }
      } else {
        edgeTypes.push((this.ctx.graph.getEdgeAttributes(edges[0]) as any).type);
      }
    }

    // Check each template for subsequence match
    for (const template of ATTACK_PATH_TEMPLATES) {
      if (isSubsequence(template.edge_sequence, edgeTypes)) {
        return template;
      }
    }

    return undefined;
  }

  /**
   * Pre-compute attack paths from owned nodes to all HVTs.
   * Returns enriched paths with optional template annotation.
   */
  preComputeAttackPaths(pathAnalyzer: PathAnalyzer, optimize: PathOptimize = 'balanced'): PreComputedPath[] {
    const owned = this.getOwnedNodes();
    const hvts = this.getHighValueTargets();
    if (owned.length === 0 || hvts.length === 0) return [];

    const results: PreComputedPath[] = [];
    const seen = new Set<string>();

    for (const from of owned) {
      for (const to of hvts) {
        if (from === to) continue;
        const key = `${from}→${to}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const paths = pathAnalyzer.findPaths(from, to, 1, optimize);
        if (paths.length === 0) continue;

        const bestPath = paths[0];
        const template = this.matchPathTemplate(bestPath.nodes);

        results.push({
          from,
          to,
          path: bestPath,
          matched_template: template?.id,
        });
      }
    }

    // Sort by confidence descending, then by noise ascending
    results.sort((a, b) => {
      const confDiff = b.path.total_confidence - a.path.total_confidence;
      if (Math.abs(confDiff) > 0.01) return confDiff;
      return a.path.total_opsec_noise - b.path.total_opsec_noise;
    });

    return results;
  }
}

/**
 * Check if `needle` is a subsequence of `haystack`.
 * Elements must appear in order but don't need to be contiguous.
 */
function isSubsequence(needle: EdgeType[], haystack: EdgeType[]): boolean {
  if (needle.length === 0) return true;
  let ni = 0;
  for (let hi = 0; hi < haystack.length && ni < needle.length; hi++) {
    if (haystack[hi] === needle[ni]) ni++;
  }
  return ni === needle.length;
}
