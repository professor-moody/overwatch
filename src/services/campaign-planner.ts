// ============================================================
// Overwatch — Campaign Planner
// Groups frontier items into coherent campaigns (credential
// spray, enumeration, post-exploitation, network discovery).
// Builds on ChainScorer chain groups for spray campaigns.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type { EngineContext } from './engine-context.js';
import type { FrontierItem, Campaign, CampaignStrategy, AbortCondition } from '../types.js';
import type { ChainGroup } from './chain-scorer.js';

// Edge types representing confirmed access to a host
const ACCESS_EDGE_TYPES = new Set([
  'ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE',
]);

// Minimum items to form an enumeration campaign
const ENUMERATION_GROUP_THRESHOLD = 3;

// Default abort conditions per strategy
const DEFAULT_ABORT_CONDITIONS: Record<CampaignStrategy, AbortCondition[]> = {
  credential_spray: [
    { type: 'consecutive_failures', threshold: 5 },
    { type: 'total_failures_pct', threshold: 0.9 },
  ],
  enumeration: [
    { type: 'consecutive_failures', threshold: 10 },
  ],
  post_exploitation: [
    { type: 'consecutive_failures', threshold: 3 },
  ],
  network_discovery: [],
  custom: [],
};

export class CampaignPlanner {
  private ctx: EngineContext;
  /** Active campaigns by ID — status tracking persists across frontier regenerations */
  private campaigns = new Map<string, Campaign>();
  /** Maps chain_id → campaign_id for stable spray campaign identity across recomputation */
  private chainToCampaign = new Map<string, string>();

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  // =============================================
  // Campaign generation from frontier + chain data
  // =============================================

  /**
   * Generate campaigns from frontier items and chain groups.
   * Merges with existing campaign state (status, progress) when
   * a matching campaign already exists.
   */
  generateCampaigns(frontier: FrontierItem[], chainGroups: ChainGroup[]): Campaign[] {
    const generated: Campaign[] = [];

    // 1. Credential spray campaigns from chain groups
    for (const group of chainGroups) {
      if (group.total_count <= 1) continue; // single-target chains stay individual
      const items = frontier.filter(
        fi => fi.chain_id === group.chain_id && fi.type === 'inferred_edge',
      );
      if (items.length === 0) continue;

      const campaign = this.upsertCampaign(
        group.chain_id,
        'credential_spray',
        () => this.nameCredentialSpray(group),
        items.map(fi => fi.id),
        { chain_id: group.chain_id },
      );
      generated.push(campaign);
    }

    // 2. Enumeration campaigns: group incomplete_node items by node type
    const incompleteByType = new Map<string, FrontierItem[]>();
    for (const item of frontier) {
      if (item.type !== 'incomplete_node' || !item.node_id) continue;
      const node = this.ctx.graph.hasNode(item.node_id)
        ? this.ctx.graph.getNodeAttributes(item.node_id)
        : null;
      if (!node) continue;
      const key = `enum-${node.type}`;
      let group = incompleteByType.get(key);
      if (!group) {
        group = [];
        incompleteByType.set(key, group);
      }
      group.push(item);
    }
    for (const [key, items] of incompleteByType) {
      if (items.length < ENUMERATION_GROUP_THRESHOLD) continue;
      const nodeType = key.replace('enum-', '');
      const campaign = this.upsertCampaign(
        key,
        'enumeration',
        () => `Enumerate ${items.length} ${nodeType} nodes`,
        items.map(fi => fi.id),
      );
      generated.push(campaign);
    }

    // 3. Post-exploitation campaigns: group items from compromised hosts
    const postExByHost = new Map<string, FrontierItem[]>();
    for (const item of frontier) {
      if (item.type !== 'inferred_edge' || !item.edge_source) continue;
      if (item.chain_id) continue; // already in a spray campaign
      const sourceHost = this.resolveAccessHost(item.edge_source);
      if (!sourceHost) continue;
      let group = postExByHost.get(sourceHost);
      if (!group) {
        group = [];
        postExByHost.set(sourceHost, group);
      }
      group.push(item);
    }
    for (const [hostId, items] of postExByHost) {
      if (items.length < 2) continue;
      const hostNode = this.ctx.graph.hasNode(hostId)
        ? this.ctx.graph.getNodeAttributes(hostId)
        : null;
      const label = hostNode?.label || hostId;
      const campaign = this.upsertCampaign(
        `postex-${hostId}`,
        'post_exploitation',
        () => `Post-exploitation on ${label} (${items.length} items)`,
        items.map(fi => fi.id),
      );
      generated.push(campaign);
    }

    // 4. Network discovery campaigns: group by CIDR
    const discoveryItems = frontier.filter(fi => fi.type === 'network_discovery' && fi.target_cidr);
    for (const item of discoveryItems) {
      const campaign = this.upsertCampaign(
        `discovery-${item.target_cidr}`,
        'network_discovery',
        () => `Discover hosts in ${item.target_cidr}`,
        [item.id],
      );
      generated.push(campaign);
    }

    return generated;
  }

  // =============================================
  // Campaign lifecycle
  // =============================================

  getCampaign(id: string): Campaign | null {
    return this.campaigns.get(id) || null;
  }

  listCampaigns(filter?: { status?: string }): Campaign[] {
    const all = Array.from(this.campaigns.values());
    if (filter?.status) {
      return all.filter(c => c.status === filter.status);
    }
    return all;
  }

  pauseCampaign(id: string): Campaign | null {
    const c = this.campaigns.get(id);
    if (!c || c.status !== 'active') return null;
    c.status = 'paused';
    return c;
  }

  resumeCampaign(id: string): Campaign | null {
    const c = this.campaigns.get(id);
    if (!c || c.status !== 'paused') return null;
    c.status = 'active';
    return c;
  }

  abortCampaign(id: string): Campaign | null {
    const c = this.campaigns.get(id);
    if (!c || c.status === 'completed' || c.status === 'aborted') return null;
    c.status = 'aborted';
    c.completed_at = new Date().toISOString();
    return c;
  }

  activateCampaign(id: string): Campaign | null {
    const c = this.campaigns.get(id);
    if (!c || c.status !== 'draft') return null;
    c.status = 'active';
    c.started_at = new Date().toISOString();
    return c;
  }

  // =============================================
  // Progress tracking
  // =============================================

  updateCampaignProgress(
    campaignId: string,
    frontierItemId: string,
    result: 'success' | 'failure',
    findingId?: string,
  ): Campaign | null {
    const c = this.campaigns.get(campaignId);
    if (!c) return null;

    // Only track items that belong to this campaign
    if (!c.items.includes(frontierItemId)) return c;

    c.progress.completed++;
    if (result === 'success') {
      c.progress.succeeded++;
      c.progress.consecutive_failures = 0;
      if (findingId) c.findings.push(findingId);
    } else {
      c.progress.failed++;
      c.progress.consecutive_failures++;
    }

    // Auto-complete when all items processed (unless abort conditions are triggered)
    if (c.progress.completed >= c.progress.total && c.status === 'active') {
      const abort = this.checkAbortConditions(campaignId);
      if (!abort.should_abort) {
        c.status = 'completed';
        c.completed_at = new Date().toISOString();
      }
    }

    return c;
  }

  checkAbortConditions(campaignId: string): { should_abort: boolean; reason?: string } {
    const c = this.campaigns.get(campaignId);
    if (!c) return { should_abort: false };

    for (const cond of c.abort_conditions) {
      switch (cond.type) {
        case 'consecutive_failures':
          if (c.progress.consecutive_failures >= cond.threshold) {
            return {
              should_abort: true,
              reason: `${c.progress.consecutive_failures} consecutive failures (threshold: ${cond.threshold})`,
            };
          }
          break;

        case 'total_failures_pct':
          if (c.progress.completed > 0) {
            const failPct = c.progress.failed / c.progress.completed;
            if (failPct >= cond.threshold && c.progress.completed >= 3) {
              return {
                should_abort: true,
                reason: `${(failPct * 100).toFixed(0)}% failure rate (threshold: ${(cond.threshold * 100).toFixed(0)}%)`,
              };
            }
          }
          break;

        case 'opsec_noise_ceiling':
          // Noise ceiling checked externally against OPSEC tracker (future)
          break;

        case 'time_limit_seconds':
          if (c.started_at) {
            const elapsed = (Date.now() - new Date(c.started_at).getTime()) / 1000;
            if (elapsed >= cond.threshold) {
              return {
                should_abort: true,
                reason: `Time limit exceeded: ${elapsed.toFixed(0)}s (threshold: ${cond.threshold}s)`,
              };
            }
          }
          break;
      }
    }

    return { should_abort: false };
  }

  /**
   * Find which campaign contains a given frontier item.
   */
  findCampaignForItem(frontierItemId: string): Campaign | null {
    for (const c of this.campaigns.values()) {
      if (c.items.includes(frontierItemId)) return c;
    }
    return null;
  }

  // =============================================
  // Internal helpers
  // =============================================

  /**
   * Create or update a campaign. Stable key ensures the same logical
   * campaign (e.g., "spray cred-admin") keeps its ID and status across
   * frontier recomputations.
   */
  private upsertCampaign(
    stableKey: string,
    strategy: CampaignStrategy,
    nameFn: () => string,
    itemIds: string[],
    extra?: Partial<Campaign>,
  ): Campaign {
    const existingId = this.chainToCampaign.get(stableKey);
    const existing = existingId ? this.campaigns.get(existingId) : null;

    if (existing) {
      // Refresh item list (frontier may have changed) but preserve status/progress
      existing.items = itemIds;
      existing.progress.total = itemIds.length;
      return existing;
    }

    const id = uuidv4();
    const campaign: Campaign = {
      id,
      name: nameFn(),
      strategy,
      status: 'draft',
      items: itemIds,
      abort_conditions: [...DEFAULT_ABORT_CONDITIONS[strategy]],
      progress: { total: itemIds.length, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
      created_at: new Date().toISOString(),
      findings: [],
      ...extra,
    };

    this.campaigns.set(id, campaign);
    this.chainToCampaign.set(stableKey, id);
    return campaign;
  }

  /**
   * Check if a node has confirmed access (HAS_SESSION, ADMIN_TO, etc.
   * with confidence ≥ 0.9). Returns the host ID if accessible.
   */
  private resolveAccessHost(nodeId: string): string | null {
    // First check if nodeId itself is an accessed host
    if (this.ctx.graph.hasNode(nodeId)) {
      const attrs = this.ctx.graph.getNodeAttributes(nodeId);
      if (attrs.type === 'host' && this.hasConfirmedAccess(nodeId)) {
        return nodeId;
      }
    }

    // Walk inbound RUNS edges to find parent host
    if (!this.ctx.graph.hasNode(nodeId)) return null;
    for (const edgeId of this.ctx.graph.inEdges(nodeId) as string[]) {
      const edgeAttrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (edgeAttrs.type === 'RUNS') {
        const source = this.ctx.graph.source(edgeId);
        if (this.hasConfirmedAccess(source)) return source;
      }
    }
    return null;
  }

  private hasConfirmedAccess(hostId: string): boolean {
    if (!this.ctx.graph.hasNode(hostId)) return false;
    for (const edgeId of this.ctx.graph.inEdges(hostId) as string[]) {
      const edgeAttrs = this.ctx.graph.getEdgeAttributes(edgeId);
      if (ACCESS_EDGE_TYPES.has(edgeAttrs.type) && edgeAttrs.confidence >= 0.9) {
        return true;
      }
    }
    return false;
  }

  private nameCredentialSpray(group: ChainGroup): string {
    const credNode = this.ctx.graph.hasNode(group.credential_id)
      ? this.ctx.graph.getNodeAttributes(group.credential_id)
      : null;
    const credLabel = credNode?.label || group.credential_id;
    return `Spray ${credLabel} → ${group.total_count} targets`;
  }
}
