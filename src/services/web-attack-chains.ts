// ============================================================
// Overwatch — Web Attack Chain Enricher
// Multi-step web attack path templates matched against the
// graph post-ingest to surface chain-aware frontier items.
// ============================================================

import type { EngineContext } from './engine-context.js';
import type { EdgeType, NodeProperties } from '../types.js';

// --- Chain Template Definitions ---

export interface ChainHop {
  /** Edge type to traverse in this hop. */
  edge_type: EdgeType;
  /** Direction from the current position: 'outbound' follows src→tgt, 'inbound' follows tgt→src. */
  direction: 'outbound' | 'inbound';
  /** Optional: the target node must match this type. */
  target_type?: string;
  /** Optional: the target node must have these properties. */
  target_match?: Record<string, unknown>;
}

export interface WebChainTemplate {
  id: string;
  name: string;
  description: string;
  /** First hop must originate from a node matching this type. */
  entry_type: string;
  /** Optional property match on the entry node. */
  entry_match?: Record<string, unknown>;
  /** Ordered hops constituting the chain. */
  hops: ChainHop[];
  /** Confidence modifier applied to matched chains. */
  confidence_modifier: number;
}

export interface MatchedChain {
  template_id: string;
  template_name: string;
  /** Node IDs traversed (entry + one per hop). */
  node_path: string[];
  /** How many hops are confirmed (edge exists in graph). */
  confirmed_hops: number;
  /** Total hops in template. */
  total_hops: number;
  /** Fraction complete (0.0–1.0). */
  completion: number;
  /** First missing hop index, or -1 if fully complete. */
  gap_index: number;
}

// --- Templates ---

export const WEB_CHAIN_TEMPLATES: WebChainTemplate[] = [
  {
    id: 'sqli-to-lateral',
    name: 'SQLi → Credential Extraction → Lateral Movement',
    description: 'SQL injection exploited to extract credentials, then used for lateral movement to another host',
    entry_type: 'vulnerability',
    entry_match: { vuln_type: 'sqli', exploitable: true },
    hops: [
      { edge_type: 'EXPLOITS', direction: 'outbound', target_type: 'credential' },
      { edge_type: 'VALID_ON', direction: 'outbound', target_type: 'service' },
      { edge_type: 'RUNS', direction: 'inbound', target_type: 'host' },
    ],
    confidence_modifier: 1.3,
  },
  {
    id: 'lfi-to-creds',
    name: 'LFI → File Read → Credential Extraction',
    description: 'Local file inclusion vulnerability used to read configuration files containing credentials',
    entry_type: 'vulnerability',
    entry_match: { vuln_type: 'lfi' },
    hops: [
      { edge_type: 'EXPLOITS', direction: 'outbound', target_type: 'host' },
      { edge_type: 'DUMPED_FROM', direction: 'inbound', target_type: 'credential' },
    ],
    confidence_modifier: 1.2,
  },
  {
    id: 'auth-bypass-to-admin',
    name: 'Auth Bypass → Admin Access → Host Compromise',
    description: 'Authentication bypass on webapp grants admin access leading to host compromise via webapp management',
    entry_type: 'vulnerability',
    entry_match: { vuln_type: 'auth_bypass' },
    hops: [
      { edge_type: 'AUTH_BYPASS', direction: 'outbound', target_type: 'webapp' },
      { edge_type: 'HOSTS', direction: 'inbound', target_type: 'service' },
      { edge_type: 'RUNS', direction: 'inbound', target_type: 'host' },
    ],
    confidence_modifier: 1.25,
  },
  {
    id: 'ssrf-to-cloud',
    name: 'SSRF → IMDS → Cloud Identity Pivot',
    description: 'Server-side request forgery to cloud metadata service yields cloud credentials for lateral movement',
    entry_type: 'vulnerability',
    entry_match: { vuln_type: 'ssrf' },
    hops: [
      { edge_type: 'EXPLOITS', direction: 'outbound', target_type: 'host' },
      { edge_type: 'POTENTIAL_AUTH', direction: 'outbound', target_type: 'cloud_identity' },
    ],
    confidence_modifier: 1.3,
  },
  {
    id: 'rce-to-pivot',
    name: 'RCE → Shell → Host Enumeration → Lateral Movement',
    description: 'Remote code execution on webapp yields shell access, enabling enumeration and lateral movement',
    entry_type: 'vulnerability',
    entry_match: { vuln_type: 'rce' },
    hops: [
      { edge_type: 'EXPLOITS', direction: 'outbound', target_type: 'host' },
      { edge_type: 'HAS_SESSION', direction: 'inbound', target_type: 'user' },
      { edge_type: 'ADMIN_TO', direction: 'outbound', target_type: 'host' },
    ],
    confidence_modifier: 1.4,
  },
];

// --- Enricher ---

export class WebChainEnricher {
  private ctx: EngineContext;
  private matched: MatchedChain[] = [];

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  /**
   * Scan graph for entry nodes matching each template, then walk hops.
   * Returns matched chains with completion percentages.
   */
  matchChainTemplates(): MatchedChain[] {
    this.matched = [];
    const graph = this.ctx.graph;

    for (const tpl of WEB_CHAIN_TEMPLATES) {
      // Find all entry nodes
      graph.forEachNode((_id: string, attrs) => {
        const node = attrs as NodeProperties;
        if (node.type !== tpl.entry_type) return;
        if (tpl.entry_match && !propsMatch(node, tpl.entry_match)) return;

        // Walk the hops
        const nodePath = [node.id];
        let currentId = node.id;
        let confirmedHops = 0;
        let gapIndex = -1;

        for (let i = 0; i < tpl.hops.length; i++) {
          const hop = tpl.hops[i];
          const nextId = this.findHop(currentId, hop);
          if (nextId) {
            nodePath.push(nextId);
            currentId = nextId;
            confirmedHops++;
          } else {
            if (gapIndex === -1) gapIndex = i;
            break; // Stop at first gap — can't continue without previous hop
          }
        }

        // Only record chains that have at least one confirmed hop
        if (confirmedHops > 0) {
          this.matched.push({
            template_id: tpl.id,
            template_name: tpl.name,
            node_path: nodePath,
            confirmed_hops: confirmedHops,
            total_hops: tpl.hops.length,
            completion: confirmedHops / tpl.hops.length,
            gap_index: confirmedHops === tpl.hops.length ? -1 : gapIndex,
          });
        }
      });
    }

    return this.matched;
  }

  /** Return previously matched chains. */
  getMatchedChains(): MatchedChain[] {
    return this.matched;
  }

  /** Find the next node from `currentId` following the hop specification. */
  private findHop(currentId: string, hop: ChainHop): string | null {
    const graph = this.ctx.graph;

    if (hop.direction === 'outbound') {
      for (const edgeId of graph.outEdges(currentId)) {
        const attrs = graph.getEdgeAttributes(edgeId);
        if (attrs.type !== hop.edge_type) continue;
        const tgt = graph.target(edgeId);
        if (hop.target_type) {
          const tgtNode = graph.getNodeAttributes(tgt) as NodeProperties;
          if (tgtNode.type !== hop.target_type) continue;
          if (hop.target_match && !propsMatch(tgtNode, hop.target_match)) continue;
        }
        return tgt;
      }
    } else {
      // inbound: look for edges where currentId is the target
      for (const edgeId of graph.inEdges(currentId)) {
        const attrs = graph.getEdgeAttributes(edgeId);
        if (attrs.type !== hop.edge_type) continue;
        const src = graph.source(edgeId);
        if (hop.target_type) {
          const srcNode = graph.getNodeAttributes(src) as NodeProperties;
          if (srcNode.type !== hop.target_type) continue;
          if (hop.target_match && !propsMatch(srcNode, hop.target_match)) continue;
        }
        return src;
      }
    }
    return null;
  }
}

/** Check if node properties satisfy all key/value pairs in match. */
function propsMatch(node: NodeProperties, match: Record<string, unknown>): boolean {
  for (const [key, val] of Object.entries(match)) {
    if ((node as any)[key] !== val) return false;
  }
  return true;
}
