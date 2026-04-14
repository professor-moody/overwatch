// ============================================================
// Overwatch — Cold Store
// Promotion-only compaction for large network sweeps.
// Hosts with no services and no interesting edges are stored
// here instead of in the hot graphology graph. Promotion is
// idempotent and one-way (cold → hot; never hot → cold).
// ============================================================

import type { NodeProperties, EdgeType } from '../types.js';

// --- Cold node record: minimal footprint for census tracking ---

export interface ColdNodeRecord {
  id: string;
  type: string;
  label: string;
  ip?: string;
  hostname?: string;
  discovered_at: string;
  last_seen_at: string;
  subnet_cidr?: string;
  provenance?: string;
  alive?: boolean;
  confidence?: number;
  finding_id?: string;
  action_id?: string;
}

// --- Interesting edge types that force a host into the hot graph ---

const INTERESTING_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'HAS_SESSION',
  'ADMIN_TO',
  'RUNS_ON',
  'VULNERABLE_TO',
  'RUNS',
  'HOSTS',
] as EdgeType[]);

export function isInterestingEdgeType(type: EdgeType): boolean {
  return INTERESTING_EDGE_TYPES.has(type);
}

// --- Temperature classifier: pure function ---

export function classifyNodeTemperature(
  node: Pick<NodeProperties, 'id' | 'type' | 'alive' | 'hostname' | 'os'>,
  hasInterestingEdge: boolean,
): 'hot' | 'cold' {
  // All non-host types are always hot
  if (node.type !== 'host') return 'hot';

  // Hosts that aren't confirmed alive stay hot (need scope tracking)
  if (node.alive !== true) return 'hot';

  // Hosts with a hostname are identity-bearing — need reconciliation, stay hot
  if (node.hostname) return 'hot';

  // Hosts with OS info are enriched beyond a simple ping, stay hot
  if (node.os) return 'hot';

  // Alive host with interesting edges → hot
  if (hasInterestingEdge) return 'hot';

  // Alive host with no interesting edges, no hostname, no OS → cold candidate
  // These are pure ping-sweep responses (IP only).
  // Caller must additionally verify no outbound RUNS edges before demoting.
  return 'cold';
}

// --- Cold store: in-memory Map with serialization ---

export class ColdStore {
  private store = new Map<string, ColdNodeRecord>();

  add(record: ColdNodeRecord): void {
    const existing = this.store.get(record.id);
    if (existing) {
      // Merge: keep earliest discovered_at, latest last_seen_at
      this.store.set(record.id, {
        ...existing,
        ...record,
        discovered_at: existing.discovered_at < record.discovered_at
          ? existing.discovered_at
          : record.discovered_at,
        last_seen_at: existing.last_seen_at > record.last_seen_at
          ? existing.last_seen_at
          : record.last_seen_at,
      });
    } else {
      this.store.set(record.id, record);
    }
  }

  get(id: string): ColdNodeRecord | undefined {
    return this.store.get(id);
  }

  has(id: string): boolean {
    return this.store.has(id);
  }

  promote(id: string): ColdNodeRecord | undefined {
    const record = this.store.get(id);
    if (record) {
      this.store.delete(id);
    }
    return record;
  }

  count(): number {
    return this.store.size;
  }

  countBySubnet(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const record of this.store.values()) {
      const key = record.subnet_cidr || 'unknown';
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }

  summary(): { total: number; by_subnet: Record<string, number> } {
    return {
      total: this.count(),
      by_subnet: this.countBySubnet(),
    };
  }

  /** All cold records as an array (for serialization). */
  export(): ColdNodeRecord[] {
    return Array.from(this.store.values());
  }

  /** Restore from a serialized array. */
  import(records: ColdNodeRecord[]): void {
    this.store.clear();
    for (const r of records) {
      this.store.set(r.id, r);
    }
  }

  clear(): void {
    this.store.clear();
  }

  /** Iterate over all cold records. */
  forEach(fn: (record: ColdNodeRecord) => void): void {
    for (const record of this.store.values()) {
      fn(record);
    }
  }
}

// --- Helper: build a ColdNodeRecord from NodeProperties ---

export function toColdRecord(
  node: NodeProperties,
  subnetCidr?: string,
  context?: { finding_id?: string; action_id?: string },
): ColdNodeRecord {
  return {
    id: node.id,
    type: node.type,
    label: node.label,
    ip: node.ip,
    hostname: node.hostname,
    discovered_at: node.discovered_at,
    last_seen_at: node.last_seen_at || node.discovered_at,
    subnet_cidr: subnetCidr,
    provenance: node.discovered_by,
    alive: node.alive,
    confidence: node.confidence,
    finding_id: context?.finding_id,
    action_id: context?.action_id,
  };
}
