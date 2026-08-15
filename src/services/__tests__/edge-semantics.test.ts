import { describe, it, expect } from 'vitest';
import {
  MATERIAL_ACCESS_EDGE_TYPES,
  ATTACK_PATH_EDGE_TYPES,
  OBJECTIVE_ACCESS_EDGE_TYPES,
  HOST_ACCESS_EDGE_TYPES,
  isMaterialAccessEdge,
  isAttackPathEdge,
  isObjectiveAccessEdge,
  isHostAccessEdge,
  isCredentialAccessEdge,
  isTopologyEdge,
} from '../edge-semantics.js';

// These pin the canonical sets that four consumers (objective-manager, eval-run,
// engagement-scorecard, path-analyzer) now derive from, so a future edit to the registry
// that silently changes any consumer's behavior fails here first.
describe('canonical edge-type semantics registry', () => {
  it('MATERIAL_ACCESS is the material offensive-access set (the retired ORCH_ACCESS set)', () => {
    expect([...MATERIAL_ACCESS_EDGE_TYPES].sort()).toEqual([
      'ADMIN_TO', 'ASSUMES_ROLE', 'CAN_DCSYNC', 'CAN_GET_CHANGES', 'CAN_GET_CHANGES_ALL',
      'CAN_PSREMOTE', 'CAN_RDPINTO', 'GENERIC_ALL', 'HAS_SESSION', 'OWNS_CRED', 'TESTED_CRED', 'VALID_ON',
    ]);
  });

  it('ATTACK_PATH is material access plus exploited weaknesses, and excludes topology', () => {
    expect(ATTACK_PATH_EDGE_TYPES.has('EXPLOITS')).toBe(true);
    expect(ATTACK_PATH_EDGE_TYPES.has('AUTH_BYPASS')).toBe(true);
    expect(ATTACK_PATH_EDGE_TYPES.has('ADMIN_TO')).toBe(true);
    expect(ATTACK_PATH_EDGE_TYPES.has('BACKED_BY')).toBe(false);       // topology
    expect(ATTACK_PATH_EDGE_TYPES.has('FEDERATES_WITH')).toBe(false);  // topology
  });

  it('OBJECTIVE_ACCESS is the narrow default "obtained" set', () => {
    expect([...OBJECTIVE_ACCESS_EDGE_TYPES].sort()).toEqual(['ADMIN_TO', 'HAS_SESSION', 'OWNS_CRED']);
  });

  it('HOST_ACCESS roots an attack-path start: a live session or admin', () => {
    expect([...HOST_ACCESS_EDGE_TYPES].sort()).toEqual(['ADMIN_TO', 'HAS_SESSION']);
  });

  it('predicates agree with the sets and tolerate undefined', () => {
    expect(isMaterialAccessEdge('OWNS_CRED')).toBe(true);
    expect(isAttackPathEdge('EXPLOITS')).toBe(true);
    expect(isObjectiveAccessEdge('CAN_DCSYNC')).toBe(false);   // material access, but not a default objective edge
    expect(isHostAccessEdge('OWNS_CRED')).toBe(false);         // access, but doesn't root a host beachhead
    expect(isCredentialAccessEdge('OWNS_CRED')).toBe(true);
    expect(isTopologyEdge('BACKED_BY')).toBe(true);
    expect(isMaterialAccessEdge(undefined)).toBe(false);
    expect(isTopologyEdge('RUNS')).toBe(false);                // plain discovery — no special role
  });

  it('topology edges are never material access (the drift that overstated orchestration progress)', () => {
    for (const t of ['BACKED_BY', 'FEDERATES_WITH', 'AUTHENTICATES_VIA']) {
      expect(isTopologyEdge(t)).toBe(true);
      expect(isMaterialAccessEdge(t)).toBe(false);
      expect(isAttackPathEdge(t)).toBe(false);
    }
  });
});
