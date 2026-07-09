import { describe, expect, it } from 'vitest';
import { communityColor, colorForNode, COMMUNITY_PALETTE, TIER_COLORS } from '../graph-color';
import { NODE_COLORS } from '../graph-constants';
import type { ExportedNode } from '../types';

function node(over: Partial<ExportedNode>): ExportedNode {
  return { id: 'n', type: 'host', label: 'n', confidence: 1, discovered_at: '', ...over };
}

describe('communityColor', () => {
  it('is stable and always in-palette, including negative/large ids', () => {
    expect(communityColor(0)).toBe(COMMUNITY_PALETTE[0]);
    expect(communityColor(0)).toBe(communityColor(0));
    for (const id of [-1, -17, 15, 16, 9999, 2 ** 31]) {
      expect(COMMUNITY_PALETTE).toContain(communityColor(id));
    }
  });

  it('falls back to a neutral color for a missing/NaN community id', () => {
    expect(communityColor(undefined)).toBe(communityColor(undefined));
    expect(COMMUNITY_PALETTE).not.toContain(communityColor(undefined));
  });
});

describe('colorForNode', () => {
  const attrs = { nodeType: 'webapp', community: 3, _props: node({ type: 'webapp' }) };

  it('type mode uses NODE_COLORS by node type', () => {
    expect(colorForNode(attrs, 'type')).toBe(NODE_COLORS.webapp);
  });

  it('community mode uses the community palette', () => {
    expect(colorForNode(attrs, 'community')).toBe(communityColor(3));
  });

  it('tier mode uses TIER_COLORS by derived tier (webapp -> app)', () => {
    expect(colorForNode(attrs, 'tier')).toBe(TIER_COLORS.app);
  });

  it('tier mode maps a host to the network tier', () => {
    expect(colorForNode({ nodeType: 'host', _props: node({ type: 'host' }) }, 'tier')).toBe(TIER_COLORS.network);
  });
});
