import { describe, it, expect } from 'vitest';
import { NODE_TYPES } from '../types';
import { NODE_COLORS, NODE_BASE_SIZES } from '../graph-constants';

// The graph's default node-type filter seeds from Object.keys(NODE_COLORS)
// (GraphPage.tsx: `s.activeFilters = new Set(Object.keys(NODE_COLORS))`), and
// graph presets filter by `NODE_COLORS[t]`. A NODE_TYPE missing from NODE_COLORS
// is therefore HIDDEN BY DEFAULT and not restored by Reset. These tests lock the
// invariant so a newly-added node type can never silently become invisible.
describe('graph-constants cover every NODE_TYPE', () => {
  it('every NODE_TYPE has a NODE_COLORS entry (else hidden-by-default + Reset won\'t restore it)', () => {
    const missing = NODE_TYPES.filter(t => !(t in NODE_COLORS));
    expect(missing).toEqual([]);
  });

  it('every NODE_TYPE has a NODE_BASE_SIZES entry', () => {
    const missing = NODE_TYPES.filter(t => !(t in NODE_BASE_SIZES));
    expect(missing).toEqual([]);
  });
});
