import { describe, expect, it } from 'vitest';
import { buildPanelPath, isPanelId, parseHash } from '../../hooks/useNavigation';

describe('dashboard navigation helpers', () => {
  it('parses legacy hash deep links for route redirects', () => {
    expect(parseHash('#panel=frontier&item=host-1')).toEqual({
      panel: 'frontier',
      item: 'host-1',
      subview: undefined,
    });
    expect(parseHash('#panel=nope&item=host-1')).toBeNull();
  });

  it('builds route-first panel links with panel-specific query names', () => {
    expect(buildPanelPath({ panel: 'frontier', item: 'host-1' })).toBe('/frontier?node=host-1');
    expect(buildPanelPath({ panel: 'evidence', item: 'cred-1' })).toBe('/evidence?node=cred-1');
    expect(buildPanelPath({ panel: 'evidence', subview: 'obj-1' })).toBe('/evidence?objective=obj-1');
    expect(buildPanelPath({ panel: 'agents', item: 'task-1' })).toBe('/agents?item=task-1');
  });

  it('recognizes only supported dashboard panels', () => {
    expect(isPanelId('overview')).toBe(true);
    expect(isPanelId('graph')).toBe(false);
    expect(isPanelId(undefined)).toBe(false);
  });
});
