import { describe, expect, it } from 'vitest';
import { buildLegacyPanelPath, isLegacyPanelId, parseLegacyHash } from '../legacy-navigation';

describe('dashboard navigation helpers', () => {
  it('redirects legacy hash bookmarks during the 0.2.x compatibility window', () => {
    expect(parseLegacyHash('#panel=frontier&item=host-1')).toEqual({
      panel: 'frontier',
      item: 'host-1',
      subview: undefined,
    });
    expect(parseLegacyHash('#panel=nope&item=host-1')).toBeNull();
  });

  it('builds route-first panel links with panel-specific query names', () => {
    expect(buildLegacyPanelPath({ panel: 'frontier', item: 'host-1' })).toBe('/frontier?node=host-1');
    expect(buildLegacyPanelPath({ panel: 'evidence', item: 'cred-1' })).toBe('/evidence?node=cred-1');
    expect(buildLegacyPanelPath({ panel: 'evidence', subview: 'obj-1' })).toBe('/evidence?objective=obj-1');
    expect(buildLegacyPanelPath({ panel: 'agents', item: 'task-1' })).toBe('/agents?item=task-1');
  });

  it('recognizes only supported dashboard panels', () => {
    expect(isLegacyPanelId('overview')).toBe(true);
    expect(isLegacyPanelId('graph')).toBe(false);
    expect(isLegacyPanelId(undefined)).toBe(false);
  });
});
