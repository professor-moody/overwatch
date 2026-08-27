import {
  LEGACY_PANEL_IDS,
  type LegacyPanelId,
} from './workspace-navigation';

/**
 * Compatibility-only model for pre-0.4 dashboard hashes and panel URLs.
 * Runtime navigation must use the canonical workspace route builders instead.
 */
export interface LegacyNavigationTarget {
  panel: LegacyPanelId;
  item?: string;
  subview?: string;
}

export function isLegacyPanelId(value: string | undefined): value is LegacyPanelId {
  return !!value && (LEGACY_PANEL_IDS as readonly string[]).includes(value);
}

export function buildLegacyPanelPath(target: LegacyNavigationTarget): string {
  const params = new URLSearchParams();
  if (target.item) {
    if (target.panel === 'frontier' || target.panel === 'evidence') params.set('node', target.item);
    else params.set('item', target.item);
  }
  if (target.subview) {
    if (target.panel === 'evidence') params.set('objective', target.subview);
    else params.set('subview', target.subview);
  }
  const query = params.toString();
  return `/${target.panel}${query ? `?${query}` : ''}`;
}

/** One-release redirect reader for pre-route dashboard bookmarks. */
export function parseLegacyHash(hash: string): LegacyNavigationTarget | null {
  if (!hash || hash === '#') return null;
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const panel = params.get('panel') || undefined;
  if (!isLegacyPanelId(panel)) return null;
  return {
    panel,
    item: params.get('item') || undefined,
    subview: params.get('subview') || undefined,
  };
}
