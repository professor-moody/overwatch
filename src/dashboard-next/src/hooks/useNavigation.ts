// ============================================================
// useNavigation — cross-panel deep linking with route state
// ============================================================

import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import type { PanelId } from '../components/layout/OperatorLayout';
import { buildGraphTargetPath, type GraphNavigationTarget } from '../lib/graph-target';

export const PANEL_IDS = [
  'overview',
  'campaigns',
  'agents',
  'sessions',
  'actions',
  'frontier',
  'activity',
  'analysis',
  'evidence',
  'identity',
  'credentials',
  'paths',
  'findings',
  'engagements',
  'smoke',
  'settings',
] as const satisfies PanelId[];

export interface NavigationTarget {
  panel: PanelId;
  item?: string;
  subview?: string;
}

export function isPanelId(value: string | undefined): value is PanelId {
  return !!value && (PANEL_IDS as readonly string[]).includes(value);
}

export function buildPanelPath(target: NavigationTarget): string {
  const params = new URLSearchParams();
  if (target.item) {
    if (target.panel === 'frontier') params.set('node', target.item);
    else if (target.panel === 'evidence') params.set('node', target.item);
    else params.set('item', target.item);
  }
  if (target.subview) {
    if (target.panel === 'evidence') params.set('objective', target.subview);
    else params.set('subview', target.subview);
  }
  const q = params.toString();
  return `/${target.panel}${q ? `?${q}` : ''}`;
}

/**
 * Parses the current URL hash into a NavigationTarget.
 * Format: #panel=X&item=Y&subview=Z
 */
export function parseHash(hash: string): NavigationTarget | null {
  if (!hash || hash === '#') return null;
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const panelParam = params.get('panel') || undefined;
  if (!isPanelId(panelParam)) return null;
  return {
    panel: panelParam,
    item: params.get('item') || undefined,
    subview: params.get('subview') || undefined,
  };
}

/**
 * Builds a URL hash string from a NavigationTarget.
 */
export function buildHash(target: NavigationTarget): string {
  const params = new URLSearchParams();
  params.set('panel', target.panel);
  if (target.item) params.set('item', target.item);
  if (target.subview) params.set('subview', target.subview);
  return `#${params.toString()}`;
}

export function useNavigation() {
  const navigate = useNavigate();

  const navigateToGraphTarget = useCallback((target: GraphNavigationTarget) => {
    navigate(buildGraphTargetPath(target));
  }, [navigate]);

  const navigateToGraph = useCallback((nodeId?: string, hops?: number) => {
    if (!nodeId) {
      navigate('/graph');
      return;
    }
    navigate(buildGraphTargetPath({ kind: 'node', nodeId, hops }));
  }, [navigate]);

  const navigateToGraphFilter = useCallback((filter: string) => {
    const params = new URLSearchParams({ filter });
    navigate(`/graph?${params.toString()}`);
  }, [navigate]);

  const navigateToPanel = useCallback((panel: PanelId, item?: string, subview?: string) => {
    navigate(buildPanelPath({ panel, item, subview }));
  }, [navigate]);

  const navigateToEvidence = useCallback((nodeId: string) => {
    navigateToPanel('evidence', nodeId);
  }, [navigateToPanel]);

  const navigateToEvidenceObjective = useCallback((objectiveId: string) => {
    navigateToPanel('evidence', undefined, objectiveId);
  }, [navigateToPanel]);

  const navigateToCampaign = useCallback((campaignId: string) => {
    navigateToPanel('campaigns', campaignId);
  }, [navigateToPanel]);

  const navigateToAgent = useCallback((agentId: string) => {
    navigateToPanel('agents', agentId);
  }, [navigateToPanel]);

  const navigateToFrontier = useCallback((nodeId: string) => {
    navigateToPanel('frontier', nodeId);
  }, [navigateToPanel]);

  const navigateToFinding = useCallback((findingId: string) => {
    navigateToPanel('findings', findingId);
  }, [navigateToPanel]);

  const navigateToSession = useCallback((sessionId: string) => {
    navigateToPanel('sessions', sessionId);
  }, [navigateToPanel]);

  // The run-centric Analysis workspace, optionally focused on one action's run
  // (the run that produced an evidence chain). Distinct from 'actions' (Approvals).
  const navigateToAction = useCallback((actionId: string) => {
    navigateToPanel('analysis', actionId);
  }, [navigateToPanel]);

  // Attack Paths "Custom path" picker, prefilled from a node (e.g. graph
  // context-menu "paths from/to here"). Uses from/to/objective query keys that
  // the picker reads — not buildPanelPath's item/subview mapping.
  const navigateToPaths = useCallback((params: { from?: string; to?: string; objective?: string }) => {
    const qs = new URLSearchParams();
    if (params.from) qs.set('from', params.from);
    if (params.to) qs.set('to', params.to);
    if (params.objective) qs.set('objective', params.objective);
    const q = qs.toString();
    navigate(`/paths${q ? `?${q}` : ''}`);
  }, [navigate]);

  return {
    navigateToGraphTarget,
    navigateToGraph,
    navigateToGraphFilter,
    navigateToPanel,
    navigateToEvidence,
    navigateToEvidenceObjective,
    navigateToCampaign,
    navigateToAgent,
    navigateToFrontier,
    navigateToFinding,
    navigateToSession,
    navigateToAction,
    navigateToPaths,
  };
}
