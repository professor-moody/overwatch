// ============================================================
// useNavigation — cross-panel deep linking with URL hash state
// ============================================================

import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import type { PanelId } from '../components/layout/OperatorLayout';

export interface NavigationTarget {
  panel: PanelId;
  item?: string;
  subview?: string;
}

/**
 * Parses the current URL hash into a NavigationTarget.
 * Format: #panel=X&item=Y&subview=Z
 */
export function parseHash(hash: string): NavigationTarget | null {
  if (!hash || hash === '#') return null;
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const panel = params.get('panel');
  if (!panel) return null;
  return {
    panel: panel as PanelId,
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

  const navigateToGraph = useCallback((nodeId?: string, hops?: number) => {
    if (!nodeId) {
      navigate('/graph');
      return;
    }
    const params = new URLSearchParams({ node: nodeId });
    if (hops) params.set('hops', String(hops));
    navigate(`/graph?${params.toString()}`);
  }, [navigate]);

  const navigateToPanel = useCallback((panel: PanelId, item?: string, subview?: string) => {
    const target: NavigationTarget = { panel, item, subview };
    // Navigate to root with hash state
    navigate(`/${buildHash(target)}`);
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

  return {
    navigateToGraph,
    navigateToPanel,
    navigateToEvidence,
    navigateToEvidenceObjective,
    navigateToCampaign,
    navigateToAgent,
  };
}
