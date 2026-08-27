import { useCallback } from 'react';
import { useNavigate } from 'react-router';
import { buildGraphTargetPath, type GraphNavigationTarget } from '../lib/graph-target';
import {
  buildWorkspacePath,
  type WorkspaceRouteTarget,
} from '../lib/workspace-navigation';

/** Canonical navigation for the four-workspace runtime. */
export function useWorkspaceNavigation() {
  const navigate = useNavigate();

  const navigateToWorkspace = useCallback((target: WorkspaceRouteTarget, options?: { replace?: boolean }) => {
    navigate(buildWorkspacePath(target), options);
  }, [navigate]);

  const navigateToGraphTarget = useCallback((target: GraphNavigationTarget) => {
    navigate(buildGraphTargetPath(target));
  }, [navigate]);

  const navigateToGraph = useCallback((nodeId?: string, hops?: number) => {
    if (!nodeId) {
      navigateToWorkspace({ workspace: 'investigate', lens: 'topology' });
      return;
    }
    navigate(buildGraphTargetPath({ kind: 'node', nodeId, hops }));
  }, [navigate, navigateToWorkspace]);

  const navigateToGraphFilter = useCallback((filter: string) => {
    navigateToWorkspace({ workspace: 'investigate', lens: 'topology', context: { filter } });
  }, [navigateToWorkspace]);

  const navigateToEvidence = useCallback((nodeId: string) => {
    navigateToWorkspace({
      workspace: 'investigate',
      lens: 'topology',
      selection: { kind: 'node', id: nodeId },
      tab: 'proof',
      context: { node: nodeId, context: 'evidence' },
    });
  }, [navigateToWorkspace]);

  const navigateToEvidenceObjective = useCallback((objectiveId: string) => {
    navigateToWorkspace({ workspace: 'review', view: 'proof', context: { objective: objectiveId } });
  }, [navigateToWorkspace]);

  const navigateToCampaign = useCallback((campaignId: string) => {
    navigateToWorkspace({ workspace: 'operate', view: 'campaigns', selection: { kind: 'campaign', id: campaignId } });
  }, [navigateToWorkspace]);

  const navigateToAgent = useCallback((agentId: string) => {
    navigateToWorkspace({ workspace: 'operate', view: 'active', selection: { kind: 'agent', id: agentId } });
  }, [navigateToWorkspace]);

  const navigateToFrontier = useCallback((frontierId: string) => {
    navigateToWorkspace({ workspace: 'operate', view: 'ready', selection: { kind: 'frontier', id: frontierId } });
  }, [navigateToWorkspace]);

  const navigateToFinding = useCallback((findingId: string) => {
    navigateToWorkspace({ workspace: 'review', view: 'readiness', selection: { kind: 'finding', id: findingId } });
  }, [navigateToWorkspace]);

  const navigateToSession = useCallback((sessionId: string) => {
    navigateToWorkspace({ workspace: 'operate', drawer: { kind: 'sessions', item: sessionId } });
  }, [navigateToWorkspace]);

  const navigateToAction = useCallback((actionId: string) => {
    navigateToWorkspace({ workspace: 'operate', drawer: { kind: 'run', item: actionId } });
  }, [navigateToWorkspace]);

  const navigateToPaths = useCallback((context: { from?: string; to?: string; objective?: string }) => {
    navigateToWorkspace({ workspace: 'investigate', lens: 'paths', context });
  }, [navigateToWorkspace]);

  return {
    navigateToWorkspace,
    navigateToGraphTarget,
    navigateToGraph,
    navigateToGraphFilter,
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
