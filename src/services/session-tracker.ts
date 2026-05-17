// ============================================================
// Session Tracker
// Session → graph integration: HAS_SESSION edge lifecycle,
// frontier edge marking, startup reconciliation.
// Extracted from GraphEngine.
// ============================================================

import type { EngineContext, ActivityLogEntry } from './engine-context.js';

export interface SessionTrackerHost {
  ctx: EngineContext;
  logActionEvent(event: Omit<Partial<ActivityLogEntry>, 'event_id' | 'timestamp'> & { description: string }): ActivityLogEntry;
  log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void;
  persist(detail?: Record<string, unknown>): void;
  invalidateFrontierCache(): void;
  invalidatePathGraph(): void;
}

export function ingestSessionResult(
  host: SessionTrackerHost,
  result: {
    success: boolean;
    confirmed?: boolean;
    target_node: string;
    principal_node?: string;
    credential_node?: string;
    session_id?: string;
    agent_id?: string;
    action_id?: string;
    frontier_item_id?: string;
  },
): void {
  const { success, target_node, principal_node, credential_node, session_id, agent_id, action_id, frontier_item_id } = result;
  const confirmed = result.confirmed !== false; // default true for backward compat

  if (success) {
    let sessionEdgeCreated = false;

    // Only create HAS_SESSION edges when auth is positively confirmed.
    // Unconfirmed success (session alive but no shell detected) is logged
    // but does NOT create graph edges — the operator can confirm manually.
    if (confirmed && principal_node && host.ctx.graph.hasNode(principal_node)) {
      const principalAttrs = host.ctx.graph.getNodeAttributes(principal_node);
      const validSourceTypes = new Set(['user', 'group', 'credential']);
      if (validSourceTypes.has(principalAttrs.type)) {
        sessionEdgeCreated = true;
        const edgeId = `session-${principal_node}-${target_node}`;
        if (!host.ctx.graph.hasEdge(edgeId)) {
          host.ctx.graph.addEdgeWithKey(edgeId, principal_node, target_node, {
            type: 'HAS_SESSION',
            confidence: 1.0,
            discovered_at: new Date().toISOString(),
            discovered_by: 'session-manager',
            tested: true,
            test_result: 'success',
            confirmed_at: new Date().toISOString(),
            session_live: true,
            session_id,
          });
          host.invalidateFrontierCache();
          host.invalidatePathGraph();
        } else {
          host.ctx.graph.mergeEdgeAttributes(edgeId, {
            confidence: 1.0,
            tested: true,
            test_result: 'success',
            confirmed_at: new Date().toISOString(),
            session_live: true,
            session_id,
            session_unconfirmed: undefined,
          });
        }
      }
    }

    // Frontier edge: confirmed = success, unconfirmed = partial (needs operator review)
    markFrontierEdgeTested(host, frontier_item_id, action_id, confirmed ? 'success' : 'partial');

    const eventType = confirmed ? 'session_access_confirmed' : 'session_access_unconfirmed';
    host.logActionEvent({
      event_type: eventType,
      description: `SSH session ${session_id || '(unknown)'} to ${target_node} ${confirmed ? 'succeeded' : 'connected but unconfirmed — no shell detected'}${principal_node ? ` as ${principal_node}` : ''}`,
      agent_id,
      action_id,
      frontier_item_id,
      category: 'system',
      details: {
        session_id,
        target_node,
        principal_node,
        credential_node,
        confirmed,
        has_session_edge_created: sessionEdgeCreated,
      },
    });
  } else {
    // Failure: mark only the specific frontier item's edge
    markFrontierEdgeTested(host, frontier_item_id, action_id, 'failure');

    host.logActionEvent({
      event_type: 'session_error',
      description: `SSH session to ${target_node} failed${principal_node ? ` as ${principal_node}` : ''}`,
      agent_id,
      action_id,
      frontier_item_id,
      category: 'system',
      outcome: 'failure',
      details: {
        session_id,
        target_node,
        principal_node,
        credential_node,
      },
    });
  }

  host.persist();
}

/**
 * Called when a session is closed (operator close, process exit, or shutdown).
 * Downgrades HAS_SESSION edges to historical state so get_state no longer
 * reports the host as having live access.
 */
export function onSessionClosed(host: SessionTrackerHost, sessionId: string, targetNode?: string, principalNode?: string): void {
  if (!targetNode) return;

  // Find and downgrade matching HAS_SESSION edges.
  //
  // Safety: a HAS_SESSION edge to `targetNode` may have been created by a
  // *different* live session (different user/credential). If the caller
  // does not tell us which principal owned this session, the only edges we
  // can safely downgrade are ones tagged with this exact session_id.
  // Downgrading every edge on (target) would erase legitimate live access
  // from other concurrent sessions.
  const edgesToDowngrade: string[] = [];
  host.ctx.graph.forEachEdge((_edgeId, attrs, source, target) => {
    if (attrs.type !== 'HAS_SESSION') return;
    if (target !== targetNode) return;
    if (principalNode) {
      if (source !== principalNode) return;
    } else {
      // No principal — only match by recorded session_id.
      const edgeSessionId = (attrs as { session_id?: string }).session_id;
      if (!edgeSessionId || edgeSessionId !== sessionId) return;
    }
    edgesToDowngrade.push(_edgeId);
  });

  for (const edgeId of edgesToDowngrade) {
    const props = {
      session_live: false,
      session_closed_at: new Date().toISOString(),
    };
    host.ctx.journalMutation('merge_edge_attrs', { edge_id: edgeId, props });
    host.ctx.graph.mergeEdgeAttributes(edgeId, props);
  }

  if (edgesToDowngrade.length > 0) {
    host.invalidateFrontierCache();
    // Persist immediately so the on-disk state and bundle exports reflect the
    // closed session — without this the live edge attributes survive until the
    // next unrelated persist, which may never come (P1 session-close fix).
    host.persist();
  }
}

/**
 * Reconcile all HAS_SESSION edges on startup: mark any that claim to be
 * live as no longer live, since all runtime sessions are gone after restart.
 */
export function reconcileSessionEdgesOnStartup(host: SessionTrackerHost): void {
  let downgraded = 0;
  host.ctx.graph.forEachEdge((_edgeId, attrs) => {
    if (attrs.type !== 'HAS_SESSION') return;
    // Only downgrade edges that are still marked as live (or have no session_live flag,
    // meaning they were created before this feature and never closed properly)
    if (attrs.session_live !== false) {
      const props = {
        session_live: false,
        session_closed_at: attrs.session_closed_at || new Date().toISOString(),
      };
      host.ctx.journalMutation('merge_edge_attrs', { edge_id: _edgeId, props });
      host.ctx.graph.mergeEdgeAttributes(_edgeId, props);
      downgraded++;
    }
  });
  if (downgraded > 0) {
    host.log(`Reconciled ${downgraded} stale HAS_SESSION edge(s) on startup — marked as historical`, undefined, { category: 'system', event_type: 'system' });
    host.invalidateFrontierCache();
    // Persist so the reconciled edge attributes reach disk before the first
    // tool call changes something else (P1 session-close fix).
    host.persist();
  }
}

function markFrontierEdgeTested(
  host: SessionTrackerHost,
  frontier_item_id: string | undefined,
  action_id: string | undefined,
  test_result: 'success' | 'failure' | 'partial',
): void {
  if (!frontier_item_id && !action_id) return;

  // If frontier_item_id is present, find the edge it refers to
  if (frontier_item_id) {
    // Frontier edge IDs follow pattern "frontier-edge-{edgeId}"
    const edgeId = frontier_item_id.replace(/^frontier-edge-/, '');
    if (edgeId !== frontier_item_id && host.ctx.graph.hasEdge(edgeId)) {
      host.ctx.graph.mergeEdgeAttributes(edgeId, {
        tested: true,
        test_result,
      });
      host.invalidateFrontierCache();
      host.invalidatePathGraph();
      return;
    }
  }

  // Fallback: if action_id is set, check the action→frontier mapping
  if (action_id && frontier_item_id) {
    // The frontier_item_id itself encodes the edge — already tried above
    // No additional blanket marking — this is intentionally scoped
  }
}
