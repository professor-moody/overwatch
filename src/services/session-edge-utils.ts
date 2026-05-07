// ============================================================
// Session-edge utilities.
//
// session-tracker.ts marks HAS_SESSION edges with `session_live: false`
// when a shell closes or the server restarts (see session-tracker.ts:152
// and :172). Several consumers — frontier scoring, imperative pivot
// inference, path reachability, objective achievement — used to gate on
// `type === 'HAS_SESSION'` and `confidence` only, so historical sessions
// continued to drive active-state reasoning even after the shell was
// dead. The helpers here centralize the "is this edge a live access
// path?" predicate so every consumer applies it consistently.
//
// Pre-existing edges with no `session_live` field are treated as live
// for backwards compatibility with engagements that pre-date the
// session_live flag — only the explicit `false` value disables an
// edge. Newly-created edges in session-tracker.ts always set
// `session_live: true` on creation.
// ============================================================

/** Bare attributes shape we need from a graph edge to make the call. */
export interface SessionEdgeAttrs {
  type?: string;
  confidence?: number;
  session_live?: boolean;
  [k: string]: unknown;
}

/**
 * True iff the edge is a `HAS_SESSION` edge that has NOT been marked
 * dead. Use this everywhere a live shell is required — frontier
 * pivots, path reachability, objective achievement.
 *
 * Use the type-only variant `isHasSessionEdge` when you also want to
 * include historical sessions (reporting, retrospectives, audit).
 */
export function isLiveSessionEdge(attrs: SessionEdgeAttrs | undefined | null): boolean {
  if (!attrs) return false;
  if (attrs.type !== 'HAS_SESSION') return false;
  return attrs.session_live !== false;
}

/** True for any HAS_SESSION edge (live or dead). For reporting/retros. */
export function isHasSessionEdge(attrs: SessionEdgeAttrs | undefined | null): boolean {
  return !!attrs && attrs.type === 'HAS_SESSION';
}
