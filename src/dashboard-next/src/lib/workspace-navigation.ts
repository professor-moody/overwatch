// Canonical route contract for the four-workspace dashboard.  Keep all route
// translation in one pure module so bookmarks, toasts, tests, and UI navigation
// cannot drift apart while the legacy 0.3.x panel URLs remain supported.

export const WORKSPACE_IDS = ['operate', 'investigate', 'review', 'manage'] as const;
export type WorkspaceId = typeof WORKSPACE_IDS[number];

export const OPERATE_VIEWS = ['attention', 'active', 'ready', 'campaigns', 'history'] as const;
export type OperateView = typeof OPERATE_VIEWS[number];

export const INVESTIGATE_LENSES = ['topology', 'assets', 'identity', 'credentials', 'paths'] as const;
export type InvestigateLens = typeof INVESTIGATE_LENSES[number];

export const REVIEW_VIEWS = ['readiness', 'proof', 'reports'] as const;
export type ReviewView = typeof REVIEW_VIEWS[number];

export const MANAGE_SECTIONS = ['engagement', 'settings', 'diagnostics'] as const;
export type ManageSection = typeof MANAGE_SECTIONS[number];

export type SelectionKind =
  | 'agent'
  | 'frontier'
  | 'approval'
  | 'finding'
  | 'node'
  | 'edge'
  | 'credential'
  | 'path'
  | 'campaign'
  | 'evidence'
  | 'question'
  | 'plan'
  | 'playbook'
  | 'proof_gap';

export interface SelectionRef {
  kind: SelectionKind;
  id: string;
}

export type DrawerKind = 'activity' | 'sessions' | 'run';

export interface DrawerRef {
  kind: DrawerKind;
  item?: string;
}

export type WorkspaceQueryValue = string | number | boolean | null | undefined;

export type InvestigateContextKey =
  | 'context'
  | 'node'
  | 'nodes'
  | 'edge'
  | 'edges'
  | 'filter'
  | 'hops'
  | 'from'
  | 'to'
  | 'objective'
  | 'source'
  | 'target'
  | 'edge_type'
  | 'frontier'
  | 'finding'
  | 'evidence'
  | 'label';

export type WorkspaceContext = Partial<Record<InvestigateContextKey, WorkspaceQueryValue>>;

interface SharedWorkspaceTarget {
  selection?: SelectionRef | null;
  tab?: string;
  drawer?: DrawerRef | null;
  context?: WorkspaceContext;
}

export type WorkspaceRouteTarget =
  | (SharedWorkspaceTarget & { workspace: 'operate'; view?: OperateView })
  | (SharedWorkspaceTarget & { workspace: 'investigate'; lens?: InvestigateLens })
  | (SharedWorkspaceTarget & { workspace: 'review'; view?: ReviewView; readiness?: 'draft' | 'needs_validation' | 'client_ready' })
  | (SharedWorkspaceTarget & { workspace: 'manage'; section?: ManageSection });

/** Action identifiers are the only drawer selections that can move between
 * Activity and Runs. Production IDs use the `act_` prefix; the deterministic
 * fixture retains its historical hexadecimal `a…` IDs. */
export function isActionDrawerItem(item: string): boolean {
  return /^(?:act(?:_|-)|a[0-9a-f]{8,})/i.test(item);
}

export function transitionDrawer(current: DrawerRef | null, next: DrawerKind | null): DrawerRef | null {
  if (!next) return null;
  if (!current || next === 'sessions' || current.kind === 'sessions') return { kind: next };
  if (!current.item) return { kind: next };
  const preserveAction = current.kind === 'run' || isActionDrawerItem(current.item);
  return { kind: next, item: preserveAction ? current.item : undefined };
}

/**
 * Compatibility-only identifiers accepted by the 0.4.x route adapters. Runtime
 * navigation translates these immediately into a canonical workspace URL.
 */
export const LEGACY_PANEL_IDS = [
  'overview', 'campaigns', 'agents', 'sessions', 'actions', 'frontier',
  'activity', 'analysis', 'evidence', 'identity', 'credentials', 'recon',
  'paths', 'findings', 'engagements', 'smoke', 'settings',
] as const;
export type LegacyPanelId = typeof LEGACY_PANEL_IDS[number];

const LEGACY_PATHS = new Set<string>([...LEGACY_PANEL_IDS, 'graph']);

export function isWorkspaceId(value: string | undefined): value is WorkspaceId {
  return !!value && (WORKSPACE_IDS as readonly string[]).includes(value);
}

export function isLegacyDashboardPath(value: string | undefined): boolean {
  return !!value && LEGACY_PATHS.has(value);
}

function copyParams(source: URLSearchParams): URLSearchParams {
  return new URLSearchParams(source);
}

function withDefault(params: URLSearchParams, key: string, value: string) {
  if (!params.has(key)) params.set(key, value);
}

function move(params: URLSearchParams, from: string, to: string) {
  const value = params.get(from);
  if (value && !params.has(to)) params.set(to, value);
  if (from !== to) params.delete(from);
}

function pathWithParams(path: string, params: URLSearchParams): string {
  const query = params.toString();
  return `${path}${query ? `?${query}` : ''}`;
}

/** Serialize a canonical four-workspace destination from typed route state. */
export function buildWorkspacePath(target: WorkspaceRouteTarget): string {
  const params = new URLSearchParams();
  if (target.workspace === 'operate' && target.view) params.set('view', target.view);
  if (target.workspace === 'investigate' && target.lens) params.set('lens', target.lens);
  if (target.workspace === 'review') {
    if (target.view) params.set('view', target.view);
    if (target.readiness) params.set('readiness', target.readiness);
  }
  if (target.workspace === 'manage' && target.section) params.set('section', target.section);

  if (target.selection) {
    params.set('kind', target.selection.kind);
    params.set('item', target.selection.id);
  }
  if (target.tab) params.set('tab', target.tab);
  if (target.drawer) {
    params.set('drawer', target.drawer.kind);
    if (target.drawer.item) params.set('drawerItem', target.drawer.item);
  }
  for (const [key, value] of Object.entries(target.context || {})) {
    if (value === undefined || value === null || value === false || value === '') continue;
    params.set(key, String(value));
  }
  return pathWithParams(`/${target.workspace}`, params);
}

/** Translate a 0.3.x panel path to the four-workspace route model. */
export function legacyPathToWorkspacePath(
  legacyPath: string,
  source: URLSearchParams = new URLSearchParams(),
): string {
  const panel = legacyPath.replace(/^\//, '').split('/')[0];
  const params = copyParams(source);

  switch (panel) {
    case 'overview':
      return pathWithParams('/operate', params);
    case 'agents':
      withDefault(params, 'view', 'active');
      withDefault(params, 'kind', 'agent');
      return pathWithParams('/operate', params);
    case 'frontier':
      withDefault(params, 'view', 'ready');
      withDefault(params, 'kind', 'frontier');
      move(params, 'node', 'item');
      return pathWithParams('/operate', params);
    case 'actions':
      withDefault(params, 'view', 'attention');
      withDefault(params, 'kind', 'approval');
      return pathWithParams('/operate', params);
    case 'campaigns':
      withDefault(params, 'view', 'campaigns');
      withDefault(params, 'kind', 'campaign');
      return pathWithParams('/operate', params);
    case 'sessions':
      params.set('drawer', 'sessions');
      move(params, 'item', 'drawerItem');
      return pathWithParams('/operate', params);
    case 'activity':
      params.set('drawer', 'activity');
      return pathWithParams('/operate', params);
    case 'analysis':
      params.set('drawer', 'run');
      move(params, 'item', 'drawerItem');
      return pathWithParams('/operate', params);
    case 'graph':
      withDefault(params, 'lens', 'topology');
      return pathWithParams('/investigate', params);
    case 'recon':
      params.set('lens', 'assets');
      return pathWithParams('/investigate', params);
    case 'identity':
      params.set('lens', 'identity');
      return pathWithParams('/investigate', params);
    case 'credentials':
      params.set('lens', 'credentials');
      return pathWithParams('/investigate', params);
    case 'paths':
      params.set('lens', 'paths');
      return pathWithParams('/investigate', params);
    case 'evidence': {
      const node = params.get('node');
      const objective = params.get('objective');
      if (node || objective) {
        params.set('lens', 'topology');
        params.set('tab', 'proof');
        if (node) {
          params.set('entity', 'node');
          params.set('item', node);
          params.set('context', 'evidence');
        }
        return pathWithParams('/investigate', params);
      }
      params.set('view', 'proof');
      return pathWithParams('/review', params);
    }
    case 'findings':
      params.set('view', 'readiness');
      return pathWithParams('/review', params);
    case 'engagements':
      params.set('section', 'engagement');
      return pathWithParams('/manage', params);
    case 'settings':
      params.set('section', 'settings');
      return pathWithParams('/manage', params);
    case 'smoke':
      params.set('section', 'diagnostics');
      return pathWithParams('/manage', params);
    default:
      return pathWithParams('/operate', params);
  }
}

export function selectionFromParams(params: URLSearchParams): SelectionRef | null {
  const kind = params.get('kind') || params.get('entity');
  const id = params.get('item');
  const allowed: SelectionKind[] = [
    'agent', 'frontier', 'approval', 'finding', 'node', 'edge', 'credential', 'path',
    'campaign', 'evidence', 'question', 'plan', 'playbook', 'proof_gap',
  ];
  if (kind && id && allowed.includes(kind as SelectionKind)) {
    return { kind: kind as SelectionKind, id };
  }

  // Graph bookmarks predate SelectionRef and intentionally retain their
  // `node` / `edge` context through the 0.4.x compatibility window. Treat the
  // focused graph entity as the inspector selection without rewriting those
  // stable, shareable parameters.
  const edgeId = params.get('edge');
  if (edgeId) return { kind: 'edge', id: edgeId };
  const nodeId = params.get('node');
  if (nodeId) return { kind: 'node', id: nodeId };
  return null;
}

export function drawerFromParams(params: URLSearchParams): DrawerRef | null {
  const kind = params.get('drawer');
  if (kind !== 'activity' && kind !== 'sessions' && kind !== 'run') return null;
  return { kind, item: params.get('drawerItem') || undefined };
}

export function clearSelectionParams(source: URLSearchParams): URLSearchParams {
  const params = copyParams(source);
  // The new selection pair and legacy graph deep-link target describe the same
  // transient inspector context. Clear them together so an old `node`/`edge`
  // parameter cannot immediately reopen an inspector after it is closed.
  // Filters and path-building context remain part of the surrounding workspace.
  for (const key of [
    'kind', 'entity', 'item', 'tab',
    'context', 'node', 'nodes', 'edge', 'edges', 'source', 'target', 'edge_type',
    'frontier', 'finding', 'evidence', 'label',
  ]) params.delete(key);
  return params;
}

export function setSelectionParams(source: URLSearchParams, selection: SelectionRef | null): URLSearchParams {
  const params = clearSelectionParams(source);
  if (selection) {
    params.set('kind', selection.kind);
    params.set('item', selection.id);
  }
  return params;
}

export function setDrawerParams(source: URLSearchParams, drawer: DrawerRef | null): URLSearchParams {
  const params = copyParams(source);
  params.delete('drawer');
  params.delete('drawerItem');
  if (drawer) {
    params.set('drawer', drawer.kind);
    if (drawer.item) params.set('drawerItem', drawer.item);
  }
  return params;
}
