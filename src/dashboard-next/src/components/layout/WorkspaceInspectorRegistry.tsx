import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useSearchParams } from 'react-router';
import {
  clearSelectionParams,
  selectionFromParams,
  type SelectionKind,
  type SelectionRef,
} from '../../lib/workspace-navigation';

export interface InspectorTabSpec {
  value: string;
  label: ReactNode;
}

export interface InspectorRenderContext {
  selection: SelectionRef;
  tab?: string;
  setTab: (tab: string) => void;
  close: () => void;
}

export interface WorkspaceInspectorAdapter {
  /** False after the owning data source has resolved means the selection was deleted. */
  available?: boolean;
  /** False while the owning data source is still hydrating. */
  resolved?: boolean;
  tabs?: readonly InspectorTabSpec[];
  defaultTab?: string;
  render: (context: InspectorRenderContext) => ReactNode;
}

export type WorkspaceInspectorAdapters = Partial<Record<SelectionKind, WorkspaceInspectorAdapter>>;

interface InspectorRegistrationContextValue {
  register: (owner: symbol, adapters: WorkspaceInspectorAdapters) => void;
  unregister: (owner: symbol) => void;
}

const InspectorRegistrationContext = createContext<InspectorRegistrationContextValue | null>(null);

export interface ResolvedInspectorState {
  tab?: string;
  invalidRequestedTab: boolean;
}

export function resolveInspectorTab(
  requestedTab: string | null,
  adapter: Pick<WorkspaceInspectorAdapter, 'tabs' | 'defaultTab'>,
): ResolvedInspectorState {
  const tabs = adapter.tabs || [];
  if (tabs.length === 0) return { tab: undefined, invalidRequestedTab: Boolean(requestedTab) };
  const defaultTab = adapter.defaultTab || tabs[0].value;
  const valid = requestedTab && tabs.some(tab => tab.value === requestedTab);
  return {
    tab: valid ? requestedTab : defaultTab,
    invalidRequestedTab: Boolean(requestedTab && !valid),
  };
}

/**
 * One route-driven inspector switchboard. Workspaces own entity presentation,
 * while selection recovery, tab validation, close behavior, and URL semantics
 * remain identical everywhere.
 */
export function WorkspaceInspectorRegistry({ adapters }: { adapters: WorkspaceInspectorAdapters }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const selection = selectionFromParams(searchParams);
  const adapter = selection ? adapters[selection.kind] : undefined;
  const requestedTab = searchParams.get('tab');
  const state = adapter ? resolveInspectorTab(requestedTab, adapter) : null;

  useEffect(() => {
    if (!selection || !adapter || adapter.resolved === false || adapter.available !== false) return;
    // Adapter registration follows the workspace render. Defer recovery by one
    // task so a newly selected entity can replace the previous adapter before
    // we decide that its route target was deleted.
    const timeout = window.setTimeout(() => {
      setSearchParams(clearSelectionParams(searchParams), { replace: true });
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [adapter, searchParams, selection, setSearchParams]);

  useEffect(() => {
    if (!adapter || !state?.invalidRequestedTab) return;
    const timeout = window.setTimeout(() => {
      const next = new URLSearchParams(searchParams);
      next.delete('tab');
      setSearchParams(next, { replace: true });
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [adapter, searchParams, setSearchParams, state?.invalidRequestedTab]);

  if (!selection || !adapter || adapter.available === false || adapter.resolved === false) return null;

  const close = () => setSearchParams(clearSelectionParams(searchParams), { replace: true });
  const setTab = (tab: string) => {
    const next = new URLSearchParams(searchParams);
    if (tab === adapter.defaultTab || (!adapter.defaultTab && tab === adapter.tabs?.[0]?.value)) next.delete('tab');
    else next.set('tab', tab);
    setSearchParams(next, { replace: true });
  };

  return adapter.render({ selection, tab: state?.tab, setTab, close });
}

/** Shell-owned registry host. Multiple nested workspace surfaces may contribute
 * adapters (for example Review plus its Proof library), while only one registry
 * interprets and renders the current route selection. */
export function WorkspaceInspectorRegistryProvider({ children }: { children: ReactNode }) {
  const registrations = useRef(new Map<symbol, WorkspaceInspectorAdapters>());
  const [revision, setRevision] = useState(0);
  const register = useCallback((owner: symbol, adapters: WorkspaceInspectorAdapters) => {
    registrations.current.set(owner, adapters);
    setRevision(value => value + 1);
  }, []);
  const unregister = useCallback((owner: symbol) => {
    if (!registrations.current.delete(owner)) return;
    setRevision(value => value + 1);
  }, []);
  const adapters = useMemo(() => {
    const merged: WorkspaceInspectorAdapters = {};
    for (const contribution of registrations.current.values()) Object.assign(merged, contribution);
    return merged;
    // Revision is the durable signal that the registration map changed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision]);
  const value = useMemo(() => ({ register, unregister }), [register, unregister]);

  return (
    <InspectorRegistrationContext.Provider value={value}>
      {children}
      <WorkspaceInspectorRegistry adapters={adapters} />
    </InspectorRegistrationContext.Provider>
  );
}

export function useWorkspaceInspectorAdapters(adapters: WorkspaceInspectorAdapters) {
  const registry = useContext(InspectorRegistrationContext);
  const owner = useRef(Symbol('workspace-inspector-adapters'));
  // Registration is part of layout, not a post-paint side effect. Publishing
  // the new adapter before passive URL recovery runs prevents a just-selected
  // row from being judged against the previous selection's adapter.
  useLayoutEffect(() => {
    if (!registry) return;
    const currentOwner = owner.current;
    registry.register(currentOwner, adapters);
    return () => registry.unregister(currentOwner);
  }, [adapters, registry]);
}
