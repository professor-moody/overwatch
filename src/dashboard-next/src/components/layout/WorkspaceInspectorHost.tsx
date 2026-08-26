import { createContext, useContext, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

const WorkspaceInspectorHostContext = createContext<HTMLElement | null>(null);

export function WorkspaceInspectorHostProvider({
  host,
  children,
}: {
  host: HTMLElement | null;
  children: ReactNode;
}) {
  return (
    <WorkspaceInspectorHostContext.Provider value={host}>
      {children}
    </WorkspaceInspectorHostContext.Provider>
  );
}

/**
 * Routes every workspace inspector through the shell-owned slot. The inline
 * fallback keeps isolated component tests and compatibility renders useful
 * before a shell host is mounted.
 */
export function WorkspaceInspectorPortal({ children }: { children: ReactNode }) {
  const host = useContext(WorkspaceInspectorHostContext);
  return host ? createPortal(children, host) : children;
}
