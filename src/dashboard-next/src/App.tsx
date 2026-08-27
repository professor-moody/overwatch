import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router';
import { WsProvider } from './providers/ws-provider';
import { WorkspaceShell } from './components/layout/WorkspaceShell';
import { ToastContainer } from './components/shared/ToastContainer';
import { buildLegacyPanelPath, parseLegacyHash } from './lib/legacy-navigation';
import { buildWorkspacePath, isLegacyDashboardPath, isWorkspaceId, legacyPathToWorkspacePath } from './lib/workspace-navigation';

function DashboardRoute() {
  const location = useLocation();
  const segment = location.pathname.replace(/^\//, '').split('/')[0] || undefined;
  const legacyHash = parseLegacyHash(location.hash);
  if (legacyHash) {
    const oldPath = buildLegacyPanelPath(legacyHash);
    const parsed = new URL(oldPath, 'http://overwatch.local');
    return <Navigate to={legacyPathToWorkspacePath(parsed.pathname, parsed.searchParams)} replace />;
  }
  if (!segment) return <Navigate to={`/operate${location.search}${location.hash}`} replace />;
  if (isWorkspaceId(segment)) return <WorkspaceShell workspace={segment} />;
  if (isLegacyDashboardPath(segment)) {
    return <Navigate to={`${legacyPathToWorkspacePath(segment, new URLSearchParams(location.search))}${location.hash}`} replace />;
  }
  return <Navigate to={buildWorkspacePath({ workspace: 'operate' })} replace />;
}

export function App() {
  return (
    <WsProvider>
      <BrowserRouter basename={import.meta.env.BASE_URL}>
        <Routes>
          <Route path="*" element={<DashboardRoute />} />
        </Routes>
        <ToastContainer />
      </BrowserRouter>
    </WsProvider>
  );
}
