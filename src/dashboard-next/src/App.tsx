import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { WsProvider } from './providers/ws-provider';
import { OperatorLayout } from './components/layout/OperatorLayout';
import { ToastContainer } from './components/shared/ToastContainer';

const LazyGraphPage = lazy(() =>
  import('./components/graph/GraphPage').then(m => ({ default: m.GraphPage })),
);

function GraphSpinner() {
  return (
    <div className="h-screen flex items-center justify-center bg-background">
      <div className="text-sm text-muted-foreground animate-pulse">Loading Graph Explorer…</div>
    </div>
  );
}

export function App() {
  return (
    <WsProvider>
      <BrowserRouter basename={import.meta.env.BASE_URL}>
        <Routes>
          <Route
            path="/graph"
            element={
              <Suspense fallback={<GraphSpinner />}>
                <LazyGraphPage />
              </Suspense>
            }
          />
          <Route path="/" element={<OperatorLayout />} />
          <Route path="/:panelId" element={<OperatorLayout />} />
          <Route path="*" element={<Navigate to="/agents" replace />} />
        </Routes>
        <ToastContainer />
      </BrowserRouter>
    </WsProvider>
  );
}
