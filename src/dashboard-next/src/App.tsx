import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
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
      <BrowserRouter>
        <Routes>
          <Route path="/*" element={<OperatorLayout />} />
          <Route
            path="/graph"
            element={
              <Suspense fallback={<GraphSpinner />}>
                <LazyGraphPage />
              </Suspense>
            }
          />
        </Routes>
        <ToastContainer />
      </BrowserRouter>
    </WsProvider>
  );
}
