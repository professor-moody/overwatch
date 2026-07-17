import {
  lazy,
  Suspense,
  useState,
  useEffect,
  useCallback,
  type ComponentType,
  type LazyExoticComponent,
} from 'react';
import { useNavigate, useLocation, useParams } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Toolbar } from './Toolbar';
import { Breadcrumb } from './Breadcrumb';
import { useWs } from '../../providers/ws-provider';
import { useKeyboardShortcuts, SHORTCUT_HELP } from '../../hooks/useKeyboardShortcuts';
import { buildPanelPath, isPanelId, parseHash } from '../../hooks/useNavigation';
import { cn } from '../../lib/utils';
import { ErrorBoundary } from '../shared/ErrorBoundary';
import { RecoveryBanner } from '../shared/RecoveryBanner';

export type PanelId =
  | 'overview'
  | 'campaigns'
  | 'agents'
  | 'sessions'
  | 'actions'
  | 'frontier'
  | 'activity'
  | 'analysis'
  | 'evidence'
  | 'identity'
  | 'credentials'
  | 'recon'
  | 'paths'
  | 'findings'
  | 'engagements'
  | 'smoke'
  | 'settings';

const PANEL_COMPONENTS: Record<PanelId, LazyExoticComponent<ComponentType>> = {
  overview: lazy(() => import('../panels/OverviewPanel').then(module => ({ default: module.OverviewPanel }))),
  campaigns: lazy(() => import('../panels/CampaignsPanel').then(module => ({ default: module.CampaignsPanel }))),
  agents: lazy(() => import('../panels/AgentsPanel').then(module => ({ default: module.AgentsPanel }))),
  sessions: lazy(() => import('../panels/SessionsPanel').then(module => ({ default: module.SessionsPanel }))),
  actions: lazy(() => import('../panels/ActionsPanel').then(module => ({ default: module.ActionsPanel }))),
  frontier: lazy(() => import('../panels/FrontierPanel').then(module => ({ default: module.FrontierPanel }))),
  activity: lazy(() => import('../panels/ActivityPanel').then(module => ({ default: module.ActivityPanel }))),
  analysis: lazy(() => import('../panels/AnalysisPanel').then(module => ({ default: module.AnalysisPanel }))),
  evidence: lazy(() => import('../panels/EvidencePanel').then(module => ({ default: module.EvidencePanel }))),
  identity: lazy(() => import('../panels/IdentityPanel').then(module => ({ default: module.IdentityPanel }))),
  credentials: lazy(() => import('../panels/CredentialsPanel').then(module => ({ default: module.CredentialsPanel }))),
  recon: lazy(() => import('../panels/ReconPanel').then(module => ({ default: module.ReconPanel }))),
  paths: lazy(() => import('../panels/AttackPathsPanel').then(module => ({ default: module.AttackPathsPanel }))),
  findings: lazy(() => import('../panels/FindingsPanel').then(module => ({ default: module.FindingsPanel }))),
  engagements: lazy(() => import('../panels/EngagementsPanel').then(module => ({ default: module.EngagementsPanel }))),
  smoke: lazy(() => import('../panels/SmokePanel').then(module => ({ default: module.SmokePanel }))),
  settings: lazy(() => import('../panels/SettingsPanel').then(module => ({ default: module.SettingsPanel }))),
};

function PanelLoading({ panel }: { panel: PanelId }) {
  return (
    <div className="flex min-h-48 items-center justify-center text-sm text-muted-foreground" role="status">
      <span className="animate-pulse">Loading {panel}…</span>
    </div>
  );
}

export function OperatorLayout() {
  const { panelId } = useParams();
  // The Operator Console is the operator's home: the default landing panel.
  const activePanel: PanelId = isPanelId(panelId) ? panelId : 'agents';
  const [selectedItem, setSelectedItem] = useState<string | undefined>(undefined);
  const [showHelp, setShowHelp] = useState(false);
  const [sidebarExpanded, setSidebarExpanded] = useState(() => {
    if (typeof window === 'undefined') return true;
    return window.localStorage.getItem('overwatch-sidebar-expanded') !== 'false';
  });
  const navigate = useNavigate();
  const location = useLocation();

  // Temporary compatibility shim for old #panel=... deep links.
  useEffect(() => {
    const target = parseHash(location.hash);
    if (target) {
      navigate(buildPanelPath(target), { replace: true });
      return;
    }
    if (!isPanelId(panelId)) {
      navigate('/agents', { replace: true });
      return;
    }
    const params = new URLSearchParams(location.search);
    setSelectedItem(params.get('node') || params.get('item') || params.get('objective') || undefined);
  }, [location.hash, location.search, navigate, panelId]);

  const handlePanelChange = useCallback((panel: PanelId) => {
    setSelectedItem(undefined);
    navigate(buildPanelPath({ panel }));
  }, [navigate]);

  useKeyboardShortcuts({
    onPanelChange: handlePanelChange,
    onNavigateGraph: useCallback(() => navigate('/graph'), [navigate]),
    onNavigateEvidence: useCallback(() => handlePanelChange('evidence'), [handlePanelChange]),
  });

  useEffect(() => {
    const toggle = () => setShowHelp(prev => !prev);
    const close = () => setShowHelp(false);
    document.addEventListener('toggle-shortcut-help', toggle);
    document.addEventListener('close-overlay', close);
    return () => {
      document.removeEventListener('toggle-shortcut-help', toggle);
      document.removeEventListener('close-overlay', close);
    };
  }, []);

  useEffect(() => {
    window.localStorage.setItem('overwatch-sidebar-expanded', String(sidebarExpanded));
  }, [sidebarExpanded]);

  const ActiveComponent = PANEL_COMPONENTS[activePanel];
  const { connected } = useWs();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Toolbar */}
      <Toolbar />

      {/* Sidebar Nav */}
      <Sidebar
        activePanel={activePanel}
        onPanelChange={handlePanelChange}
        expanded={sidebarExpanded}
        onExpandedChange={setSidebarExpanded}
      />

      {/* Main Content */}
      <main className={cn(
        'flex-1 overflow-y-auto pt-12 transition-[padding-left] duration-200',
        sidebarExpanded ? 'pl-16 md:pl-56' : 'pl-16',
      )}>
        <RecoveryBanner />
        {!connected && (
          <div className="mx-6 mt-2 mb-0 px-3 py-1.5 bg-destructive/5 border border-destructive/20 rounded text-xs text-destructive flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-destructive animate-pulse" />
            Disconnected — reconnecting…
          </div>
        )}
        {activePanel !== 'agents' && (
          <div className="px-6 pt-2">
            <button
              onClick={() => handlePanelChange('agents')}
              className="inline-flex items-center gap-1.5 rounded border border-accent/30 bg-accent-dim/40 px-2 py-1 text-xs text-accent hover:bg-accent/20"
              title="Return to the Operator Console (press c)"
            >
              ← Back to Console
            </button>
          </div>
        )}
        <Breadcrumb panel={activePanel} item={selectedItem} />
        <div className="p-6 max-w-[1400px]">
          <ErrorBoundary fallbackLabel={activePanel}>
            <Suspense fallback={<PanelLoading panel={activePanel} />}>
              <ActiveComponent />
            </Suspense>
          </ErrorBoundary>
        </div>
      </main>

      {/* Shortcut Help Overlay */}
      {showHelp && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowHelp(false)}>
          <div className="bg-surface border border-border rounded-lg p-6 max-w-xs" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-3">Keyboard Shortcuts</h3>
            <div className="space-y-1.5">
              {SHORTCUT_HELP.map(s => (
                <div key={s.key} className="flex items-center gap-3 text-xs">
                  <kbd className="px-1.5 py-0.5 rounded bg-elevated border border-border font-mono text-accent min-w-[2rem] text-center">{s.key}</kbd>
                  <span className="text-muted-foreground">{s.desc}</span>
                </div>
              ))}
            </div>
            <p className="text-[10px] text-muted mt-3">Press ? or Esc to close</p>
          </div>
        </div>
      )}
    </div>
  );
}
