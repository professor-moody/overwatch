import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Toolbar } from './Toolbar';
import { Breadcrumb } from './Breadcrumb';
import { useWs } from '../../providers/ws-provider';
import { useKeyboardShortcuts, SHORTCUT_HELP } from '../../hooks/useKeyboardShortcuts';
import { parseHash, buildHash } from '../../hooks/useNavigation';
import { OverviewPanel } from '../panels/OverviewPanel';
import { CampaignsPanel } from '../panels/CampaignsPanel';
import { AgentsPanel } from '../panels/AgentsPanel';
import { SessionsPanel } from '../panels/SessionsPanel';
import { ActionsPanel } from '../panels/ActionsPanel';
import { FrontierPanel } from '../panels/FrontierPanel';
import { ActivityPanel } from '../panels/ActivityPanel';
import { EvidencePanel } from '../panels/EvidencePanel';
import { EngagementsPanel } from '../panels/EngagementsPanel';
import { SettingsPanel } from '../panels/SettingsPanel';
import { IdentityPanel } from '../panels/IdentityPanel';
import { AttackPathsPanel } from '../panels/AttackPathsPanel';
import { FindingsPanel } from '../panels/FindingsPanel';
import { CredentialsPanel } from '../panels/CredentialsPanel';
import { SmokePanel } from '../panels/SmokePanel';
import { ErrorBoundary } from '../shared/ErrorBoundary';

export type PanelId =
  | 'overview'
  | 'campaigns'
  | 'agents'
  | 'sessions'
  | 'actions'
  | 'frontier'
  | 'activity'
  | 'evidence'
  | 'identity'
  | 'credentials'
  | 'paths'
  | 'findings'
  | 'engagements'
  | 'smoke'
  | 'settings';

const PANEL_COMPONENTS: Record<PanelId, React.ComponentType> = {
  overview: OverviewPanel,
  campaigns: CampaignsPanel,
  agents: AgentsPanel,
  sessions: SessionsPanel,
  actions: ActionsPanel,
  frontier: FrontierPanel,
  activity: ActivityPanel,
  evidence: EvidencePanel,
  identity: IdentityPanel,
  credentials: CredentialsPanel,
  paths: AttackPathsPanel,
  findings: FindingsPanel,
  engagements: EngagementsPanel,
  smoke: SmokePanel,
  settings: SettingsPanel,
};

export function OperatorLayout() {
  const [activePanel, setActivePanel] = useState<PanelId>('overview');
  const [selectedItem, setSelectedItem] = useState<string | undefined>(undefined);
  const [showHelp, setShowHelp] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Read URL hash on mount and on hash change
  useEffect(() => {
    const target = parseHash(location.hash);
    if (target) {
      setActivePanel(target.panel);
      setSelectedItem(target.item);
    }
  }, [location.hash]);

  // Write hash when panel changes
  const handlePanelChange = useCallback((panel: PanelId) => {
    setActivePanel(panel);
    setSelectedItem(undefined);
    window.history.replaceState(null, '', `/${buildHash({ panel })}`);
  }, []);

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

  const ActiveComponent = PANEL_COMPONENTS[activePanel];
  const { connected } = useWs();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Toolbar */}
      <Toolbar />

      {/* Sidebar Nav */}
      <Sidebar activePanel={activePanel} onPanelChange={handlePanelChange} />

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto pt-12 pl-16">
        {!connected && (
          <div className="mx-6 mt-2 mb-0 px-3 py-1.5 bg-destructive/5 border border-destructive/20 rounded text-xs text-destructive flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-destructive animate-pulse" />
            Disconnected — reconnecting…
          </div>
        )}
        <Breadcrumb panel={activePanel} item={selectedItem} />
        <div className="p-6 max-w-[1400px]">
          <ErrorBoundary fallbackLabel={activePanel}>
            <ActiveComponent />
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
