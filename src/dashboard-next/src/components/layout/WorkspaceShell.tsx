import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Crosshair,
  KeyRound,
  Maximize2,
  Minimize2,
  Network,
  Search,
  Settings,
  ShieldAlert,
  Terminal,
  X,
} from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useWs } from '../../providers/ws-provider';
import { useEngagementStore } from '../../stores/engagement-store';
import { useDashboardUiStore } from '../../stores/dashboard-ui-store';
import { cn } from '../../lib/utils';
import type { CommandItem, PanelCommandDef } from '../../lib/command-palette';
import type { FindingDto } from '../../lib/api';
import * as api from '../../lib/api';
import {
  clearSelectionParams,
  buildWorkspacePath,
  drawerFromParams,
  selectionFromParams,
  setDrawerParams,
  transitionDrawer,
  type DrawerKind,
  type WorkspaceId,
} from '../../lib/workspace-navigation';
import { CommandPalette } from './CommandPalette';
import { WorkspaceInspectorHostProvider } from './WorkspaceInspectorHost';
import { WorkspaceInspectorRegistryProvider } from './WorkspaceInspectorRegistry';
import { TapeToggle } from './TapeToggle';
import { RecoveryBanner } from '../shared/RecoveryBanner';
import { ErrorBoundary } from '../shared/ErrorBoundary';

const OperateWorkspace = lazy(() => import('../workspaces/OperateWorkspace').then(module => ({ default: module.OperateWorkspace })));
const InvestigateWorkspace = lazy(() => import('../workspaces/InvestigateWorkspace').then(module => ({ default: module.InvestigateWorkspace })));
const ReviewWorkspace = lazy(() => import('../workspaces/ReviewWorkspace').then(module => ({ default: module.ReviewWorkspace })));
const ManageWorkspace = lazy(() => import('../workspaces/ManageWorkspace').then(module => ({ default: module.ManageWorkspace })));

const ActivityDrawer = lazy(() => import('../drawer/ActivityDrawer').then(module => ({ default: module.ActivityDrawer })));
const SessionsDrawer = lazy(() => import('../drawer/SessionsDrawer').then(module => ({ default: module.SessionsDrawer })));
const RunsDrawer = lazy(() => import('../drawer/RunsDrawer').then(module => ({ default: module.RunsDrawer })));

type DrawerMode = 'compact' | 'focus';

const WORKSPACES: Array<{
  id: WorkspaceId;
  label: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'operate', label: 'Operate', description: 'Decide, dispatch, and steer', icon: Crosshair },
  { id: 'investigate', label: 'Investigate', description: 'Understand the environment', icon: Network },
  { id: 'review', label: 'Review', description: 'Close proof gaps and report', icon: ShieldAlert },
  { id: 'manage', label: 'Manage', description: 'Configure and diagnose', icon: Settings },
];

const PALETTE_NAV: PanelCommandDef[] = WORKSPACES.map(workspace => ({
  path: buildWorkspacePath({ workspace: workspace.id }),
  label: workspace.label,
  group: 'Workspace',
}));

function WorkspaceLoading() {
  return (
    <div className="flex min-h-64 items-center justify-center text-xs text-muted-foreground" role="status">
      <span className="workspace-pulse">Loading workspace…</span>
    </div>
  );
}

export function WorkspaceShell({ workspace }: { workspace: WorkspaceId }) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { connected } = useWs();
  const engagement = useEngagementStore(state => state.engagement);
  const accessLevel = useEngagementStore(state => state.accessLevel);
  const graph = useEngagementStore(state => state.graph);
  const graphSummary = useEngagementStore(state => state.graphSummary);
  const agents = useEngagementStore(state => state.agents);
  const campaigns = useEngagementStore(state => state.campaigns);
  const objectives = useEngagementStore(state => state.objectives);
  const pendingActions = useEngagementStore(state => state.pendingActions);
  const opsec = useEngagementStore(state => state.opsecBudget);
  const recovery = useEngagementStore(state => state.persistenceRecovery);
  const initialized = useEngagementStore(state => state.initialized);
  const stateRevision = useEngagementStore(state => state.stateRevision);
  const paletteOpen = useDashboardUiStore(state => state.commandPaletteOpen);
  const setPaletteOpen = useDashboardUiStore(state => state.setCommandPaletteOpen);
  const launcherOpen = useDashboardUiStore(state => state.startWorkOpen);
  const setLauncherOpen = useDashboardUiStore(state => state.setStartWorkOpen);
  const drawer = drawerFromParams(searchParams);
  const [drawerMode, setDrawerMode] = useState<DrawerMode>('compact');
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [inspectorHost, setInspectorHost] = useState<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    void api.getFindings()
      .then(result => { if (!cancelled) setFindings(result.findings || []); })
      .catch(() => { /* the palette remains useful without findings */ });
    return () => { cancelled = true; };
  }, [stateRevision]);

  useEffect(() => {
    if (!drawer) setDrawerMode('compact');
  }, [drawer]);

  // Global escape ordering: launcher → palette → overlay inspector → focused
  // drawer returns to compact → drawer closes.
  // Docked inspectors stay as persistent context at 1280px and above.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.tagName === 'SELECT' || target?.isContentEditable;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        if (typing && !paletteOpen) return;
        event.preventDefault();
        setPaletteOpen(!paletteOpen);
        return;
      }
      if (event.key !== 'Escape') return;
      // Read canonical route state at the keystroke rather than from the last
      // React render. Rapid sequential Escapes can otherwise observe a stale
      // selection after its inspector has already unmounted and require a
      // redundant third keypress before the drawer closes.
      const currentParams = new URLSearchParams(window.location.search);
      const currentSelection = selectionFromParams(currentParams);
      const currentDrawer = drawerFromParams(currentParams);
      if (launcherOpen) {
        event.preventDefault();
        setLauncherOpen(false);
      } else if (paletteOpen) {
        event.preventDefault();
        setPaletteOpen(false);
      } else if (currentSelection && window.innerWidth < 1280) {
        event.preventDefault();
        setSearchParams(clearSelectionParams(currentParams), { replace: true });
      } else if (currentDrawer && drawerMode === 'focus') {
        event.preventDefault();
        setDrawerMode('compact');
      } else if (currentDrawer) {
        event.preventDefault();
        setSearchParams(setDrawerParams(currentParams, null), { replace: true });
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawerMode, launcherOpen, paletteOpen, setLauncherOpen, setPaletteOpen, setSearchParams]);

  const paletteItems = useMemo<CommandItem[]>(() => {
    const items: CommandItem[] = WORKSPACES.map(item => ({
      id: `workspace:${item.id}`,
      kind: 'workspace',
      label: item.label,
      hint: item.description,
      path: `/${item.id}`,
    }));
    for (const agent of agents) {
      const id = agent.task_id ?? agent.id;
      items.push({
        id: `agent:${id}`,
        kind: 'agent',
        label: agent.agent_label || agent.agent_id || 'Agent',
        hint: `${agent.status} · ${agent.archetype || agent.role || 'agent'}`,
        taskId: id,
        selectionKind: 'agent',
        selectionId: id,
        path: buildWorkspacePath({ workspace: 'operate', view: agent.status === 'completed' ? 'history' : 'active', selection: { kind: 'agent', id } }),
      });
    }
    for (const node of graph.nodes) {
      const credential = node.type === 'credential';
      items.push({
        id: `${credential ? 'credential' : 'asset'}:${node.id}`,
        kind: credential ? 'credential' : 'asset',
        label: String(node.label || node.id),
        hint: credential ? 'Credential' : node.type,
        selectionKind: credential ? 'credential' : 'node',
        selectionId: node.id,
        path: buildWorkspacePath({
          workspace: 'investigate',
          lens: credential ? 'credentials' : 'topology',
          selection: { kind: credential ? 'credential' : 'node', id: node.id },
          context: credential ? undefined : { node: node.id },
        }),
      });
    }
    for (const campaign of campaigns) {
      items.push({
        id: `campaign:${campaign.id}`,
        kind: 'campaign',
        label: campaign.name || campaign.id,
        hint: campaign.status || 'campaign',
        selectionKind: 'campaign',
        selectionId: campaign.id,
        path: buildWorkspacePath({ workspace: 'operate', view: 'campaigns', selection: { kind: 'campaign', id: campaign.id } }),
      });
    }
    for (const finding of findings) {
      items.push({
        id: `finding:${finding.id}`,
        kind: 'finding',
        label: finding.title || finding.id,
        hint: `${finding.severity} · finding`,
        selectionKind: 'finding',
        selectionId: finding.id,
        path: buildWorkspacePath({ workspace: 'review', view: 'readiness', selection: { kind: 'finding', id: finding.id } }),
      });
    }
    for (const objective of objectives) {
      items.push({
        id: `path:${objective.id}`,
        kind: 'path',
        label: objective.description || objective.id,
        hint: `${objective.achieved ? 'achieved' : 'open'} objective path`,
        selectionKind: 'path',
        selectionId: objective.id,
        path: buildWorkspacePath({ workspace: 'investigate', lens: 'paths', context: { objective: objective.id } }),
      });
    }
    return items;
  }, [agents, campaigns, findings, graph.nodes, objectives]);

  const choosePaletteItem = useCallback((item: CommandItem) => {
    if (item.path) navigate(item.path);
    else if (item.taskId) navigate(buildWorkspacePath({ workspace: 'operate', view: 'active', selection: { kind: 'agent', id: item.taskId } }));
  }, [navigate]);

  const Workspace = workspace === 'operate'
    ? OperateWorkspace
    : workspace === 'investigate'
      ? InvestigateWorkspace
      : workspace === 'review'
        ? ReviewWorkspace
        : ManageWorkspace;

  const opsecPct = opsec?.max_noise
    ? Math.max(0, Math.min(100, Math.round((opsec.noise_budget_remaining / opsec.max_noise) * 100)))
    : null;
  const recoveryWarning = recovery && (
    recovery.status === 'critical'
    || recovery.status === 'warning'
    || recovery.config_recovery?.status === 'diverged'
  );

  return (
    <div className="workspace-shell flex h-screen min-w-[1024px] overflow-hidden bg-background text-[13px] text-foreground">
      <aside className="flex w-[176px] flex-shrink-0 flex-col border-r border-border-subtle bg-surface/75 xl:w-[208px]">
        <button
          type="button"
          className="flex h-14 items-center gap-2.5 border-b border-border-subtle px-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
          onClick={() => navigate(buildWorkspacePath({ workspace: 'operate' }))}
          title="Open Operate"
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-md border border-accent/30 bg-accent/10 text-[11px] font-black text-accent">OW</span>
          <span className="min-w-0">
            <span className="block text-[11px] font-semibold uppercase tracking-[0.16em] text-foreground">Overwatch</span>
            <span className="block truncate text-[10px] text-muted-foreground">Operator workspace</span>
          </span>
        </button>

        <nav className="flex-1 px-2 py-3" aria-label="Primary workspaces">
          <div className="space-y-1">
            {WORKSPACES.map(item => {
              const Icon = item.icon;
              const active = item.id === workspace;
              const badge = item.id === 'operate'
                ? pendingActions.length
                : item.id === 'investigate'
                  ? graph.nodes.length
                  : item.id === 'review'
                    ? findings.length
                    : recoveryWarning ? 1 : 0;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigate(buildWorkspacePath({ workspace: item.id }))}
                  aria-current={active ? 'page' : undefined}
                  className={cn(
                    'group relative flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70',
                    active ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover/55 hover:text-foreground',
                  )}
                >
                  {active && <span className="absolute inset-y-2 left-0 w-0.5 rounded-r bg-accent" />}
                  <Icon className={cn('h-4 w-4 flex-shrink-0', active && 'text-accent')} />
                  <span className="min-w-0 flex-1">
                    <span className="block text-xs font-medium">{item.label}</span>
                    <span className="hidden truncate text-[9px] text-muted-foreground xl:block">{item.description}</span>
                  </span>
                  {badge > 0 && (
                    <span className={cn(
                      'min-w-4 rounded-full px-1 py-0.5 text-center text-[9px] tabular-nums',
                      active ? 'bg-accent/15 text-accent' : 'bg-background/70 text-muted-foreground',
                    )}>
                      {badge > 99 ? '99+' : badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </nav>

        <div className="border-t border-border-subtle p-3">
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex h-8 w-full items-center gap-2 rounded-md border border-border-subtle bg-background/50 px-2.5 text-[11px] text-muted-foreground transition-colors hover:border-border hover:text-foreground"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="flex-1 text-left">Find anything</span>
            <kbd className="text-[9px] text-muted">⌘K</kbd>
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 flex-shrink-0 items-center gap-3 border-b border-border-subtle bg-background/95 px-4 lg:px-5">
          <button
            type="button"
            onClick={() => navigate(buildWorkspacePath({ workspace: 'manage', section: 'engagement' }))}
            className="min-w-0 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70"
            title="Open engagement settings"
          >
            <div className="truncate text-xs font-medium text-foreground">{engagement?.name || (initialized ? 'No active engagement' : 'Loading engagement')}</div>
            <div className="truncate text-[10px] text-muted-foreground">{engagement?.profile || 'operator'} · {accessLevel} access</div>
          </button>

          <div className="h-5 w-px bg-border-subtle" />

          <StatusSignal connected={connected} />
          {opsec && (
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground" title={opsec.warning || `${opsec.noise_budget_remaining}/${opsec.max_noise} noise budget remaining`}>
              <span className={cn('h-1.5 w-1.5 rounded-full', opsecPct != null && opsecPct < 20 ? 'bg-destructive' : opsecPct != null && opsecPct < 45 ? 'bg-warning' : 'bg-success')} />
              <span>OPSEC {opsec.recommended_approach}</span>
              {opsecPct != null && <span className="tabular-nums text-foreground">{opsecPct}%</span>}
            </div>
          )}
          {recoveryWarning && <span className="text-[10px] text-warning">Recovery needs review</span>}

          <div className="flex-1" />
          <div className="hidden items-center gap-3 text-[10px] text-muted-foreground lg:flex">
            <span aria-label="Engagement asset count"><strong data-testid="asset-count" className="font-medium text-foreground">{graphSummary?.total_nodes ?? graph.nodes.length}</strong> assets</span>
            <span aria-label="Running agent count"><strong data-testid="active-agent-count" className="font-medium text-foreground">{agents.filter(agent => agent.status === 'running').length}</strong> active</span>
          </div>
          <TapeToggle />
        </header>

        <RecoveryBanner />
        {opsec && (opsec.warning || opsec.defensive_signals.length > 0 || (opsecPct != null && opsecPct <= 20)) && (
          <div
            role={opsec.defensive_signals.length > 0 || opsecPct === 0 ? 'alert' : 'status'}
            className={cn(
              'flex min-h-8 flex-shrink-0 items-center gap-2 border-b px-5 py-1.5 text-[11px]',
              opsec.defensive_signals.length > 0 || opsecPct === 0
                ? 'border-destructive/20 bg-destructive/5 text-destructive'
                : 'border-warning/20 bg-warning/5 text-warning',
            )}
          >
            <ShieldAlert className="h-3.5 w-3.5 flex-shrink-0" />
            <span className="min-w-0 flex-1 truncate">{opsec.warning || (opsec.defensive_signals.length > 0 ? `${opsec.defensive_signals.length} defensive signal${opsec.defensive_signals.length === 1 ? '' : 's'} detected` : `OPSEC noise headroom is down to ${opsecPct}%`)}</span>
            <button type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'manage', section: 'settings' }))} className="flex-shrink-0 font-medium underline-offset-2 hover:underline">Review OPSEC</button>
          </div>
        )}
        {!connected && (
          <div className="flex h-8 flex-shrink-0 items-center gap-2 border-b border-destructive/20 bg-destructive/5 px-5 text-[11px] text-destructive">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-destructive" />
            Disconnected — showing the last synchronized engagement state while Overwatch reconnects.
          </div>
        )}

        <WorkspaceInspectorHostProvider host={inspectorHost}>
          <WorkspaceInspectorRegistryProvider key={workspace}>
            <main className="relative flex min-h-0 flex-1 flex-col overflow-hidden">
              <div className="relative flex min-h-0 flex-1 overflow-hidden">
                <div className="flex min-w-0 flex-1">
                  <ErrorBoundary fallbackLabel={workspace}>
                    <Suspense fallback={<WorkspaceLoading />}>
                      <Workspace />
                    </Suspense>
                  </ErrorBoundary>
                </div>
                <div ref={setInspectorHost} className="contents" data-testid="workspace-inspector-host" />
              </div>
              <WorkspaceDrawer
                drawer={drawer}
                mode={drawerMode}
                onModeChange={setDrawerMode}
                onChange={(kind) => {
                  if (!kind) {
                    setSearchParams(setDrawerParams(searchParams, null), { replace: true });
                    return;
                  }
                  setSearchParams(setDrawerParams(searchParams, transitionDrawer(drawer, kind)), { replace: true });
                }}
                onSelect={(item) => {
                  if (!drawer) return;
                  setSearchParams(setDrawerParams(searchParams, { kind: drawer.kind, item: item || undefined }), { replace: true });
                }}
                onOpenItem={(kind, item) => {
                  setSearchParams(setDrawerParams(searchParams, { kind, item }), { replace: true });
                }}
              />
            </main>
          </WorkspaceInspectorRegistryProvider>
        </WorkspaceInspectorHostProvider>
      </div>

      <CommandPalette
        open={paletteOpen}
        panels={PALETTE_NAV}
        agents={agents}
        items={paletteItems}
        onClose={() => setPaletteOpen(false)}
        onSelect={choosePaletteItem}
      />
    </div>
  );
}

function StatusSignal({ connected }: { connected: boolean }) {
  return (
    <div className={cn('flex items-center gap-1.5 text-[10px]', connected ? 'text-success' : 'text-destructive')}>
      <span className={cn('h-1.5 w-1.5 rounded-full', connected ? 'bg-success' : 'bg-destructive')} />
      {connected ? 'Live' : 'Offline'}
    </div>
  );
}

function WorkspaceDrawer({
  drawer,
  mode,
  onModeChange,
  onChange,
  onSelect,
  onOpenItem,
}: {
  drawer: { kind: DrawerKind; item?: string } | null;
  mode: DrawerMode;
  onModeChange: (mode: DrawerMode) => void;
  onChange: (drawer: DrawerKind | null) => void;
  onSelect: (item: string | null) => void;
  onOpenItem: (drawer: DrawerKind, item: string) => void;
}) {
  const tabs: Array<{ id: DrawerKind; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: 'activity', label: 'Activity', icon: Activity },
    { id: 'sessions', label: 'Sessions', icon: Terminal },
    { id: 'run', label: 'Runs', icon: KeyRound },
  ];
  const activeKind = drawer?.kind ?? null;

  return (
    <section className={cn(
      'z-30 flex flex-shrink-0 flex-col border-t border-border-subtle bg-surface transition-[height] duration-150 motion-reduce:transition-none',
      !drawer ? 'h-9' : mode === 'focus' ? 'h-[clamp(480px,72vh,760px)]' : 'h-[clamp(280px,38vh,480px)]',
    )} aria-label="Operator drawer" data-drawer-mode={mode}>
      <div className="flex h-9 flex-shrink-0 items-center gap-1 px-2">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onChange(activeKind === tab.id ? null : tab.id)}
              className={cn(
                'flex h-7 items-center gap-1.5 rounded px-2.5 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70',
                activeKind === tab.id ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover/50 hover:text-foreground',
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          );
        })}
        <span className="ml-auto pr-2 text-[9px] text-muted">{mode === 'focus' ? 'Esc compacts' : 'Esc closes'}</span>
        {drawer && (
          <button type="button" onClick={() => onModeChange(mode === 'focus' ? 'compact' : 'focus')} className="flex h-7 items-center gap-1 rounded px-2 text-[9px] text-muted-foreground hover:bg-hover hover:text-foreground" aria-label={mode === 'focus' ? 'Compact drawer' : 'Focus drawer'} title={mode === 'focus' ? 'Compact drawer' : 'Focus drawer'}>
            {mode === 'focus' ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
            {mode === 'focus' ? 'Compact' : 'Focus'}
          </button>
        )}
        {drawer && (
          <button type="button" onClick={() => onChange(null)} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground" aria-label="Close drawer">
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      {drawer && (
        <div className="workspace-drawer-content min-h-0 flex-1 overflow-hidden border-t border-border-subtle">
          <ErrorBoundary fallbackLabel={`${drawer.kind} drawer`}>
            <Suspense fallback={<WorkspaceLoading />}>
              {drawer.kind === 'activity' && (
                <ActivityDrawer
                  mode={mode}
                  selectedItem={drawer.item}
                  onSelect={onSelect}
                  onOpenRun={(actionId) => onOpenItem('run', actionId)}
                />
              )}
              {drawer.kind === 'sessions' && (
                <SessionsDrawer selectedItem={drawer.item} onSelect={onSelect} onRequestFocus={() => onModeChange('focus')} />
              )}
              {drawer.kind === 'run' && (
                <RunsDrawer
                  mode={mode}
                  selectedItem={drawer.item}
                  onSelect={onSelect}
                  onOpenActivity={(actionId) => onOpenItem('activity', actionId)}
                />
              )}
            </Suspense>
          </ErrorBoundary>
        </div>
      )}
    </section>
  );
}
