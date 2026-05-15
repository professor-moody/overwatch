import {
  LayoutGrid,
  Bookmark,
  User,
  Terminal,
  Clock,
  Crosshair,
  Activity,
  FileText,
  Briefcase,
  Settings,
  KeyRound,
  Route,
  ShieldAlert,
  Key,
  FlaskConical,
  Network,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import type { PanelId } from './OperatorLayout';

interface SidebarProps {
  activePanel: PanelId;
  onPanelChange: (panel: PanelId) => void;
}

type SidebarItem = {
  id?: PanelId;
  path?: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
};

const NAV_GROUPS: { label: string; items: SidebarItem[] }[] = [
  {
    label: 'Operate',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutGrid },
      { id: 'frontier', label: 'Frontier', icon: Crosshair },
      { id: 'actions', label: 'Actions', icon: Clock },
      { id: 'agents', label: 'Agents', icon: User },
      { id: 'sessions', label: 'Sessions', icon: Terminal },
      { id: 'campaigns', label: 'Campaigns', icon: Bookmark },
    ],
  },
  {
    label: 'Evidence',
    items: [
      { path: '/graph', label: 'Graph', icon: Network },
      { id: 'evidence', label: 'Evidence', icon: FileText },
      { id: 'identity', label: 'Identity', icon: KeyRound },
      { id: 'credentials', label: 'Credentials', icon: Key },
      { id: 'paths', label: 'Attack Paths', icon: Route },
      { id: 'findings', label: 'Findings', icon: ShieldAlert },
      { id: 'activity', label: 'Activity', icon: Activity },
    ],
  },
  {
    label: 'Admin',
    items: [
      { id: 'engagements', label: 'Engagements', icon: Briefcase },
      { id: 'smoke', label: 'Smoke', icon: FlaskConical },
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

export function Sidebar({ activePanel, onPanelChange }: SidebarProps) {
  const navigate = useNavigate();
  const runningAgents = useEngagementStore((s) => s.agents.filter(a => a.status === 'running').length);
  const pendingActions = useEngagementStore((s) => s.pendingActions.length);
  const frontierCount = useEngagementStore((s) => s.frontier.length);
  const credentialCount = useEngagementStore((s) => s.graph.nodes.filter(n => n.type === 'credential').length);
  const expiredCredCount = useEngagementStore((s) => {
    const now = Date.now();
    return s.graph.nodes.filter(n => {
      if (n.type !== 'credential') return false;
      const exp = n.cred_token_expires_at as string | undefined;
      return exp ? new Date(exp).getTime() < now : false;
    }).length;
  });

  const badges: Partial<Record<PanelId, number>> = {
    agents: runningAgents,
    actions: pendingActions,
    frontier: frontierCount,
    credentials: expiredCredCount > 0 ? expiredCredCount : credentialCount,
  };

  return (
    <nav className="fixed left-0 top-12 bottom-0 w-16 bg-surface border-r border-border flex flex-col items-center py-2 z-40">
      <div className="flex flex-col gap-2 flex-1">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="flex flex-col items-center gap-1">
            <div className="text-[8px] uppercase tracking-[0.12em] text-muted h-3">{group.label.slice(0, 3)}</div>
            {group.items.map((item) => {
              const active = item.id ? activePanel === item.id : false;
              return (
                <SidebarButton
                  key={item.id || item.path}
                  item={item}
                  active={active}
                  badge={item.id ? badges[item.id] || 0 : 0}
                  onClick={() => {
                    if (item.path) navigate(item.path);
                    else if (item.id) onPanelChange(item.id);
                  }}
                />
              );
            })}
          </div>
        ))}
      </div>
    </nav>
  );
}

function SidebarButton({
  item,
  active,
  badge,
  onClick,
}: {
  item: SidebarItem;
  active: boolean;
  badge?: number;
  onClick: () => void;
}) {
  const Icon = item.icon;
  return (
    <button
      className={cn(
        'group w-10 h-9 flex items-center justify-center rounded-md text-muted-foreground transition-colors relative',
        'hover:text-foreground hover:bg-hover',
        active && 'text-accent bg-accent-dim',
      )}
      onClick={onClick}
      title={item.label}
    >
      <Icon className="w-4 h-4" />
      {active && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r bg-accent" />}
      <span className="pointer-events-none absolute left-12 top-1/2 -translate-y-1/2 whitespace-nowrap rounded bg-elevated border border-border px-2 py-1 text-[11px] text-foreground opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
        {item.label}
      </span>
      {badge != null && badge > 0 && (
        <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-[14px] flex items-center justify-center rounded-full bg-accent text-background text-[8px] font-bold leading-none px-0.5">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </button>
  );
}
