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
  ScrollText,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import type { PanelId } from './OperatorLayout';

interface SidebarProps {
  activePanel: PanelId;
  onPanelChange: (panel: PanelId) => void;
  expanded: boolean;
  onExpandedChange: (expanded: boolean) => void;
}

type SidebarItem = {
  id?: PanelId;
  path?: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
};

// Console-first IA (Phase 4a): the Operator Console is the home + the top group;
// everything the operator ACTS with sits in CONSOLE, investigation destinations
// in INVESTIGATE, engagement/admin in MANAGE. (Approvals stays reachable here as
// its own item until Phase 4b folds approve/deny into the console and demotes it.)
const NAV_GROUPS: { label: string; items: SidebarItem[] }[] = [
  {
    label: 'Console',
    items: [
      { id: 'agents', label: 'Console', icon: User },
      { id: 'frontier', label: 'Frontier', icon: Crosshair },
      { id: 'actions', label: 'Approvals', icon: Clock },
      { id: 'campaigns', label: 'Campaigns', icon: Bookmark },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { path: '/graph', label: 'Graph', icon: Network },
      { id: 'findings', label: 'Findings', icon: ShieldAlert },
      { id: 'paths', label: 'Attack Paths', icon: Route },
      { id: 'evidence', label: 'Evidence', icon: FileText },
      { id: 'analysis', label: 'Analysis', icon: ScrollText },
      { id: 'identity', label: 'Identity', icon: KeyRound },
      { id: 'credentials', label: 'Credentials', icon: Key },
      { id: 'activity', label: 'Activity', icon: Activity },
      { id: 'overview', label: 'Overview', icon: LayoutGrid },
    ],
  },
  {
    label: 'Manage',
    items: [
      { id: 'sessions', label: 'Sessions', icon: Terminal },
      { id: 'engagements', label: 'Engagements', icon: Briefcase },
      { id: 'settings', label: 'Settings', icon: Settings },
      { id: 'smoke', label: 'Smoke', icon: FlaskConical },
    ],
  },
];

export function Sidebar({ activePanel, onPanelChange, expanded, onExpandedChange }: SidebarProps) {
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
    <nav
      className={cn(
        'fixed left-0 top-12 bottom-0 bg-surface border-r border-border flex flex-col py-2 z-40 transition-[width] duration-200',
        expanded ? 'w-16 md:w-56' : 'w-16',
      )}
    >
      <div className="flex flex-col gap-2 flex-1 px-2">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="flex flex-col gap-1">
            <div className={cn(
              'h-4 uppercase text-muted',
              expanded
                ? 'hidden md:block px-2 text-[10px] tracking-[0.16em]'
                : 'text-center text-[8px] tracking-[0.12em]',
            )}>
              {expanded ? group.label : group.label.slice(0, 3)}
            </div>
            {group.items.map((item) => {
              const active = item.id ? activePanel === item.id : false;
              return (
                <SidebarButton
                  key={item.id || item.path}
                  item={item}
                  active={active}
                  expanded={expanded}
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
      <button
        className={cn(
          'mx-2 mt-2 h-9 rounded-md text-muted-foreground hover:text-foreground hover:bg-hover transition-colors flex items-center justify-center',
          expanded && 'md:justify-start md:gap-3 md:px-3',
        )}
        onClick={() => onExpandedChange(!expanded)}
        title={expanded ? 'Collapse navigation' : 'Expand navigation'}
      >
        {expanded ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />}
        {expanded && <span className="hidden md:inline text-xs">Collapse</span>}
      </button>
    </nav>
  );
}

function SidebarButton({
  item,
  active,
  expanded,
  badge,
  onClick,
}: {
  item: SidebarItem;
  active: boolean;
  expanded: boolean;
  badge?: number;
  onClick: () => void;
}) {
  const Icon = item.icon;
  return (
    <button
      className={cn(
        'group h-9 flex items-center rounded-md text-muted-foreground transition-colors relative',
        'hover:text-foreground hover:bg-hover',
        expanded ? 'w-10 justify-center md:w-full md:justify-start md:gap-3 md:px-3' : 'w-10 justify-center',
        active && 'text-accent bg-accent-dim',
      )}
      onClick={onClick}
      title={item.label}
    >
      <Icon className="w-4 h-4" />
      {active && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r bg-accent" />}
      {expanded && <span className="hidden md:inline truncate text-xs font-medium">{item.label}</span>}
      <span className={cn(
        'pointer-events-none absolute left-12 top-1/2 -translate-y-1/2 whitespace-nowrap rounded bg-elevated border border-border px-2 py-1 text-[11px] text-foreground opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100',
        expanded && 'md:hidden',
      )}>
        {item.label}
      </span>
      {badge != null && badge > 0 && (
        <span className={cn(
          'absolute min-w-[14px] h-[14px] flex items-center justify-center rounded-full bg-accent text-background text-[8px] font-bold leading-none px-0.5',
          expanded ? '-top-0.5 -right-0.5 md:top-1/2 md:right-2 md:-translate-y-1/2' : '-top-0.5 -right-0.5',
        )}>
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </button>
  );
}
