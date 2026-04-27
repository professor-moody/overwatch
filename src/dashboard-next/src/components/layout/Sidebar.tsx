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
} from 'lucide-react';
import { cn } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import type { PanelId } from './OperatorLayout';

interface SidebarProps {
  activePanel: PanelId;
  onPanelChange: (panel: PanelId) => void;
}

const NAV_ITEMS: { id: PanelId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'engagements', label: 'Engagements', icon: Briefcase },
  { id: 'campaigns', label: 'Campaigns', icon: Bookmark },
  { id: 'agents', label: 'Agents', icon: User },
  { id: 'sessions', label: 'Sessions', icon: Terminal },
  { id: 'actions', label: 'Actions', icon: Clock },
  { id: 'frontier', label: 'Frontier', icon: Crosshair },
  { id: 'activity', label: 'Activity', icon: Activity },
  { id: 'evidence', label: 'Evidence', icon: FileText },
];

const BOTTOM_ITEMS: { id: PanelId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'settings', label: 'Settings', icon: Settings },
];

export function Sidebar({ activePanel, onPanelChange }: SidebarProps) {
  const runningAgents = useEngagementStore((s) => s.agents.filter(a => a.status === 'running').length);
  const pendingActions = useEngagementStore((s) => s.pendingActions.length);
  const frontierCount = useEngagementStore((s) => s.frontier.length);

  const badges: Partial<Record<PanelId, number>> = {
    agents: runningAgents,
    actions: pendingActions,
    frontier: frontierCount,
  };

  return (
    <nav className="fixed left-0 top-12 bottom-0 w-16 bg-surface border-r border-border flex flex-col items-center py-2 z-40">
      <div className="flex flex-col gap-1 flex-1">
        {NAV_ITEMS.map((item) => (
          <SidebarButton
            key={item.id}
            item={item}
            active={activePanel === item.id}
            badge={badges[item.id] || 0}
            onClick={() => onPanelChange(item.id)}
          />
        ))}
      </div>
      <div className="flex flex-col gap-1 mb-2">
        {BOTTOM_ITEMS.map((item) => (
          <SidebarButton
            key={item.id}
            item={item}
            active={activePanel === item.id}
            onClick={() => onPanelChange(item.id)}
          />
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
  item: { id: string; label: string; icon: React.ComponentType<{ className?: string }> };
  active: boolean;
  badge?: number;
  onClick: () => void;
}) {
  const Icon = item.icon;
  return (
    <button
      className={cn(
        'w-12 h-12 flex flex-col items-center justify-center rounded-md text-muted-foreground transition-colors relative',
        'hover:text-foreground hover:bg-hover',
        active && 'text-accent bg-accent-dim',
      )}
      onClick={onClick}
      title={item.label}
    >
      <Icon className="w-4 h-4" />
      <span className="text-[9px] mt-0.5 leading-none">{item.label}</span>
      {badge != null && badge > 0 && (
        <span className="absolute top-1 right-1 min-w-[14px] h-[14px] flex items-center justify-center rounded-full bg-accent text-background text-[8px] font-bold leading-none px-0.5">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </button>
  );
}
