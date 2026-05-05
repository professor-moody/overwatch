import { Link } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useWs } from '../../providers/ws-provider';
import { cn } from '../../lib/utils';
import { TapeToggle } from './TapeToggle';

export function Toolbar() {
  const engagement = useEngagementStore((s) => s.engagement);
  const graphSummary = useEngagementStore((s) => s.graphSummary);
  const accessLevel = useEngagementStore((s) => s.accessLevel);
  const { connected } = useWs();

  return (
    <header className="fixed top-0 left-0 right-0 h-12 bg-surface border-b border-border flex items-center px-4 gap-4 z-50">
      <span className="text-accent font-semibold text-sm tracking-wide">◆ OVERWATCH</span>
      <h1 className="text-sm font-medium text-foreground truncate">
        {engagement?.name || '—'}
      </h1>

      {/* Connection status */}
      <div
        className={cn(
          'flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full',
          connected
            ? 'bg-success/10 text-success'
            : 'bg-destructive/10 text-destructive',
        )}
      >
        <span className={cn(
          'w-1.5 h-1.5 rounded-full',
          connected ? 'bg-success' : 'bg-destructive',
        )} />
        <span>{connected ? 'Live' : 'Disconnected'}</span>
      </div>

      <div className="flex-1" />

      {/* Tape recorder */}
      <TapeToggle />

      {/* Stats */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <div className="flex flex-col items-center">
          <span className="text-foreground font-medium tabular-nums">
            {graphSummary?.total_nodes ?? 0}
          </span>
          <span>Nodes</span>
        </div>
        <div className="flex flex-col items-center">
          <span className="text-foreground font-medium tabular-nums">
            {graphSummary?.total_edges ?? 0}
          </span>
          <span>Edges</span>
        </div>
        <div className="flex flex-col items-center">
          <span className="text-foreground font-medium tabular-nums">
            {accessLevel}
          </span>
          <span>Access</span>
        </div>
      </div>

      {/* Graph link */}
      <Link
        to="/graph"
        className="text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
      >
        Graph →
      </Link>
    </header>
  );
}
