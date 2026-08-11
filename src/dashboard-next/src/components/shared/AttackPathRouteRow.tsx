import { ExternalLink, Route } from 'lucide-react';
import type { DisplayAttackPath } from '../../lib/attack-path-workspace';
import { pathHops } from '../../lib/attack-path-workspace';
import { cn } from '../../lib/utils';
import { ActionButton } from './primitives';

interface AttackPathRouteRowProps {
  path: DisplayAttackPath;
  index?: number;
  compact?: boolean;
  onInspect: (path: DisplayAttackPath) => void;
  onFrontier?: (targetNodeId: string) => void;
}

const TIER_DOT_CLASS: Record<string, string> = {
  network: 'bg-blue-300',
  app: 'bg-purple-300',
  cloud: 'bg-orange-300',
  identity: 'bg-emerald-300',
  unknown: 'bg-muted-foreground',
};

const RISK_CLASS = {
  success: 'text-success bg-success/10 border-success/20',
  warning: 'text-warning bg-warning/10 border-warning/20',
  danger: 'text-destructive bg-destructive/10 border-destructive/20',
};

export function AttackPathRouteRow({ path, index, compact = false, onInspect, onFrontier }: AttackPathRouteRowProps) {
  const hops = pathHops(path);

  return (
    <div className={cn(
      'rounded-md border border-border bg-surface transition-colors hover:border-accent/30 hover:bg-hover/25',
      compact ? 'p-3' : 'p-4',
    )}>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-[10px]">
            {index !== undefined && <span className="text-muted-foreground tabular-nums">#{index + 1}</span>}
            <span className="rounded border border-border bg-background/70 px-1.5 py-0.5 text-muted-foreground">
              {path.hopCount} hop{path.hopCount === 1 ? '' : 's'}
            </span>
            <span className={cn('rounded border px-1.5 py-0.5', RISK_CLASS[path.riskTone])}>
              {path.riskLabel}
            </span>
            <span className="rounded border border-border bg-background/70 px-1.5 py-0.5 text-muted-foreground">
              {path.confidenceLabel}
            </span>
            <span className="flex items-center gap-1.5 text-muted-foreground">
              {path.tiers.map(tier => (
                <span key={tier} className="inline-flex items-center gap-1">
                  <span className={cn('h-1.5 w-1.5 rounded-full', TIER_DOT_CLASS[tier] || TIER_DOT_CLASS.unknown)} />
                  {tier}
                </span>
              ))}
            </span>
          </div>

          <div className={cn('mt-2 font-medium text-foreground', compact ? 'text-sm' : 'text-base')}>
            {path.headline}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            {path.reason}
          </div>

          {/* Followable hop narrative: foothold → objective, one explained step per hop. */}
          <div className="mt-3 space-y-0.5 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="text-[9px] uppercase tracking-wide text-muted-foreground">Foothold</span>
              <span className={cn('h-1.5 w-1.5 flex-shrink-0 rounded-full', TIER_DOT_CLASS[path.source.tier] || TIER_DOT_CLASS.unknown)} />
              <span className="min-w-0 truncate font-medium text-foreground">{path.source.label}</span>
            </div>
            {hops.map((hop, idx) => (
              <div key={hop.edge?.id ?? idx} className="flex items-center gap-1.5 pl-2">
                <span className="text-muted-foreground" aria-hidden="true">↳</span>
                <span className="text-muted-foreground">{hop.phrase}</span>
                <span className={cn('h-1.5 w-1.5 flex-shrink-0 rounded-full', TIER_DOT_CLASS[hop.to.tier] || TIER_DOT_CLASS.unknown)} />
                <span className="min-w-0 truncate text-foreground">{hop.to.label}</span>
                {hop.crossesTier && (
                  <span className="flex-shrink-0 rounded border border-accent/30 px-1 text-[9px] text-accent">crosses into {hop.to.tier}</span>
                )}
                {idx === hops.length - 1 && (
                  <span className="flex-shrink-0 rounded border border-warning/30 px-1 text-[9px] uppercase tracking-wide text-warning">objective</span>
                )}
              </div>
            ))}
          </div>

          <details className="mt-3 text-xs">
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
              Raw graph details
            </summary>
            <div className="mt-2 grid gap-1 rounded border border-border bg-background/50 p-2 font-mono text-[10px] text-muted-foreground">
              <div className="break-all">nodes: {path.nodeIds.join(' -> ')}</div>
              <div className="break-all">edges: {path.rawEdgeTypes.length > 0 ? path.rawEdgeTypes.join(' -> ') : 'not provided'}</div>
              <div className="break-all">edge ids: {path.edgeIds.length > 0 ? path.edgeIds.join(' -> ') : 'not provided'}</div>
              <div>confidence: {path.totalConfidence.toFixed(2)}; noise: {path.totalNoise.toFixed(2)}</div>
            </div>
          </details>
        </div>

        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
          <ActionButton onClick={() => onInspect(path)} variant="primary" size="sm" title="Inspect this route in the graph">
            <Route className="h-3.5 w-3.5" aria-hidden="true" />
            Inspect Path
          </ActionButton>
          {onFrontier && (
            <ActionButton onClick={() => onFrontier(path.target.id)} variant="secondary" size="sm" title="Open frontier items for this target">
              <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
              Frontier
            </ActionButton>
          )}
        </div>
      </div>
    </div>
  );
}

