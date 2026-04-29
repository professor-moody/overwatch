import { useEffect, useState, useCallback } from 'react';
import * as api from '../../lib/api';
import type { TelemetryResponse } from '../../lib/api';
import { cn } from '../../lib/utils';

export function TelemetrySection() {
  const [data, setData] = useState<TelemetryResponse | null>(null);
  const [expanded, setExpanded] = useState(false);

  const fetch = useCallback(async () => {
    try {
      const res = await api.getTelemetry();
      setData(res);
    } catch { /* silent — telemetry is non-critical */ }
  }, []);

  useEffect(() => {
    fetch();
    const timer = setInterval(fetch, 15_000);
    return () => clearInterval(timer);
  }, [fetch]);

  if (!data) {
    return (
      <section className="bg-surface border border-border rounded-lg p-4">
        <div className="flex items-center justify-between text-sm font-medium">
          <span className="text-muted-foreground">Telemetry</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-muted-foreground">no data</span>
        </div>
      </section>
    );
  }

  const { tool_telemetry, inference_effectiveness, health } = data;

  return (
    <section className="bg-surface border border-border rounded-lg p-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between text-sm font-medium cursor-pointer"
      >
        <span className="flex items-center gap-2">
          Telemetry
          {tool_telemetry && (
            <span className="text-[10px] font-mono text-muted-foreground">
              {tool_telemetry.total_calls} calls
            </span>
          )}
        </span>
        <div className="flex items-center gap-2">
          <HealthBadge status={health.status} counts={health.counts} />
          <span className="text-muted-foreground text-xs">{expanded ? '▾' : '▸'}</span>
        </div>
      </button>

      {expanded && (
        <div className="mt-3 space-y-4">
          {/* Tool Usage */}
          {tool_telemetry && tool_telemetry.top_tools.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground mb-2">Top Tools</h4>
              <div className="space-y-1">
                {tool_telemetry.top_tools.map((tool) => (
                  <ToolRow key={tool.name} tool={tool} maxCalls={tool_telemetry.top_tools[0].calls} />
                ))}
              </div>
              <div className="flex items-center gap-4 mt-2 text-[10px] text-muted-foreground">
                <span>{tool_telemetry.total_calls} total calls</span>
                <span>{tool_telemetry.total_errors} errors</span>
                {tool_telemetry.unused_tools.length > 0 && (
                  <span>{tool_telemetry.unused_tools.length} unused tools</span>
                )}
              </div>
            </div>
          )}

          {/* Common Sequences */}
          {tool_telemetry && tool_telemetry.common_sequences.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground mb-2">Common Patterns</h4>
              <div className="space-y-1">
                {tool_telemetry.common_sequences.slice(0, 5).map((seq, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-muted-foreground w-5 text-right">{seq.count}×</span>
                    <span className="text-muted-foreground">
                      {seq.sequence.map((s, j) => (
                        <span key={j}>
                          {j > 0 && <span className="text-border mx-1">→</span>}
                          <span className="text-foreground">{s}</span>
                        </span>
                      ))}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Inference Effectiveness */}
          {inference_effectiveness.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground mb-2">Inference Rule Effectiveness</h4>
              <div className="space-y-1">
                {inference_effectiveness
                  .filter(r => r.total > 0)
                  .sort((a, b) => b.total - a.total)
                  .map((rule) => (
                    <div key={rule.rule_id} className="flex items-center gap-2 text-xs">
                      <span className="text-muted-foreground flex-1 truncate">{rule.rule_id}</span>
                      <span className="font-mono text-foreground">{rule.confirmed}/{rule.total}</span>
                      <ConfidenceBar rate={rule.confirmation_rate} />
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Health Issues */}
          {health.top_issues.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground mb-2">
                Health Issues
                <span className="ml-1 font-normal">
                  ({health.counts.critical} critical, {health.counts.warning} warning)
                </span>
              </h4>
              <div className="space-y-1">
                {health.top_issues.slice(0, 5).map((issue, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className={cn(
                      'mt-0.5 flex-shrink-0',
                      issue.severity === 'critical' ? 'text-destructive' : 'text-warning',
                    )}>
                      {issue.severity === 'critical' ? '●' : '▲'}
                    </span>
                    <span className="text-muted-foreground">
                      <span className="text-foreground font-medium">{issue.check}</span>: {issue.message}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Empty state */}
          {!tool_telemetry && inference_effectiveness.length === 0 && health.top_issues.length === 0 && (
            <p className="text-xs text-muted-foreground">No telemetry data available yet</p>
          )}
        </div>
      )}
    </section>
  );
}

// ---- Sub-components ----

function ToolRow({ tool, maxCalls }: {
  tool: { name: string; calls: number; avg_ms: number; error_rate: number };
  maxCalls: number;
}) {
  const pct = maxCalls > 0 ? (tool.calls / maxCalls) * 100 : 0;
  const hasErrors = tool.error_rate > 0;

  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-28 truncate text-foreground font-mono text-[11px]">{tool.name}</span>
      <div className="flex-1 h-1.5 bg-elevated rounded-full overflow-hidden">
        <div
          className={cn('h-full rounded-full', hasErrors ? 'bg-warning' : 'bg-accent')}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="font-mono text-muted-foreground w-8 text-right">{tool.calls}</span>
      <span className="font-mono text-muted-foreground w-12 text-right">{tool.avg_ms}ms</span>
      {hasErrors && (
        <span className="font-mono text-warning text-[10px]">
          {(tool.error_rate * 100).toFixed(0)}% err
        </span>
      )}
    </div>
  );
}

function HealthBadge({ status, counts }: {
  status: string;
  counts: { warning: number; critical: number };
}) {
  if (status === 'healthy') {
    return <span className="text-[10px] px-1.5 py-0.5 rounded bg-success/10 text-success">healthy</span>;
  }
  if (status === 'critical') {
    return (
      <span className="text-[10px] px-1.5 py-0.5 rounded bg-destructive/10 text-destructive">
        {counts.critical} critical
      </span>
    );
  }
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">
      {counts.warning} warnings
    </span>
  );
}

function ConfidenceBar({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100);
  const color = pct >= 70 ? 'bg-success' : pct >= 30 ? 'bg-warning' : 'bg-destructive';
  return (
    <div className="flex items-center gap-1 w-20">
      <div className="flex-1 h-1.5 bg-elevated rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-muted-foreground text-[10px] w-8 text-right">{pct}%</span>
    </div>
  );
}
