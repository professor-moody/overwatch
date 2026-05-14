// ============================================================
// SmokePanel — live subsystem health checks
//
// Pings every significant API endpoint and the WS connection,
// displays pass / fail / pending per check with latency, and
// lets the operator re-run individual groups or everything at
// once. Useful after a restart or config change to confirm the
// server is fully operational before starting work.
// ============================================================

import { useState, useCallback, useEffect, useRef } from 'react';
import { useWs } from '../../providers/ws-provider';
import { useNavigation } from '../../hooks/useNavigation';
import { cn } from '../../lib/utils';
import type { PanelId } from '../layout/OperatorLayout';

// ---- types ----

type CheckStatus = 'pending' | 'running' | 'pass' | 'fail' | 'skip';

interface CheckResult {
  status: CheckStatus;
  latencyMs?: number;
  detail?: string;
  /** Panel to navigate to when clicking the row */
  panel?: PanelId;
}

interface CheckDef {
  id: string;
  label: string;
  description: string;
  group: string;
  panel?: PanelId;
  run: () => Promise<{ ok: boolean; detail?: string }>;
}

// ---- helpers ----

async function probe(url: string): Promise<{ ok: boolean; detail?: string }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
  return { ok: true };
}

async function probeJson<T>(
  url: string,
  validate?: (data: T) => string | undefined,
): Promise<{ ok: boolean; detail?: string }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
  const data = (await res.json()) as T;
  const msg = validate?.(data);
  return msg ? { ok: false, detail: msg } : { ok: true };
}

// ---- check definitions ----

const CHECKS: CheckDef[] = [
  // Core API
  {
    id: 'api_health',
    label: '/api/health',
    description: 'Graph engine health endpoint',
    group: 'Core API',
    run: () => probeJson<{ status: string }>('/api/health', d =>
      d.status === 'critical' ? 'status=critical' : undefined,
    ),
  },
  {
    id: 'api_state',
    label: '/api/state',
    description: 'Engagement state + graph summary',
    group: 'Core API',
    panel: 'overview',
    run: () => probeJson<{ state: unknown }>('/api/state', d =>
      !d.state ? 'no state in response' : undefined,
    ),
  },
  {
    id: 'api_graph',
    label: '/api/graph',
    description: 'Raw graph export (nodes + edges)',
    group: 'Core API',
    run: () => probeJson<{ nodes: unknown[] }>('/api/graph', d =>
      !Array.isArray(d.nodes) ? 'nodes field missing' : undefined,
    ),
  },
  {
    id: 'api_config',
    label: '/api/config',
    description: 'Engagement config (scope, OPSEC)',
    group: 'Core API',
    panel: 'settings',
    run: () => probe('/api/config'),
  },

  // Subsystems
  {
    id: 'agents',
    label: '/api/agents',
    description: 'Agent manager — task list',
    group: 'Subsystems',
    panel: 'agents',
    run: () => probeJson<{ agents: unknown[] }>('/api/agents', d =>
      !Array.isArray(d.agents) ? 'agents field missing' : undefined,
    ),
  },
  {
    id: 'sessions',
    label: '/api/sessions',
    description: 'Session manager — active shells',
    group: 'Subsystems',
    panel: 'sessions',
    run: () => probeJson<{ sessions: unknown[] }>('/api/sessions', d =>
      !Array.isArray(d.sessions) ? 'sessions field missing' : undefined,
    ),
  },
  {
    id: 'actions_pending',
    label: '/api/actions/pending',
    description: 'Approval queue — pending actions',
    group: 'Subsystems',
    panel: 'actions',
    run: () => probeJson<{ actions: unknown[] }>('/api/actions/pending', d =>
      !Array.isArray(d.actions) ? 'actions field missing' : undefined,
    ),
  },
  {
    id: 'campaigns',
    label: '/api/campaigns',
    description: 'Campaign list',
    group: 'Subsystems',
    panel: 'campaigns',
    run: () => probeJson<{ campaigns: unknown[] }>('/api/campaigns', d =>
      !Array.isArray(d.campaigns) ? 'campaigns field missing' : undefined,
    ),
  },
  {
    id: 'opsec_budget',
    label: '/api/opsec/budget',
    description: 'OPSEC noise budget and window',
    group: 'Subsystems',
    run: () => probe('/api/opsec/budget'),
  },

  // Evidence + Reports
  {
    id: 'findings',
    label: '/api/findings',
    description: 'Classified findings from current graph',
    group: 'Evidence & Reports',
    panel: 'findings',
    run: () => probeJson<{ findings: unknown[] }>('/api/findings', d =>
      !Array.isArray(d.findings) ? 'findings field missing' : undefined,
    ),
  },
  {
    id: 'reports',
    label: '/api/reports',
    description: 'Report archive manifest',
    group: 'Evidence & Reports',
    panel: 'findings',
    run: () => probeJson<{ reports: unknown[] }>('/api/reports', d =>
      !Array.isArray(d.reports) ? 'reports field missing' : undefined,
    ),
  },

  // Tooling + Inference
  {
    id: 'tools',
    label: '/api/tools',
    description: 'Registered MCP tool list',
    group: 'Tooling',
    run: () => probeJson<{ tools: unknown[] }>('/api/tools', d => {
      if (!Array.isArray(d.tools)) return 'tools field missing';
      if (d.tools.length < 40) return `only ${d.tools.length} tools registered (expected 60+)`;
      return undefined;
    }),
  },
  {
    id: 'inference_rules',
    label: '/api/inference-rules',
    description: 'Loaded inference rule definitions',
    group: 'Tooling',
    run: () => probeJson<{ rules: unknown[] }>('/api/inference-rules', d => {
      if (!Array.isArray(d.rules)) return 'rules field missing';
      if (d.rules.length < 30) return `only ${d.rules.length} rules loaded (expected 60+)`;
      return undefined;
    }),
  },
  {
    id: 'telemetry',
    label: '/api/telemetry',
    description: 'Tool usage telemetry + graph health',
    group: 'Tooling',
    run: () => probe('/api/telemetry'),
  },
  {
    id: 'frontier_weights',
    label: '/api/frontier/weights',
    description: 'Frontier scoring weight config',
    group: 'Tooling',
    run: () => probe('/api/frontier/weights'),
  },

  // Engagements
  {
    id: 'engagements',
    label: '/api/engagements',
    description: 'Engagement registry list',
    group: 'Engagements',
    panel: 'engagements',
    run: () => probeJson<{ engagements: unknown[] }>('/api/engagements', d =>
      !Array.isArray(d.engagements) ? 'engagements field missing' : undefined,
    ),
  },
  {
    id: 'templates',
    label: '/api/templates',
    description: 'Engagement template catalog',
    group: 'Engagements',
    panel: 'engagements',
    run: () => probe('/api/templates'),
  },

  // Tape
  {
    id: 'tape',
    label: '/api/tape',
    description: 'JSON-RPC tape recorder status',
    group: 'Tape & Audit',
    run: () => probe('/api/tape'),
  },
];

const GROUPS = [...new Set(CHECKS.map(c => c.group))];

// ---- component ----

export function SmokePanel() {
  const { connected } = useWs();
  const { navigateToPanel } = useNavigation();
  const [results, setResults] = useState<Record<string, CheckResult>>(() =>
    Object.fromEntries(CHECKS.map(c => [c.id, { status: 'pending' as CheckStatus }])),
  );
  const [wsStatus, setWsStatus] = useState<CheckStatus>('pending');
  const [lastRun, setLastRun] = useState<Date | null>(null);
  const runningRef = useRef(false);

  // Mirror live WS state into the check result.
  useEffect(() => {
    setWsStatus(connected ? 'pass' : wsStatus === 'pending' ? 'pending' : 'fail');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connected]);

  const runCheck = useCallback(async (check: CheckDef) => {
    setResults(prev => ({ ...prev, [check.id]: { status: 'running', panel: check.panel } }));
    const t0 = performance.now();
    try {
      const { ok, detail } = await check.run();
      const latencyMs = Math.round(performance.now() - t0);
      setResults(prev => ({
        ...prev,
        [check.id]: { status: ok ? 'pass' : 'fail', latencyMs, detail, panel: check.panel },
      }));
    } catch (err) {
      const latencyMs = Math.round(performance.now() - t0);
      const detail = err instanceof Error ? err.message : String(err);
      setResults(prev => ({
        ...prev,
        [check.id]: { status: 'fail', latencyMs, detail, panel: check.panel },
      }));
    }
  }, []);

  const runAll = useCallback(async () => {
    if (runningRef.current) return;
    runningRef.current = true;
    setWsStatus(connected ? 'pass' : 'fail');
    // Reset all to running first so the UI snaps immediately.
    setResults(Object.fromEntries(CHECKS.map(c => [c.id, { status: 'running', panel: c.panel }])));
    // Run in parallel within each group, groups sequentially to avoid thundering herd.
    for (const group of GROUPS) {
      const groupChecks = CHECKS.filter(c => c.group === group);
      await Promise.all(groupChecks.map(c => runCheck(c)));
    }
    setLastRun(new Date());
    runningRef.current = false;
  }, [connected, runCheck]);

  const runGroup = useCallback(async (group: string) => {
    const groupChecks = CHECKS.filter(c => c.group === group);
    setResults(prev => {
      const next = { ...prev };
      for (const c of groupChecks) next[c.id] = { status: 'running', panel: c.panel };
      return next;
    });
    await Promise.all(groupChecks.map(c => runCheck(c)));
  }, [runCheck]);

  // Auto-run once on mount.
  useEffect(() => { void runAll(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const allResults = Object.values(results);
  const passing = allResults.filter(r => r.status === 'pass').length + (wsStatus === 'pass' ? 1 : 0);
  const failing = allResults.filter(r => r.status === 'fail').length + (wsStatus === 'fail' ? 1 : 0);
  const running = allResults.filter(r => r.status === 'running').length;
  const totalCount = allResults.length + 1; // +1 for WebSocket

  const overallStatus: CheckStatus =
    running > 0 ? 'running' :
    failing > 0 ? 'fail' :
    passing === totalCount ? 'pass' : 'pending';

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold">Smoke</h2>
          <StatusPill status={overallStatus} />
          {overallStatus !== 'running' && (
            <span className="text-xs text-muted-foreground font-mono">
              {passing}/{totalCount} pass
              {failing > 0 && <span className="text-destructive ml-1">· {failing} fail</span>}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {lastRun && (
            <span className="text-[10px] text-muted-foreground font-mono">
              last run {lastRun.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => void runAll()}
            disabled={overallStatus === 'running'}
            className={cn(
              'text-xs px-3 py-1 rounded border transition-colors',
              overallStatus === 'running'
                ? 'border-border text-muted-foreground cursor-not-allowed'
                : 'border-border hover:border-accent text-muted-foreground hover:text-foreground',
            )}
          >
            {overallStatus === 'running' ? 'Running…' : 'Re-run all'}
          </button>
        </div>
      </div>

      {/* WebSocket row (special — live state, not a fetch) */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <GroupHeader
          label="WebSocket"
          checks={[]}
          results={{}}
          onRerun={() => setWsStatus(connected ? 'pass' : 'fail')}
        />
        <div className="border-t border-border">
          <CheckRow
            label="WebSocket /ws"
            description="Live push connection for graph updates and agent events"
            result={{ status: wsStatus, panel: undefined }}
            onNavigate={undefined}
          />
        </div>
      </div>

      {/* Per-group check tables */}
      {GROUPS.map(group => {
        const groupChecks = CHECKS.filter(c => c.group === group);
        const groupResults = Object.fromEntries(groupChecks.map(c => [c.id, results[c.id] ?? { status: 'pending' as CheckStatus }]));
        return (
          <div key={group} className="bg-surface border border-border rounded-lg overflow-hidden">
            <GroupHeader
              label={group}
              checks={groupChecks}
              results={groupResults}
              onRerun={() => void runGroup(group)}
            />
            <div className="border-t border-border divide-y divide-border">
              {groupChecks.map(check => (
                <CheckRow
                  key={check.id}
                  label={check.label}
                  description={check.description}
                  result={results[check.id] ?? { status: 'pending' }}
                  onNavigate={check.panel ? () => navigateToPanel(check.panel!) : undefined}
                />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---- sub-components ----

function GroupHeader({
  label,
  checks,
  results,
  onRerun,
}: {
  label: string;
  checks: CheckDef[];
  results: Record<string, CheckResult>;
  onRerun: () => void;
}) {
  const vals = Object.values(results);
  const passing = vals.filter(r => r.status === 'pass').length;
  const failing = vals.filter(r => r.status === 'fail').length;
  const running = vals.filter(r => r.status === 'running').length;

  return (
    <div className="px-3 py-2 flex items-center justify-between text-xs">
      <span className="font-medium text-foreground">{label}</span>
      <div className="flex items-center gap-2">
        {checks.length > 0 && (
          <span className="font-mono text-muted-foreground">
            {running > 0 ? (
              <span className="text-accent">running…</span>
            ) : (
              <>
                <span className={failing > 0 ? 'text-destructive' : 'text-success'}>{passing}</span>
                <span className="text-muted">/{checks.length}</span>
                {failing > 0 && <span className="text-destructive ml-1">{failing} fail</span>}
              </>
            )}
          </span>
        )}
        <button
          onClick={onRerun}
          className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground hover:text-foreground hover:border-accent/50 transition-colors"
        >
          re-run
        </button>
      </div>
    </div>
  );
}

function CheckRow({
  label,
  description,
  result,
  onNavigate,
}: {
  label: string;
  description: string;
  result: CheckResult;
  onNavigate?: () => void;
}) {
  return (
    <div className="px-3 py-2 flex items-center gap-3 hover:bg-hover/40 transition-colors">
      <StatusDot status={result.status} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-foreground">{label}</span>
          {result.detail && result.status === 'fail' && (
            <span className="text-[10px] text-destructive truncate max-w-48">{result.detail}</span>
          )}
        </div>
        <div className="text-[10px] text-muted-foreground">{description}</div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        {result.latencyMs !== undefined && (
          <span className={cn(
            'text-[10px] font-mono',
            result.latencyMs < 100 ? 'text-success' :
            result.latencyMs < 500 ? 'text-warning' : 'text-destructive',
          )}>
            {result.latencyMs}ms
          </span>
        )}
        {onNavigate && (
          <button
            onClick={onNavigate}
            className="text-[10px] px-1.5 py-0.5 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors"
          >
            open →
          </button>
        )}
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: CheckStatus }) {
  return (
    <span className={cn(
      'w-2 h-2 rounded-full flex-shrink-0',
      status === 'pass' && 'bg-success',
      status === 'fail' && 'bg-destructive',
      status === 'running' && 'bg-accent animate-pulse',
      status === 'pending' && 'bg-elevated border border-border',
      status === 'skip' && 'bg-muted',
    )} />
  );
}

function StatusPill({ status }: { status: CheckStatus }) {
  const map: Record<CheckStatus, string> = {
    pass: 'bg-success/10 text-success',
    fail: 'bg-destructive/10 text-destructive',
    running: 'bg-accent/10 text-accent',
    pending: 'bg-elevated text-muted-foreground',
    skip: 'bg-elevated text-muted-foreground',
  };
  const label: Record<CheckStatus, string> = {
    pass: 'all pass',
    fail: 'failures',
    running: 'running',
    pending: 'pending',
    skip: 'skipped',
  };
  return (
    <span className={cn('text-xs px-2 py-0.5 rounded', map[status])}>
      {label[status]}
    </span>
  );
}
