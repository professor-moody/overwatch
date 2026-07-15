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
import { getReadiness } from '../../lib/api';
import {
  validateHostToolsSmoke,
  validateMcpToolsSmoke,
  validatePendingActionsSmoke,
  topLevelKeys,
  type SmokeValidationResult,
} from '../../lib/smoke-checks';
import type { DashboardReadinessSummary } from '../../lib/types';
import type { PanelId } from '../layout/OperatorLayout';
import { ActionButton, PageHeader } from '../shared/primitives';
import { dashboardFetch } from '../../lib/dashboard-transport';

// ---- types ----

type CheckStatus = 'pending' | 'running' | 'pass' | 'warn' | 'fail' | 'skip';

interface CheckResult {
  status: CheckStatus;
  latencyMs?: number;
  detail?: string;
  expected?: string;
  actualKeys?: string[];
  statusCode?: number;
  action?: string;
  /** Panel to navigate to when clicking the row */
  panel?: PanelId;
}

interface CheckDef {
  id: string;
  label: string;
  description: string;
  group: string;
  severity: 'required' | 'optional' | 'profile';
  panel?: PanelId;
  run: () => Promise<SmokeValidationResult & { statusCode?: number }>;
}

// ---- helpers ----

async function probe(url: string): Promise<SmokeValidationResult & { statusCode?: number }> {
  const res = await dashboardFetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return { ok: false, status: 'fail', detail: `endpoint broken: HTTP ${res.status}`, statusCode: res.status };
  return { ok: true, status: 'pass', statusCode: res.status };
}

async function probeOptional(url: string, action = 'Enable this surface only when the active workflow needs it.'): Promise<SmokeValidationResult & { statusCode?: number }> {
  const res = await dashboardFetch(url, { signal: AbortSignal.timeout(5000) });
  if (res.status === 503) {
    return {
      ok: false,
      status: 'warn',
      detail: 'optional surface unavailable',
      statusCode: res.status,
      action,
    };
  }
  if (!res.ok) return { ok: false, status: 'fail', detail: `endpoint broken: HTTP ${res.status}`, statusCode: res.status };
  return { ok: true, status: 'pass', statusCode: res.status };
}

async function probeJson<T>(
  url: string,
  validate?: (data: T) => SmokeValidationResult | string | undefined,
): Promise<SmokeValidationResult & { statusCode?: number }> {
  const res = await dashboardFetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return { ok: false, status: 'fail', detail: `endpoint broken: HTTP ${res.status}`, statusCode: res.status };
  const data = (await res.json()) as T;
  const result = validate?.(data);
  if (typeof result === 'string') {
    return {
      ok: false,
      status: 'fail',
      detail: `shape mismatch: ${result}`,
      actualKeys: topLevelKeys(data),
      statusCode: res.status,
    };
  }
  if (result && !result.ok) return { ...result, statusCode: res.status };
  return { ok: true, status: 'pass', statusCode: res.status };
}

// ---- check definitions ----

const CHECKS: CheckDef[] = [
  // Core API
  {
    id: 'api_health',
    label: '/api/health',
    description: 'Graph engine health endpoint',
    group: 'Core API',
    severity: 'required',
    run: () => probeJson<{ health_checks?: { status?: string } }>('/api/health', d => {
      if (!d.health_checks) return 'health_checks field missing';
      if (d.health_checks.status === 'critical') {
        return {
          ok: false,
          status: 'warn',
          detail: 'graph health critical',
          expected: '{ graph_stats, ad_context, health_checks }',
          actualKeys: topLevelKeys(d),
          action: 'Review readiness details before trusting derived graph views.',
        };
      }
      return undefined;
    }),
  },
  {
    id: 'api_state',
    label: '/api/state',
    description: 'Engagement state + graph summary',
    group: 'Core API',
    severity: 'required',
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
    severity: 'required',
    run: () => probeJson<{ nodes: unknown[] }>('/api/graph', d =>
      !Array.isArray(d.nodes) ? 'nodes field missing' : undefined,
    ),
  },
  {
    id: 'api_config',
    label: '/api/config',
    description: 'Engagement config (scope, OPSEC)',
    group: 'Core API',
    severity: 'required',
    panel: 'settings',
    run: () => probe('/api/config'),
  },
  {
    id: 'api_readiness',
    label: '/api/readiness',
    description: 'Operator readiness summary',
    group: 'Core API',
    severity: 'required',
    run: () => probeJson<{ status?: string; graph?: unknown; api?: unknown }>('/api/readiness', d => {
      if (!d.status || !d.graph || !d.api) return 'readiness summary fields missing';
      return undefined;
    }),
  },

  // Subsystems
  {
    id: 'agents',
    label: '/api/agents',
    description: 'Agent manager — task list',
    group: 'Subsystems',
    severity: 'required',
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
    severity: 'required',
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
    severity: 'required',
    panel: 'actions',
    run: () => probeJson('/api/actions/pending', validatePendingActionsSmoke),
  },
  {
    id: 'campaigns',
    label: '/api/campaigns',
    description: 'Campaign list',
    group: 'Subsystems',
    severity: 'required',
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
    severity: 'profile',
    run: () => probe('/api/opsec/budget'),
  },

  // Evidence + Reports
  {
    id: 'findings',
    label: '/api/findings',
    description: 'Classified findings from current graph',
    group: 'Evidence & Reports',
    severity: 'required',
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
    severity: 'required',
    panel: 'findings',
    run: () => probeJson<{ reports: unknown[] }>('/api/reports', d =>
      !Array.isArray(d.reports) ? 'reports field missing' : undefined,
    ),
  },
  {
    id: 'trust_signals',
    label: '/api/trust-signals',
    description: 'Operator verification signal summary',
    group: 'Evidence & Reports',
    severity: 'required',
    panel: 'activity',
    run: () => probeJson<{ signals: unknown[]; counts?: Record<string, number>; total?: number }>('/api/trust-signals', d => {
      if (!Array.isArray(d.signals)) return 'signals field missing';
      if (!d.counts || typeof d.total !== 'number') return 'summary fields missing';
      return undefined;
    }),
  },

  // Tooling + Inference
  {
    id: 'host_tools',
    label: '/api/tools',
    description: 'Host binary availability (nmap, certipy, nxc, etc.)',
    group: 'Tooling',
    severity: 'optional',
    run: () => probeJson('/api/tools', validateHostToolsSmoke),
  },
  {
    id: 'mcp_tools',
    label: '/api/mcp-tools',
    description: 'Registered MCP tool surface',
    group: 'Tooling',
    severity: 'required',
    run: () => probeJson('/api/mcp-tools', validateMcpToolsSmoke),
  },
  {
    id: 'inference_rules',
    label: '/api/inference-rules',
    description: 'Loaded inference rule definitions',
    group: 'Tooling',
    severity: 'required',
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
    severity: 'optional',
    run: () => probe('/api/telemetry'),
  },
  {
    id: 'frontier_weights',
    label: '/api/frontier/weights',
    description: 'Frontier scoring weight config',
    group: 'Tooling',
    severity: 'required',
    run: () => probe('/api/frontier/weights'),
  },

  // Engagements
  {
    id: 'engagements',
    label: '/api/engagements',
    description: 'Engagement registry list',
    group: 'Engagements',
    severity: 'optional',
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
    severity: 'optional',
    panel: 'engagements',
    run: () => probe('/api/templates'),
  },

  // Tape
  {
    id: 'tape',
    label: '/api/tape',
    description: 'JSON-RPC tape recorder status',
    group: 'Tape & Audit',
    severity: 'optional',
    run: () => probeOptional('/api/tape', 'Attach the tape controller through normal app bootstrap to toggle recording from the dashboard.'),
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
  const [readiness, setReadiness] = useState<DashboardReadinessSummary | null>(null);
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
      const result = await check.run();
      const latencyMs = Math.round(performance.now() - t0);
      setResults(prev => ({
        ...prev,
        [check.id]: {
          status: result.ok ? 'pass' : result.status ?? 'fail',
          latencyMs,
          detail: result.detail,
          expected: result.expected,
          actualKeys: result.actualKeys,
          statusCode: result.statusCode,
          action: result.action,
          panel: check.panel,
        },
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
    getReadiness().then(setReadiness).catch(() => setReadiness(null));
    // Reset all to running first so the UI snaps immediately.
    setResults(Object.fromEntries(CHECKS.map(c => [c.id, { status: 'running', panel: c.panel }])));
    // Run in parallel within each group, groups sequentially to avoid thundering herd.
    for (const group of GROUPS) {
      const groupChecks = CHECKS.filter(c => c.group === group);
      await Promise.all(groupChecks.map(c => runCheck(c)));
    }
    getReadiness().then(setReadiness).catch(() => setReadiness(null));
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
  const warning = allResults.filter(r => r.status === 'warn').length + (wsStatus === 'warn' ? 1 : 0);
  const failing = allResults.filter(r => r.status === 'fail').length + (wsStatus === 'fail' ? 1 : 0);
  const running = allResults.filter(r => r.status === 'running').length;
  const totalCount = allResults.length + 1; // +1 for WebSocket

  const overallStatus: CheckStatus =
    running > 0 ? 'running' :
    failing > 0 ? 'fail' :
    warning > 0 ? 'warn' :
    passing === totalCount ? 'pass' : 'pending';

  return (
    <div className="space-y-5">
      <PageHeader
        title="Smoke"
        meta={
          <span className="inline-flex items-center gap-3">
          <StatusPill status={overallStatus} />
          {overallStatus !== 'running' && (
            <span className="text-xs text-muted-foreground font-mono">
              {passing}/{totalCount} pass
              {warning > 0 && <span className="text-warning ml-1">· {warning} warn</span>}
              {failing > 0 && <span className="text-destructive ml-1">· {failing} fail</span>}
            </span>
          )}
          </span>
        }
        actions={
          <>
          {lastRun && (
            <span className="text-[10px] text-muted-foreground font-mono">
              last run {lastRun.toLocaleTimeString()}
            </span>
          )}
          <ActionButton
            onClick={() => void runAll()}
            disabled={overallStatus === 'running'}
            variant="secondary"
          >
            {overallStatus === 'running' ? 'Running…' : 'Re-run all'}
          </ActionButton>
          </>
        }
      />

      <ReadinessStrip readiness={readiness} wsStatus={wsStatus} apiStatus={overallStatus} />

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
            severity="required"
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
                  severity={check.severity}
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

function ReadinessStrip({
  readiness,
  wsStatus,
  apiStatus,
}: {
  readiness: DashboardReadinessSummary | null;
  wsStatus: CheckStatus;
  apiStatus: CheckStatus;
}) {
  const cells = [
    {
      label: 'Graph',
      value: readiness ? `${readiness.graph.nodes}N / ${readiness.graph.edges}E` : 'pending',
      status: readiness?.graph.status === 'critical' ? 'fail' : readiness?.graph.status === 'warning' ? 'warn' : readiness ? 'pass' : 'pending',
    },
    {
      label: 'API',
      value: apiStatus === 'running' ? 'running' : apiStatus,
      status: apiStatus,
    },
    {
      label: 'Tape',
      value: readiness?.tape?.enabled
        ? `on${readiness.tape.started_by ? ` · ${readiness.tape.started_by}` : ''}`
        : readiness ? 'off' : 'pending',
      status: readiness?.tape?.enabled ? 'pass' : readiness ? 'warn' : 'pending',
    },
    {
      label: 'Sessions',
      value: readiness ? `${readiness.sessions.active}/${readiness.sessions.total} active` : 'pending',
      status: 'pass',
    },
    {
      label: 'Approvals',
      value: readiness ? String(readiness.actions.pending) : 'pending',
      status: readiness && readiness.actions.pending > 0 ? 'warn' : readiness ? 'pass' : 'pending',
    },
    {
      label: 'Agents',
      value: readiness ? `${readiness.agents.running} run / ${readiness.agents.failed} fail` : 'pending',
      status: readiness && readiness.agents.failed > 0 ? 'warn' : readiness ? 'pass' : 'pending',
    },
    {
      label: 'WS',
      value: wsStatus,
      status: wsStatus,
    },
  ] as const;

  return (
    <div className="bg-surface border border-border rounded-lg px-3 py-2">
      <div className="flex items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-foreground">Readiness</span>
          <StatusPill status={readiness?.status === 'critical' ? 'fail' : readiness?.status === 'warning' ? 'warn' : readiness ? 'pass' : 'pending'} />
        </div>
        {readiness?.persistence.dirty && (
          <span className="text-[10px] text-warning font-mono">state dirty</span>
        )}
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2">
        {cells.map(cell => (
          <div key={cell.label} className="bg-elevated/50 border border-border rounded px-2 py-1 min-w-0">
            <div className="flex items-center gap-1.5">
              <StatusDot status={cell.status} />
              <span className="text-[9px] uppercase tracking-normal text-muted-foreground">{cell.label}</span>
            </div>
            <div className="text-[11px] font-mono text-foreground truncate mt-1">{cell.value}</div>
          </div>
        ))}
      </div>
      {readiness?.issues.length ? (
        <div className="mt-2 text-[10px] text-warning truncate">
          {readiness.issues[0]}
        </div>
      ) : null}
    </div>
  );
}

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
  const warning = vals.filter(r => r.status === 'warn').length;
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
                {warning > 0 && <span className="text-warning ml-1">{warning} warn</span>}
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
  severity,
  result,
  onNavigate,
}: {
  label: string;
  description: string;
  severity: CheckDef['severity'];
  result: CheckResult;
  onNavigate?: () => void;
}) {
  const showDetail = result.detail && (result.status === 'fail' || result.status === 'warn');
  return (
    <div className="px-3 py-2 flex items-start gap-3 hover:bg-hover/40 transition-colors">
      <StatusDot status={result.status} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono text-foreground">{label}</span>
          <span className={cn(
            'text-[9px] uppercase tracking-normal px-1.5 py-0.5 rounded border',
            severity === 'required' && 'border-destructive/30 text-destructive',
            severity === 'optional' && 'border-border text-muted-foreground',
            severity === 'profile' && 'border-warning/30 text-warning',
          )}>
            {severity}
          </span>
          {showDetail && (
            <span className={cn(
              'text-[10px] truncate max-w-80',
              result.status === 'warn' ? 'text-warning' : 'text-destructive',
            )}>{result.detail}</span>
          )}
        </div>
        <div className="text-[10px] text-muted-foreground">{description}</div>
        {showDetail && (
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] font-mono text-muted-foreground">
            {result.expected && <span>expected: {result.expected}</span>}
            {result.actualKeys && <span>keys: {result.actualKeys.length > 0 ? result.actualKeys.join(', ') : 'none'}</span>}
            {result.statusCode !== undefined && <span>http: {result.statusCode}</span>}
            {result.action && <span className="text-foreground">{result.action}</span>}
          </div>
        )}
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
      status === 'warn' && 'bg-warning',
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
    warn: 'bg-warning/10 text-warning',
    fail: 'bg-destructive/10 text-destructive',
    running: 'bg-accent/10 text-accent',
    pending: 'bg-elevated text-muted-foreground',
    skip: 'bg-elevated text-muted-foreground',
  };
  const label: Record<CheckStatus, string> = {
    pass: 'all pass',
    warn: 'warnings',
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
