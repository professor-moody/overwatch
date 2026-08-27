import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Download, Plus, RefreshCw, Save, XCircle } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { buildDashboardPath } from '@overwatch/dashboard-api-contracts';
import * as api from '../../lib/api';
import { downloadDashboardResource } from '../../lib/dashboard-transport';
import type {
  EngagementConfig,
  EngagementDetail,
  EngagementListItem,
  EngagementTemplate,
  OpsecConfig,
  PersistenceRecoveryStatus,
} from '../../lib/types';
import { cn } from '../../lib/utils';
import { reconcileRuntimeEngagement } from '../../lib/manage-workspace';
import { useEngagementStore } from '../../stores/engagement-store';
import { ActionButton, StatusPill, WorkspaceEmpty, WorkspaceInspector, WorkspaceRow } from '../shared/primitives';

type LoadState = 'loading' | 'ready' | 'stale' | 'unavailable';

export function NativeEngagementManagement() {
  const runtime = useEngagementStore(state => state.engagement);
  const runtimeObjectives = useEngagementStore(state => state.objectives);
  const phases = useEngagementStore(state => state.phases);
  const [searchParams, setSearchParams] = useSearchParams();
  const [library, setLibrary] = useState<EngagementListItem[]>([]);
  const [libraryAvailable, setLibraryAvailable] = useState(false);
  const [templates, setTemplates] = useState<EngagementTemplate[]>([]);
  const [config, setConfig] = useState<EngagementConfig | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState<EngagementDetail | null>(null);
  const selectedId = searchParams.get('item');

  const load = useCallback(async () => {
    try {
      const [engagements, templatesResponse, activeConfig] = await Promise.all([
        api.getEngagements(),
        api.getTemplates().catch(() => ({ templates: [], total: 0 })),
        api.getConfig().catch(() => null),
      ]);
      setLibrary(engagements.engagements || []);
      setLibraryAvailable(engagements.library_available);
      setTemplates(templatesResponse.templates || []);
      setConfig(activeConfig);
      setState('ready');
      setError(null);
    } catch (cause) {
      setState(current => current === 'loading' ? 'unavailable' : 'stale');
      setError(cause instanceof Error ? cause.message : 'Engagement configuration could not be loaded.');
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    if (!selectedId || !libraryAvailable) {
      setSelectedDetail(null);
      return;
    }
    let cancelled = false;
    api.getEngagement(selectedId).then(detail => { if (!cancelled) setSelectedDetail(detail); }).catch(() => {
      if (!cancelled) {
        const next = new URLSearchParams(searchParams); next.delete('item'); setSearchParams(next, { replace: true });
      }
    });
    return () => { cancelled = true; };
  }, [libraryAvailable, searchParams, selectedId, setSearchParams]);

  const reconciledLibrary = reconcileRuntimeEngagement(runtime, library, libraryAvailable);
  const runtimeLibraryRecord = reconciledLibrary.matchingRecord;
  const scope = config?.scope || runtime?.scope || { cidrs: [], domains: [], exclusions: [] };

  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1 overflow-y-auto">
        <ManageToolbar title="Runtime engagement" detail="The running engagement is authoritative; library controls appear only when the server supports them." state={state} onRefresh={() => void load()} actions={libraryAvailable ? <ActionButton variant="primary" onClick={() => setCreateOpen(true)}><Plus className="h-3 w-3" />New engagement</ActionButton> : undefined} />
        {error && <InlineNotice tone="danger">{error}</InlineNotice>}

        {runtime ? (
          <section className="border-b border-border-subtle px-5 py-4">
            <div className="flex min-w-0 items-start gap-3">
              <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="text-base font-semibold text-foreground">{runtime.name}</h2><StatusPill tone="success">● active runtime</StatusPill>{reconciledLibrary.runtimeOnly && <StatusPill tone="muted">Runtime only</StatusPill>}<StatusPill tone="accent">{runtime.profile || 'operator'}</StatusPill></div><div className="mt-1 truncate font-mono text-[9px] text-muted-foreground">{runtime.id}</div></div>
              <ActionButton onClick={() => setScopeOpen(true)}>Edit scope</ActionButton>
            </div>
            <div className="mt-4 grid gap-x-8 gap-y-3 sm:grid-cols-2 xl:grid-cols-4">
              <ManageFact label="CIDRs" value={(scope.cidrs || []).join(', ') || 'None'} mono />
              <ManageFact label="Domains" value={(scope.domains || []).join(', ') || 'None'} mono />
              <ManageFact label="Exclusions" value={(scope.exclusions || []).join(', ') || 'None'} mono />
              <ManageFact label="Lifecycle" value={runtimeLibraryRecord ? 'Runtime + library record' : 'Runtime state only'} />
            </div>
          </section>
        ) : <WorkspaceEmpty title="No runtime engagement" detail="Start Overwatch with an engagement before operational controls are available." />}

        <section className="border-b border-border-subtle">
          <SectionHeading title="Objectives" count={runtimeObjectives.length} action={<ObjectiveCreator onCreated={() => void load()} />} />
          {runtimeObjectives.length ? runtimeObjectives.map(objective => <div key={objective.id} className="flex min-h-10 items-center gap-2 border-t border-border-subtle px-5 py-2"><span className={cn('h-1.5 w-1.5 rounded-full', objective.achieved ? 'bg-success' : 'bg-warning')} /><span className="min-w-0 flex-1 truncate text-[11px] text-foreground">{objective.description}</span><span className="font-mono text-[8px] text-muted-foreground">{objective.id}</span><StatusPill tone={objective.achieved ? 'success' : 'warning'}>{objective.achieved ? 'achieved' : 'open'}</StatusPill><ActionButton size="xs" onClick={() => void api.updateObjective(objective.id, { achieved: !objective.achieved }).then(load)}>{objective.achieved ? 'Reopen' : 'Mark achieved'}</ActionButton><ActionButton size="xs" variant="danger" onClick={() => { if (window.confirm(`Delete objective “${objective.description}”?`)) void api.deleteObjective(objective.id).then(load); }}>Delete</ActionButton></div>) : <WorkspaceEmpty title="No objectives" detail="Add a measurable objective to drive readiness and path analysis." />}
        </section>

        <section className="border-b border-border-subtle">
          <SectionHeading title="Phases and failure patterns" count={phases.length + (config?.failure_patterns?.length || 0)} />
          <div className="grid gap-5 px-5 py-3 lg:grid-cols-2">
            <StructuredList title="Phases" empty="No phase gates configured." rows={phases.map(phase => ({ title: phase.name, meta: `${phase.status || 'pending'} · order ${phase.order}`, id: phase.id }))} />
            <StructuredList title="Failure patterns" empty="No reusable failure warnings configured." rows={(config?.failure_patterns || []).map((pattern, index) => ({ title: pattern.technique, meta: pattern.warning, id: `${pattern.target_pattern || 'any'}:${index}` }))} />
          </div>
        </section>

        <section>
          <SectionHeading title="Import, export, and bundles" />
          <div className="flex flex-wrap gap-2 px-5 py-3"><GraphExportButton /><BundleButton />{libraryAvailable ? <span className="self-center text-[9px] text-muted-foreground">Library creation and editing remain file-backed; loading another configuration still requires the server’s restart guidance.</span> : <span className="self-center text-[9px] text-muted-foreground">File-backed library controls are unavailable for this runtime.</span>}</div>
        </section>

        {libraryAvailable && <section className="border-t border-border-subtle"><SectionHeading title="Engagement library" count={reconciledLibrary.libraryRecords.length} /><div>{reconciledLibrary.libraryRecords.map(item => <WorkspaceRow key={item.id} selected={selectedId === item.id} onClick={() => { const next = new URLSearchParams(searchParams); next.set('item', item.id); setSearchParams(next); }}><div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-foreground">{item.name}</div><div className="truncate font-mono text-[8px] text-muted-foreground">{item.id}</div></div><span className="w-28 truncate text-[9px] text-muted-foreground">{item.profile || 'operator'}</span><span className="w-28 text-[9px] text-muted-foreground">{item.objectives_count} objectives</span><span className="min-w-0 flex-1 truncate font-mono text-[8px] text-muted-foreground">{item.config_path || 'No config path'}</span></WorkspaceRow>)}</div>{reconciledLibrary.libraryRecords.length === 0 && <WorkspaceEmpty title="No other library engagements" detail="The active runtime record is reconciled above instead of being duplicated." />}</section>}
      </div>

      {selectedDetail && <LibraryInspector detail={selectedDetail} onClose={() => { const next = new URLSearchParams(searchParams); next.delete('item'); setSearchParams(next); }} onSaved={() => { void load(); setSelectedDetail(null); const next = new URLSearchParams(searchParams); next.delete('item'); setSearchParams(next); }} />}
      {scopeOpen && <ScopeEditor scope={scope} onClose={() => setScopeOpen(false)} onSaved={() => { setScopeOpen(false); void load(); }} />}
      {createOpen && <CreateEngagementDialog templates={templates} onClose={() => setCreateOpen(false)} onCreated={() => { setCreateOpen(false); void load(); }} />}
    </div>
  );
}

export function NativeSettingsManagement() {
  const recoveryStore = useEngagementStore(state => state.persistenceRecovery);
  const [config, setConfig] = useState<EngagementConfig | null>(null);
  const [settings, setSettings] = useState<Awaited<ReturnType<typeof api.getSettings>> | null>(null);
  const [archetypes, setArchetypes] = useState<api.AgentArchetypeSummary[]>([]);
  const [rules, setRules] = useState<Awaited<ReturnType<typeof api.getInferenceRules>>['rules']>([]);
  const [state, setState] = useState<LoadState>('loading');
  const [message, setMessage] = useState<string | null>(null);
  const [opsecDraft, setOpsecDraft] = useState<OpsecConfig>({});
  const [failureJson, setFailureJson] = useState('[]');
  const [policyJson, setPolicyJson] = useState('{}');
  const [fanOutJson, setFanOutJson] = useState('{}');
  const [noiseJson, setNoiseJson] = useState('{}');

  const load = useCallback(async () => {
    try {
      const [cfg, set, weight, archetypeResponse, ruleResponse] = await Promise.all([
        api.getConfig(), api.getSettings(), api.getFrontierWeights(), api.getArchetypes().catch(() => ({ archetypes: [] })), api.getInferenceRules().catch(() => ({ rules: [], total: 0 })),
      ]);
      setConfig(cfg); setSettings(set); setArchetypes(archetypeResponse.archetypes || []); setRules(ruleResponse.rules || []);
      setOpsecDraft(set.opsec); setFailureJson(JSON.stringify(cfg.failure_patterns || [], null, 2)); setPolicyJson(JSON.stringify(cfg.operator_policy || {}, null, 2)); setFanOutJson(JSON.stringify(weight.fan_out, null, 2)); setNoiseJson(JSON.stringify(weight.noise, null, 2));
      setState('ready'); setMessage(null);
    } catch (cause) { setState(current => current === 'loading' ? 'unavailable' : 'stale'); setMessage(cause instanceof Error ? cause.message : 'Settings could not be loaded.'); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const writesAllowed = recoveryStore?.writable !== false && recoveryStore?.config_recovery?.status !== 'write_incomplete';
  const flash = (value: string) => { setMessage(value); window.setTimeout(() => setMessage(null), 3200); };

  const saveSafety = async () => {
    if (!writesAllowed) return;
    try { await api.updateSettings(opsecDraft); flash('Safety settings saved.'); void load(); } catch (cause) { flash(cause instanceof Error ? cause.message : 'Safety settings failed to save.'); }
  };
  const savePlanning = async () => {
    if (!writesAllowed) return;
    try {
      const failurePatterns = JSON.parse(failureJson);
      const operatorPolicy = JSON.parse(policyJson);
      const fanOut = JSON.parse(fanOutJson);
      const noise = JSON.parse(noiseJson);
      await Promise.all([api.updateConfig({ failure_patterns: failurePatterns, operator_policy: operatorPolicy }), api.updateFrontierWeights({ fan_out: fanOut, noise })]);
      flash('Planning configuration saved.'); void load();
    } catch (cause) { flash(cause instanceof Error ? cause.message : 'Planning JSON is invalid or was rejected.'); }
  };

  return <div className="h-full min-h-0 overflow-y-auto">
    <ManageToolbar title="Settings" detail="Safety, planning, agent defaults, and runtime preferences use the existing validated write APIs." state={state} onRefresh={() => void load()} />
    {message && <InlineNotice tone={/failed|invalid|rejected|could not/i.test(message) ? 'danger' : 'success'}>{message}</InlineNotice>}
    {!writesAllowed && <InlineNotice tone="warning">Recovery state is read-only. Configuration controls remain visible for diagnosis but saves are disabled.</InlineNotice>}

    <SettingsGroup number="01" title="Safety" description="OPSEC posture, approvals, time window, blacklist, and dispatch limits.">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <label className="flex items-center gap-2 text-[10px] text-foreground"><input type="checkbox" checked={Boolean(opsecDraft.enabled)} onChange={event => setOpsecDraft(current => ({ ...current, enabled: event.target.checked }))} />OPSEC enforcement enabled</label>
        <Field label="Max noise"><input type="number" min={0} max={1} step={0.05} value={opsecDraft.max_noise ?? 0.7} onChange={event => setOpsecDraft(current => ({ ...current, max_noise: Number(event.target.value) }))} className="manage-input" /></Field>
        <Field label="Approval mode"><select value={opsecDraft.approval_mode || 'approve-critical'} onChange={event => setOpsecDraft(current => ({ ...current, approval_mode: event.target.value as OpsecConfig['approval_mode'] }))} className="manage-input"><option value="auto-approve">Auto approve</option><option value="approve-critical">Approve critical</option><option value="approve-all">Approve all</option></select></Field>
        <Field label="Approval timeout (ms)"><input type="number" min={1000} value={opsecDraft.approval_timeout_ms ?? 300000} onChange={event => setOpsecDraft(current => ({ ...current, approval_timeout_ms: Number(event.target.value) }))} className="manage-input" /></Field>
      </div>
      <Field label="Blacklisted techniques (comma separated)"><input value={(opsecDraft.blacklisted_techniques || []).join(', ')} onChange={event => setOpsecDraft(current => ({ ...current, blacklisted_techniques: event.target.value.split(',').map(value => value.trim()).filter(Boolean) }))} className="manage-input" /></Field>
      <div className="flex justify-end"><ActionButton variant="primary" disabled={!writesAllowed} onClick={() => void saveSafety()}><Save className="h-3 w-3" />Save safety</ActionButton></div>
    </SettingsGroup>

    <SettingsGroup number="02" title="Planning" description="Frontier weights, failure patterns, inference visibility, and durable operator policy.">
      <div className="grid gap-3 lg:grid-cols-2"><JsonField label="Frontier fan-out weights" value={fanOutJson} onChange={setFanOutJson} /><JsonField label="Frontier noise weights" value={noiseJson} onChange={setNoiseJson} /><JsonField label="Failure patterns" value={failureJson} onChange={setFailureJson} /><JsonField label="Operator policy and dispatch limits" value={policyJson} onChange={setPolicyJson} /></div>
      <div className="text-[9px] text-muted-foreground">{rules.length} active inference rules are server-owned; this view does not create new execution semantics.</div>
      <div className="flex justify-end gap-2"><ActionButton disabled={!writesAllowed} onClick={() => void api.resetFrontierWeights().then(load)}>Reset weights</ActionButton><ActionButton variant="primary" disabled={!writesAllowed} onClick={() => void savePlanning()}><Save className="h-3 w-3" />Save planning</ActionButton></div>
    </SettingsGroup>

    <SettingsGroup number="03" title="Agents" description="Available archetypes and the active runtime’s operator defaults.">
      <div className="divide-y divide-border-subtle border-y border-border-subtle">{archetypes.map(archetype => <div key={archetype.id} className="grid min-h-9 grid-cols-[10rem_1fr_10rem] items-center gap-3 py-2 text-[9px]"><span className="font-medium text-foreground">{archetype.label}</span><span className="truncate text-muted-foreground">{archetype.description || 'Specialized operator role'}</span><span className="font-mono text-muted-foreground">{archetype.id}</span></div>)}</div>
      {!archetypes.length && <WorkspaceEmpty title="Archetypes unavailable" detail="The runtime did not expose the archetype registry." />}
    </SettingsGroup>

    <SettingsGroup number="04" title="Runtime preferences" description="Engagement identity and remaining operator/runtime defaults.">
      <div className="grid gap-3 sm:grid-cols-3"><ManageFact label="Engagement" value={config?.name || '—'} /><ManageFact label="Profile" value={settings?.profile || config?.profile || '—'} /><ManageFact label="Community resolution" value={String(config?.community_resolution ?? 'default')} /></div>
      <div className="text-[9px] text-muted-foreground">Settings not represented by a dedicated control remain preserved in server configuration and are not overwritten by these partial updates.</div>
    </SettingsGroup>
  </div>;
}

interface DiagnosticItem {
  id: string;
  group: string;
  label: string;
  status: 'pass' | 'warning' | 'fail' | 'running';
  detail: string;
  action: string;
}

export function NativeDiagnostics() {
  const connected = useEngagementStore(state => state.connected);
  const setRecovery = useEngagementStore(state => state.setPersistenceRecovery);
  const [items, setItems] = useState<DiagnosticItem[]>([]);
  const [recovery, setLocalRecovery] = useState<PersistenceRecoveryStatus | null>(null);
  const [running, setRunning] = useState(false);
  const [resolveBusy, setResolveBusy] = useState<'use_file' | 'use_state' | null>(null);

  const run = useCallback(async () => {
    setRunning(true);
    setItems([{ id: 'transport', group: 'Synchronization and transport', label: 'Main transport', status: connected ? 'pass' : 'warning', detail: connected ? 'WebSocket state is synchronized.' : 'The dashboard is retaining last-good data while disconnected.', action: connected ? 'No action required.' : 'Restore the daemon or transport, then reconcile.' }]);
    const checks = await Promise.allSettled([api.getRecovery(), api.getHealth(), api.getReadiness(), api.getTools(), api.getMcpTools(), api.getTelemetry()]);
    const next: DiagnosticItem[] = [];
    const recoveryResult = checks[0];
    if (recoveryResult.status === 'fulfilled') {
      const value = recoveryResult.value; setLocalRecovery(value); setRecovery(value);
      const diverged = value.config_recovery?.status === 'diverged' || value.config_recovery?.status === 'write_incomplete';
      next.push({ id: 'recovery', group: 'Recovery and configuration convergence', label: 'Durable recovery', status: value.status === 'critical' ? 'fail' : diverged || value.status === 'warning' ? 'warning' : 'pass', detail: `${value.outcome} from ${value.source}; ${value.highest_contiguous_applied_seq}/${value.highest_on_disk_seq} journal entries applied.`, action: diverged ? 'Choose a validated authority below; writes remain constrained until convergence.' : 'No recovery action required.' });
    } else next.push(failedDiagnostic('recovery', 'Recovery and configuration convergence', 'Recovery API', recoveryResult.reason, 'Inspect daemon persistence and the configured state path.'));
    const healthResult = checks[1];
    if (healthResult.status === 'fulfilled') {
      const value = healthResult.value; next.push({ id: 'health', group: 'Runtime and transport health', label: 'Graph runtime', status: value.health_checks.status === 'critical' ? 'fail' : value.health_checks.status === 'warning' ? 'warning' : 'pass', detail: `${value.graph_stats.nodes} nodes · ${value.graph_stats.edges} edges · ${value.health_checks.issues.length} issues.`, action: value.health_checks.issues[0]?.message || 'No action required.' });
    } else next.push(failedDiagnostic('health', 'Runtime and transport health', 'Runtime health API', healthResult.reason, 'Restart or repair the dashboard API.'));
    const readinessResult = checks[2];
    if (readinessResult.status === 'fulfilled') next.push({ id: 'readiness', group: 'Synchronization and transport', label: 'Readiness projection', status: readinessResult.value.status === 'critical' ? 'fail' : readinessResult.value.status === 'warning' ? 'warning' : 'pass', detail: `Readiness reports ${readinessResult.value.status}.`, action: readinessResult.value.status === 'ready' ? 'No action required.' : 'Review readiness warnings before operating.' });
    else next.push(failedDiagnostic('readiness', 'Synchronization and transport', 'Readiness API', readinessResult.reason, 'Reconcile API and dashboard build versions.'));
    const toolsResult = checks[3];
    if (toolsResult.status === 'fulfilled') {
      const available = toolsResult.value.installed_count; const missing = toolsResult.value.missing_count;
      next.push({ id: 'tools', group: 'Tool and API checks', label: 'Host tool inventory', status: missing ? 'warning' : 'pass', detail: `${available} available · ${missing} optional tools missing.`, action: missing ? 'Install only the host tools required by the active workflow.' : 'No action required.' });
    } else next.push(failedDiagnostic('tools', 'Tool and API checks', 'Host tools', toolsResult.reason, 'Check host permissions and tool discovery.'));
    const mcpResult = checks[4];
    if (mcpResult.status === 'fulfilled') next.push({ id: 'mcp', group: 'Tool and API checks', label: 'MCP registry', status: 'pass', detail: `${mcpResult.value.tools.length} registered tools passed the dashboard contract.`, action: 'No action required.' });
    else next.push(failedDiagnostic('mcp', 'Tool and API checks', 'MCP registry', mcpResult.reason, 'Regenerate the tool manifest and reconcile server/dashboard builds.'));
    const telemetryResult = checks[5];
    if (telemetryResult.status === 'fulfilled') next.push({ id: 'telemetry', group: 'Persistence and tape status', label: 'Telemetry projection', status: telemetryResult.value.health.status === 'critical' ? 'fail' : telemetryResult.value.health.status === 'warning' ? 'warning' : 'pass', detail: `${telemetryResult.value.graph_stats.total_nodes} nodes · ${telemetryResult.value.graph_stats.total_edges} edges · ${telemetryResult.value.health.counts.warning} warnings.`, action: telemetryResult.value.health.top_issues[0]?.message || 'No action required.' });
    else next.push(failedDiagnostic('telemetry', 'Persistence and tape status', 'Telemetry API', telemetryResult.reason, 'Inspect telemetry configuration; operational state remains authoritative.'));
    setItems(current => [current[0], ...next]); setRunning(false);
  }, [connected, setRecovery]);
  useEffect(() => { void run(); }, [run]);

  const resolve = async (mode: 'use_file' | 'use_state') => {
    const config = recovery?.config_recovery;
    if (!config?.file_hash || !config.state_hash) return;
    const authority = mode === 'use_file' ? 'apply validated engagement.json semantics to runtime and durable state' : 'overwrite engagement.json from durable state';
    if (!window.confirm(`Confirm ${mode}: ${authority}?`)) return;
    setResolveBusy(mode);
    try { await api.resolveConfigDivergence({ resolution: mode, expected_file_hash: config.file_hash, expected_state_hash: config.state_hash }); await run(); }
    finally { setResolveBusy(null); }
  };

  const groups = [...new Set(items.map(item => item.group))];
  return <div className="h-full min-h-0 overflow-y-auto"><ManageToolbar title="Diagnostics" detail="One stream for recovery, runtime, synchronization, tools, persistence, and smoke results." state={running ? 'loading' : 'ready'} onRefresh={() => void run()} actions={<ActionButton variant="primary" disabled={running} onClick={() => void run()}>{running ? 'Running…' : 'Run all checks'}</ActionButton>} />
    {recovery?.config_recovery?.status === 'diverged' && <InlineNotice tone="warning"><span className="min-w-0 flex-1">Configuration ownership is diverged. Recovery controls preserve hash preconditions and the server’s read-only constraints.</span><ActionButton size="xs" disabled={Boolean(resolveBusy)} onClick={() => void resolve('use_file')}>Use file</ActionButton><ActionButton size="xs" disabled={Boolean(resolveBusy)} onClick={() => void resolve('use_state')}>Use durable state</ActionButton></InlineNotice>}
    {groups.map(group => <section key={group} className="border-b border-border-subtle"><SectionHeading title={group} count={items.filter(item => item.group === group).length} /><div>{items.filter(item => item.group === group).map(item => <div key={item.id} className="grid min-h-12 grid-cols-[1rem_minmax(10rem,0.8fr)_minmax(14rem,1.4fr)_minmax(14rem,1fr)] items-start gap-3 border-t border-border-subtle px-5 py-2"><DiagnosticCue status={item.status} /><div><div className="text-[10px] font-medium text-foreground">{item.label}</div><div className="font-mono text-[8px] text-muted-foreground">{item.id}</div></div><div className="text-[9px] leading-4 text-muted-foreground">{item.detail}</div><div className="text-[9px] leading-4 text-foreground">{item.action}</div></div>)}</div></section>)}
  </div>;
}

function ManageToolbar({ title, detail, state, onRefresh, actions }: { title: string; detail: string; state: LoadState; onRefresh: () => void; actions?: React.ReactNode }) {
  return <div className="flex min-h-14 items-center gap-3 border-b border-border-subtle px-5 py-2"><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold text-foreground">{title}</h2><p className="mt-0.5 text-[10px] text-muted-foreground">{detail}</p></div><StatusPill tone={state === 'ready' ? 'success' : state === 'stale' ? 'warning' : state === 'unavailable' ? 'danger' : 'accent'}>{state}</StatusPill>{actions}<button type="button" onClick={onRefresh} className="rounded p-1.5 text-muted-foreground hover:bg-hover hover:text-foreground" title="Refresh"><RefreshCw className={cn('h-3.5 w-3.5', state === 'loading' && 'animate-spin')} /></button></div>;
}

function ScopeEditor({ scope, onClose, onSaved }: { scope: NonNullable<EngagementConfig['scope']>; onClose: () => void; onSaved: () => void }) {
  const [draft, setDraft] = useState({ cidrs: (scope.cidrs || []).join('\n'), domains: (scope.domains || []).join('\n'), exclusions: (scope.exclusions || []).join('\n') });
  const [preview, setPreview] = useState<api.ScopeChangePreview | null>(null);
  const [busy, setBusy] = useState(false);
  const body = { cidrs: lines(draft.cidrs), domains: lines(draft.domains), exclusions: lines(draft.exclusions) };
  const review = async () => { setBusy(true); try { setPreview(await api.previewScope(body)); } finally { setBusy(false); } };
  const apply = async () => { setBusy(true); try { const current = await api.getConfig(); const fresh = await api.previewScope(body); if (JSON.stringify(fresh) !== JSON.stringify(preview) || JSON.stringify(current.scope || {}) !== JSON.stringify(scope)) { setPreview(fresh); return; } await api.updateScope(body); onSaved(); } finally { setBusy(false); } };
  return <Modal title="Edit runtime scope" detail="Scope changes use the canonical server dry-run. If concurrent state changes the impact, review is required again." onClose={onClose}><div className="grid gap-3 sm:grid-cols-3"><Multiline label="CIDRs" value={draft.cidrs} onChange={value => { setDraft(current => ({ ...current, cidrs: value })); setPreview(null); }} /><Multiline label="Domains" value={draft.domains} onChange={value => { setDraft(current => ({ ...current, domains: value })); setPreview(null); }} /><Multiline label="Exclusions" value={draft.exclusions} onChange={value => { setDraft(current => ({ ...current, exclusions: value })); setPreview(null); }} /></div>{preview && <div className="mt-3 grid grid-cols-2 gap-2 rounded border border-border-subtle bg-background p-3 text-[9px] sm:grid-cols-4"><ManageFact label="Entering scope" value={String(preview.nodes_entering_scope)} /><ManageFact label="Leaving scope" value={String(preview.nodes_leaving_scope)} /><ManageFact label="Added" value={String(preview.added.cidrs.length + preview.added.domains.length + preview.added.exclusions.length)} /><ManageFact label="Removed" value={String(preview.removed.cidrs.length + preview.removed.domains.length + preview.removed.exclusions.length)} /></div>}<div className="mt-4 flex justify-end gap-2"><ActionButton onClick={onClose}>Cancel</ActionButton>{preview ? <ActionButton variant="primary" disabled={busy} onClick={() => void apply()}>Confirm scope update</ActionButton> : <ActionButton variant="primary" disabled={busy} onClick={() => void review()}>{busy ? 'Previewing…' : 'Review impact'}</ActionButton>}</div></Modal>;
}

function CreateEngagementDialog({ templates, onClose, onCreated }: { templates: EngagementTemplate[]; onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState(''); const [profile, setProfile] = useState('network'); const [templateId, setTemplateId] = useState(''); const [cidrs, setCidrs] = useState(''); const [domains, setDomains] = useState(''); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const create = async () => { setBusy(true); setError(null); try { if (templateId) await api.createEngagementFromTemplate(templateId, { name }); else await api.createEngagement({ name, profile: profile as 'network', cidrs: lines(cidrs), domains: lines(domains) }); onCreated(); } catch (cause) { setError(cause instanceof Error ? cause.message : 'Engagement creation failed.'); } finally { setBusy(false); } };
  return <Modal title="New engagement" detail="Creates a restart-loadable library configuration. It does not silently switch the active runtime." onClose={onClose}><div className="grid gap-3 sm:grid-cols-2"><Field label="Name"><input value={name} onChange={event => setName(event.target.value)} className="manage-input" /></Field><Field label="Template"><select value={templateId} onChange={event => setTemplateId(event.target.value)} className="manage-input"><option value="">No template</option>{templates.map(template => <option key={template.id} value={template.id}>{template.name}</option>)}</select></Field><Field label="Profile"><select value={profile} onChange={event => setProfile(event.target.value)} className="manage-input"><option value="network">Network</option><option value="web_app">Web app</option><option value="cloud">Cloud</option><option value="hybrid">Hybrid</option><option value="goad_ad">GOAD AD</option><option value="single_host">Single host</option></select></Field><span />{!templateId && <><Multiline label="CIDRs" value={cidrs} onChange={setCidrs} /><Multiline label="Domains" value={domains} onChange={setDomains} /></>}</div>{error && <InlineNotice tone="danger">{error}</InlineNotice>}<div className="mt-4 flex justify-end gap-2"><ActionButton onClick={onClose}>Cancel</ActionButton><ActionButton variant="primary" disabled={busy || !name.trim()} onClick={() => void create()}>{busy ? 'Creating…' : 'Create configuration'}</ActionButton></div></Modal>;
}

function LibraryInspector({ detail, onClose, onSaved }: { detail: EngagementDetail; onClose: () => void; onSaved: () => void }) {
  const [json, setJson] = useState(JSON.stringify({ name: detail.name, profile: detail.profile, scope: detail.scope, opsec: detail.opsec, failure_patterns: detail.failure_patterns, objectives: detail.objectives, phases: detail.phases, operator_policy: detail.operator_policy }, null, 2));
  const [error, setError] = useState<string | null>(null);
  return <WorkspaceInspector label="Library engagement" title={detail.name} identifier={detail.id} onClose={onClose}><div className="space-y-3"><StatusPill tone={detail.is_active ? 'success' : 'muted'}>{detail.is_active ? 'active runtime record' : 'restart-loadable'}</StatusPill><div className="grid gap-y-2 text-[9px]"><ManageFact label="Config" value={detail.config_path || '—'} mono /><ManageFact label="State" value={detail.state_path || '—'} mono /></div><JsonField label="Validated library configuration" value={json} onChange={setJson} rows={18} />{error && <div className="text-[9px] text-destructive">{error}</div>}<ActionButton variant="primary" onClick={() => { try { const parsed = JSON.parse(json); void api.updateEngagement(detail.id, parsed).then(onSaved).catch(cause => setError(cause instanceof Error ? cause.message : 'Update failed.')); } catch (cause) { setError(cause instanceof Error ? cause.message : 'Invalid JSON.'); } }}><Save className="h-3 w-3" />Save library record</ActionButton><div className="text-[9px] leading-4 text-muted-foreground">Saving changes the library record only. Use the recorded config path as restart guidance to activate another engagement.</div></div></WorkspaceInspector>;
}

function ObjectiveCreator({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false); const [description, setDescription] = useState('');
  if (!open) return <ActionButton size="xs" onClick={() => setOpen(true)}><Plus className="h-3 w-3" />Add objective</ActionButton>;
  return <div className="flex items-center gap-1"><input value={description} onChange={event => setDescription(event.target.value)} placeholder="Objective description" className="h-7 w-64 rounded border border-border-subtle bg-background px-2 text-[9px] outline-none" /><ActionButton size="xs" variant="primary" disabled={!description.trim()} onClick={() => void api.addObjective({ description }).then(() => { setOpen(false); setDescription(''); onCreated(); })}>Add</ActionButton><ActionButton size="xs" onClick={() => setOpen(false)}>Cancel</ActionButton></div>;
}

function GraphExportButton() {
  const [busy, setBusy] = useState(false); const [detail, setDetail] = useState('');
  const run = async () => { setBusy(true); try { const graph = await api.exportGraphJson(); const blob = new Blob([JSON.stringify(graph, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `overwatch-graph-${new Date().toISOString().slice(0, 10)}.json`; anchor.click(); URL.revokeObjectURL(url); setDetail(`${graph.nodes.length} nodes · ${graph.edges.length} edges`); } catch { setDetail('Export failed'); } finally { setBusy(false); } };
  return <div><ActionButton disabled={busy} onClick={() => void run()}><Download className="h-3 w-3" />{busy ? 'Exporting…' : 'Export graph JSON'}</ActionButton>{detail && <div className="mt-1 text-[8px] text-muted-foreground">{detail}</div>}</div>;
}

function BundleButton() {
  const [busy, setBusy] = useState(false); const [detail, setDetail] = useState('');
  const run = async () => { setBusy(true); try { const result = await downloadDashboardResource(buildDashboardPath('bundleEngagement', {})); setDetail(`${result.filename}${result.bytes ? ` · ${(result.bytes / 1024 / 1024).toFixed(2)} MiB` : ''}`); } catch (cause) { setDetail(cause instanceof Error ? cause.message : 'Bundle failed'); } finally { setBusy(false); } };
  return <div><ActionButton disabled={busy} onClick={() => void run()}><Download className="h-3 w-3" />{busy ? 'Building…' : 'Download engagement bundle'}</ActionButton>{detail && <div className="mt-1 text-[8px] text-muted-foreground">{detail}</div>}</div>;
}

function SettingsGroup({ number, title, description, children }: { number: string; title: string; description: string; children: React.ReactNode }) { return <section className="border-b border-border-subtle px-5 py-4"><div className="grid gap-4 lg:grid-cols-[11rem_1fr]"><div><div className="font-mono text-[8px] text-accent">{number}</div><h3 className="mt-1 text-xs font-semibold text-foreground">{title}</h3><p className="mt-1 text-[9px] leading-4 text-muted-foreground">{description}</p></div><div className="space-y-3">{children}</div></div></section>; }
function SectionHeading({ title, count, action }: { title: string; count?: number; action?: React.ReactNode }) { return <div className="flex min-h-10 items-center gap-2 px-5"><h3 className="text-[10px] font-semibold uppercase tracking-[0.12em] text-foreground">{title}</h3>{count != null && <span className="rounded bg-elevated px-1.5 font-mono text-[8px] text-muted-foreground">{count}</span>}<div className="ml-auto">{action}</div></div>; }
function ManageFact({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div className="min-w-0"><div className="text-[8px] uppercase tracking-[0.12em] text-muted">{label}</div><div className={cn('mt-0.5 break-words text-[10px] text-foreground', mono && 'font-mono')}>{value}</div></div>; }
function StructuredList({ title, empty, rows }: { title: string; empty: string; rows: Array<{ title: string; meta: string; id: string }> }) { return <div><div className="mb-1 text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground">{title}</div>{rows.length ? <div className="divide-y divide-border-subtle border-y border-border-subtle">{rows.map(row => <div key={row.id} className="py-2"><div className="text-[10px] text-foreground">{row.title}</div><div className="mt-0.5 text-[8px] text-muted-foreground">{row.meta}</div></div>)}</div> : <div className="text-[9px] text-muted-foreground">{empty}</div>}</div>; }
function Field({ label, children }: { label: string; children: React.ReactNode }) { return <label className="flex min-w-0 flex-col gap-1 text-[9px] text-muted-foreground">{label}{children}</label>; }
function JsonField({ label, value, onChange, rows = 8 }: { label: string; value: string; onChange: (value: string) => void; rows?: number }) { return <Field label={label}><textarea rows={rows} value={value} onChange={event => onChange(event.target.value)} spellCheck={false} className="w-full resize-y rounded border border-border-subtle bg-background p-2 font-mono text-[9px] leading-4 text-foreground outline-none focus:border-accent/50" /></Field>; }
function Multiline({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) { return <Field label={`${label} · one per line`}><textarea rows={5} value={value} onChange={event => onChange(event.target.value)} className="w-full rounded border border-border-subtle bg-background p-2 font-mono text-[9px] text-foreground outline-none focus:border-accent/50" /></Field>; }
function InlineNotice({ tone, children }: { tone: 'success' | 'warning' | 'danger'; children: React.ReactNode }) { return <div className={cn('mx-5 my-2 flex items-center gap-2 rounded border px-3 py-2 text-[9px]', tone === 'success' ? 'border-success/20 bg-success/5 text-success' : tone === 'warning' ? 'border-warning/20 bg-warning/5 text-warning' : 'border-destructive/20 bg-destructive/5 text-destructive')}>{children}</div>; }
function Modal({ title, detail, onClose, children }: { title: string; detail: string; onClose: () => void; children: React.ReactNode }) { return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-6" role="dialog" aria-modal="true" aria-label={title}><div className="max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-lg border border-border bg-elevated p-4 shadow-2xl"><div className="flex items-start gap-3"><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold text-foreground">{title}</h2><p className="mt-1 text-[10px] text-muted-foreground">{detail}</p></div><button type="button" onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground"><XCircle className="h-4 w-4" /></button></div><div className="mt-4">{children}</div></div></div>; }
function DiagnosticCue({ status }: { status: DiagnosticItem['status'] }) { if (status === 'pass') return <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 text-success" />; if (status === 'running') return <RefreshCw className="mt-0.5 h-3.5 w-3.5 animate-spin text-accent" />; if (status === 'fail') return <XCircle className="mt-0.5 h-3.5 w-3.5 text-destructive" />; return <AlertTriangle className="mt-0.5 h-3.5 w-3.5 text-warning" />; }
function failedDiagnostic(id: string, group: string, label: string, cause: unknown, action: string): DiagnosticItem { return { id, group, label, status: 'fail', detail: cause instanceof Error ? cause.message : 'The check could not complete.', action }; }
function lines(value: string): string[] { return value.split(/\r?\n|,/).map(item => item.trim()).filter(Boolean); }
