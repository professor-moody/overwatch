import { useState, useEffect, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { ENGAGEMENT_PROFILES, PROFILE_LABELS } from '../../lib/profiles';
import {
  getConfig,
  updateConfig,
  addObjective,
  updateObjective,
  deleteObjective,
  getSettings,
  updateSettings,
  getHealth,
  getFrontierWeights,
  updateFrontierWeights,
  resetFrontierWeights,
  getTools,
  getInferenceRules,
  getTemplates,
  exportGraphJson,
  getRecovery,
  resolveConfigDivergence,
} from '../../lib/api';
import type {
  EngagementConfig,
  Objective,
  FailurePattern,
  HealthStatus,
  FrontierWeights,
  ToolCheckResult,
  InferenceRuleInfo,
  EngagementTemplate,
  OperatorPolicy,
  OperatorApprovalRule,
  OpsecConfig,
  PersistenceRecoveryStatus,
} from '../../lib/types';
import {
  OBJECTIVE_EDGE_TYPES,
  OBJECTIVE_NODE_TYPES,
  type ObjectiveCreateRequest,
  type SettingsDto,
} from '@overwatch/dashboard-contracts';
import { downloadDashboardResource } from '../../lib/dashboard-transport';
import { buildDashboardPath } from '@overwatch/dashboard-api-contracts';
import { recoveryPresentation } from '../../lib/recovery-presentation';
import { useEngagementStore } from '../../stores/engagement-store';
import { ActionButton, PageHeader, PanelSection, StatusPill } from '../shared/primitives';

export function SettingsPanel() {
  const [config, setConfig] = useState<EngagementConfig | null>(null);
  const [settings, setSettings] = useState<SettingsDto | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [weights, setWeights] = useState<FrontierWeights | null>(null);
  const [toolCheck, setToolCheck] = useState<ToolCheckResult | null>(null);
  const [rules, setRules] = useState<InferenceRuleInfo[] | null>(null);
  const [templates, setTemplates] = useState<EngagementTemplate[] | null>(null);
  const [saveStatus, setSaveStatus] = useState('');
  const [recovery, setRecovery] = useState<PersistenceRecoveryStatus | null>(null);
  const [recoveryError, setRecoveryError] = useState('');
  const [resolvingMode, setResolvingMode] = useState<'use_file' | 'use_state' | null>(null);
  const setPersistenceRecovery = useEngagementStore(state => state.setPersistenceRecovery);

  const load = useCallback(async () => {
    try {
      setRecoveryError('');
      const [cfg, sets, h, w, tpl, recoveryStatus] = await Promise.all([
        getConfig(),
        getSettings().catch(() => null),
        getHealth().catch(() => null),
        getFrontierWeights().catch(() => null),
        getTemplates().then(r => r.templates).catch(() => null),
        getRecovery().catch(error => {
          setRecoveryError(error instanceof Error ? error.message : 'Unable to inspect recovery status');
          return null;
        }),
      ]);
      setConfig(cfg);
      setSettings(sets);
      setHealth(h);
      setWeights(w);
      setTemplates(tpl);
      if (recoveryStatus) {
        setRecovery(recoveryStatus);
        setPersistenceRecovery(recoveryStatus);
      }
    } catch { /* silent */ }
  }, [setPersistenceRecovery]);

  useEffect(() => { load(); }, [load]);

  const flash = (msg: string, _ok = true) => {
    setSaveStatus(msg);
    setTimeout(() => setSaveStatus(''), 3000);
  };

  const resolveRecovery = async (mode: 'use_file' | 'use_state') => {
    const configRecovery = recovery?.config_recovery;
    if (!configRecovery?.file_hash || !configRecovery.state_hash) {
      flash('Error: refresh recovery status before reconciling', false);
      return;
    }
    const authority = mode === 'use_file'
      ? 'apply the validated engagement.json semantics to runtime and durable state'
      : 'overwrite engagement.json with the durable-state configuration';
    if (!window.confirm(`Confirm ${mode}: ${authority}?`)) return;
    setResolvingMode(mode);
    try {
      await resolveConfigDivergence({
        resolution: mode,
        expected_file_hash: configRecovery.file_hash,
        expected_state_hash: configRecovery.state_hash,
      });
      flash(`Configuration reconciled with ${mode === 'use_file' ? 'file' : 'durable state'} authority ✓`);
    } catch (error) {
      flash(`Error: ${error instanceof Error ? error.message : 'reconciliation failed'}`, false);
    } finally {
      await load();
      setResolvingMode(null);
    }
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        title="Settings"
        actions={
          <>
          {saveStatus && (
            <span className={cn('text-xs', saveStatus.includes('Error') ? 'text-destructive' : 'text-success')}>
              {saveStatus}
            </span>
          )}
          <ActionButton onClick={load} variant="secondary">
            Refresh
          </ActionButton>
          </>
        }
      />

      <RecoverySection
        recovery={recovery}
        error={recoveryError}
        resolvingMode={resolvingMode}
        onResolve={resolveRecovery}
      />

      {config && <IdentitySection config={config} onSave={async (body) => {
        try { await updateConfig(body); flash('Saved ✓'); load(); } catch { flash('Error saving', false); }
      }} />}
      {config && <ObjectivesSection objectives={config.objectives || []} onReload={load} />}
      {config && <FailurePatternsSection patterns={config.failure_patterns || []} onSave={async (fp) => {
        try { await updateConfig({ failure_patterns: fp } as Partial<EngagementConfig>); flash('Saved ✓'); load(); } catch { flash('Error saving', false); }
      }} />}
      {settings && <OpsecSection settings={settings} onSave={async (body) => {
        try { await updateSettings(body); flash('Saved ✓'); load(); } catch { flash('Error saving', false); }
      }} />}
      {config && <OperatorPolicySection policy={config.operator_policy} onSave={async (p) => {
        try { await updateConfig({ operator_policy: p } as Partial<EngagementConfig>); flash('Saved ✓'); load(); } catch { flash('Error saving', false); }
      }} />}
      {weights && <FrontierWeightsSection weights={weights} onSave={async (w) => {
        try { await updateFrontierWeights(w); flash('Weights saved ✓'); load(); } catch { flash('Error saving', false); }
      }} onReset={async () => {
        try { await resetFrontierWeights(); flash('Weights reset ✓'); load(); } catch { flash('Error resetting', false); }
      }} />}
      <ToolInventorySection tools={toolCheck} onRefresh={async () => {
        try { setToolCheck(await getTools()); } catch {}
      }} />
      <InferenceRulesSection rules={rules} onRefresh={async () => {
        try { const r = await getInferenceRules(); setRules(r.rules); } catch {}
      }} />
      {templates && <TemplatesBrowserSection templates={templates} />}
      <GraphExportSection health={health} />
      <BundleSection />
      <HealthSection health={health} onRefresh={async () => { try { setHealth(await getHealth()); } catch {} }} />
    </div>
  );
}

/* ============ Recovery ============ */

function shortHash(hash?: string): string {
  return hash ? `${hash.slice(0, 12)}…${hash.slice(-8)}` : '—';
}

export function RecoverySection({
  recovery,
  error,
  resolvingMode,
  onResolve,
}: {
  recovery: PersistenceRecoveryStatus | null;
  error: string;
  resolvingMode: 'use_file' | 'use_state' | null;
  onResolve: (mode: 'use_file' | 'use_state') => Promise<void>;
}) {
  if (!recovery && !error) return null;
  const view = recoveryPresentation(recovery);
  const config = recovery?.config_recovery;
  const migration = recovery?.state_migration;
  const configTone = config?.status === 'diverged'
    ? 'warning'
    : config?.status === 'write_incomplete'
      ? 'danger'
      : 'success';

  return (
    <PanelSection
      title="Recovery and configuration ownership"
      meta={config && <StatusPill tone={configTone}>{config.status.replace(/_/g, ' ')}</StatusPill>}
      className={view?.tone === 'critical'
        ? 'border-destructive/30'
        : view?.tone === 'warning'
          ? 'border-warning/30'
          : undefined}
    >
      {error && <p role="alert" className="mb-3 text-xs text-destructive">Unable to refresh recovery status: {error}</p>}
      {recovery && (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
            <RecoveryValue label="Persistence" value={`${recovery.outcome} from ${recovery.source}`} />
            <RecoveryValue
              label="Journal checkpoint"
              value={`${recovery.highest_contiguous_applied_seq} / ${recovery.highest_on_disk_seq} on disk`}
            />
            <RecoveryValue label="Writable" value={recovery.writable ? 'yes' : 'no'} />
            <RecoveryValue
              label="State format"
              value={migration
                ? `${migration.observed_state_version ?? '—'} / supported ${migration.supported_state_version}`
                : '—'}
            />
            <RecoveryValue
              label="Journal format"
              value={migration
                ? `${migration.observed_journal_version ?? '—'} / supported ${migration.supported_journal_version}`
                : `${recovery.journal.format_version ?? '—'}`}
            />
            <RecoveryValue label="Migration" value={migration?.status.replace(/_/g, ' ') ?? '—'} />
            <RecoveryValue label="File revision" value={config?.file_revision?.toString() ?? '—'} />
            <RecoveryValue label="State revision" value={config?.state_revision?.toString() ?? '—'} />
            <RecoveryValue label="Runtime revision" value={config?.runtime_revision?.toString() ?? '—'} />
            <RecoveryValue label="File hash" value={shortHash(config?.file_hash)} title={config?.file_hash} mono />
            <RecoveryValue label="State hash" value={shortHash(config?.state_hash)} title={config?.state_hash} mono />
            <RecoveryValue label="Runtime hash" value={shortHash(config?.runtime_hash)} title={config?.runtime_hash} mono />
          </div>

          {(view || config?.reason || recovery.reason) && (
            <div className={cn(
              'mt-3 rounded border px-3 py-2 text-xs',
              view?.tone === 'critical'
                ? 'border-destructive/20 bg-destructive/5 text-destructive'
                : view?.tone === 'warning'
                  ? 'border-warning/20 bg-warning/5 text-warning'
                  : 'border-border bg-elevated text-muted-foreground',
            )}>
              <div className="font-medium">{view?.title ?? 'Recovery status'}</div>
              <div className="mt-0.5">{view?.message ?? config?.reason ?? recovery.reason}</div>
              {recovery.persistence_reason && (
                <div className="mt-1">Underlying persistence: {recovery.persistence_reason}</div>
              )}
              {view?.blockedReason && view.blockedReason !== recovery.persistence_reason && (
                <div className="mt-1">{view.blockedReason}</div>
              )}
            </div>
          )}

          {config?.intent_present && (
            <div className="mt-3 text-xs text-muted-foreground">
              Recorded write intent: <code title={config.intent_path}>{config.intent_path ?? 'present'}</code>
            </div>
          )}
          {migration?.backup_path && (
            <div className="mt-3 text-xs text-muted-foreground">
              Migration backup: <code title={migration.backup_path}>{migration.backup_path}</code>
              {migration.backup_manifest_sha256 && (
                <> · manifest <code title={migration.backup_manifest_sha256}>{shortHash(migration.backup_manifest_sha256)}</code></>
              )}
            </div>
          )}
          {config?.last_resolution && (
            <div className="mt-1 text-xs text-muted-foreground">Last resolution: {config.last_resolution}</div>
          )}
          {recovery.runtime_ownership_warnings?.length ? (
            <div className="mt-3 rounded border border-warning/20 bg-warning/5 px-3 py-2 text-xs text-warning">
              <div className="font-medium">Runtime ownership needs review</div>
              <ul className="mt-1 space-y-1">
                {recovery.runtime_ownership_warnings.map(warning => (
                  <li key={warning.run_id}>
                    <code>{warning.run_id}</code>
                    {warning.pid !== undefined ? ` · PID ${warning.pid}` : ''}
                    {` · ${warning.message}`}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {config?.status === 'diverged' && view && (
            <div className="mt-4 flex flex-wrap gap-2">
              {view.canUseFile && (
                <ActionButton
                  variant="warning"
                  disabled={resolvingMode !== null}
                  onClick={() => onResolve('use_file')}
                  title="Validate engagement.json, apply its semantic diff, and make runtime/state/file share a new revision"
                >
                  {resolvingMode === 'use_file' ? 'Applying file…' : 'Use file authority'}
                </ActionButton>
              )}
              {view.canUseState && (
                <ActionButton
                  variant="secondary"
                  disabled={resolvingMode !== null}
                  onClick={() => onResolve('use_state')}
                  title="Atomically restore engagement.json from the durable-state configuration"
                >
                  {resolvingMode === 'use_state' ? 'Restoring file…' : 'Use durable state'}
                </ActionButton>
              )}
              {!view.canUseFile && !view.canUseState && (
                <span className="text-xs text-muted-foreground">{view.blockedReason ?? 'No reconciliation mode is available.'}</span>
              )}
            </div>
          )}
        </>
      )}
    </PanelSection>
  );
}

function RecoveryValue({
  label,
  value,
  title,
  mono = false,
}: {
  label: string;
  value: string;
  title?: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={cn('truncate text-foreground', mono && 'font-mono')} title={title}>{value}</div>
    </div>
  );
}

/* ============ Identity ============ */

function IdentitySection({ config, onSave }: { config: EngagementConfig; onSave: (b: Partial<EngagementConfig>) => Promise<void> }) {
  const [name, setName] = useState(config.name || '');
  const [profile, setProfile] = useState(config.profile || '');
  const [communityRes, setCommunityRes] = useState(config.community_resolution ?? 1.0);

  useEffect(() => {
    setName(config.name || '');
    setProfile(config.profile || '');
    setCommunityRes(config.community_resolution ?? 1.0);
  }, [config]);

  return (
    <Section title="Identity">
      <div className="grid grid-cols-2 gap-4">
        <Field label="Name">
          <input value={name} onChange={e => setName(e.target.value)} className="settings-input w-full" />
        </Field>
        <Field label="Profile">
          {/* Options come from the shared ENGAGEMENT_PROFILES list so they can't drift
              from the engagementConfigSchema `profile` enum (src/types.ts). This panel
              previously emitted "ad"/"webapp", which aren't in the enum, so saving those
              failed validation (400) and the valid profiles were unselectable. */}
          <select value={profile} onChange={e => setProfile(e.target.value)} className="settings-input w-full">
            <option value="">—</option>
            {ENGAGEMENT_PROFILES.map(p => <option key={p} value={p}>{PROFILE_LABELS[p]}</option>)}
          </select>
        </Field>
      </div>
      <Field label={`Community Resolution: ${communityRes.toFixed(1)}`}>
        <input type="range" min="0.1" max="5.0" step="0.1" value={communityRes} onChange={e => setCommunityRes(parseFloat(e.target.value))}
          className="w-full accent-accent" />
      </Field>
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        {config.id && <span>ID: <code className="text-foreground">{config.id}</code></span>}
        {config.created_at && <span>Created: {new Date(config.created_at).toLocaleString()}</span>}
        {config.template && <span>Template: {config.template}</span>}
      </div>
      <button onClick={() => onSave({ name, profile: profile || undefined, community_resolution: communityRes })}
        className="settings-save-btn">Save Identity</button>
    </Section>
  );
}

/* ============ Scope ============ */

/* ============ Objectives ============ */

function ObjectivesSection({ objectives, onReload }: { objectives: Objective[]; onReload: () => void }) {
  const [showForm, setShowForm] = useState(false);
  const [desc, setDesc] = useState('');
  const [nodeType, setNodeType] = useState<NonNullable<ObjectiveCreateRequest['target_node_type']> | ''>('');
  const [edgeTypes, setEdgeTypes] = useState<NonNullable<ObjectiveCreateRequest['achievement_edge_types']>>([]);
  const [formError, setFormError] = useState('');

  const submit = async () => {
    if (!desc.trim()) return;
    try {
      setFormError('');
      await addObjective({
        description: desc.trim(),
        target_node_type: nodeType || undefined,
        achievement_edge_types: edgeTypes.length > 0 ? edgeTypes : undefined,
      });
      setDesc(''); setNodeType(''); setEdgeTypes([]); setShowForm(false);
      onReload();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Unable to add objective');
    }
  };

  const toggle = async (obj: Objective) => {
    try { await updateObjective(obj.id, { achieved: !obj.achieved }); onReload(); } catch {}
  };

  const remove = async (id: string) => {
    try { await deleteObjective(id); onReload(); } catch {}
  };

  return (
    <Section title="Objectives">
      {objectives.length === 0 ? (
        <p className="text-xs text-muted-foreground">No objectives defined</p>
      ) : (
        <div className="space-y-2">
          {objectives.map(obj => (
            <div key={obj.id} className={cn('flex items-start gap-2 p-2 rounded border', obj.achieved ? 'border-success/20 bg-success/5' : 'border-border bg-elevated')}>
              <input
                type="checkbox"
                aria-label={`Mark objective ${obj.description} ${obj.achieved ? 'incomplete' : 'achieved'}`}
                checked={obj.achieved}
                onChange={() => toggle(obj)}
                className="mt-0.5 accent-success"
              />
              <div className="flex-1 min-w-0">
                <div className="text-xs">{obj.description}</div>
                <div className="text-[10px] text-muted-foreground mt-0.5 flex gap-2">
                  {obj.target_node_type && <span>type: {obj.target_node_type}</span>}
                  {obj.achievement_edge_types?.length ? <span>edges: {obj.achievement_edge_types.join(', ')}</span> : null}
                  {obj.achieved_at && <span className="text-success">{'✓'} {new Date(obj.achieved_at).toLocaleDateString()}</span>}
                </div>
              </div>
              <button
                aria-label={`Delete objective ${obj.description}`}
                onClick={() => remove(obj.id)}
                className="text-muted-foreground hover:text-destructive text-xs"
              >&times;</button>
            </div>
          ))}
        </div>
      )}

      {showForm ? (
        <div className="space-y-2 p-3 rounded border border-border bg-elevated mt-2">
          <input value={desc} onChange={e => setDesc(e.target.value)} placeholder="Objective description" className="settings-input w-full" />
          <div className="grid grid-cols-2 gap-2">
            <select
              value={nodeType}
              onChange={e => setNodeType(e.target.value as typeof nodeType)}
              className="settings-input w-full"
              aria-label="Target node type"
            >
              <option value="">Any target node type</option>
              {OBJECTIVE_NODE_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
            </select>
            <select
              multiple
              value={edgeTypes}
              onChange={e => setEdgeTypes(Array.from(e.currentTarget.selectedOptions, option => option.value) as typeof edgeTypes)}
              className="settings-input w-full min-h-24"
              aria-label="Achievement edge types"
            >
              {OBJECTIVE_EDGE_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
            </select>
          </div>
          {formError && <p role="alert" className="text-xs text-destructive">{formError}</p>}
          <div className="flex gap-2">
            <button onClick={submit} className="settings-save-btn">Add</button>
            <button onClick={() => setShowForm(false)} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
          </div>
        </div>
      ) : (
        <button onClick={() => setShowForm(true)} className="text-xs text-accent hover:underline mt-1">+ Add objective</button>
      )}
    </Section>
  );
}

/* ============ Failure Patterns ============ */

function FailurePatternsSection({ patterns, onSave }: { patterns: FailurePattern[]; onSave: (fp: FailurePattern[]) => Promise<void> }) {
  const [list, setList] = useState<FailurePattern[]>(patterns);
  const [showForm, setShowForm] = useState(false);
  const [technique, setTechnique] = useState('');
  const [target, setTarget] = useState('');
  const [warning, setWarning] = useState('');

  useEffect(() => { setList(patterns); }, [patterns]);

  const add = () => {
    if (!technique.trim() || !warning.trim()) return;
    const updated = [...list, { technique: technique.trim(), target_pattern: target.trim() || undefined, warning: warning.trim() }];
    setList(updated);
    onSave(updated);
    setTechnique(''); setTarget(''); setWarning(''); setShowForm(false);
  };

  const remove = (i: number) => {
    const updated = list.filter((_, idx) => idx !== i);
    setList(updated);
    onSave(updated);
  };

  return (
    <Section title="Failure Patterns">
      {list.length === 0 ? (
        <p className="text-xs text-muted-foreground">No failure patterns</p>
      ) : (
        <div className="space-y-1.5">
          {list.map((fp, i) => (
            <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-elevated border border-border">
              <span className="font-mono text-accent">{fp.technique}</span>
              {fp.target_pattern && <span className="text-muted-foreground">{fp.target_pattern}</span>}
              <span className="text-warning flex-1 truncate">{fp.warning}</span>
              <button onClick={() => remove(i)} className="text-muted-foreground hover:text-destructive">&times;</button>
            </div>
          ))}
        </div>
      )}
      {showForm ? (
        <div className="space-y-2 p-3 rounded border border-border bg-elevated mt-2">
          <input value={technique} onChange={e => setTechnique(e.target.value)} placeholder="Technique" className="settings-input w-full" />
          <input value={target} onChange={e => setTarget(e.target.value)} placeholder="Target pattern (optional)" className="settings-input w-full" />
          <input value={warning} onChange={e => setWarning(e.target.value)} placeholder="Warning message" className="settings-input w-full" />
          <div className="flex gap-2">
            <button onClick={add} className="settings-save-btn">Add</button>
            <button onClick={() => setShowForm(false)} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
          </div>
        </div>
      ) : (
        <button onClick={() => setShowForm(true)} className="text-xs text-accent hover:underline mt-1">+ Add failure pattern</button>
      )}
    </Section>
  );
}

/* ============ OPSEC Settings ============ */

function OpsecSection({ settings, onSave }: { settings: SettingsDto; onSave: (b: Partial<OpsecConfig>) => Promise<void> }) {
  const opsec = settings.opsec;
  const noiseState = settings.noise_state;
  const opsecStatus = settings.opsec_status;

  const [enabled, setEnabled] = useState(opsec.enabled);
  const [maxNoise, setMaxNoise] = useState<number>(opsec.max_noise ?? 0.7);
  const [approvalMode, setApprovalMode] = useState<string>(opsec.approval_mode || 'approve-critical');
  const [timeout, setTimeout_] = useState<number>(Math.round((opsec.approval_timeout_ms || 300000) / 1000));
  const [twStart, setTwStart] = useState<string>(opsec.time_window?.start_hour?.toString() ?? '');
  const [twEnd, setTwEnd] = useState<string>(opsec.time_window?.end_hour?.toString() ?? '');
  const [blacklist, setBlacklist] = useState<string>((opsec.blacklisted_techniques || []).join('\n'));

  const spent = noiseState.global_noise_spent || 0;
  const max = maxNoise || 1;
  const pct = Math.min(100, (spent / max) * 100);

  const save = () => {
    // 0.5: send the keys the server actually consumes. Previously this
    // posted approval_timeout_seconds and {start, end}, which the server
    // silently dropped (config-manager expected approval_timeout_ms and
    // {start_hour, end_hour}). The strict zod parser on the server-side
    // route now rejects unknown keys, so the client must match exactly.
    const tw = twStart && twEnd ? { start_hour: parseInt(twStart), end_hour: parseInt(twEnd) } : null;
    onSave({
      enabled,
      max_noise: maxNoise,
      approval_mode: approvalMode as 'auto-approve' | 'approve-critical' | 'approve-all',
      approval_timeout_ms: timeout * 1000,
      time_window: tw,
      blacklisted_techniques: blacklist.split('\n').map(s => s.trim()).filter(Boolean),
    });
  };

  return (
    <Section title="OPSEC">
      <div className="space-y-3">
        <label className="flex items-center justify-between gap-3 rounded border border-border bg-elevated px-3 py-2 text-xs">
          <span>
            <span className="block font-medium text-foreground">Enforce OPSEC policy</span>
            <span className="text-muted-foreground">Apply the configured approval, noise, blacklist, and time-window controls.</span>
          </span>
          <input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} className="h-4 w-4 accent-accent" />
        </label>
        {/* Phase B: inert badge — config has noise/blacklist/time_window set but enabled=false. */}
        {opsecStatus?.inert && (
          <div className="rounded border border-warning bg-warning/10 px-3 py-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="rounded bg-warning px-1.5 py-0.5 font-mono text-[10px] uppercase text-warning-foreground">OPSEC INERT</span>
              <span className="text-muted-foreground">Configured fields are not enforced (opsec.enabled=false).</span>
            </div>
            <div className="mt-1 font-mono text-[11px] text-muted-foreground">
              configured: {opsecStatus.configured_fields.join(', ')}
            </div>
          </div>
        )}

        {/* Noise gauge */}
        <div>
          <div className="flex justify-between text-xs mb-1">
            <span className="text-muted-foreground">Noise Budget</span>
            <span className="font-mono">{spent.toFixed(2)} / {max.toFixed(2)}</span>
          </div>
          <div className="h-2 bg-elevated rounded-full overflow-hidden">
            <div className={cn('h-full rounded-full transition-all', pct > 85 ? 'bg-destructive' : pct > 60 ? 'bg-warning' : 'bg-success')}
              style={{ width: `${pct}%` }} />
          </div>
        </div>

        <Field label={`Max Noise: ${maxNoise.toFixed(2)}`}>
          <input type="range" min="0" max="1" step="0.01" value={maxNoise} onChange={e => setMaxNoise(parseFloat(e.target.value))}
            className="w-full accent-accent" />
        </Field>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Approval Mode">
            <select value={approvalMode} onChange={e => setApprovalMode(e.target.value)} className="settings-input w-full">
              <option value="auto-approve">Auto Approve</option>
              <option value="approve-critical">Approve Critical</option>
              <option value="approve-all">Approve All</option>
            </select>
          </Field>
          <Field label={`Approval Timeout: ${timeout}s`}>
            <input type="range" min="10" max="1800" step="10" value={timeout} onChange={e => setTimeout_(parseInt(e.target.value))}
              className="w-full accent-accent" />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Time Window Start (hour)">
            <input type="number" min="0" max="23" value={twStart} onChange={e => setTwStart(e.target.value)} className="settings-input w-full" placeholder="—" />
          </Field>
          <Field label="Time Window End (hour)">
            <div className="flex gap-2">
              <input type="number" min="0" max="23" value={twEnd} onChange={e => setTwEnd(e.target.value)} className="settings-input flex-1 min-w-0" placeholder="—" />
              <button onClick={() => { setTwStart(''); setTwEnd(''); }} className="text-xs text-muted-foreground hover:text-foreground">Clear</button>
            </div>
          </Field>
        </div>

        <Field label="Blacklisted Techniques">
          <textarea value={blacklist} onChange={e => setBlacklist(e.target.value)} rows={3}
            className="settings-input w-full font-mono" placeholder="One technique per line" />
        </Field>
      </div>
      <button onClick={save} className="settings-save-btn">Save OPSEC</button>
    </Section>
  );
}

/* ============ Operator Policy ============ */

const APPROVAL_MODES = ['auto-approve', 'approve-critical', 'approve-all'] as const;
const HOST_CLASSES = ['', 'in_scope', 'unverified', 'excluded'] as const;

function OperatorPolicySection({ policy, onSave }: { policy?: OperatorPolicy; onSave: (p: OperatorPolicy) => Promise<void> }) {
  const [rules, setRules] = useState<OperatorApprovalRule[]>(policy?.approval_rules ?? []);
  const [maxSubnet, setMaxSubnet] = useState<string>(policy?.dispatch_limits?.max_per_subnet?.toString() ?? '');
  const [maxTarget, setMaxTarget] = useState<string>(policy?.dispatch_limits?.max_per_target?.toString() ?? '');

  const setRule = (i: number, next: Partial<OperatorApprovalRule>) =>
    setRules(rs => rs.map((r, idx) => idx === i ? { ...r, ...next, match: { ...r.match, ...next.match } } : r));
  const addRule = () => setRules(rs => [...rs, { match: {}, require: 'approve-all' }]);
  const removeRule = (i: number) => setRules(rs => rs.filter((_, idx) => idx !== i));

  const save = () => {
    const dispatch_limits: OperatorPolicy['dispatch_limits'] = {};
    if (maxSubnet.trim()) dispatch_limits.max_per_subnet = parseInt(maxSubnet, 10);
    if (maxTarget.trim()) dispatch_limits.max_per_target = parseInt(maxTarget, 10);
    // Drop empty match fields so the strict server schema accepts the rule.
    const cleanRules = rules.map(r => ({
      require: r.require,
      match: Object.fromEntries(Object.entries(r.match).filter(([, v]) => v)) as OperatorApprovalRule['match'],
    }));
    onSave({
      version: 1,
      ...(cleanRules.length ? { approval_rules: cleanRules } : {}),
      ...(Object.keys(dispatch_limits).length ? { dispatch_limits } : {}),
    });
  };

  return (
    <Section title="Operator Policy">
      <p className="mb-3 text-xs text-muted-foreground">
        Durable, enforced rules — not prompt text. Approval rules can only <em>tighten</em> the gate
        (the strictest match wins, never weaker than the engagement/phase mode). Dispatch caps limit
        concurrent target-facing agents per /24 or host.
      </p>

      <Field label="Approval rules">
        <div className="space-y-2">
          {rules.length === 0 && <div className="text-xs text-muted-foreground">No rules — the engagement/phase approval mode applies as-is.</div>}
          {rules.map((r, i) => (
            <div key={i} className="grid grid-cols-[1fr_1.2fr_1.2fr_1fr_auto] items-center gap-1.5">
              <select value={r.match.host_class ?? ''} onChange={e => setRule(i, { match: { host_class: (e.target.value || undefined) as OperatorApprovalRule['match']['host_class'] } })} className="settings-input" title="host class">
                {HOST_CLASSES.map(h => <option key={h} value={h}>{h || 'any host'}</option>)}
              </select>
              <input value={r.match.network ?? ''} onChange={e => setRule(i, { match: { network: e.target.value || undefined } })} className="settings-input" placeholder="network CIDR" />
              <input value={r.match.technique ?? ''} onChange={e => setRule(i, { match: { technique: e.target.value || undefined } })} className="settings-input" placeholder="technique" />
              <select value={r.require} onChange={e => setRule(i, { require: e.target.value as OperatorApprovalRule['require'] })} className="settings-input" title="require">
                {APPROVAL_MODES.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
              <button onClick={() => removeRule(i)} className="text-xs text-destructive hover:underline" title="Remove rule">✕</button>
            </div>
          ))}
          <button onClick={addRule} className="text-xs text-accent hover:underline">+ Add rule</button>
        </div>
      </Field>

      <div className="mt-3 grid grid-cols-2 gap-4">
        <Field label="Max target-facing agents / subnet (/24)">
          <input type="number" min="1" value={maxSubnet} onChange={e => setMaxSubnet(e.target.value)} className="settings-input w-full" placeholder="unlimited" />
        </Field>
        <Field label="Max target-facing agents / host">
          <input type="number" min="1" value={maxTarget} onChange={e => setMaxTarget(e.target.value)} className="settings-input w-full" placeholder="unlimited" />
        </Field>
      </div>

      <button onClick={save} className="settings-save-btn">Save Policy</button>
    </Section>
  );
}

/* ============ Health ============ */

function HealthSection({ health, onRefresh }: { health: HealthStatus | null; onRefresh: () => Promise<void> }) {
  const stats = health?.graph_stats;
  const checks = health?.health_checks;
  const issues = checks?.issues || [];
  const warnings = issues.filter(issue => issue.severity === 'warning');
  const critical = issues.filter(issue => issue.severity === 'critical');
  const totalIssues = issues.length;

  return (
    <Section title="Health">
      <div className="flex items-center gap-2">
        <span className={cn('w-2 h-2 rounded-full', totalIssues === 0 ? 'bg-success' : critical.length > 0 ? 'bg-destructive' : 'bg-warning')} />
        <span className="text-xs">
          {stats ? `${stats.nodes} nodes, ${stats.edges} edges${health?.ad_context ? ' (AD)' : ''}` : 'Loading…'}
        </span>
        <button onClick={onRefresh} className="text-xs text-muted-foreground hover:text-foreground ml-auto">Refresh</button>
      </div>
      {stats?.node_types && (
        <div className="text-xs text-muted-foreground mt-2">
          {Object.entries(stats.node_types).sort(([, a], [, b]) => b - a).map(([t, c]) => `${t}: ${c}`).join(' \u00b7 ')}
        </div>
      )}
      {totalIssues > 0 && (
        <div className="mt-2 space-y-0.5">
          {critical.map((e, i) => <div key={i} className="text-xs text-destructive">{'\u2715'} {e.message}</div>)}
          {warnings.map((w, i) => <div key={i} className="text-xs text-warning">{'\u26a0'} {w.message}</div>)}
        </div>
      )}
    </Section>
  );
}

/* ============ Frontier Weights ============ */

function FrontierWeightsSection({ weights, onSave, onReset }: {
  weights: FrontierWeights;
  onSave: (w: Partial<FrontierWeights>) => Promise<void>;
  onReset: () => Promise<void>;
}) {
  const [fanOut, setFanOut] = useState<Record<string, number>>(weights.fan_out);
  const [noise, setNoise] = useState<Record<string, number>>(weights.noise);

  useEffect(() => { setFanOut(weights.fan_out); setNoise(weights.noise); }, [weights]);

  const updateVal = (obj: Record<string, number>, setter: (v: Record<string, number>) => void, key: string, val: string) => {
    const num = parseFloat(val);
    if (!isNaN(num)) setter({ ...obj, [key]: num });
  };

  return (
    <Section title="Frontier Weights">
      <div className="grid grid-cols-2 gap-6">
        <div>
          <h4 className="text-xs font-medium mb-2 text-muted-foreground">Fan-out</h4>
          <WeightTable data={fanOut} onChange={(k, v) => updateVal(fanOut, setFanOut, k, v)} />
        </div>
        <div>
          <h4 className="text-xs font-medium mb-2 text-muted-foreground">Noise</h4>
          <WeightTable data={noise} onChange={(k, v) => updateVal(noise, setNoise, k, v)} />
        </div>
      </div>
      <div className="flex gap-2 mt-2">
        <button onClick={() => onSave({ fan_out: fanOut, noise })} className="settings-save-btn">Save Weights</button>
        <button onClick={onReset} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors">Reset</button>
      </div>
    </Section>
  );
}

function WeightTable({ data, onChange }: { data: Record<string, number>; onChange: (key: string, val: string) => void }) {
  const keys = Object.keys(data).sort((a, b) => a === 'default' ? 1 : b === 'default' ? -1 : a.localeCompare(b));
  return (
    <div className="space-y-1">
      {keys.map(key => (
        <div key={key} className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground w-28 truncate font-mono">{key}</span>
          <input type="number" step="any" value={data[key]} onChange={e => onChange(key, e.target.value)}
            className="settings-input flex-1 text-right font-mono" />
        </div>
      ))}
    </div>
  );
}

/* ============ Tool Inventory ============ */

function ToolInventorySection({ tools, onRefresh }: { tools: ToolCheckResult | null; onRefresh: () => Promise<void> }) {
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    setLoading(true);
    try { await onRefresh(); } finally { setLoading(false); }
  };

  return (
    <Section title="Tool Inventory">
      {!tools ? (
        <div className="flex items-center gap-2">
          <p className="text-xs text-muted-foreground flex-1">Scan to detect installed offensive tools</p>
          <button onClick={scan} disabled={loading} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50">
            {loading ? 'Scanning…' : 'Scan Tools'}
          </button>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3 mb-2">
            <span className="text-xs">
              <span className="text-success font-medium">{tools.installed_count}</span>
              <span className="text-muted-foreground"> installed</span>
              <span className="text-muted-foreground mx-1">\u00b7</span>
              <span className="text-muted-foreground">{tools.missing_count} missing</span>
            </span>
            <button onClick={scan} disabled={loading} className="text-xs text-muted-foreground hover:text-foreground ml-auto">
              {loading ? 'Scanning…' : 'Rescan'}
            </button>
          </div>
          <div className="grid grid-cols-2 gap-1">
            {tools.tools.map(t => (
              <div key={t.name} className="flex items-center gap-2 text-xs py-1 px-2 rounded bg-elevated">
                <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', t.installed ? 'bg-success' : 'bg-muted')} />
                <span className={cn('font-mono truncate', t.installed ? 'text-foreground' : 'text-muted-foreground')}>{t.name}</span>
                {t.version && <span className="text-muted-foreground text-[10px] truncate ml-auto">{t.version.slice(0, 30)}</span>}
              </div>
            ))}
          </div>
        </>
      )}
    </Section>
  );
}

/* ============ Inference Rules ============ */

function InferenceRulesSection({ rules, onRefresh }: { rules: InferenceRuleInfo[] | null; onRefresh: () => Promise<void> }) {
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const loadRules = async () => {
    setLoading(true);
    try { await onRefresh(); } finally { setLoading(false); }
  };

  return (
    <Section title="Inference Rules">
      {!rules ? (
        <div className="flex items-center gap-2">
          <p className="text-xs text-muted-foreground flex-1">Load active inference rules from the graph engine</p>
          <button onClick={loadRules} disabled={loading} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50">
            {loading ? 'Loading…' : 'Load Rules'}
          </button>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs text-muted-foreground">{rules.length} active rules</span>
            <button onClick={loadRules} disabled={loading} className="text-xs text-muted-foreground hover:text-foreground ml-auto">Refresh</button>
          </div>
          <div className="space-y-1">
            {rules.map(rule => (
              <div key={rule.id} className="rounded border border-border bg-elevated">
                <button
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-xs hover:bg-hover transition-colors"
                  onClick={() => setExpanded(expanded === rule.id ? null : rule.id)}
                >
                  <span className="text-accent font-mono text-[10px]">{expanded === rule.id ? '\u25BC' : '\u25B6'}</span>
                  <span className="font-medium truncate flex-1">{rule.name}</span>
                  {rule.trigger.node_type && <span className="text-muted-foreground text-[10px]">{rule.trigger.node_type}</span>}
                  <span className="text-muted-foreground text-[10px]">{rule.produces.length} edge{rule.produces.length !== 1 ? 's' : ''}</span>
                </button>
                {expanded === rule.id && (
                  <div className="px-2 pb-2 text-xs space-y-1 border-t border-border pt-1.5">
                    <p className="text-muted-foreground">{rule.description}</p>
                    {rule.trigger.node_type && (
                      <div className="text-[10px]">
                        <span className="text-muted-foreground">Trigger: </span>
                        <span className="font-mono text-foreground">{rule.trigger.node_type}</span>
                        {rule.trigger.property_match && (
                          <span className="text-muted-foreground ml-1">
                            {Object.entries(rule.trigger.property_match).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')}
                          </span>
                        )}
                      </div>
                    )}
                    {rule.produces.map((p, i) => (
                      <div key={i} className="text-[10px] font-mono flex items-center gap-1.5">
                        <span className="text-muted-foreground">{p.source_selector}</span>
                        <span className="text-accent">{'→'} {p.edge_type}</span>
                        <span className="text-muted-foreground">{'→'} {p.target_selector}</span>
                        <span className="text-muted-foreground ml-auto">conf: {p.confidence}</span>
                      </div>
                    ))}
                    {rule.self_confirming && <span className="text-[10px] text-warning">self-confirming</span>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </Section>
  );
}

/* ============ Templates Browser ============ */

function TemplatesBrowserSection({ templates }: { templates: EngagementTemplate[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (templates.length === 0) {
    return (
      <Section title="Templates">
        <p className="text-xs text-muted-foreground">No templates available</p>
      </Section>
    );
  }

  return (
    <Section title="Templates">
      <p className="text-xs text-muted-foreground mb-2">{templates.length} template{templates.length !== 1 ? 's' : ''} available</p>
      <div className="space-y-1">
        {templates.map(tpl => (
          <div key={tpl.id} className="rounded border border-border bg-elevated">
            <button
              className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-xs hover:bg-hover transition-colors"
              onClick={() => setExpanded(expanded === tpl.id ? null : tpl.id)}
            >
              <span className="text-accent font-mono text-[10px]">{expanded === tpl.id ? '\u25BC' : '\u25B6'}</span>
              <span className="font-medium truncate flex-1">{tpl.name}</span>
              {tpl.profile && <span className="text-[10px] px-1 rounded bg-surface border border-border text-muted-foreground">{tpl.profile}</span>}
            </button>
            {expanded === tpl.id && (
              <div className="px-2 pb-2 text-xs space-y-1.5 border-t border-border pt-1.5">
                {tpl.description && <p className="text-muted-foreground">{tpl.description}</p>}
                {tpl.objectives && tpl.objectives.length > 0 && (
                  <div>
                    <span className="text-[10px] text-muted-foreground">Objectives: </span>
                    {tpl.objectives.map((o, i) => (
                      <span key={i} className="text-[10px] text-foreground">{i > 0 ? ', ' : ''}{o.description}</span>
                    ))}
                  </div>
                )}
                {tpl.opsec && (
                  <div className="text-[10px] text-muted-foreground flex gap-2 flex-wrap">
                    {tpl.opsec.max_noise != null && <span>noise: {tpl.opsec.max_noise}</span>}
                    {tpl.opsec.approval_mode && <span>approval: {tpl.opsec.approval_mode}</span>}
                    {tpl.opsec.blacklisted_techniques?.length ? <span>blacklist: {tpl.opsec.blacklisted_techniques.length}</span> : null}
                  </div>
                )}
                {tpl.phases && tpl.phases.length > 0 && (
                  <div className="text-[10px] text-muted-foreground">
                    Phases: {tpl.phases.map(p => p.name).join(' → ')}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </Section>
  );
}

/* ============ Graph Export ============ */

function GraphExportSection({ health }: { health: HealthStatus | null }) {
  const [exporting, setExporting] = useState(false);
  const [lastSize, setLastSize] = useState<string | null>(null);

  const doExport = async () => {
    setExporting(true);
    try {
      const graph = await exportGraphJson();
      const json = JSON.stringify(graph, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `overwatch-graph-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      const sizeMB = (blob.size / 1024 / 1024).toFixed(2);
      setLastSize(`${sizeMB} MB — ${graph.nodes.length} nodes, ${graph.edges.length} edges`);
    } catch {
      setLastSize('Export failed');
    } finally {
      setExporting(false);
    }
  };

  const stats = health?.graph_stats;

  return (
    <Section title="Graph Export">
      <div className="flex items-center gap-3">
        <div className="flex-1">
          {stats && (
            <span className="text-xs text-muted-foreground">
              Current graph: {stats.nodes} nodes, {stats.edges} edges
            </span>
          )}
        </div>
        <button onClick={doExport} disabled={exporting}
          className="text-xs px-3 py-1.5 rounded bg-accent/10 border border-accent/20 text-accent hover:bg-accent/20 transition-colors disabled:opacity-50">
          {exporting ? 'Exporting…' : 'Export JSON'}
        </button>
      </div>
      {lastSize && <p className="text-[10px] text-muted-foreground mt-1">{lastSize}</p>}
    </Section>
  );
}

/* ============ Engagement Bundle ============ */

function BundleSection() {
  const [status, setStatus] = useState<'idle' | 'building' | 'done' | 'error'>('idle');
  const [detail, setDetail] = useState<string | null>(null);

  const download = async () => {
    setStatus('building');
    setDetail(null);
    try {
      const result = await downloadDashboardResource(buildDashboardPath('bundleEngagement', {}));
      const sizeMB = result.bytes > 0 ? `${(result.bytes / 1024 / 1024).toFixed(2)} MB — ` : '';
      setStatus('done');
      setDetail(`${sizeMB}${result.filename}`);
    } catch (err) {
      setStatus('error');
      setDetail(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <Section title="Engagement Bundle">
      <div className="flex items-center gap-3">
        <div className="flex-1 text-xs text-muted-foreground">
          Archive containing the state file, evidence, and reports as a portable .tar.gz
        </div>
        <button
          onClick={download}
          disabled={status === 'building'}
          className="text-xs px-3 py-1.5 rounded bg-accent/10 border border-accent/20 text-accent hover:bg-accent/20 transition-colors disabled:opacity-50 flex-shrink-0"
        >
          {status === 'building' ? 'Building…' : 'Download Bundle'}
        </button>
      </div>
      {detail && (
        <p className={`text-[10px] mt-1 ${status === 'error' ? 'text-destructive' : 'text-muted-foreground'}`}>
          {status === 'done' ? '✓ ' : ''}{detail}
        </p>
      )}
    </Section>
  );
}

/* ============ Layout helpers ============ */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <PanelSection title={title} className="space-y-3">
      {children}
    </PanelSection>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-[11px] text-muted-foreground mb-1 block">{label}</label>
      {children}
    </div>
  );
}
