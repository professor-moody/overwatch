import { useState, useEffect, useCallback } from 'react';
import { TagInput } from '../shared';
import { cn } from '../../lib/utils';
import {
  getConfig,
  updateConfig,
  addObjective,
  updateObjective,
  deleteObjective,
  getSettings,
  getHealth,
  getFrontierWeights,
  updateFrontierWeights,
  resetFrontierWeights,
  getTools,
  getInferenceRules,
  getTemplates,
  exportGraphJson,
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
} from '../../lib/types';

export function SettingsPanel() {
  const [config, setConfig] = useState<EngagementConfig | null>(null);
  const [settings, setSettings] = useState<Record<string, unknown> | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [weights, setWeights] = useState<FrontierWeights | null>(null);
  const [toolCheck, setToolCheck] = useState<ToolCheckResult | null>(null);
  const [rules, setRules] = useState<InferenceRuleInfo[] | null>(null);
  const [templates, setTemplates] = useState<EngagementTemplate[] | null>(null);
  const [saveStatus, setSaveStatus] = useState('');

  const load = useCallback(async () => {
    try {
      const [cfg, sets, h, w, tpl] = await Promise.all([
        getConfig(),
        getSettings().catch(() => null),
        getHealth().catch(() => null),
        getFrontierWeights().catch(() => null),
        getTemplates().then(r => r.templates).catch(() => null),
      ]);
      setConfig(cfg);
      setSettings(sets as Record<string, unknown>);
      setHealth(h);
      setWeights(w);
      setTemplates(tpl);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { load(); }, [load]);

  const flash = (msg: string, _ok = true) => {
    setSaveStatus(msg);
    setTimeout(() => setSaveStatus(''), 3000);
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Settings</h2>
        <div className="flex items-center gap-3">
          {saveStatus && (
            <span className={cn('text-xs', saveStatus.includes('Error') ? 'text-destructive' : 'text-success')}>
              {saveStatus}
            </span>
          )}
          <button onClick={load} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {config && <IdentitySection config={config} onSave={async (body) => {
        try { await updateConfig(body); flash('Saved \u2713'); load(); } catch { flash('Error saving', false); }
      }} />}
      {config && <ObjectivesSection objectives={config.objectives || []} onReload={load} />}
      {config && <FailurePatternsSection patterns={config.failure_patterns || []} onSave={async (fp) => {
        try { await updateConfig({ failure_patterns: fp } as Partial<EngagementConfig>); flash('Saved \u2713'); load(); } catch { flash('Error saving', false); }
      }} />}
      {settings && <OpsecSection settings={settings} onSave={async (body) => {
        try { await updateConfig(body); flash('Saved \u2713'); load(); } catch { flash('Error saving', false); }
      }} />}
      {weights && <FrontierWeightsSection weights={weights} onSave={async (w) => {
        try { await updateFrontierWeights(w); flash('Weights saved \u2713'); load(); } catch { flash('Error saving', false); }
      }} onReset={async () => {
        try { await resetFrontierWeights(); flash('Weights reset \u2713'); load(); } catch { flash('Error resetting', false); }
      }} />}
      <ToolInventorySection tools={toolCheck} onRefresh={async () => {
        try { setToolCheck(await getTools()); } catch {}
      }} />
      <InferenceRulesSection rules={rules} onRefresh={async () => {
        try { const r = await getInferenceRules(); setRules(r.rules); } catch {}
      }} />
      {templates && <TemplatesBrowserSection templates={templates} />}
      <GraphExportSection health={health} />
      <HealthSection health={health} onRefresh={async () => { try { setHealth(await getHealth()); } catch {} }} />
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
          <input value={name} onChange={e => setName(e.target.value)} className="settings-input" />
        </Field>
        <Field label="Profile">
          <select value={profile} onChange={e => setProfile(e.target.value)} className="settings-input">
            <option value="">—</option>
            <option value="network">network</option>
            <option value="ad">ad</option>
            <option value="cloud">cloud</option>
            <option value="webapp">webapp</option>
            <option value="hybrid">hybrid</option>
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

/* ============ Objectives ============ */

function ObjectivesSection({ objectives, onReload }: { objectives: Objective[]; onReload: () => void }) {
  const [showForm, setShowForm] = useState(false);
  const [desc, setDesc] = useState('');
  const [nodeType, setNodeType] = useState('');
  const [edgeTypes, setEdgeTypes] = useState('');

  const submit = async () => {
    if (!desc.trim()) return;
    try {
      await addObjective({
        description: desc.trim(),
        target_node_type: nodeType || undefined,
        achievement_edge_types: edgeTypes ? edgeTypes.split(',').map(s => s.trim()).filter(Boolean) : undefined,
      });
      setDesc(''); setNodeType(''); setEdgeTypes(''); setShowForm(false);
      onReload();
    } catch { /* silent */ }
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
              <input type="checkbox" checked={obj.achieved} onChange={() => toggle(obj)} className="mt-0.5 accent-success" />
              <div className="flex-1 min-w-0">
                <div className="text-xs">{obj.description}</div>
                <div className="text-[10px] text-muted-foreground mt-0.5 flex gap-2">
                  {obj.target_node_type && <span>type: {obj.target_node_type}</span>}
                  {obj.achievement_edge_types?.length ? <span>edges: {obj.achievement_edge_types.join(', ')}</span> : null}
                  {obj.achieved_at && <span className="text-success">{'\u2713'} {new Date(obj.achieved_at).toLocaleDateString()}</span>}
                </div>
              </div>
              <button onClick={() => remove(obj.id)} className="text-muted-foreground hover:text-destructive text-xs">&times;</button>
            </div>
          ))}
        </div>
      )}

      {showForm ? (
        <div className="space-y-2 p-3 rounded border border-border bg-elevated mt-2">
          <input value={desc} onChange={e => setDesc(e.target.value)} placeholder="Objective description" className="settings-input w-full" />
          <div className="grid grid-cols-2 gap-2">
            <input value={nodeType} onChange={e => setNodeType(e.target.value)} placeholder="Target node type (optional)" className="settings-input" />
            <input value={edgeTypes} onChange={e => setEdgeTypes(e.target.value)} placeholder="Edge types, comma-sep (optional)" className="settings-input" />
          </div>
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

function OpsecSection({ settings, onSave }: { settings: Record<string, unknown>; onSave: (b: Partial<EngagementConfig>) => Promise<void> }) {
  const opsec = (settings as { opsec?: Record<string, unknown> }).opsec || {};
  const noiseState = (settings as { noise_state?: Record<string, number> }).noise_state || {};

  const [maxNoise, setMaxNoise] = useState<number>((opsec.max_noise as number) ?? 0.7);
  const [approvalMode, setApprovalMode] = useState<string>((opsec.approval_mode as string) || 'approve-critical');
  const [timeout, setTimeout_] = useState<number>(Math.round(((opsec.approval_timeout_ms as number) || 300000) / 1000));
  const [twStart, setTwStart] = useState<string>((opsec.time_window as { start_hour?: number })?.start_hour?.toString() ?? '');
  const [twEnd, setTwEnd] = useState<string>((opsec.time_window as { end_hour?: number })?.end_hour?.toString() ?? '');
  const [blacklist, setBlacklist] = useState<string>(((opsec.blacklisted_techniques as string[]) || []).join('\n'));

  const spent = (noiseState.global_noise_spent as number) || 0;
  const max = maxNoise || 1;
  const pct = Math.min(100, (spent / max) * 100);

  const save = () => {
    const tw = twStart && twEnd ? { start_hour: parseInt(twStart), end_hour: parseInt(twEnd) } : null;
    onSave({
      opsec: {
        max_noise: maxNoise,
        approval_mode: approvalMode as 'auto-approve' | 'approve-critical' | 'approve-all',
        approval_timeout_seconds: timeout,
        time_window: tw ? { start: tw.start_hour, end: tw.end_hour } : undefined,
        blacklisted_techniques: blacklist.split('\n').map(s => s.trim()).filter(Boolean),
      },
    });
  };

  return (
    <Section title="OPSEC">
      <div className="space-y-3">
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
            <select value={approvalMode} onChange={e => setApprovalMode(e.target.value)} className="settings-input">
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
            <input type="number" min="0" max="23" value={twStart} onChange={e => setTwStart(e.target.value)} className="settings-input" placeholder="—" />
          </Field>
          <Field label="Time Window End (hour)">
            <div className="flex gap-2">
              <input type="number" min="0" max="23" value={twEnd} onChange={e => setTwEnd(e.target.value)} className="settings-input flex-1" placeholder="—" />
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

/* ============ Health ============ */

function HealthSection({ health, onRefresh }: { health: HealthStatus | null; onRefresh: () => Promise<void> }) {
  const stats = health?.graph_stats;
  const checks = health?.health_checks;
  const warnings = checks?.warnings || [];
  const errors = checks?.errors || [];
  const totalIssues = warnings.length + errors.length;

  return (
    <Section title="Health">
      <div className="flex items-center gap-2">
        <span className={cn('w-2 h-2 rounded-full', totalIssues === 0 ? 'bg-success' : errors.length > 0 ? 'bg-destructive' : 'bg-warning')} />
        <span className="text-xs">
          {stats ? `${stats.nodes} nodes, ${stats.edges} edges${health?.ad_context ? ' (AD)' : ''}` : 'Loading\u2026'}
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
          {errors.map((e, i) => <div key={i} className="text-xs text-destructive">{'\u2715'} {e.message}</div>)}
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
            {loading ? 'Scanning\u2026' : 'Scan Tools'}
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
              {loading ? 'Scanning\u2026' : 'Rescan'}
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
            {loading ? 'Loading\u2026' : 'Load Rules'}
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
                        <span className="text-accent">{'\u2192'} {p.edge_type}</span>
                        <span className="text-muted-foreground">{'\u2192'} {p.target_selector}</span>
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
                    Phases: {tpl.phases.map(p => p.name).join(' \u2192 ')}
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
      setLastSize(`${sizeMB} MB \u2014 ${graph.nodes.length} nodes, ${graph.edges.length} edges`);
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
          {exporting ? 'Exporting\u2026' : 'Export JSON'}
        </button>
      </div>
      {lastSize && <p className="text-[10px] text-muted-foreground mt-1">{lastSize}</p>}
    </Section>
  );
}

/* ============ Layout helpers ============ */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="bg-surface border border-border rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-medium">{title}</h3>
      {children}
    </section>
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
