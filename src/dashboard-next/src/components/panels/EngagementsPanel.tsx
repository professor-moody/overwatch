import { useState, useEffect, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { TagInput, EmptyState, StatusBadge } from '../shared';
import { getEngagements, getTemplates, createEngagement, getEngagement, updateEngagement } from '../../lib/api';
import type {
  EngagementListItem,
  EngagementTemplate,
  EngagementDetail,
  EngagementPhase,
  PhaseCriterion,
  CampaignStrategy,
  FailurePattern,
} from '../../lib/types';

const PROFILES = ['network', 'ad', 'cloud', 'webapp', 'hybrid'] as const;
const CLOUD_PROFILES = new Set(['cloud', 'hybrid']);
const APPROVAL_MODES = [
  { value: 'auto-approve', label: 'Auto Approve' },
  { value: 'approve-critical', label: 'Approve Critical' },
  { value: 'approve-all', label: 'Approve All' },
] as const;
const STRATEGIES: CampaignStrategy[] = ['credential_spray', 'enumeration', 'post_exploitation', 'network_discovery', 'custom'];
const CRITERION_TYPES = ['always', 'phase_completed', 'objective_achieved', 'node_count', 'access_level'] as const;
const ACCESS_LEVELS = ['user', 'local_admin', 'domain_admin'] as const;

/* ============ Main Panel ============ */

export function EngagementsPanel() {
  const [engagements, setEngagements] = useState<EngagementListItem[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [templates, setTemplates] = useState<EngagementTemplate[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [loadHint, setLoadHint] = useState<EngagementListItem | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [engData, tmplData] = await Promise.all([
        getEngagements(),
        getTemplates().catch(() => ({ templates: [], total: 0 })),
      ]);
      setEngagements(engData.engagements || []);
      setActiveId(engData.active_id || null);
      setTemplates(tmplData.templates || []);
    } catch {}
  }, []);

  useEffect(() => { load(); }, [load]);

  if (detailId) {
    return (
      <EngagementDetailDrawer
        id={detailId}
        onBack={() => { setDetailId(null); load(); }}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Engagements <span className="text-muted-foreground font-normal text-sm">({engagements.length})</span>
        </h2>
        <button onClick={() => setShowForm(!showForm)} className="settings-save-btn">
          {showForm ? 'Cancel' : '+ New Engagement'}
        </button>
      </div>

      {showForm && (
        <CreateEngagementForm
          templates={templates}
          onCreated={() => { setShowForm(false); load(); }}
          onCancel={() => setShowForm(false)}
        />
      )}

      {loadHint && (
        <div className="bg-elevated border border-warning/20 rounded-lg p-3 text-xs space-y-1">
          <div className="text-warning font-medium">To load this engagement, restart the server with:</div>
          <code className="block text-foreground bg-background p-1.5 rounded font-mono">{loadHint.config_path}</code>
          <button onClick={() => setLoadHint(null)} className="text-muted-foreground hover:text-foreground">Dismiss</button>
        </div>
      )}

      {!showForm && (
        engagements.length === 0 ? (
          <EmptyState message="No engagements yet. Create one above." />
        ) : (
          <div className="space-y-2">
            {engagements.map(e => {
              const isActive = e.is_active || e.id === activeId;
              const scopeStr = e.scope_cidrs.length ? e.scope_cidrs.join(', ') : (e.scope_domains.join(', ') || '\u2014');
              return (
                <div key={e.id}
                  onClick={() => setDetailId(e.id)}
                  className={cn('bg-surface border rounded-lg p-4 cursor-pointer hover:border-accent/40 transition-colors', isActive ? 'border-accent/30' : 'border-border')}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium">{e.name}</span>
                    {isActive && <StatusBadge status="active" />}
                    {e.profile && <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-muted-foreground">{e.profile}</span>}
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground mb-1">
                    <span>{e.objectives_count} obj</span>
                    <span>{e.phases_count} phases</span>
                    {(e.exclusions_count ?? 0) > 0 && <span>{e.exclusions_count} exclusions</span>}
                  </div>
                  <div className="text-xs text-muted-foreground truncate">{scopeStr}</div>
                  <div className="flex items-center gap-2 mt-2 text-xs">
                    <span className="font-mono text-muted">{e.id}</span>
                    {e.created_at && <span className="text-muted-foreground">{new Date(e.created_at).toLocaleDateString()}</span>}
                    {!isActive && (
                      <button onClick={(ev) => { ev.stopPropagation(); setLoadHint(e); }}
                        className="ml-auto text-accent hover:underline">Load</button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )
      )}
    </div>
  );
}

/* ============ Shared Field Helpers ============ */

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-[11px] text-muted-foreground mb-1 block">{label}</label>
      {children}
    </div>
  );
}

function Section({ title, children, collapsed, onToggle }: { title: string; children: React.ReactNode; collapsed?: boolean; onToggle?: () => void }) {
  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button onClick={onToggle} type="button"
        className="w-full flex items-center justify-between px-3 py-2 bg-elevated text-xs font-medium hover:bg-elevated/80 transition-colors">
        {title}
        {onToggle && <span className="text-muted-foreground">{collapsed ? '+' : '\u2212'}</span>}
      </button>
      {!collapsed && <div className="p-3 space-y-3">{children}</div>}
    </div>
  );
}

/* ============ Create Engagement Form ============ */

function CreateEngagementForm({ templates, onCreated, onCancel }: {
  templates: EngagementTemplate[];
  onCreated: () => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState('');
  const [templateId, setTemplateId] = useState('');
  const [profile, setProfile] = useState('network');
  const [creating, setCreating] = useState(false);

  // Scope
  const [cidrs, setCidrs] = useState<string[]>([]);
  const [domains, setDomains] = useState<string[]>([]);
  const [exclusions, setExclusions] = useState<string[]>([]);
  const [hosts, setHosts] = useState<string[]>([]);
  const [urlPatterns, setUrlPatterns] = useState<string[]>([]);
  const [awsAccounts, setAwsAccounts] = useState<string[]>([]);
  const [azureSubs, setAzureSubs] = useState<string[]>([]);
  const [gcpProjects, setGcpProjects] = useState<string[]>([]);

  // OPSEC
  const [maxNoise, setMaxNoise] = useState(0.7);
  const [approvalMode, setApprovalMode] = useState('approve-critical');
  const [approvalTimeout, setApprovalTimeout] = useState(300);
  const [twStart, setTwStart] = useState('');
  const [twEnd, setTwEnd] = useState('');
  const [blacklist, setBlacklist] = useState('');

  // Objectives
  const [objectives, setObjectives] = useState<string[]>([]);

  // Failure patterns
  const [failurePatterns, setFailurePatterns] = useState<FailurePattern[]>([]);

  // Phases
  const [phases, setPhases] = useState<EngagementPhase[]>([]);

  // Collapsible sections
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ opsec: true, failures: true, phases: true });
  const toggle = (key: string) => setCollapsed(prev => ({ ...prev, [key]: !prev[key] }));

  const isCloud = CLOUD_PROFILES.has(profile);

  const applyTemplate = (id: string) => {
    setTemplateId(id);
    if (!id) return;
    const tmpl = templates.find(t => t.id === id);
    if (!tmpl) return;
    if (tmpl.profile) setProfile(tmpl.profile);
    if (tmpl.opsec?.max_noise != null) setMaxNoise(tmpl.opsec.max_noise);
    if (tmpl.opsec?.approval_mode) setApprovalMode(tmpl.opsec.approval_mode);
    if (tmpl.opsec?.blacklisted_techniques?.length) setBlacklist(tmpl.opsec.blacklisted_techniques.join('\n'));
    if (tmpl.objectives?.length) setObjectives(tmpl.objectives.map(o => o.description));
    if (tmpl.phases?.length) setPhases(tmpl.phases);
    if (tmpl.failure_patterns?.length) setFailurePatterns(tmpl.failure_patterns);
  };

  // Soft validation
  const hasScope = cidrs.length > 0 || domains.length > 0 || hosts.length > 0;
  const hasObjectives = objectives.some(o => o.trim());
  const warnings: string[] = [];
  if (!hasScope) warnings.push('No scope defined \u2014 the agent won\u2019t have targets.');
  if (!hasObjectives) warnings.push('No objectives defined \u2014 the agent won\u2019t have goals.');

  const submit = async () => {
    if (!name.trim()) return;
    setCreating(true);
    try {
      const objs = objectives.filter(d => d.trim()).map((d, i) => ({ id: `obj-${i + 1}`, description: d.trim() }));
      const tw = twStart && twEnd ? { start_hour: parseInt(twStart), end_hour: parseInt(twEnd) } : null;
      const bl = blacklist.split('\n').map(s => s.trim()).filter(Boolean);

      await createEngagement({
        name: name.trim(),
        profile,
        cidrs,
        domains,
        exclusions,
        hosts: hosts.length ? hosts : undefined,
        url_patterns: urlPatterns.length ? urlPatterns : undefined,
        aws_accounts: awsAccounts.length ? awsAccounts : undefined,
        azure_subscriptions: azureSubs.length ? azureSubs : undefined,
        gcp_projects: gcpProjects.length ? gcpProjects : undefined,
        opsec: {
          max_noise: maxNoise,
          approval_mode: approvalMode,
          approval_timeout_ms: approvalTimeout * 1000,
          time_window: tw,
          blacklisted_techniques: bl.length ? bl : undefined,
        },
        objectives: objs,
        failure_patterns: failurePatterns.length ? failurePatterns : undefined,
        phases: phases.length ? phases : undefined,
        ...(templateId ? { template_id: templateId } : {}),
      });
      onCreated();
    } catch (err) {
      alert('Failed: ' + (err instanceof Error ? err.message : 'unknown error'));
    } finally { setCreating(false); }
  };

  return (
    <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-medium">Create Engagement</h3>

      {/* Warnings */}
      {warnings.length > 0 && (
        <div className="bg-warning/5 border border-warning/20 rounded p-2 space-y-0.5">
          {warnings.map((w, i) => (
            <div key={i} className="text-xs text-warning flex items-center gap-1.5">
              <span className="w-1 h-1 rounded-full bg-warning flex-shrink-0" />
              {w}
            </div>
          ))}
        </div>
      )}

      {/* Identity */}
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name *">
          <input value={name} onChange={e => setName(e.target.value)} className="settings-input" placeholder="Engagement name" autoFocus />
        </Field>
        <Field label="Template">
          <select value={templateId} onChange={e => applyTemplate(e.target.value)} className="settings-input">
            <option value="">None</option>
            {templates.map(t => (
              <option key={t.id} value={t.id}>{t.name}{t.description ? ` \u2014 ${t.description.slice(0, 50)}` : ''}</option>
            ))}
          </select>
        </Field>
      </div>

      <Field label="Profile">
        <select value={profile} onChange={e => setProfile(e.target.value)} className="settings-input">
          {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      </Field>

      {/* Scope */}
      <Section title="Scope">
        <Field label="CIDRs"><TagInput tags={cidrs} onChange={setCidrs} placeholder="10.0.0.0/24" /></Field>
        <Field label="Domains"><TagInput tags={domains} onChange={setDomains} placeholder="corp.local" /></Field>
        <Field label="Exclusions"><TagInput tags={exclusions} onChange={setExclusions} placeholder="10.0.0.1" /></Field>
        <Field label="Hosts"><TagInput tags={hosts} onChange={setHosts} placeholder="dc01.corp.local" /></Field>
        <Field label="URL Patterns"><TagInput tags={urlPatterns} onChange={setUrlPatterns} placeholder="https://app.*" /></Field>
        {isCloud && (
          <>
            <Field label="AWS Accounts"><TagInput tags={awsAccounts} onChange={setAwsAccounts} placeholder="123456789012" /></Field>
            <Field label="Azure Subscriptions"><TagInput tags={azureSubs} onChange={setAzureSubs} placeholder="sub-id" /></Field>
            <Field label="GCP Projects"><TagInput tags={gcpProjects} onChange={setGcpProjects} placeholder="project-id" /></Field>
          </>
        )}
      </Section>

      {/* Objectives */}
      <Section title={`Objectives (${objectives.filter(o => o.trim()).length})`}>
        <ObjectivesEditor objectives={objectives} onChange={setObjectives} />
      </Section>

      {/* OPSEC */}
      <Section title="OPSEC" collapsed={collapsed.opsec} onToggle={() => toggle('opsec')}>
        <Field label={`Max Noise: ${maxNoise.toFixed(2)}`}>
          <input type="range" min="0" max="1" step="0.01" value={maxNoise} onChange={e => setMaxNoise(parseFloat(e.target.value))} className="w-full accent-accent" />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Approval Mode">
            <select value={approvalMode} onChange={e => setApprovalMode(e.target.value)} className="settings-input">
              {APPROVAL_MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </Field>
          <Field label={`Approval Timeout: ${approvalTimeout}s`}>
            <input type="range" min="10" max="1800" step="10" value={approvalTimeout} onChange={e => setApprovalTimeout(parseInt(e.target.value))} className="w-full accent-accent" />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Time Window Start (hour)">
            <input type="number" min="0" max="23" value={twStart} onChange={e => setTwStart(e.target.value)} className="settings-input" placeholder="\u2014" />
          </Field>
          <Field label="Time Window End (hour)">
            <div className="flex gap-2">
              <input type="number" min="0" max="23" value={twEnd} onChange={e => setTwEnd(e.target.value)} className="settings-input flex-1" placeholder="\u2014" />
              <button onClick={() => { setTwStart(''); setTwEnd(''); }} className="text-xs text-muted-foreground hover:text-foreground">Clear</button>
            </div>
          </Field>
        </div>
        <Field label="Blacklisted Techniques">
          <textarea value={blacklist} onChange={e => setBlacklist(e.target.value)} rows={3} className="settings-input w-full font-mono" placeholder="One technique per line" />
        </Field>
      </Section>

      {/* Failure Patterns */}
      <Section title={`Failure Patterns (${failurePatterns.length})`} collapsed={collapsed.failures} onToggle={() => toggle('failures')}>
        <FailurePatternsEditor patterns={failurePatterns} onChange={setFailurePatterns} />
      </Section>

      {/* Phases */}
      <Section title={`Phases (${phases.length})`} collapsed={collapsed.phases} onToggle={() => toggle('phases')}>
        <PhasesEditor phases={phases} onChange={setPhases} objectives={objectives} />
      </Section>

      <div className="flex gap-2 pt-1">
        <button onClick={submit} disabled={creating} className="settings-save-btn">{creating ? 'Creating\u2026' : 'Create Engagement'}</button>
        <button onClick={onCancel} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
      </div>
    </div>
  );
}

/* ============ Objectives Editor ============ */

function ObjectivesEditor({ objectives, onChange }: { objectives: string[]; onChange: (v: string[]) => void }) {
  const add = () => onChange([...objectives, '']);
  const update = (i: number, val: string) => onChange(objectives.map((o, j) => j === i ? val : o));
  const remove = (i: number) => onChange(objectives.filter((_, j) => j !== i));

  return (
    <div className="space-y-1.5">
      {objectives.map((desc, i) => (
        <div key={i} className="flex gap-2">
          <input value={desc} onChange={e => update(i, e.target.value)}
            className="settings-input flex-1" placeholder="e.g. Compromise Domain Controller" />
          <button onClick={() => remove(i)} className="text-muted-foreground hover:text-destructive text-xs">&times;</button>
        </div>
      ))}
      <button onClick={add} className="text-xs text-accent hover:underline">+ Add objective</button>
    </div>
  );
}

/* ============ Failure Patterns Editor ============ */

function FailurePatternsEditor({ patterns, onChange }: { patterns: FailurePattern[]; onChange: (v: FailurePattern[]) => void }) {
  const [technique, setTechnique] = useState('');
  const [target, setTarget] = useState('');
  const [warning, setWarning] = useState('');

  const add = () => {
    if (!technique.trim() || !warning.trim()) return;
    onChange([...patterns, { technique: technique.trim(), target_pattern: target.trim() || undefined, warning: warning.trim() }]);
    setTechnique(''); setTarget(''); setWarning('');
  };
  const remove = (i: number) => onChange(patterns.filter((_, j) => j !== i));

  return (
    <div className="space-y-2">
      {patterns.map((fp, i) => (
        <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-elevated border border-border">
          <span className="font-mono text-accent">{fp.technique}</span>
          {fp.target_pattern && <span className="text-muted-foreground">{fp.target_pattern}</span>}
          <span className="text-warning flex-1 truncate">{fp.warning}</span>
          <button onClick={() => remove(i)} className="text-muted-foreground hover:text-destructive">&times;</button>
        </div>
      ))}
      <div className="grid grid-cols-3 gap-2">
        <input value={technique} onChange={e => setTechnique(e.target.value)} placeholder="Technique" className="settings-input text-xs" />
        <input value={target} onChange={e => setTarget(e.target.value)} placeholder="Target pattern (opt)" className="settings-input text-xs" />
        <input value={warning} onChange={e => setWarning(e.target.value)} placeholder="Warning message" className="settings-input text-xs" />
      </div>
      <button onClick={add} className="text-xs text-accent hover:underline">+ Add pattern</button>
    </div>
  );
}

/* ============ Phase Builder ============ */

function PhasesEditor({ phases, onChange, objectives }: { phases: EngagementPhase[]; onChange: (v: EngagementPhase[]) => void; objectives: string[] }) {
  const addPhase = () => {
    const order = phases.length;
    onChange([...phases, {
      id: `phase-${order + 1}`,
      name: `Phase ${order + 1}`,
      order,
      strategies: [],
      entry_criteria: order === 0 ? [{ type: 'always' }] : [],
      exit_criteria: [],
    }]);
  };

  const updatePhase = (i: number, partial: Partial<EngagementPhase>) => {
    onChange(phases.map((p, j) => j === i ? { ...p, ...partial } : p));
  };

  const removePhase = (i: number) => {
    onChange(phases.filter((_, j) => j !== i).map((p, j) => ({ ...p, order: j })));
  };

  const movePhase = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= phases.length) return;
    const next = [...phases];
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next.map((p, k) => ({ ...p, order: k })));
  };

  return (
    <div className="space-y-3">
      {phases.map((phase, i) => (
        <div key={phase.id} className="border border-border rounded p-3 space-y-2 bg-elevated/50">
          <div className="flex items-center gap-2">
            <div className="flex gap-0.5">
              <button onClick={() => movePhase(i, -1)} disabled={i === 0} className="text-xs text-muted-foreground hover:text-foreground disabled:opacity-30">\u25b2</button>
              <button onClick={() => movePhase(i, 1)} disabled={i === phases.length - 1} className="text-xs text-muted-foreground hover:text-foreground disabled:opacity-30">\u25bc</button>
            </div>
            <span className="text-[10px] text-muted-foreground">#{phase.order + 1}</span>
            <input value={phase.name} onChange={e => updatePhase(i, { name: e.target.value })}
              className="settings-input flex-1 text-xs font-medium" placeholder="Phase name" />
            {phase.status && (
              <span className={cn('text-[10px] px-1.5 py-0.5 rounded',
                phase.status === 'completed' ? 'bg-success/10 text-success' :
                phase.status === 'active' ? 'bg-accent/10 text-accent' :
                'bg-elevated text-muted-foreground'
              )}>{phase.status}</span>
            )}
            <button onClick={() => removePhase(i)} className="text-muted-foreground hover:text-destructive text-xs">&times;</button>
          </div>

          <Field label="Strategies">
            <div className="flex flex-wrap gap-1.5">
              {STRATEGIES.map(s => {
                const active = phase.strategies.includes(s);
                return (
                  <button key={s} onClick={() => {
                    const next = active ? phase.strategies.filter(x => x !== s) : [...phase.strategies, s];
                    updatePhase(i, { strategies: next });
                  }} className={cn('text-[10px] px-2 py-0.5 rounded border transition-colors',
                    active ? 'border-accent/40 bg-accent/10 text-accent' : 'border-border text-muted-foreground hover:border-accent/20'
                  )}>{s.replace(/_/g, ' ')}</button>
                );
              })}
            </div>
          </Field>

          <CriteriaEditor label="Entry Criteria" criteria={phase.entry_criteria}
            onChange={c => updatePhase(i, { entry_criteria: c })} phases={phases} objectives={objectives} currentPhaseIdx={i} />
          <CriteriaEditor label="Exit Criteria" criteria={phase.exit_criteria}
            onChange={c => updatePhase(i, { exit_criteria: c })} phases={phases} objectives={objectives} currentPhaseIdx={i} />
        </div>
      ))}
      <button onClick={addPhase} className="text-xs text-accent hover:underline">+ Add phase</button>
    </div>
  );
}

/* ============ Criteria Editor ============ */

function CriteriaEditor({ label, criteria, onChange, phases, objectives, currentPhaseIdx }: {
  label: string;
  criteria: PhaseCriterion[];
  onChange: (c: PhaseCriterion[]) => void;
  phases: EngagementPhase[];
  objectives: string[];
  currentPhaseIdx: number;
}) {
  const addCriterion = () => onChange([...criteria, { type: 'always' }]);
  const removeCriterion = (i: number) => onChange(criteria.filter((_, j) => j !== i));

  const updateCriterion = (i: number, type: string) => {
    let c: PhaseCriterion;
    switch (type) {
      case 'phase_completed': c = { type: 'phase_completed', phase_id: phases[0]?.id || '' }; break;
      case 'objective_achieved': c = { type: 'objective_achieved', objective_id: 'obj-1' }; break;
      case 'node_count': c = { type: 'node_count', node_type: 'host', min: 1 }; break;
      case 'access_level': c = { type: 'access_level', min_level: 'user' }; break;
      default: c = { type: 'always' };
    }
    onChange(criteria.map((cr, j) => j === i ? c : cr));
  };

  const patchCriterion = (i: number, patch: Record<string, unknown>) => {
    onChange(criteria.map((cr, j) => j === i ? { ...cr, ...patch } as PhaseCriterion : cr));
  };

  return (
    <Field label={label}>
      <div className="space-y-1.5">
        {criteria.map((c, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <select value={c.type} onChange={e => updateCriterion(i, e.target.value)} className="settings-input w-36">
              {CRITERION_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
            </select>

            {c.type === 'phase_completed' && (
              <select value={c.phase_id} onChange={e => patchCriterion(i, { phase_id: e.target.value })} className="settings-input flex-1">
                {phases.filter((_, pi) => pi !== currentPhaseIdx).map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            )}

            {c.type === 'objective_achieved' && (
              <select value={c.objective_id} onChange={e => patchCriterion(i, { objective_id: e.target.value })} className="settings-input flex-1">
                {objectives.filter(o => o.trim()).map((o, oi) => (
                  <option key={oi} value={`obj-${oi + 1}`}>{o.slice(0, 60)}</option>
                ))}
              </select>
            )}

            {c.type === 'node_count' && (
              <>
                <input value={c.node_type} onChange={e => patchCriterion(i, { node_type: e.target.value })}
                  className="settings-input w-24" placeholder="host" />
                <input type="number" min="1" value={c.min} onChange={e => patchCriterion(i, { min: parseInt(e.target.value) || 1 })}
                  className="settings-input w-16" />
              </>
            )}

            {c.type === 'access_level' && (
              <select value={c.min_level} onChange={e => patchCriterion(i, { min_level: e.target.value })} className="settings-input flex-1">
                {ACCESS_LEVELS.map(l => <option key={l} value={l}>{l.replace(/_/g, ' ')}</option>)}
              </select>
            )}

            <button onClick={() => removeCriterion(i)} className="text-muted-foreground hover:text-destructive">&times;</button>
          </div>
        ))}
        <button onClick={addCriterion} className="text-[10px] text-accent hover:underline">+ Add criterion</button>
      </div>
    </Field>
  );
}

/* ============ Detail / Edit Drawer ============ */

function EngagementDetailDrawer({ id, onBack }: { id: string; onBack: () => void }) {
  const [detail, setDetail] = useState<EngagementDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState('');
  const [editing, setEditing] = useState(false);

  // Editable state
  const [name, setName] = useState('');
  const [profile, setProfile] = useState('');
  const [cidrs, setCidrs] = useState<string[]>([]);
  const [domains, setDomains] = useState<string[]>([]);
  const [exclusions, setExclusions] = useState<string[]>([]);
  const [hosts, setHosts] = useState<string[]>([]);
  const [urlPatterns, setUrlPatterns] = useState<string[]>([]);
  const [awsAccounts, setAwsAccounts] = useState<string[]>([]);
  const [azureSubs, setAzureSubs] = useState<string[]>([]);
  const [gcpProjects, setGcpProjects] = useState<string[]>([]);
  const [maxNoise, setMaxNoise] = useState(0.7);
  const [approvalMode, setApprovalMode] = useState('approve-critical');
  const [approvalTimeout, setApprovalTimeout] = useState(300);
  const [twStart, setTwStart] = useState('');
  const [twEnd, setTwEnd] = useState('');
  const [blacklist, setBlacklist] = useState('');
  const [objectives, setObjectives] = useState<string[]>([]);
  const [failurePatterns, setFailurePatterns] = useState<FailurePattern[]>([]);
  const [phases, setPhases] = useState<EngagementPhase[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await getEngagement(id);
      setDetail(d);
      populateEditable(d);
    } catch { /* silent */ }
    setLoading(false);
  }, [id]);

  const populateEditable = (d: EngagementDetail) => {
    setName(d.name || '');
    setProfile(d.profile || 'network');
    setCidrs(d.scope?.cidrs || []);
    setDomains(d.scope?.domains || []);
    setExclusions(d.scope?.exclusions || []);
    setHosts(d.scope?.hosts || []);
    setUrlPatterns(d.scope?.url_patterns || []);
    setAwsAccounts(d.scope?.aws_accounts || []);
    setAzureSubs(d.scope?.azure_subscriptions || []);
    setGcpProjects(d.scope?.gcp_projects || []);
    setMaxNoise(d.opsec?.max_noise ?? 0.7);
    setApprovalMode(d.opsec?.approval_mode || 'approve-critical');
    setApprovalTimeout(d.opsec?.approval_timeout_seconds ?? 300);
    setTwStart(d.opsec?.time_window?.start?.toString() ?? '');
    setTwEnd(d.opsec?.time_window?.end?.toString() ?? '');
    setBlacklist((d.opsec?.blacklisted_techniques || []).join('\n'));
    setObjectives((d.objectives || []).map(o => o.description));
    setFailurePatterns(d.failure_patterns || []);
    setPhases(d.phases || []);
  };

  useEffect(() => { load(); }, [load]);

  const isCloud = CLOUD_PROFILES.has(profile);

  const save = async () => {
    setSaving(true);
    setSaveMsg('');
    try {
      const tw = twStart && twEnd ? { start: parseInt(twStart), end: parseInt(twEnd) } : undefined;
      const bl = blacklist.split('\n').map(s => s.trim()).filter(Boolean);
      const objs = objectives.filter(d => d.trim()).map((d, i) => ({
        id: `obj-${i + 1}`,
        description: d.trim(),
        achieved: detail?.objectives?.[i]?.achieved ?? false,
      }));

      await updateEngagement(id, {
        name,
        profile,
        scope: {
          cidrs, domains, exclusions,
          ...(hosts.length ? { hosts } : {}),
          ...(urlPatterns.length ? { url_patterns: urlPatterns } : {}),
          ...(awsAccounts.length ? { aws_accounts: awsAccounts } : {}),
          ...(azureSubs.length ? { azure_subscriptions: azureSubs } : {}),
          ...(gcpProjects.length ? { gcp_projects: gcpProjects } : {}),
        },
        opsec: {
          max_noise: maxNoise,
          approval_mode: approvalMode,
          approval_timeout_seconds: approvalTimeout,
          time_window: tw,
          blacklisted_techniques: bl.length ? bl : [],
        },
        objectives: objs,
        failure_patterns: failurePatterns,
        phases,
      });
      setSaveMsg('Saved \u2713');
      setEditing(false);
      load();
    } catch {
      setSaveMsg('Error saving');
    }
    setSaving(false);
    setTimeout(() => setSaveMsg(''), 3000);
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <button onClick={onBack} className="text-xs text-muted-foreground hover:text-foreground">&larr; Back</button>
        <div className="text-sm text-muted-foreground animate-pulse">Loading\u2026</div>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="space-y-4">
        <button onClick={onBack} className="text-xs text-muted-foreground hover:text-foreground">&larr; Back</button>
        <EmptyState message="Engagement not found." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button onClick={onBack} className="text-xs text-muted-foreground hover:text-foreground">&larr; Back</button>
          <h2 className="text-lg font-semibold">{detail.name}</h2>
          {detail.is_active && <StatusBadge status="active" />}
        </div>
        <div className="flex items-center gap-2">
          {saveMsg && <span className={cn('text-xs', saveMsg.includes('Error') ? 'text-destructive' : 'text-success')}>{saveMsg}</span>}
          {editing ? (
            <>
              <button onClick={save} disabled={saving} className="settings-save-btn">{saving ? 'Saving\u2026' : 'Save'}</button>
              <button onClick={() => { setEditing(false); if (detail) populateEditable(detail); }} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </>
          ) : (
            <button onClick={() => setEditing(true)} className="settings-save-btn">Edit</button>
          )}
        </div>
      </div>

      <div className="text-xs text-muted-foreground flex items-center gap-3">
        <span className="font-mono">{detail.id}</span>
        {detail.created_at && <span>{new Date(detail.created_at).toLocaleString()}</span>}
        {detail.template && <span>Template: {detail.template}</span>}
      </div>

      {/* Identity */}
      <Section title="Identity">
        {editing ? (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} className="settings-input" /></Field>
            <Field label="Profile">
              <select value={profile} onChange={e => setProfile(e.target.value)} className="settings-input">
                {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </Field>
          </div>
        ) : (
          <div className="text-xs space-y-1">
            <div><span className="text-muted-foreground">Profile:</span> {detail.profile || '\u2014'}</div>
          </div>
        )}
      </Section>

      {/* Scope */}
      <Section title="Scope">
        {editing ? (
          <div className="space-y-3">
            <Field label="CIDRs"><TagInput tags={cidrs} onChange={setCidrs} placeholder="10.0.0.0/24" /></Field>
            <Field label="Domains"><TagInput tags={domains} onChange={setDomains} placeholder="corp.local" /></Field>
            <Field label="Exclusions"><TagInput tags={exclusions} onChange={setExclusions} placeholder="10.0.0.1" /></Field>
            <Field label="Hosts"><TagInput tags={hosts} onChange={setHosts} placeholder="dc01.corp.local" /></Field>
            <Field label="URL Patterns"><TagInput tags={urlPatterns} onChange={setUrlPatterns} placeholder="https://app.*" /></Field>
            {isCloud && (
              <>
                <Field label="AWS Accounts"><TagInput tags={awsAccounts} onChange={setAwsAccounts} placeholder="123456789012" /></Field>
                <Field label="Azure Subscriptions"><TagInput tags={azureSubs} onChange={setAzureSubs} placeholder="sub-id" /></Field>
                <Field label="GCP Projects"><TagInput tags={gcpProjects} onChange={setGcpProjects} placeholder="project-id" /></Field>
              </>
            )}
          </div>
        ) : (
          <ScopeReadView detail={detail} />
        )}
      </Section>

      {/* Objectives */}
      <Section title={`Objectives (${(detail.objectives || []).length})`}>
        {editing ? (
          <ObjectivesEditor objectives={objectives} onChange={setObjectives} />
        ) : (
          <div className="space-y-1.5">
            {(detail.objectives || []).length === 0 ? (
              <p className="text-xs text-muted-foreground">No objectives defined</p>
            ) : (detail.objectives || []).map((obj, i) => (
              <div key={i} className={cn('flex items-center gap-2 text-xs p-1.5 rounded border',
                obj.achieved ? 'border-success/20 bg-success/5' : 'border-border bg-elevated')}>
                <span className={obj.achieved ? 'text-success' : 'text-muted-foreground'}>{obj.achieved ? '\u2713' : '\u25cb'}</span>
                <span className="flex-1">{obj.description}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* OPSEC */}
      <Section title="OPSEC">
        {editing ? (
          <div className="space-y-3">
            <Field label={`Max Noise: ${maxNoise.toFixed(2)}`}>
              <input type="range" min="0" max="1" step="0.01" value={maxNoise} onChange={e => setMaxNoise(parseFloat(e.target.value))} className="w-full accent-accent" />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Approval Mode">
                <select value={approvalMode} onChange={e => setApprovalMode(e.target.value)} className="settings-input">
                  {APPROVAL_MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </select>
              </Field>
              <Field label={`Timeout: ${approvalTimeout}s`}>
                <input type="range" min="10" max="1800" step="10" value={approvalTimeout} onChange={e => setApprovalTimeout(parseInt(e.target.value))} className="w-full accent-accent" />
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Time Window Start">
                <input type="number" min="0" max="23" value={twStart} onChange={e => setTwStart(e.target.value)} className="settings-input" placeholder="\u2014" />
              </Field>
              <Field label="Time Window End">
                <input type="number" min="0" max="23" value={twEnd} onChange={e => setTwEnd(e.target.value)} className="settings-input" placeholder="\u2014" />
              </Field>
            </div>
            <Field label="Blacklisted Techniques">
              <textarea value={blacklist} onChange={e => setBlacklist(e.target.value)} rows={3} className="settings-input w-full font-mono" placeholder="One per line" />
            </Field>
          </div>
        ) : (
          <OpsecReadView detail={detail} />
        )}
      </Section>

      {/* Failure Patterns */}
      <Section title={`Failure Patterns (${(detail.failure_patterns || []).length})`}>
        {editing ? (
          <FailurePatternsEditor patterns={failurePatterns} onChange={setFailurePatterns} />
        ) : (
          <div className="space-y-1">
            {(detail.failure_patterns || []).length === 0 ? (
              <p className="text-xs text-muted-foreground">None</p>
            ) : (detail.failure_patterns || []).map((fp, i) => (
              <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-elevated border border-border">
                <span className="font-mono text-accent">{fp.technique}</span>
                {fp.target_pattern && <span className="text-muted-foreground">{fp.target_pattern}</span>}
                <span className="text-warning flex-1 truncate">{fp.warning}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Phases */}
      <Section title={`Phases (${(detail.phases || []).length})`}>
        {editing ? (
          <PhasesEditor phases={phases} onChange={setPhases} objectives={objectives} />
        ) : (
          <div className="space-y-2">
            {(detail.phases || []).length === 0 ? (
              <p className="text-xs text-muted-foreground">No phases defined</p>
            ) : (detail.phases || []).map((phase, i) => (
              <div key={i} className="border border-border rounded p-2 bg-elevated/50 space-y-1">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground">#{phase.order + 1}</span>
                  <span className="font-medium">{phase.name}</span>
                  {phase.status && (
                    <span className={cn('text-[10px] px-1.5 py-0.5 rounded',
                      phase.status === 'completed' ? 'bg-success/10 text-success' :
                      phase.status === 'active' ? 'bg-accent/10 text-accent' :
                      'bg-elevated text-muted-foreground'
                    )}>{phase.status}</span>
                  )}
                </div>
                {phase.strategies.length > 0 && (
                  <div className="flex gap-1 flex-wrap">
                    {phase.strategies.map(s => (
                      <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">{s.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                )}
                {phase.entry_criteria.length > 0 && (
                  <div className="text-[10px] text-muted-foreground">Entry: {phase.entry_criteria.map(c => criterionLabel(c)).join(', ')}</div>
                )}
                {phase.exit_criteria.length > 0 && (
                  <div className="text-[10px] text-muted-foreground">Exit: {phase.exit_criteria.map(c => criterionLabel(c)).join(', ')}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

/* ============ Read-only Sub-views ============ */

function ScopeReadView({ detail }: { detail: EngagementDetail }) {
  const scope = detail.scope || {};
  const fields: [string, string[] | undefined][] = [
    ['CIDRs', scope.cidrs],
    ['Domains', scope.domains],
    ['Exclusions', scope.exclusions],
    ['Hosts', scope.hosts],
    ['URL Patterns', scope.url_patterns],
    ['AWS Accounts', scope.aws_accounts],
    ['Azure Subs', scope.azure_subscriptions],
    ['GCP Projects', scope.gcp_projects],
  ];
  const populated = fields.filter(([, v]) => v && v.length > 0);
  if (populated.length === 0) return <p className="text-xs text-muted-foreground">No scope defined</p>;
  return (
    <div className="space-y-1.5">
      {populated.map(([label, values]) => (
        <div key={label} className="text-xs">
          <span className="text-muted-foreground">{label}:</span>{' '}
          <span className="font-mono">{values!.join(', ')}</span>
        </div>
      ))}
    </div>
  );
}

function OpsecReadView({ detail }: { detail: EngagementDetail }) {
  const o = detail.opsec || {};
  return (
    <div className="space-y-1 text-xs">
      <div><span className="text-muted-foreground">Max Noise:</span> {o.max_noise?.toFixed(2) ?? '\u2014'}</div>
      <div><span className="text-muted-foreground">Approval:</span> {o.approval_mode || '\u2014'}</div>
      {o.approval_timeout_seconds && <div><span className="text-muted-foreground">Timeout:</span> {o.approval_timeout_seconds}s</div>}
      {o.time_window && <div><span className="text-muted-foreground">Time Window:</span> {o.time_window.start}:00\u2013{o.time_window.end}:00</div>}
      {o.blacklisted_techniques && o.blacklisted_techniques.length > 0 && (
        <div><span className="text-muted-foreground">Blacklisted:</span> <span className="font-mono">{o.blacklisted_techniques.join(', ')}</span></div>
      )}
    </div>
  );
}

function criterionLabel(c: PhaseCriterion): string {
  switch (c.type) {
    case 'always': return 'always';
    case 'phase_completed': return `phase "${c.phase_id}" done`;
    case 'objective_achieved': return `objective "${c.objective_id}"`;
    case 'node_count': return `\u2265${c.min} ${c.node_type}`;
    case 'access_level': return c.min_level.replace(/_/g, ' ');
    default: return String((c as PhaseCriterion).type);
  }
}
