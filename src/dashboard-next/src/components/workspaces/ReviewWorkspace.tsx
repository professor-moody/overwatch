import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronRight, ExternalLink, FileText, TerminalSquare } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useEngagementStore } from '../../stores/engagement-store';
import * as api from '../../lib/api';
import type { FindingContextResponse } from '../../lib/types';
import { findingImpact, findingRemediation, findingSummary, findingTitle } from '../../lib/finding-display';
import { cn } from '../../lib/utils';
import { buildWorkspacePath, REVIEW_VIEWS, type ReviewView, setDrawerParams, setSelectionParams } from '../../lib/workspace-navigation';
import { RenderReportModal } from '../panels/RenderReportModal';
import { ReportsList } from '../panels/ReportsList';
import { EvidenceDebtCard } from '../panels/EvidenceDebtCard';
import { ProofLibrary } from './ProofLibrary';
import { ExecutionOutputView } from '../drawer/ExecutionOutputView';
import { useWorkspaceInspectorAdapters, type WorkspaceInspectorAdapter } from '../layout/WorkspaceInspectorRegistry';
import {
  ActionButton,
  StatusPill,
  TrustBadge,
  WorkspaceEmpty,
  WorkspaceHeader,
  WorkspaceInspector,
  WorkspaceRow,
  WorkspaceTabs,
} from '../shared/primitives';

type Readiness = api.FindingReadinessReport['findings'][number]['readiness'];
type InspectorTab = 'summary' | 'proof' | 'affected' | 'path' | 'remediation' | 'activity';

const READINESS_META: Record<Readiness, { label: string; detail: string; tone: 'warning' | 'purple' | 'success' }> = {
  draft: { label: 'Needs evidence', detail: 'No captured proof is linked yet', tone: 'warning' },
  needs_validation: { label: 'Needs validation', detail: 'Context exists but proof needs verification', tone: 'purple' },
  client_ready: { label: 'Proof ready', detail: 'Captured evidence or proof cards are present', tone: 'success' },
};

const READINESS_ORDER: Readiness[] = ['draft', 'needs_validation', 'client_ready'];

function isReviewView(value: string | null): value is ReviewView {
  return !!value && (REVIEW_VIEWS as readonly string[]).includes(value);
}

function isReadiness(value: string | null): value is Readiness {
  return value === 'draft' || value === 'needs_validation' || value === 'client_ready';
}

const FINDING_INSPECTOR_TABS: InspectorTab[] = ['summary', 'proof', 'affected', 'path', 'remediation', 'activity'];

export function ReviewWorkspace() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const connected = useEngagementStore(state => state.connected);
  const [findings, setFindings] = useState<api.FindingDto[]>([]);
  const [readiness, setReadiness] = useState<api.FindingReadinessReport | null>(null);
  const [reports, setReports] = useState<api.ReportRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [showRender, setShowRender] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [findingResult, readinessResult, reportResult] = await Promise.allSettled([
      api.getFindings(), api.getFindingReadiness(), api.listReports(),
    ]);
    if (findingResult.status === 'fulfilled') setFindings(findingResult.value.findings || []);
    if (readinessResult.status === 'fulfilled') setReadiness(readinessResult.value);
    if (reportResult.status === 'fulfilled') setReports(reportResult.value.reports || []);
    if (findingResult.status === 'rejected') setError('Findings are temporarily unavailable.');
    else if (readinessResult.status === 'rejected') setError('Proof readiness is temporarily unavailable; findings remain visible without inferred client-side status.');
    else setError(null);
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => { if (connected) void load(); }, 12_000);
    return () => window.clearInterval(timer);
  }, [connected, load]);

  const requested = searchParams.get('view');
  const view: ReviewView = isReviewView(requested) ? requested : 'readiness';
  const readinessFilter = isReadiness(searchParams.get('readiness')) ? searchParams.get('readiness') as Readiness : null;
  const selectedId = searchParams.get('item');
  const selectedFinding = selectedId ? findings.find(finding => finding.id === selectedId) ?? null : null;
  const readinessById = useMemo(() => new Map((readiness?.findings || []).map(item => [item.id, item])), [readiness]);

  const setView = (nextView: ReviewView) => {
    const next = setSelectionParams(searchParams, null);
    next.set('view', nextView);
    next.delete('readiness');
    setSearchParams(next);
  };
  const selectFinding = (id: string) => setSearchParams(setSelectionParams(searchParams, { kind: 'finding', id }));

  const findingInspectorAdapter = useMemo<WorkspaceInspectorAdapter>(() => ({
    resolved: !loading,
    available: Boolean(selectedFinding),
    tabs: FINDING_INSPECTOR_TABS.map(value => ({ value, label: value })),
    defaultTab: 'summary',
    render: ({ tab, setTab, close }) => selectedFinding ? (
      <FindingInspector
        finding={selectedFinding}
        readiness={readinessById.get(selectedFinding.id) || null}
        tab={(tab || 'summary') as InspectorTab}
        onTabChange={nextTab => setTab(nextTab)}
        onClose={close}
        onNavigate={navigate}
        onOpenRun={actionId => setSearchParams(setDrawerParams(searchParams, { kind: 'run', item: actionId }))}
      />
    ) : null,
  }), [loading, navigate, readinessById, searchParams, selectedFinding, setSearchParams]);
  const reviewInspectorAdapters = useMemo(() => ({ finding: findingInspectorAdapter }), [findingInspectorAdapter]);
  useWorkspaceInspectorAdapters(reviewInspectorAdapters);

  const tabs: Array<{ value: ReviewView; label: string; count?: number }> = [
    { value: 'readiness', label: 'Readiness', count: readiness?.summary.total ?? findings.length },
    { value: 'proof', label: 'Proof library' },
    { value: 'reports', label: 'Reports', count: reports.length },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-background">
      <WorkspaceHeader
        eyebrow="Proof and delivery"
        title="Review"
        description="Close evidence gaps, validate findings, and build deliverables from the same context."
        actions={view === 'reports' ? <ActionButton variant="primary" className="h-8" onClick={() => setShowRender(true)}><FileText className="h-3.5 w-3.5" /> Generate report</ActionButton> : undefined}
      >
        <WorkspaceTabs value={view} options={tabs} onChange={setView} ariaLabel="Review views" />
      </WorkspaceHeader>

      <div className="relative flex min-h-0 flex-1">
        <section className="min-w-0 flex-1 overflow-y-auto">
          {view === 'readiness' && (
            <div>
              <div className="border-b border-border-subtle px-4 py-2 text-[11px] leading-5 text-muted-foreground lg:px-5">
                Readiness is a derived proof heuristic, not an operator verdict. Severity remains independent and does not determine these groups.
              </div>
              <ReadinessView
                findings={findings}
                readiness={readiness}
                loading={loading}
                error={error}
                filter={readinessFilter}
                selectedId={selectedId}
                onFilter={filter => {
                  const next = new URLSearchParams(searchParams);
                  if (filter) next.set('readiness', filter); else next.delete('readiness');
                  setSearchParams(next);
                }}
                onSelect={selectFinding}
              />
            </div>
          )}
          {view === 'proof' && (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="border-b border-border-subtle p-4 lg:p-5"><EvidenceDebtCard /></div>
              <ProofLibrary findings={findings} />
            </div>
          )}
          {view === 'reports' && (
            <div className="space-y-4 p-4 lg:p-5">
              <div className="flex items-start justify-between gap-4 border-b border-border-subtle pb-4">
                <div><h2 className="text-sm font-semibold text-foreground">Report archive</h2><p className="mt-1 max-w-2xl text-[11px] leading-5 text-muted-foreground">Readiness is a proof heuristic only. Filters and readiness groups do not change which findings the current report generator includes.</p></div>
                <ActionButton variant="primary" onClick={() => setShowRender(true)}>Generate report</ActionButton>
              </div>
              {reports.length > 0 ? <ReportsList reports={reports} onRefresh={() => void load()} /> : <WorkspaceEmpty title="No reports generated" detail="Create an operator-internal or client-safe report from the current engagement state." action={<ActionButton variant="primary" onClick={() => setShowRender(true)}>Generate first report</ActionButton>} />}
            </div>
          )}
        </section>

      </div>

      {showRender && <RenderReportModal onClose={() => setShowRender(false)} onRendered={() => void load()} />}
    </div>
  );
}

function ReadinessView({
  findings,
  readiness,
  loading,
  error,
  filter,
  selectedId,
  onFilter,
  onSelect,
}: {
  findings: api.FindingDto[];
  readiness: api.FindingReadinessReport | null;
  loading: boolean;
  error: string | null;
  filter: Readiness | null;
  selectedId: string | null;
  onFilter: (filter: Readiness | null) => void;
  onSelect: (id: string) => void;
}) {
  const findingById = useMemo(() => new Map(findings.map(finding => [finding.id, finding])), [findings]);
  const groups = useMemo(() => {
    const base: Record<Readiness, api.FindingReadinessReport['findings']> = { draft: [], needs_validation: [], client_ready: [] };
    for (const item of readiness?.findings || []) base[item.readiness].push(item);
    return base;
  }, [readiness]);

  if (loading) return <div className="flex min-h-64 items-center justify-center text-xs text-muted-foreground"><span className="workspace-pulse">Assessing finding proof…</span></div>;
  if (findings.length === 0) return <WorkspaceEmpty title="No findings yet" detail="Findings appear after agents land discoveries in the graph." />;

  return (
    <div>
      {error && <div className="border-b border-warning/20 bg-warning/5 px-4 py-2 text-[11px] text-warning">{error}</div>}
      {readiness && (
        <div className="grid grid-cols-3 border-b border-border-subtle">
          {READINESS_ORDER.map(key => {
            const meta = READINESS_META[key];
            const count = readiness.summary[key];
            const active = filter === key;
            return (
              <button key={key} onClick={() => onFilter(active ? null : key)} className={cn('px-4 py-3 text-left transition-colors hover:bg-hover/40', active && 'bg-accent/[0.07]')}>
                <div className="flex items-center gap-2"><span className="text-lg font-semibold tabular-nums text-foreground">{count}</span><StatusPill tone={meta.tone}>{meta.label}</StatusPill></div>
                <div className="mt-1 text-[10px] text-muted-foreground">{meta.detail}</div>
              </button>
            );
          })}
        </div>
      )}
      {!readiness ? (
        findings.map(finding => <FallbackFindingRow key={finding.id} finding={finding} selected={selectedId === finding.id} onClick={() => onSelect(finding.id)} />)
      ) : READINESS_ORDER.filter(key => !filter || key === filter).map(key => {
        const group = groups[key];
        if (group.length === 0) return null;
        return (
          <div key={key}>
            <div className="sticky top-0 z-10 flex h-8 items-center gap-2 border-y border-border-subtle bg-background/95 px-3 backdrop-blur">
              <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">{READINESS_META[key].label}</span>
              <span className="font-mono text-[9px] text-muted">{group.length}</span>
            </div>
            {group.map(item => {
              const finding = findingById.get(item.id);
              if (!finding) return null;
              return <FindingReadinessRow key={item.id} finding={finding} readiness={item} selected={selectedId === item.id} onClick={() => onSelect(item.id)} />;
            })}
          </div>
        );
      })}
    </div>
  );
}

function FindingReadinessRow({ finding, readiness, selected, onClick }: { finding: api.FindingDto; readiness: api.FindingReadinessReport['findings'][number]; selected: boolean; onClick: () => void }) {
  return (
    <WorkspaceRow selected={selected} onClick={onClick}>
      <SeverityMark severity={finding.severity} />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-2"><span className="truncate text-xs font-medium text-foreground">{findingTitle(finding)}</span><StatusPill tone={READINESS_META[readiness.readiness].tone}>{READINESS_META[readiness.readiness].label}</StatusPill></div>
        <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{readiness.gaps[0] || findingSummary(finding)}</div>
      </div>
      <div className="hidden grid-cols-3 gap-4 text-center lg:grid">
        <SmallMetric label="assets" value={readiness.affected_assets} />
        <SmallMetric label="chains" value={readiness.evidence_chains} />
        <SmallMetric label="proof" value={readiness.proof_cards} />
      </div>
      <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-muted" />
    </WorkspaceRow>
  );
}

function FallbackFindingRow({ finding, selected, onClick }: { finding: api.FindingDto; selected: boolean; onClick: () => void }) {
  return <WorkspaceRow selected={selected} onClick={onClick}><SeverityMark severity={finding.severity} /><div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-foreground">{findingTitle(finding)}</div><div className="mt-0.5 truncate text-[10px] text-muted-foreground">{findingSummary(finding)}</div></div><StatusPill tone="muted">readiness unavailable</StatusPill><ChevronRight className="h-3.5 w-3.5 text-muted" /></WorkspaceRow>;
}

function SeverityMark({ severity }: { severity: api.FindingDto['severity'] }) {
  return <span className={cn('h-6 w-1 flex-shrink-0 rounded-full', severity === 'critical' ? 'bg-destructive' : severity === 'high' ? 'bg-warning' : severity === 'medium' ? 'bg-accent' : 'bg-muted-foreground')} title={severity} />;
}

function SmallMetric({ label, value }: { label: string; value: number }) {
  return <div><div className="font-mono text-[10px] text-foreground">{value}</div><div className="text-[8px] uppercase tracking-wide text-muted">{label}</div></div>;
}

function FindingInspector({
  finding,
  readiness,
  tab,
  onTabChange,
  onClose,
  onNavigate,
  onOpenRun,
}: {
  finding: api.FindingDto;
  readiness: api.FindingReadinessReport['findings'][number] | null;
  tab: InspectorTab;
  onTabChange: (tab: InspectorTab) => void;
  onClose: () => void;
  onNavigate: ReturnType<typeof useNavigate>;
  onOpenRun: (actionId: string) => void;
}) {
  const [context, setContext] = useState<FindingContextResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    void api.getFindingContext(finding.id)
      .then(result => { if (!cancelled) setContext(result); })
      .catch(() => { if (!cancelled) setContext(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [finding.id]);

  return (
    <WorkspaceInspector
      label="Finding inspector"
      title={findingTitle(finding)}
      identifier={finding.id}
      tabs={FINDING_INSPECTOR_TABS.map(value => ({ value, label: value }))}
      activeTab={tab}
      onTabChange={value => onTabChange(value as InspectorTab)}
      onClose={onClose}
    >
        <div className="border-b border-border-subtle pb-3">
          <div className="flex items-start gap-2"><SeverityMark severity={finding.severity} /><div className="min-w-0"><h2 className="text-sm font-semibold leading-5 text-foreground">{findingTitle(finding)}</h2><p className="mt-1 font-mono text-[9px] text-muted-foreground">{finding.id}</p></div></div>
          <div className="mt-3 flex flex-wrap gap-1.5"><StatusPill tone="danger">{finding.severity}</StatusPill>{readiness && <StatusPill tone={READINESS_META[readiness.readiness].tone}>{READINESS_META[readiness.readiness].label}</StatusPill>}</div>
        </div>
        <div className="pt-4">
          {loading ? <div className="text-[11px] text-muted-foreground">Loading finding context…</div> : (
            <FindingTab tab={tab} finding={finding} readiness={readiness} context={context} onNavigate={onNavigate} onOpenRun={onOpenRun} />
          )}
        </div>
    </WorkspaceInspector>
  );
}

function FindingTab({ tab, finding, readiness, context, onNavigate, onOpenRun }: { tab: InspectorTab; finding: api.FindingDto; readiness: api.FindingReadinessReport['findings'][number] | null; context: FindingContextResponse | null; onNavigate: ReturnType<typeof useNavigate>; onOpenRun: (actionId: string) => void }) {
  if (tab === 'summary') return <div className="space-y-4"><p className="text-xs leading-5 text-foreground">{findingSummary(finding)}</p>{findingImpact(finding) && <InfoBlock label="Impact" text={findingImpact(finding) ?? ''} />}{readiness && readiness.gaps.length > 0 && <div><SectionTitle>Proof gaps</SectionTitle><ul className="space-y-1.5">{readiness.gaps.map(gap => <li key={gap} className="flex gap-2 text-[11px] leading-5 text-muted-foreground"><span className="mt-2 h-1 w-1 flex-shrink-0 rounded-full bg-warning" />{gap}</li>)}</ul></div>}</div>;
  if (tab === 'proof') {
    const entries = context?.evidence_chains.flatMap(chain => chain.chains) || [];
    if (entries.length === 0) return <WorkspaceEmpty title="No captured proof" detail="Run or parse the action that demonstrates this finding, then return here to validate it." />;
    return <FindingProof entries={entries} onOpenRun={onOpenRun} />;
  }
  if (tab === 'affected') {
    if (!context?.affected_nodes.length) return <WorkspaceEmpty title="No affected assets linked" />;
    return <div>{context.affected_nodes.map(node => <WorkspaceRow key={node.id} onClick={() => onNavigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id: node.id }, context: { context: 'finding', node: node.id } }))}><div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-foreground">{node.label || node.asset || node.id}</div><div className="mt-0.5 truncate font-mono text-[9px] text-muted-foreground">{node.id}</div></div><ChevronRight className="h-3.5 w-3.5 text-muted" /></WorkspaceRow>)}</div>;
  }
  if (tab === 'path') {
    if (!context?.path_impacts.length) return <WorkspaceEmpty title="No objective path impact" detail="This finding is not currently present on a calculated objective path." />;
    return <div className="space-y-3">{context.path_impacts.map((path, index) => <button key={`${path.objective_id}-${index}`} onClick={() => onNavigate(buildWorkspacePath({ workspace: 'investigate', lens: 'paths', context: { objective: path.objective_id } }))} className="block w-full border-b border-border-subtle pb-3 text-left"><div className="text-xs font-medium text-foreground">{path.objective}</div><div className="mt-1 truncate font-mono text-[9px] text-muted-foreground">{path.nodes.join(' → ')}</div><div className="mt-1 text-[9px] text-muted">{Math.round(path.total_confidence * 100)}% confidence · noise {path.total_opsec_noise.toFixed(1)}</div></button>)}</div>;
  }
  if (tab === 'remediation') return <InfoBlock label="Recommended remediation" text={findingRemediation(finding)} />;
  return <div className="space-y-3"><InfoMetric label="Sessions" value={context?.sessions.length ?? 0} /><InfoMetric label="Pending actions" value={context?.pending_actions.length ?? 0} /><InfoMetric label="Frontier items" value={context?.frontier.length ?? 0} /><p className="text-[10px] leading-4 text-muted-foreground">Open the global Activity drawer for the full auditable event timeline.</p></div>;
}

function FindingProof({
  entries,
  onOpenRun,
}: {
  entries: FindingContextResponse['evidence_chains'][number]['chains'];
  onOpenRun: (actionId: string) => void;
}) {
  const [selectedAction, setSelectedAction] = useState<string | null>(null);
  return (
    <div className="space-y-3">
      {entries.map(entry => (
        <div key={entry.activity_id} className="border-b border-border-subtle pb-3">
          <div className="flex items-center gap-2"><TrustBadge trust={entry.source_trust || 'asserted'} /><span className="truncate text-[10px] text-muted-foreground">{entry.tool || entry.technique || entry.event_type || 'Evidence'}</span></div>
          <p className="mt-2 text-[11px] leading-5 text-foreground">{entry.description}</p>
          {(entry.snippet || entry.excerpts?.[0]?.resolved_snippet || entry.excerpts?.[0]?.snippet) && <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap rounded bg-background p-2 font-mono text-[9px] leading-4 text-muted-foreground">{entry.snippet || entry.excerpts?.[0]?.resolved_snippet || entry.excerpts?.[0]?.snippet}</pre>}
          {entry.content_hash && <div className="mt-2 truncate font-mono text-[9px] text-muted">sha256 {entry.content_hash}</div>}
          {entry.action_id && <div className="mt-2 flex flex-wrap gap-1.5"><ActionButton size="xs" variant={selectedAction === entry.action_id ? 'primary' : 'secondary'} onClick={() => setSelectedAction(current => current === entry.action_id ? null : entry.action_id!)}><TerminalSquare className="h-3 w-3" />{selectedAction === entry.action_id ? 'Hide output' : 'Inspect command/output'}</ActionButton><ActionButton size="xs" onClick={() => onOpenRun(entry.action_id!)}>Open in Runs <ExternalLink className="h-3 w-3" /></ActionButton></div>}
          {selectedAction === entry.action_id && <div className="mt-3 h-[28rem] overflow-hidden rounded border border-border-subtle"><ExecutionOutputView actionId={entry.action_id} onOpenInRuns={onOpenRun} /></div>}
        </div>
      ))}
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) { return <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">{children}</div>; }
function InfoBlock({ label, text }: { label: string; text: string }) { return <div><SectionTitle>{label}</SectionTitle><div className="whitespace-pre-wrap text-[11px] leading-5 text-foreground">{text}</div></div>; }
function InfoMetric({ label, value }: { label: string; value: number }) { return <div className="flex items-center justify-between border-b border-border-subtle pb-2 text-[11px]"><span className="text-muted-foreground">{label}</span><span className="font-mono text-foreground">{value}</span></div>; }
