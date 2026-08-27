import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronRight, ExternalLink, Search } from 'lucide-react';
import { useSearchParams } from 'react-router';
import * as api from '../../lib/api';
import type { EvidenceChainResponse, FindingContextResponse } from '../../lib/types';
import { findingTitle } from '../../lib/finding-display';
import { cn, formatTimestamp } from '../../lib/utils';
import { setDrawerParams, setSelectionParams } from '../../lib/workspace-navigation';
import { useWorkspaceNavigation } from '../../hooks/useWorkspaceNavigation';
import { ExecutionOutputView } from '../drawer/ExecutionOutputView';
import { useWorkspaceInspectorAdapters, type WorkspaceInspectorAdapter } from '../layout/WorkspaceInspectorRegistry';
import {
  ActionButton,
  StatusPill,
  TrustBadge,
  WorkspaceEmpty,
  WorkspaceInspector,
  WorkspaceRow,
} from '../shared/primitives';

type Trust = 'observed' | 'asserted' | 'inferred';
type ChainEntry = EvidenceChainResponse['chains'][number];

interface ProofRecord {
  id: string;
  finding: api.FindingDto;
  nodeId: string;
  nodeLabel: string;
  objectiveIds: string[];
  entry: ChainEntry;
  trust: Trust;
  captured: boolean;
}

export function ProofLibrary({ findings }: { findings: api.FindingDto[] }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const { navigateToEvidence, navigateToFinding } = useWorkspaceNavigation();
  const [contexts, setContexts] = useState<Map<string, FindingContextResponse>>(new Map());
  const [loading, setLoading] = useState(true);
  const [partialFailures, setPartialFailures] = useState(0);
  const [query, setQuery] = useState('');
  const [findingFilter, setFindingFilter] = useState('all');
  const [assetFilter, setAssetFilter] = useState('all');
  const [objectiveFilter, setObjectiveFilter] = useState('all');
  const [trustFilter, setTrustFilter] = useState<'all' | Trust>('all');
  const [availabilityFilter, setAvailabilityFilter] = useState<'all' | 'captured' | 'claim'>('all');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setPartialFailures(0);
    void Promise.allSettled(findings.map(finding => api.getFindingContext(finding.id)))
      .then(results => {
        if (cancelled) return;
        const next = new Map<string, FindingContextResponse>();
        let failures = 0;
        results.forEach((result, index) => {
          if (result.status === 'fulfilled') next.set(findings[index].id, result.value);
          else failures += 1;
        });
        setContexts(next);
        setPartialFailures(failures);
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [findings]);

  const records = useMemo<ProofRecord[]>(() => {
    const next: ProofRecord[] = [];
    for (const finding of findings) {
      const context = contexts.get(finding.id);
      if (!context) continue;
      const labels = new Map(context.affected_nodes.map(node => [node.id, String(node.label || node.asset || node.id)]));
      const objectiveIds = context.path_impacts.map(path => path.objective_id);
      for (const chain of context.evidence_chains) {
        for (const entry of chain.chains) {
          const evidenceKey = entry.evidence_id || entry.content_hash || entry.activity_id;
          const captured = Boolean(
            entry.evidence_id
            || entry.content_hash
            || entry.excerpts?.some(excerpt => excerpt.verified && (excerpt.resolved_snippet || excerpt.snippet)),
          );
          next.push({
            id: `${finding.id}:${chain.node_id}:${evidenceKey}`,
            finding,
            nodeId: chain.node_id,
            nodeLabel: labels.get(chain.node_id) || String(chain.node_props?.label || chain.node_id),
            objectiveIds,
            entry,
            trust: entry.source_trust || 'asserted',
            captured,
          });
        }
      }
    }
    return next.sort((a, b) => {
      const time = Date.parse(b.entry.timestamp) - Date.parse(a.entry.timestamp);
      return Number.isFinite(time) && time !== 0 ? time : a.id.localeCompare(b.id);
    });
  }, [contexts, findings]);

  const assets = useMemo(() => [...new Map(records.map(record => [record.nodeId, record.nodeLabel])).entries()]
    .sort((a, b) => a[1].localeCompare(b[1])), [records]);
  const objectives = useMemo(() => [...new Set(records.flatMap(record => record.objectiveIds))].sort(), [records]);
  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return records.filter(record => {
      if (findingFilter !== 'all' && record.finding.id !== findingFilter) return false;
      if (assetFilter !== 'all' && record.nodeId !== assetFilter) return false;
      if (objectiveFilter !== 'all' && !record.objectiveIds.includes(objectiveFilter)) return false;
      if (trustFilter !== 'all' && record.trust !== trustFilter) return false;
      if (availabilityFilter === 'captured' && !record.captured) return false;
      if (availabilityFilter === 'claim' && record.captured) return false;
      if (!normalized) return true;
      // Deliberately exclude snippets and commands: proof may contain credential
      // material and must never become a client-side search index.
      return [findingTitle(record.finding), record.nodeLabel, record.entry.tool, record.entry.technique]
        .filter(Boolean)
        .some(value => String(value).toLowerCase().includes(normalized));
    });
  }, [assetFilter, availabilityFilter, findingFilter, objectiveFilter, query, records, trustFilter]);

  const selectedId = searchParams.get('kind') === 'evidence' ? searchParams.get('item') : null;
  const selected = selectedId ? records.find(record => record.id === selectedId || record.entry.evidence_id === selectedId || record.entry.content_hash === selectedId) ?? null : null;

  const select = (record: ProofRecord) => setSearchParams(setSelectionParams(searchParams, { kind: 'evidence', id: record.id }));
  const openRun = useCallback((actionId: string) => {
    setSearchParams(setDrawerParams(searchParams, { kind: 'run', item: actionId }));
  }, [searchParams, setSearchParams]);
  const evidenceInspectorAdapter = useMemo<WorkspaceInspectorAdapter>(() => ({
    resolved: !loading,
    available: Boolean(selected),
    render: ({ close }) => selected ? (
      <EvidenceInspector
        record={selected}
        onClose={close}
        onOpenRun={openRun}
        onOpenFinding={navigateToFinding}
        onOpenAsset={navigateToEvidence}
      />
    ) : null,
  }), [loading, navigateToEvidence, navigateToFinding, openRun, selected]);
  const proofInspectorAdapters = useMemo(() => ({ evidence: evidenceInspectorAdapter }), [evidenceInspectorAdapter]);
  useWorkspaceInspectorAdapters(proofInspectorAdapters);

  return (
    <div className="relative flex min-h-0 flex-1">
      <section className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 border-b border-border-subtle p-3">
          <label className="relative min-w-48 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-muted" />
            <input aria-label="Search proof" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search labels, tools, techniques…" className="settings-input h-8 w-full pl-8 text-xs" />
          </label>
          <ProofSelect label="Filter proof by finding" value={findingFilter} onChange={setFindingFilter}>
            <option value="all">All findings</option>
            {findings.map(finding => <option key={finding.id} value={finding.id}>{findingTitle(finding)}</option>)}
          </ProofSelect>
          <ProofSelect label="Filter proof by asset" value={assetFilter} onChange={setAssetFilter}>
            <option value="all">All assets</option>
            {assets.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </ProofSelect>
          <ProofSelect label="Filter proof by objective" value={objectiveFilter} onChange={setObjectiveFilter}>
            <option value="all">All objectives</option>
            {objectives.map(id => <option key={id} value={id}>{id}</option>)}
          </ProofSelect>
          <ProofSelect label="Filter proof by source trust" value={trustFilter} onChange={value => setTrustFilter(value as typeof trustFilter)}>
            <option value="all">All trust</option><option value="observed">Observed</option><option value="asserted">Asserted</option><option value="inferred">Inferred</option>
          </ProofSelect>
          <ProofSelect label="Filter proof by availability" value={availabilityFilter} onChange={value => setAvailabilityFilter(value as typeof availabilityFilter)}>
            <option value="all">All availability</option><option value="captured">Captured proof</option><option value="claim">Claim only</option>
          </ProofSelect>
          <span className="ml-auto text-[10px] tabular-nums text-muted-foreground">{visible.length} proof records</span>
        </div>

        {partialFailures > 0 && <div role="status" className="border-b border-warning/20 bg-warning/5 px-3 py-2 text-[11px] text-warning">{partialFailures} finding context{partialFailures === 1 ? '' : 's'} could not be loaded. Showing available proof.</div>}
        {loading ? (
          <div className="flex min-h-56 items-center justify-center text-xs text-muted-foreground"><span className="workspace-pulse">Building proof index…</span></div>
        ) : records.length === 0 ? (
          <WorkspaceEmpty title="No proof records" detail="Captured output and evidence claims appear here once findings are linked to producing actions." />
        ) : visible.length === 0 ? (
          <WorkspaceEmpty title="No proof matches these filters" detail="Broaden the finding, asset, objective, trust, or availability filters." />
        ) : visible.map(record => (
          <WorkspaceRow key={record.id} selected={selected?.id === record.id} onClick={() => select(record)}>
            <span className={cn('h-2 w-2 flex-shrink-0 rounded-full', record.captured ? 'bg-success' : 'bg-warning')} />
            <div className="min-w-0 flex-1">
              <div className="flex min-w-0 items-center gap-2"><span className="truncate text-xs font-medium text-foreground">{record.entry.description || findingTitle(record.finding)}</span><TrustBadge trust={record.trust} /></div>
              <div className="mt-0.5 flex min-w-0 gap-2 text-[10px] text-muted-foreground"><span className="truncate">{record.nodeLabel}</span><span>·</span><span className="truncate">{findingTitle(record.finding)}</span></div>
            </div>
            <StatusPill tone={record.captured ? 'success' : 'warning'}>{record.captured ? 'captured' : 'claim only'}</StatusPill>
            <span className="hidden text-[9px] text-muted lg:block">{formatTimestamp(record.entry.timestamp)}</span>
            <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-muted" />
          </WorkspaceRow>
        ))}
      </section>

    </div>
  );
}

function ProofSelect({ label, value, onChange, children }: { label: string; value: string; onChange: (value: string) => void; children: React.ReactNode }) {
  return <select aria-label={label} value={value} onChange={event => onChange(event.target.value)} className="settings-input h-8 max-w-44 text-xs">{children}</select>;
}

function EvidenceInspector({ record, onClose, onOpenRun, onOpenFinding, onOpenAsset }: { record: ProofRecord; onClose: () => void; onOpenRun: (actionId: string) => void; onOpenFinding: (findingId: string) => void; onOpenAsset: (nodeId: string) => void }) {
  const excerpt = record.entry.snippet || record.entry.excerpts?.[0]?.resolved_snippet || record.entry.excerpts?.[0]?.snippet;
  return (
    <WorkspaceInspector label="Evidence inspector" title={record.entry.tool || record.entry.technique || 'Evidence'} identifier={record.entry.evidence_id || record.entry.activity_id} onClose={onClose}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-1.5"><TrustBadge trust={record.trust} /><StatusPill tone={record.captured ? 'success' : 'warning'}>{record.captured ? 'Captured proof' : 'Claim only'}</StatusPill></div>
        <InspectorFact label="Finding" value={findingTitle(record.finding)} />
        <InspectorFact label="Affected asset" value={record.nodeLabel} mono />
        <InspectorFact label="Captured" value={formatTimestamp(record.entry.timestamp)} />
        {record.entry.description && <InspectorFact label="Claim" value={record.entry.description} />}
        {excerpt && <div><InspectorLabel>Verified excerpt</InspectorLabel><pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-background p-2 font-mono text-[9px] leading-4 text-muted-foreground">{excerpt}</pre></div>}
        {record.entry.content_hash && <InspectorFact label="Content hash" value={`sha256 ${record.entry.content_hash}`} mono />}
        {record.entry.exit_code != null && <InspectorFact label="Exit status" value={String(record.entry.exit_code)} mono />}
        <div className="flex flex-wrap gap-1.5 border-t border-border-subtle pt-3">
          {record.entry.action_id && <ActionButton size="xs" variant="primary" onClick={() => onOpenRun(record.entry.action_id!)}>Open producing run <ExternalLink className="h-3 w-3" /></ActionButton>}
          <ActionButton size="xs" onClick={() => onOpenFinding(record.finding.id)}>Open finding</ActionButton>
          <ActionButton size="xs" onClick={() => onOpenAsset(record.nodeId)}>Open asset</ActionButton>
        </div>
        {record.entry.action_id && <div className="h-[28rem] overflow-hidden rounded border border-border-subtle"><ExecutionOutputView actionId={record.entry.action_id} onOpenInRuns={onOpenRun} /></div>}
      </div>
    </WorkspaceInspector>
  );
}

function InspectorLabel({ children }: { children: React.ReactNode }) {
  return <div className="mb-1 text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">{children}</div>;
}

function InspectorFact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><InspectorLabel>{label}</InspectorLabel><div className={cn('break-words text-[11px] leading-5 text-foreground', mono && 'font-mono text-[10px]')}>{value}</div></div>;
}
