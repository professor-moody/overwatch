import { useEffect, useId, useMemo, useRef, useState } from 'react';
import * as api from '../../lib/api';
import type { AgentInfo } from '../../lib/types';
import { useToastStore } from '../../stores/toast-store';
import { ActionButton } from '../shared/primitives';

export type AgentWorkMode = 'handoff' | 'split' | 'merge';

export function AgentWorkModal({
  agent,
  mode,
  onClose,
  onCompleted,
}: {
  agent: AgentInfo;
  mode: AgentWorkMode;
  onClose: () => void;
  onCompleted: () => void;
}) {
  const addToast = useToastStore(state => state.addToast);
  const titleId = useId();
  const summaryId = useId();
  const objectiveId = useId();
  const archetypeId = useId();
  const agentLabelId = useId();
  const childCountId = useId();
  const findingRefsId = useId();
  const evidenceRefsId = useId();
  const eventRefsId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const initialFocusRef = useRef<HTMLTextAreaElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const taskId = api.canonicalAgentTaskId(agent);
  const nodes = agent.subgraph_node_ids ?? [];
  const [summary, setSummary] = useState(
    mode === 'handoff'
      ? `Continue the work from ${api.agentDisplayLabel(agent)}.`
      : mode === 'split'
        ? `Partition the remaining work from ${api.agentDisplayLabel(agent)}.`
        : `Consolidate exact duplicate work for ${api.agentDisplayLabel(agent)}.`,
  );
  const [objective, setObjective] = useState(
    agent.objective ?? `Continue the scoped work from ${api.agentDisplayLabel(agent)}.`,
  );
  const [archetype, setArchetype] = useState(agent.archetype ?? 'default');
  const [agentLabel, setAgentLabel] = useState('');
  const [childCount, setChildCount] = useState(Math.min(2, nodes.length));
  const [findingRefs, setFindingRefs] = useState('');
  const [evidenceRefs, setEvidenceRefs] = useState('');
  const [eventRefs, setEventRefs] = useState('');
  const [busy, setBusy] = useState(false);
  const [duplicates, setDuplicates] = useState<api.AgentDuplicatesResponse | null>(null);
  const [selectedDuplicateTaskIds, setSelectedDuplicateTaskIds] = useState<string[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (mode !== 'merge') return;
    let cancelled = false;
    api.getAgentDuplicates().then(result => {
      if (!cancelled) setDuplicates(result);
    }).catch(error => {
      if (!cancelled) setLoadError(error instanceof Error ? error.message : String(error));
    });
    return () => { cancelled = true; };
  }, [mode]);

  useEffect(() => {
    returnFocusRef.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    initialFocusRef.current?.focus();
    return () => returnFocusRef.current?.focus();
  }, []);

  const duplicateGroup = useMemo(
    () => duplicates?.groups.find(group => group.candidate_task_ids.includes(taskId)),
    [duplicates, taskId],
  );
  const canonicalTaskId = duplicateGroup?.canonical_task_id;
  const eligibleDuplicateTaskIds = duplicateGroup?.tasks
    .filter(task => task.task_id !== canonicalTaskId)
    .filter(task => ['completed', 'failed', 'interrupted'].includes(task.status))
    .map(task => task.task_id) ?? [];

  useEffect(() => {
    setSelectedDuplicateTaskIds(eligibleDuplicateTaskIds);
  }, [duplicateGroup?.signature, canonicalTaskId, eligibleDuplicateTaskIds.join('\u0000')]);

  const toggleDuplicate = (taskIdToToggle: string) => {
    setSelectedDuplicateTaskIds(current => current.includes(taskIdToToggle)
      ? current.filter(candidate => candidate !== taskIdToToggle)
      : [...current, taskIdToToggle]);
  };

  const handleDialogKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape' && !busy) {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = [...(dialogRef.current?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ) ?? [])].filter(element => element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  const submit = async () => {
    if (busy || !summary.trim()) return;
    setBusy(true);
    try {
      const references = (value: string) => [...new Set(value
        .split(/[\s,]+/)
        .map(item => item.trim())
        .filter(Boolean))];
      const keyFindingIds = references(findingRefs);
      const keyEvidenceIds = references(evidenceRefs);
      const keyEventIds = references(eventRefs);
      if (mode === 'handoff') {
        const result = await api.handoffAgentWork(taskId, {
          summary: summary.trim(),
          archetype,
          objective: objective.trim(),
          ...(agentLabel.trim() ? { agent_label: agentLabel.trim() } : {}),
          ...(agent.skill ? { skill: agent.skill } : {}),
          ...(agent.model ? { model: agent.model } : {}),
          ...(keyFindingIds.length ? { key_finding_ids: keyFindingIds } : {}),
          ...(keyEvidenceIds.length ? { key_evidence_ids: keyEvidenceIds } : {}),
          ...(keyEventIds.length ? { key_event_ids: keyEventIds } : {}),
        });
        addToast({
          type: result.warnings.length > 0 ? 'warning' : 'success',
          title: result.reused_existing ? 'Existing successor reused' : 'Agent work handed off',
          message: result.warnings.includes('campaign_not_reacquired')
            ? 'The old campaign item was terminal or stale; the successor kept node scope without campaign attribution.'
            : result.warnings.includes('frontier_not_reacquired')
            ? 'The old frontier item was stale; the successor kept the source node scope.'
            : `${result.reused_existing ? 'Reused' : 'Created'} ${api.agentDisplayLabel(result.created_tasks[0]!)}`,
        });
      } else if (mode === 'split') {
        if (!Number.isInteger(childCount)
          || childCount < 2
          || childCount > Math.min(nodes.length, 20)) {
          throw new Error(`Child count must be an integer from 2 through ${Math.min(nodes.length, 20)}.`);
        }
        const count = childCount;
        const partitions = Array.from({ length: count }, () => [] as string[]);
        nodes.forEach((nodeId, index) => partitions[index % count]!.push(nodeId));
        const result = await api.splitAgentWork(taskId, {
          summary: summary.trim(),
          ...(keyFindingIds.length ? { key_finding_ids: keyFindingIds } : {}),
          ...(keyEvidenceIds.length ? { key_evidence_ids: keyEvidenceIds } : {}),
          ...(keyEventIds.length ? { key_event_ids: keyEventIds } : {}),
          children: partitions.map((targetNodeIds, index) => ({
            archetype,
            objective: `${objective.trim()} (partition ${index + 1}/${count})`,
            target_node_ids: targetNodeIds,
            ...(agent.skill ? { skill: agent.skill } : {}),
            ...(agent.model ? { model: agent.model } : {}),
          })),
        });
        addToast({
          type: 'success',
          title: result.reused_existing ? 'Existing split reused' : 'Agent work split',
          message: `${result.reused_existing ? 'Reused' : 'Created'} ${count} disjoint child tasks covering all ${nodes.length} nodes.`,
        });
      } else {
        if (!canonicalTaskId || selectedDuplicateTaskIds.length === 0) {
          throw new Error('No terminal exact duplicates are available to merge.');
        }
        const latest = await api.getAgentDuplicates();
        const latestGroup = latest.groups.find(group => group.candidate_task_ids.includes(taskId));
        if (!latestGroup) {
          throw new Error('The exact duplicate group changed; refresh and choose again.');
        }
        const displayedCandidates = [...duplicateGroup!.candidate_task_ids].sort();
        const latestCandidates = [...latestGroup.candidate_task_ids].sort();
        if (latestGroup.canonical_task_id !== canonicalTaskId
          || latestGroup.signature !== duplicateGroup!.signature
          || JSON.stringify(latestCandidates) !== JSON.stringify(displayedCandidates)) {
          setDuplicates(latest);
          throw new Error('The exact duplicate group changed; review the refreshed canonical task and candidates.');
        }
        const latestEligible = new Set(latestGroup.tasks
          .filter(task => task.task_id !== latestGroup.canonical_task_id)
          .filter(task => ['completed', 'failed', 'interrupted'].includes(task.status))
          .map(task => task.task_id));
        if (selectedDuplicateTaskIds.some(id => !latestEligible.has(id))) {
          setDuplicates(latest);
          throw new Error('Duplicate eligibility changed; review the updated selection.');
        }
        const result = await api.mergeAgentWork(latestGroup.canonical_task_id, {
          summary: summary.trim(),
          duplicate_task_ids: selectedDuplicateTaskIds,
        });
        addToast({
          type: 'success',
          title: result.reused_existing ? 'Existing merge reused' : 'Duplicate work consolidated',
          message: `Linked ${selectedDuplicateTaskIds.length} duplicate task(s) to ${latestGroup.canonical_task_id}.`,
        });
      }
      onCompleted();
      onClose();
    } catch (error) {
      addToast({
        type: 'error',
        title: `${mode === 'handoff' ? 'Handoff' : mode === 'split' ? 'Split' : 'Merge'} failed`,
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setBusy(false);
    }
  };

  const canSubmit = !busy
    && summary.trim().length > 0
    && (mode === 'merge'
      ? Boolean(canonicalTaskId && selectedDuplicateTaskIds.length > 0)
      : objective.trim().length > 0 && archetype.trim().length > 0)
    && (mode !== 'split' || (
      nodes.length >= 2
      && Number.isInteger(childCount)
      && childCount >= 2
      && childCount <= Math.min(nodes.length, 20)
    ));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={busy ? undefined : onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="relative max-h-[85vh] w-[34rem] overflow-y-auto rounded-lg border border-border bg-surface p-5 shadow-xl"
        onClick={event => event.stopPropagation()}
        onKeyDown={handleDialogKeyDown}
      >
        <h3 id={titleId} className="text-sm font-semibold">
          {mode === 'handoff' ? 'Hand off work' : mode === 'split' ? 'Split work' : 'Merge exact duplicates'}
        </h3>
        <p className="mt-1 text-[11px] text-muted-foreground">
          {mode === 'handoff'
            ? 'Creates one new agent from this terminal task. Historical evidence, sessions, processes, and transcripts stay with their original owner.'
            : mode === 'split'
              ? 'Creates disjoint child tasks whose node scopes exactly cover the source. Frontier and campaign work cannot be split.'
              : 'Consolidates only exact work signatures. Historical records remain attached to the original tasks.'}
        </p>

        <label htmlFor={summaryId} className="mt-4 block text-[10px] uppercase tracking-wider text-muted-foreground">Operator summary</label>
        <textarea
          id={summaryId}
          ref={initialFocusRef}
          value={summary}
          onChange={event => setSummary(event.target.value)}
          rows={3}
          disabled={busy}
          className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs text-foreground outline-none focus:border-accent"
        />

        {mode !== 'merge' && (
          <>
            <label htmlFor={objectiveId} className="mt-3 block text-[10px] uppercase tracking-wider text-muted-foreground">Objective</label>
            <textarea
              id={objectiveId}
              value={objective}
              onChange={event => setObjective(event.target.value)}
              rows={3}
              disabled={busy}
              className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs text-foreground outline-none focus:border-accent"
            />
            <label htmlFor={archetypeId} className="mt-3 block text-[10px] uppercase tracking-wider text-muted-foreground">Agent type</label>
            <input
              id={archetypeId}
              value={archetype}
              onChange={event => setArchetype(event.target.value)}
              disabled={busy}
              className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent"
            />
          </>
        )}

        {mode === 'handoff' && (
          <>
            <label htmlFor={agentLabelId} className="mt-3 block text-[10px] uppercase tracking-wider text-muted-foreground">New label (optional)</label>
            <input
              id={agentLabelId}
              value={agentLabel}
              onChange={event => setAgentLabel(event.target.value)}
              placeholder="Generated automatically when blank"
              disabled={busy}
              className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent"
            />
          </>
        )}

        {mode === 'split' && (
          <>
            <label htmlFor={childCountId} className="mt-3 block text-[10px] uppercase tracking-wider text-muted-foreground">Child tasks</label>
            <input
              id={childCountId}
              type="number"
              min={2}
              max={Math.min(20, nodes.length)}
              value={Number.isNaN(childCount) ? '' : childCount}
              onChange={event => setChildCount(event.target.valueAsNumber)}
              disabled={busy || nodes.length < 2}
              className="mt-1 w-28 rounded border border-border bg-elevated px-2 py-1.5 text-xs text-foreground outline-none focus:border-accent"
            />
            <p className="mt-1 text-[11px] text-muted-foreground">
              {nodes.length} source nodes will be distributed deterministically with no overlap.
            </p>
          </>
        )}

        {mode !== 'merge' && (
          <div className="mt-3 grid gap-2 sm:grid-cols-3">
            <div>
              <label htmlFor={findingRefsId} className="block text-[10px] uppercase tracking-wider text-muted-foreground">Key finding IDs</label>
              <input
                id={findingRefsId}
                value={findingRefs}
                onChange={event => setFindingRefs(event.target.value)}
                placeholder="finding-1, finding-2"
                disabled={busy}
                className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent"
              />
            </div>
            <div>
              <label htmlFor={evidenceRefsId} className="block text-[10px] uppercase tracking-wider text-muted-foreground">Key evidence IDs</label>
              <input
                id={evidenceRefsId}
                value={evidenceRefs}
                onChange={event => setEvidenceRefs(event.target.value)}
                placeholder="evidence-1"
                disabled={busy}
                className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent"
              />
            </div>
            <div>
              <label htmlFor={eventRefsId} className="block text-[10px] uppercase tracking-wider text-muted-foreground">Key event IDs</label>
              <input
                id={eventRefsId}
                value={eventRefs}
                onChange={event => setEventRefs(event.target.value)}
                placeholder="event-1"
                disabled={busy}
                className="mt-1 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent"
              />
            </div>
          </div>
        )}

        {mode === 'merge' && (
          <div className="mt-3 rounded border border-border bg-elevated/60 p-3 text-xs">
            {!duplicates && !loadError && <span className="text-muted-foreground">Finding exact duplicates…</span>}
            {loadError && <span className="text-destructive">{loadError}</span>}
            {duplicates && !duplicateGroup && <span className="text-muted-foreground">No exact duplicate group contains this task.</span>}
            {duplicateGroup && (
              <div className="space-y-1">
                <div><span className="text-muted-foreground">Canonical:</span> <span className="font-mono">{canonicalTaskId}</span></div>
                <div><span className="text-muted-foreground">Terminal merge candidates:</span> {eligibleDuplicateTaskIds.length}</div>
                {eligibleDuplicateTaskIds.map(id => (
                  <label key={id} className="flex items-start gap-2 break-all font-mono text-[10px]">
                    <input
                      type="checkbox"
                      checked={selectedDuplicateTaskIds.includes(id)}
                      onChange={() => toggleDuplicate(id)}
                      disabled={busy}
                    />
                    <span>{id}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <ActionButton onClick={onClose} variant="ghost" size="xs" disabled={busy}>Cancel</ActionButton>
          <ActionButton onClick={() => void submit()} variant="purple" size="xs" disabled={!canSubmit}>
            {busy ? 'Saving…' : mode === 'handoff' ? 'Create successor' : mode === 'split' ? 'Create children' : 'Merge duplicates'}
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
