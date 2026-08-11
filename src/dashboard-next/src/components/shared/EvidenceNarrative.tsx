import { useLayoutEffect, useRef, useState } from 'react';
import type { EvidenceNarrativeItem } from '../../lib/evidence-narrative';
import type { ProofExcerpt } from '../../lib/types';
import { cn, formatTimestamp } from '../../lib/utils';
import { GraphNodeLinks } from './GraphNodeLinks';

export function EvidenceNarrative({
  items,
  subject,
  empty = 'No supporting evidence chain found yet.',
}: {
  items: EvidenceNarrativeItem[];
  /** What the evidence proves — the vuln/finding — so the raw output is self-explanatory. */
  subject?: string;
  empty?: string;
}) {
  if (items.length === 0) {
    return <div className="text-xs text-muted-foreground">{empty}</div>;
  }

  return (
    <div className="space-y-2">
      {subject && (
        <div className="text-[11px] text-muted-foreground">
          Evidence below is what proves <span className="font-medium text-foreground">{subject}</span>:
        </div>
      )}
      {items.map(item => (
        <div key={item.id} className="rounded border border-border bg-elevated p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-accent">{sourceKindLabel(item.source_kind)}</span>
              {item.source_trust && <TrustBadge trust={item.source_trust} />}
            </div>
            <span className="text-[10px] text-muted-foreground">{item.count} event{item.count === 1 ? '' : 's'}</span>
          </div>
          <div className="mt-1 text-xs font-medium text-foreground">
            Supports evidence for{' '}
            <GraphNodeLinks
              nodeId={item.node_id}
              label={item.label}
              graphTarget={{ kind: 'evidence', nodeId: item.node_id, label: `Evidence for ${item.label || item.node_id}` }}
              className="text-accent"
            />
          </div>
          {item.command && (
            <div className="mt-1.5">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">How it was found</div>
              <pre className="mt-0.5 overflow-x-auto whitespace-pre-wrap break-words rounded border border-border bg-background/60 px-2 py-1 font-mono text-[11px] text-foreground">
                <span className="select-none text-muted-foreground">$ </span>{item.command}
              </pre>
            </div>
          )}
          {item.proof && <EvidenceProof proof={item.proof} />}
          {item.excerpts && item.excerpts.length > 0 && <MatchedSignals excerpts={item.excerpts} />}
          <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
            {item.tool && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{item.tool}</span>}
            {item.agent_id && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">agent {item.agent_id}</span>}
            {typeof item.exit_code === 'number' && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">exit {item.exit_code}</span>}
            {item.latest && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{formatTimestamp(item.latest)}</span>}
          </div>
          {(item.action_id || item.event_type || item.description || item.content_hash || item.evidence_id) && (
            <details className="mt-2">
              <summary className="cursor-pointer text-[10px] text-accent">Trace metadata</summary>
              <div className="mt-1 space-y-1 text-[10px] text-muted-foreground">
                {item.event_type && <div>Event: <span className="font-mono text-foreground">{item.event_type}</span></div>}
                {item.action_id && <div>Action: <span className="font-mono text-foreground break-all">{item.action_id}</span></div>}
                {item.evidence_id && <div>Evidence: <span className="font-mono text-foreground break-all">{item.evidence_id}</span></div>}
                {item.content_hash && <div>SHA-256: <span className="font-mono text-foreground break-all">{item.content_hash}</span></div>}
                {item.description && <div>{item.description}</div>}
              </div>
            </details>
          )}
        </div>
      ))}
    </div>
  );
}

/** The captured proof (raw tool output). Preserves formatting (mono/pre-wrap) and
 *  collapses to a fixed max height with a toggle, instead of the old 3-line clamp
 *  that made long output unreadable. The toggle appears based on the ACTUAL
 *  rendered overflow (measured against the collapsed cap) rather than a line/char
 *  heuristic — word-wrapped output can exceed the cap even when the raw text is
 *  short, and clipping evidence with no "show full output" affordance would hide it. */
function EvidenceProof({ proof }: { proof: string }) {
  const [open, setOpen] = useState(false);
  const [overflowing, setOverflowing] = useState(false);
  const ref = useRef<HTMLPreElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    // When collapsed, overflow-hidden clips to max-h-40 so scrollHeight > clientHeight
    // iff there's more to show. When expanded the cap is off (heights equal); keep the
    // toggle visible via `open` so the operator can collapse back.
    setOverflowing(el.scrollHeight > el.clientHeight + 1);
  }, [proof, open]);
  const showToggle = overflowing || open;
  return (
    <div className="mt-1">
      <pre
        ref={ref}
        className={cn(
          'whitespace-pre-wrap break-words font-mono text-[11px] leading-snug text-muted-foreground',
          !open && 'max-h-40 overflow-hidden',
        )}
      >{proof}</pre>
      {showToggle && (
        <button onClick={() => setOpen(o => !o)} className="mt-0.5 text-[10px] text-accent hover:text-foreground">
          {open ? 'show less' : 'show full output'}
        </button>
      )}
    </div>
  );
}

function sourceKindLabel(kind: EvidenceNarrativeItem['source_kind']): string {
  if (kind === 'command_output') return 'Command output';
  if (kind === 'parsed_result') return 'Parsed result';
  return 'Activity record';
}

/** Honesty label (3d): whether the evidence was directly captured (observed), merely
 *  claimed (asserted), or produced by a rule (inferred) — so the reader can tell proof
 *  from hypothesis at a glance. */
function TrustBadge({ trust }: { trust: NonNullable<EvidenceNarrativeItem['source_trust']> }) {
  const cls = trust === 'observed' ? 'border-success/40 text-success'
    : trust === 'asserted' ? 'border-warning/40 text-warning'
    : 'border-border text-muted-foreground';
  const title = trust === 'observed' ? 'Directly captured from tool output — proof.'
    : trust === 'asserted' ? 'Claimed by the tool/agent, not independently captured.'
    : 'Produced by an inference rule, not a direct observation.';
  return (
    <span className={cn('rounded border px-1.5 py-0.5 text-[9px] uppercase tracking-wide', cls)} title={title}>
      {trust}
    </span>
  );
}

/** Matched-signal excerpts (3c): the exact bytes that justify the finding, re-read and
 *  verified against the evidence blob — so a reader can see (and audit) the proof, not a
 *  paraphrase. Shows the byte range, what matched it, and the verification verdict. */
function MatchedSignals({ excerpts }: { excerpts: ProofExcerpt[] }) {
  return (
    <div className="mt-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Matched signal</div>
      <div className="mt-0.5 space-y-1">
        {excerpts.map((ex, i) => (
          <div key={i} className="rounded border border-border bg-background/60 px-2 py-1">
            <div className="flex flex-wrap items-center gap-2 text-[9px] text-muted-foreground">
              <span>bytes {ex.byte_start}–{ex.byte_end}</span>
              {ex.matched_by && <span>matched by {ex.matched_by}</span>}
              {ex.verified === true && <span className="text-success">✓ verified</span>}
              {ex.verified === false && <span className="text-destructive">✗ mismatch vs blob</span>}
            </div>
            {(ex.resolved_snippet ?? ex.snippet) && (
              <pre className="mt-0.5 overflow-x-auto whitespace-pre-wrap break-words font-mono text-[11px] text-foreground">{ex.resolved_snippet ?? ex.snippet}</pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
