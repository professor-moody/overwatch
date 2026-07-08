import { useLayoutEffect, useRef, useState } from 'react';
import type { EvidenceNarrativeItem } from '../../lib/evidence-narrative';
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
            <span className="text-[10px] font-semibold uppercase tracking-wide text-accent">{sourceKindLabel(item.source_kind)}</span>
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
          {item.proof && <EvidenceProof proof={item.proof} />}
          <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
            {item.tool && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{item.tool}</span>}
            {item.latest && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{formatTimestamp(item.latest)}</span>}
          </div>
          {(item.action_id || item.event_type || item.description) && (
            <details className="mt-2">
              <summary className="cursor-pointer text-[10px] text-accent">Trace metadata</summary>
              <div className="mt-1 space-y-1 text-[10px] text-muted-foreground">
                {item.event_type && <div>Event: <span className="font-mono text-foreground">{item.event_type}</span></div>}
                {item.action_id && <div>Action: <span className="font-mono text-foreground break-all">{item.action_id}</span></div>}
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
