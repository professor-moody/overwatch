// ============================================================
// NodePicker — a small searchable single-node select over the engagement graph.
//
// Used by the Attack Paths "Custom path" picker so the operator chooses concrete
// nodes from a list rather than typing a free-form name (which the NL command bar
// could only resolve fuzzily). Driven by ExportedNode[] from the store; matches on
// label / id / type, caps results, and reports the chosen node id.
//
// NOT GraphSearch — that component is coupled to the live graphology Graph in the
// graph view; this works off the plain exported nodes available everywhere.
// ============================================================

import { useMemo, useState } from 'react';
import type { ExportedNode } from '../../lib/types';

const MAX_RESULTS = 20;

export function NodePicker({
  nodes,
  value,
  onChange,
  placeholder = 'search nodes…',
}: {
  nodes: ExportedNode[];
  value?: string;
  onChange: (id: string | undefined) => void;
  placeholder?: string;
}) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);

  const selected = useMemo(() => nodes.find(n => n.id === value), [nodes, value]);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const out: ExportedNode[] = [];
    for (const n of nodes) {
      if (out.length >= MAX_RESULTS) break;
      if (n.id.toLowerCase().includes(q) || n.label.toLowerCase().includes(q) || n.type.toLowerCase().includes(q)) {
        out.push(n);
      }
    }
    return out;
  }, [nodes, query]);

  // Render the chip whenever a value is held — even if that id isn't in the
  // current graph (a stale deep-link target) — so the held endpoint stays visible
  // rather than silently falling back to a blank search box.
  if (value) {
    return (
      <div className="flex items-center gap-2 rounded border border-border bg-surface px-2 py-1 text-xs">
        <span className="truncate text-foreground" title={value}>{selected?.label || value}</span>
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{selected?.type ?? 'unknown'}</span>
        <button
          className="ml-auto text-muted-foreground hover:text-destructive"
          title="Clear"
          onClick={() => { onChange(undefined); setQuery(''); }}
        >✕</button>
      </div>
    );
  }

  return (
    <div className="relative">
      <input
        className="w-full rounded border border-border bg-surface px-2 py-1 text-xs outline-none placeholder:text-muted-foreground"
        placeholder={placeholder}
        value={query}
        onChange={e => { setQuery(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
      />
      {open && matches.length > 0 && (
        <ul className="absolute z-30 mt-1 max-h-56 w-full overflow-y-auto rounded border border-border bg-card shadow-lg">
          {matches.map(n => (
            <li key={n.id}>
              <button
                className="flex w-full items-center gap-2 px-2 py-1 text-left text-xs hover:bg-elevated"
                onMouseDown={() => { onChange(n.id); setQuery(''); setOpen(false); }}
              >
                <span className="truncate text-foreground" title={n.id}>{n.label || n.id}</span>
                <span className="ml-auto shrink-0 text-[10px] uppercase tracking-wide text-muted-foreground">{n.type}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
