// ============================================================
// GraphSearch — search overlay with fuzzy node matching
// ============================================================

import { useState, useRef, useEffect, useCallback } from 'react';
import type Graph from 'graphology';
import { NODE_COLORS } from '../../lib/graph-constants';
import { getNodeDisplayLabel } from '../../lib/node-display';
import { cn } from '../../lib/utils';

interface GraphSearchProps {
  graph: Graph;
  onSelect: (nodeId: string) => void;
  className?: string;
}

interface SearchResult {
  id: string;
  label: string;
  type: string;
}

export function GraphSearch({ graph, onSelect, className }: GraphSearchProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const search = useCallback((q: string) => {
    if (!q.trim()) { setResults([]); return; }
    const lower = q.toLowerCase();
    const matches: SearchResult[] = [];

    graph.forEachNode((id, attrs) => {
      if (matches.length >= 20) return;
      const props = (attrs._props as Record<string, unknown>) || {};
      const label = getNodeDisplayLabel(props, id);
      const nodeType = (attrs.nodeType as string) || 'host';
      if (
        id.toLowerCase().includes(lower) ||
        label.toLowerCase().includes(lower) ||
        nodeType.toLowerCase().includes(lower)
      ) {
        matches.push({ id, label, type: nodeType });
      }
    });

    setResults(matches);
    setSelectedIdx(0);
  }, [graph]);

  useEffect(() => {
    search(query);
  }, [query, search]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedIdx(i => Math.min(i + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSelectedIdx(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter' && results[selectedIdx]) {
      e.preventDefault();
      onSelect(results[selectedIdx].id);
      setQuery('');
      setResults([]);
    }
    else if (e.key === 'Escape') { setQuery(''); setResults([]); inputRef.current?.blur(); }
  };

  return (
    <div className={cn('pointer-events-auto w-56', className)}>
      <div className="relative">
        <svg className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-muted-foreground pointer-events-none" viewBox="0 0 14 14" fill="none">
          <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.3" />
          <path d="M9.5 9.5L13 13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
        </svg>
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search nodes…"
          className="w-56 pl-8 pr-3 py-1.5 text-xs bg-surface/90 backdrop-blur border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-accent"
        />
      </div>

      {results.length > 0 && (
        <div className="mt-1 max-h-60 overflow-y-auto bg-surface border border-border rounded-md shadow-lg">
          {results.map((r, idx) => (
            <button
              key={r.id}
              className={cn(
                'w-full px-3 py-1.5 text-left text-xs flex items-center gap-2 hover:bg-hover transition-colors',
                idx === selectedIdx && 'bg-hover',
              )}
              onClick={() => { onSelect(r.id); setQuery(''); setResults([]); }}
              onMouseEnter={() => setSelectedIdx(idx)}
            >
              <span
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ backgroundColor: NODE_COLORS[r.type] || '#888' }}
              />
              <span className="truncate flex-1">{r.label}</span>
              <span className="text-muted-foreground text-[10px]">{r.type}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
