import { useEffect, useMemo, useRef, useState } from 'react';
import { cn } from '../../lib/utils';
import { buildCommandItems, filterCommands, type CommandItem, type PanelCommandDef } from '../../lib/command-palette';
import type { AgentInfo } from '../../lib/types';

// ⌘K command palette — a keyboard-first quick-switcher for the live operator: jump to
// any panel or focus any agent without the mouse. Item-building + filtering live in the
// tested view-model (lib/command-palette.ts); this only renders + handles keys.
export function CommandPalette({
  open,
  panels,
  agents,
  items: suppliedItems,
  onClose,
  onSelect,
}: {
  open: boolean;
  panels: PanelCommandDef[];
  agents: AgentInfo[];
  /** Optional prebuilt index used by the four-workspace shell. */
  items?: CommandItem[];
  onClose: () => void;
  onSelect: (item: CommandItem) => void;
}) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const activeRef = useRef<HTMLLIElement>(null);

  const items = useMemo(
    () => suppliedItems ?? buildCommandItems({ panels, agents }),
    [suppliedItems, panels, agents],
  );
  const filtered = useMemo(() => filterCommands(items, query), [items, query]);

  // Reset + focus each time it opens; a fresh query resets the highlight to the top.
  useEffect(() => { if (open) { setQuery(''); setActive(0); inputRef.current?.focus(); } }, [open]);
  useEffect(() => { setActive(0); }, [query]);
  // Keep the highlighted row visible as the operator arrows through a long list.
  useEffect(() => { activeRef.current?.scrollIntoView({ block: 'nearest' }); }, [active]);

  if (!open) return null;

  const choose = (item: CommandItem | undefined) => {
    if (!item) return;
    onSelect(item);
    onClose();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(i => Math.min(i + 1, Math.max(0, filtered.length - 1))); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(filtered[active]); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-[14vh]"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-lg border border-border bg-surface shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Jump to a workspace, asset, finding, or agent…"
          aria-label="Search workspaces and engagement entities"
          className="w-full border-b border-border bg-transparent px-4 py-3 text-sm text-foreground outline-none placeholder:text-muted"
        />
        <ul role="listbox" aria-label="Results" className="max-h-[50vh] overflow-y-auto py-1">
          {filtered.length === 0 && (
            <li className="px-4 py-3 text-xs text-muted-foreground">No matches</li>
          )}
          {filtered.map((item, i) => (
            <li
              key={item.id}
              ref={i === active ? activeRef : undefined}
              role="option"
              aria-selected={i === active}
              onMouseEnter={() => setActive(i)}
              onClick={() => choose(item)}
              className={cn(
                'flex cursor-pointer items-center gap-2 px-4 py-2 text-sm',
                i === active ? 'bg-accent-dim text-foreground' : 'text-muted-foreground',
              )}
            >
              <span className="w-12 flex-shrink-0 text-[10px] uppercase tracking-wide text-muted">{item.kind}</span>
              <span className="min-w-0 flex-1 truncate">{item.label}</span>
              {item.hint && <span className="flex-shrink-0 font-mono text-[10px] text-muted">{item.hint}</span>}
            </li>
          ))}
        </ul>
        <div className="flex gap-3 border-t border-border px-4 py-1.5 text-[10px] text-muted">
          <span><kbd className="font-mono text-accent">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono text-accent">↵</kbd> select</span>
          <span><kbd className="font-mono text-accent">esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
