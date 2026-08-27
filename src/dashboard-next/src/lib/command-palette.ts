// View-model for the ⌘K command palette — a keyboard-first quick-switcher for the
// live operator: jump to any panel or focus any agent without the mouse. Pure and
// testable in isolation (like lib/attention-queue.ts); the CommandPalette component
// only renders + handles keys, delegating item-building and filtering to here.
import type { AgentInfo } from './types';

/** A navigable route command. Legacy panel IDs remain compatibility-only; the
 * four-workspace palette supplies canonical `path` destinations. */
export interface PanelCommandDef {
  path: string;
  label: string;
  group: string;
}

export interface CommandItem {
  /** Stable key for React + selection. */
  id: string;
  kind: 'panel' | 'workspace' | 'agent' | 'asset' | 'campaign' | 'credential' | 'finding' | 'path';
  label: string;
  /** Secondary context: the nav group for a panel, or the agent's status. */
  hint?: string;
  path?: string;
  taskId?: string;
  /** Canonical destination for non-agent entities in the four-workspace shell. */
  selectionKind?: 'agent' | 'node' | 'campaign' | 'credential' | 'finding' | 'path';
  selectionId?: string;
}

export function buildCommandItems(input: { panels: PanelCommandDef[]; agents?: AgentInfo[] }): CommandItem[] {
  const items: CommandItem[] = [];
  for (const p of input.panels) {
    items.push({
      id: `panel:${p.path}`,
      kind: 'panel',
      label: p.label,
      hint: p.group,
      path: p.path,
    });
  }
  for (const a of input.agents ?? []) {
    items.push({
      id: `agent:${a.id}`,
      kind: 'agent',
      label: a.agent_id || a.id,
      hint: a.status,
      taskId: a.id,
    });
  }
  return items;
}

/** Case-insensitive substring match, ranked: exact > prefix > earliest position,
 *  with a small nudge toward shorter labels so "Graph" beats "Attack Paths" for "gra".
 *  Returns 0 (no match) for a miss. */
function matchScore(hay: string, q: string): number {
  if (hay === q) return 10_000;
  const idx = hay.indexOf(q);
  if (idx < 0) return 0;
  const positional = idx === 0 ? 5_000 : 2_000 - Math.min(idx, 1_500);
  return positional + Math.max(0, 200 - hay.length);
}

/** Filter + rank items for a query. Empty query returns the full list unchanged
 *  (stable order = panels then agents, as built), so the palette opens on a browsable
 *  list. Matches on the label and its hint. */
export function filterCommands(items: CommandItem[], query: string): CommandItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items
    .map((it, index) => ({ it, index, score: matchScore(`${it.label} ${it.hint ?? ''}`.trimEnd().toLowerCase(), q) }))
    .filter(x => x.score > 0)
    // Stable tie-break on original index so equal scores keep their built order.
    .sort((a, b) => (b.score - a.score) || (a.index - b.index))
    .map(x => x.it);
}
