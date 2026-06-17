// Derive a list of agent "tool runs" from the activity history for the
// Analysis workspace left rail. Pure (no I/O) so it is unit-testable; the
// full per-run detail comes from getActionOutput(actionId).

import type { ActivityEntry } from './types';

export type RunStatus = 'running' | 'success' | 'failure' | 'partial' | 'neutral';

export interface ActionRun {
  actionId: string;
  tool: string | null;
  command: string | null;
  status: RunStatus;
  agentId: string | null;
  targets: string[];
  /** Representative timestamp (terminal event if present, else started). */
  timestamp: string;
  startedAt: string | null;
  description: string;
}

const LIFECYCLE = new Set(['action_started', 'action_completed', 'action_failed']);

// The frontend ActivityEntry type is a subset; the wire payload also carries
// these top-level fields, so read them through a widened view.
type RawEntry = ActivityEntry & {
  tool_name?: string;
  command_repr?: string;
  target_ips?: string[];
  target_cidrs?: string[];
};

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function asStatus(v: unknown): RunStatus | undefined {
  return v === 'success' || v === 'failure' || v === 'partial' || v === 'neutral' ? v : undefined;
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function collectTargets(rep: RawEntry, td: Record<string, unknown>, sd: Record<string, unknown>): string[] {
  const out = new Set<string>();
  for (const id of rep.target_node_ids ?? []) out.add(id);
  for (const ip of rep.target_ips ?? []) out.add(ip);
  for (const ip of rep.target_cidrs ?? []) out.add(ip);
  for (const d of [td, sd]) {
    for (const id of strArray(d.target_node_ids)) out.add(id);
    for (const ip of strArray(d.target_ips)) out.add(ip);
    for (const c of strArray(d.target_cidrs)) out.add(c);
  }
  return [...out];
}

/** Group action lifecycle events by action_id into one run summary each, newest first. */
export function buildActionRuns(entries: ActivityEntry[]): ActionRun[] {
  const byAction = new Map<string, RawEntry[]>();
  for (const e of entries as RawEntry[]) {
    if (!e.action_id || !LIFECYCLE.has(e.event_type)) continue;
    const arr = byAction.get(e.action_id) ?? [];
    arr.push(e);
    byAction.set(e.action_id, arr);
  }

  const runs: ActionRun[] = [];
  for (const [actionId, evs] of byAction) {
    const terminal = [...evs].reverse().find(
      e => e.event_type === 'action_completed' || e.event_type === 'action_failed',
    );
    const started = evs.find(e => e.event_type === 'action_started');
    const rep = terminal ?? started ?? evs[evs.length - 1];
    const td = (terminal?.details ?? {}) as Record<string, unknown>;
    const sd = (started?.details ?? {}) as Record<string, unknown>;
    const pick = (k: string) => str(td[k]) ?? str(sd[k]);

    runs.push({
      actionId,
      tool: str(rep.tool_name) ?? pick('binary') ?? pick('invoking_tool') ?? null,
      command: str(rep.command_repr) ?? pick('command') ?? pick('command_repr') ?? null,
      status: terminal
        ? (asStatus(terminal.result_classification) ?? (terminal.event_type === 'action_failed' ? 'failure' : 'success'))
        : 'running',
      agentId: rep.agent_id ?? null,
      targets: collectTargets(rep, td, sd),
      timestamp: rep.timestamp,
      startedAt: started?.timestamp ?? null,
      description: rep.description ?? '',
    });
  }

  runs.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
  return runs;
}

export function filterRuns(
  runs: ActionRun[],
  opts: { status?: RunStatus | ''; search?: string },
): ActionRun[] {
  const status = opts.status || '';
  const q = (opts.search || '').trim().toLowerCase();
  return runs.filter(r => {
    if (status && r.status !== status) return false;
    if (!q) return true;
    const hay = [r.tool, r.command, r.agentId, r.actionId, r.description, ...r.targets]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return hay.includes(q);
  });
}

/** A short, human label for a run row when no command is present. */
export function runLabel(run: ActionRun): string {
  if (run.command) return run.command;
  if (run.tool) return run.tool;
  return run.description || run.actionId;
}
