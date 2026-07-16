import type { AgentConsoleEvent, AgentConsoleSeverity } from './types';
import type { AgentQuery } from './api';

// Phase 5b — turn the focused agent's flat event stream into a readable
// CONVERSATION: your commands, the agent's acknowledgements, the actions it took
// and their results, findings it produced, and questions it's asking — top to
// bottom. Pure transform over the per-agent console events the dashboard already
// loads (+ the agent's open questions); the answer to "where are the results /
// how does it ask me / why does this feel cumbersome".

export type ThreadRole = 'operator' | 'agent' | 'system';
export type ThreadKind = 'command' | 'action' | 'finding' | 'question' | 'thought' | 'session' | 'note';

export interface ThreadEntry {
  id: string;
  timestamp: string;
  role: ThreadRole;
  kind: ThreadKind;
  title: string;
  body: string;
  severity: AgentConsoleSeverity;
  status?: string;
  links?: AgentConsoleEvent['links'];
  raw?: Record<string, unknown>;
  /** Primary entries (commands, actions, findings, questions) read loud;
   *  secondary (thoughts, system notes, sessions) read dim/compact. */
  prominence: 'primary' | 'secondary';
  // question-only:
  queryId?: string;
  options?: string[];
}

function roleForEvent(event: AgentConsoleEvent): ThreadRole {
  if (event.kind === 'command' || event.source_kind === 'dashboard') return 'operator';
  if (event.source_kind === 'system' || event.kind === 'transcript') return 'system';
  return 'agent';
}

function kindForEvent(event: AgentConsoleEvent): ThreadKind {
  switch (event.kind) {
    case 'command': return 'command';
    case 'finding': return 'finding';
    case 'action': return 'action';
    case 'thought': return 'thought';
    case 'session': return 'session';
    default: return 'note'; // approval / system / transcript / etc.
  }
}

function prominenceFor(role: ThreadRole, kind: ThreadKind): 'primary' | 'secondary' {
  if (kind === 'command' || kind === 'finding' || kind === 'question') return 'primary';
  if (kind === 'action') return 'primary';
  if (role === 'system' || kind === 'thought' || kind === 'note' || kind === 'session') return 'secondary';
  return 'primary';
}

function entryFromEvent(event: AgentConsoleEvent): ThreadEntry {
  const role = roleForEvent(event);
  const kind = kindForEvent(event);
  return {
    id: event.id,
    timestamp: event.timestamp,
    role,
    kind,
    title: event.title,
    body: event.summary,
    severity: event.severity,
    status: event.status,
    links: event.links,
    raw: event.raw,
    prominence: prominenceFor(role, kind),
  };
}

function entryFromQuestion(q: AgentQuery): ThreadEntry {
  return {
    id: `question:${q.query_id}`,
    timestamp: new Date(q.created_at).toISOString(),
    role: 'agent',
    kind: 'question',
    title: 'Agent asks',
    body: q.question,
    severity: 'warning',
    prominence: 'primary',
    queryId: q.query_id,
    options: q.options,
  };
}

export interface AgentThreadOptions {
  /** Match questions to this agent by task id and label. */
  agentId: string;
  agentLabel?: string;
  /** Cap the rendered thread (keeps the latest N). */
  limit?: number;
}

/**
 * Build the focused agent's conversation: its console events plus its open
 * questions, interleaved chronologically (oldest → newest). The display layer
 * reverses this to render newest-first and follows the top; the lib keeps the
 * chronological order. Answered questions are dropped (they've left the "needs
 * you" state).
 */
export function buildAgentThread(
  events: AgentConsoleEvent[],
  questions: AgentQuery[],
  opts: AgentThreadOptions,
): ThreadEntry[] {
  const taskIds = new Set([opts.agentId].filter((v): v is string => !!v));
  // Events first (the source array is already timestamp-sorted), then the agent's
  // open questions. The build index is the stable tiebreaker for same-timestamp
  // entries — sorting by event id would be meaningless (ids are uuids/hashes) and
  // could scramble a command→action that share a millisecond.
  const entries: ThreadEntry[] = events.map(entryFromEvent);
  for (const q of questions) {
    if (q.status !== 'open') continue;
    const ownerTaskId = q.owner_task_id ?? q.task_id;
    const owned = !!ownerTaskId && taskIds.has(ownerTaskId);
    if (owned) entries.push(entryFromQuestion(q));
  }

  const ordered = entries
    .map((entry, seq) => ({ entry, seq }))
    .sort((a, b) => a.entry.timestamp.localeCompare(b.entry.timestamp) || (a.seq - b.seq))
    .map(w => w.entry);
  return opts.limit ? ordered.slice(-opts.limit) : ordered;
}

/** Whether the thread currently has an unanswered question (for a header badge). */
export function threadHasOpenQuestion(entries: ThreadEntry[]): boolean {
  return entries.some(e => e.kind === 'question');
}
