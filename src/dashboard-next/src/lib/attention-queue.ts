import type { AgentInfo, PendingAction } from './types';
import type { AgentQuery } from './api';
import { toConsoleApprovalItem, type ConsoleApprovalItem } from './console-approvals';
import { isStuck, stuckIdleMinutes } from './agent-mission';

// Phase 5 (Mission Control) — one prioritized "what needs me" queue, merging the
// surfaces that today live as separate boxes: pending approvals (act inline),
// agent questions (answer inline), and failed/interrupted agents. The console
// shows one item expanded at a time. Stuck-agent detection joins this in Phase 2
// (the `kind` union is the extension point).

export type AttentionKind = 'approval' | 'question' | 'failed' | 'stuck';

export interface AttentionItem {
  /** Stable id so the expanded-item selection survives re-renders: `<kind>:<ref>`. */
  id: string;
  kind: AttentionKind;
  /** Higher = more urgent; the queue is sorted by this desc. */
  priority: number;
  title: string;
  detail: string;
  agentLabel?: string;
  // Action handles for the UI:
  actionId?: string;   // approval
  queryId?: string;    // question (representative of a cluster)
  /** Question fan-out: every member query_id of this cluster. Answering the
   *  item resolves them all at once. Length 1 for an un-clustered question. */
  queryIds?: string[];
  /** Distinct agent labels that asked this clustered question. */
  clusterAgentLabels?: string[];
  taskId?: string;     // failed agent
  risk?: ConsoleApprovalItem['risk'];
  options?: string[];  // question quick-answers
}

export interface AttentionQueueView {
  /** All items, priority desc. The UI caps display + offers "+N more". */
  items: AttentionItem[];
  total: number;
  counts: Record<AttentionKind, number>;
}

// Priority bands. Timeout-soon approvals auto-resolve if ignored, so they top
// the queue; questions block a live agent; high-risk approvals next; then the
// rest; failed agents are notable but not blocking.
const P_TIMEOUT_APPROVAL = 120;
const P_QUESTION = 100;
const P_HIGH_APPROVAL = 95;
const P_APPROVAL = 80;
// A stuck agent is burning a concurrency slot doing nothing — more actionable
// than a stale failure sitting in history, but below a live agent explicitly
// waiting on the operator (approval/question).
const P_STUCK = 60;
const P_FAILED = 40;

function approvalItem(action: PendingAction, now: number): AttentionItem {
  const a = toConsoleApprovalItem(action, now);
  const priority = a.lifecycle === 'timeout_soon'
    ? P_TIMEOUT_APPROVAL
    : a.risk.label === 'HIGH' ? P_HIGH_APPROVAL : P_APPROVAL;
  return {
    id: `approval:${a.action_id}`,
    kind: 'approval',
    priority,
    title: a.technique,
    detail: a.description,
    agentLabel: action.agent_id,
    actionId: a.action_id,
    risk: a.risk,
  };
}

/** Cluster key: identical question text (whitespace/case-normalized) + the same
 *  option set. Only genuinely-identical questions merge — a different option set
 *  is a different decision and stays separate. */
function questionClusterKey(q: AgentQuery): string {
  const text = q.question.trim().toLowerCase().replace(/\s+/g, ' ');
  const opts = (q.options ?? []).map(o => o.trim().toLowerCase()).sort();
  // JSON-encode rather than join on a delimiter so no option text — one
  // containing the delimiter, or a comma/space straddling a boundary — can
  // collide two different questions into one cluster (which would fan an
  // answer out to the wrong agents).
  return JSON.stringify([text, opts]);
}

// One AttentionItem per cluster of identical open questions. The representative
// (oldest — getOpen is FIFO) drives the id/detail/options; answering fans out to
// every member via queryIds.
function questionClusterItem(group: AgentQuery[]): AttentionItem {
  const rep = group[0];
  const labels = [...new Set(group.map(q => q.agent_id).filter((v): v is string => !!v))];
  const clustered = group.length > 1;
  return {
    id: `question:${rep.query_id}`,
    kind: 'question',
    priority: P_QUESTION,
    title: clustered ? `Agent question · ${group.length} agents` : 'Agent question',
    detail: rep.question,
    agentLabel: clustered ? `${labels.length || group.length} agents` : rep.agent_id,
    queryId: rep.query_id,
    queryIds: group.map(q => q.query_id),
    clusterAgentLabels: labels,
    options: rep.options,
  };
}

function failedItem(agent: AgentInfo): AttentionItem {
  return {
    id: `failed:${agent.id}`,
    kind: 'failed',
    priority: P_FAILED,
    title: agent.status === 'interrupted' ? 'Agent interrupted' : 'Agent failed',
    detail: agent.result_summary || agent.status,
    agentLabel: agent.agent_id || agent.id,
    taskId: agent.id,
  };
}

function stuckItem(agent: AgentInfo, now: number): AttentionItem {
  const idle = stuckIdleMinutes(agent, now);
  const findingMs = agent.last_finding_at ? now - new Date(agent.last_finding_at).getTime() : NaN;
  const lastFinding = Number.isFinite(findingMs)
    ? `, last finding ${Math.max(0, Math.floor(findingMs / 60_000))}m ago`
    : '';
  return {
    id: `stuck:${agent.id}`,
    kind: 'stuck',
    priority: P_STUCK,
    title: 'Agent stuck',
    detail: `Heartbeating but idle ${idle}m${lastFinding} — no progress. Consider steering or stopping it.`,
    agentLabel: agent.agent_id || agent.id,
    taskId: agent.id,
  };
}

export interface AttentionInput {
  pendingActions?: PendingAction[];
  agentQueries?: AgentQuery[];
  agents?: AgentInfo[];
  now?: number;
  /** Failed/interrupted agents only stay in the queue this long after finishing,
   *  so historical failures don't pile up forever and bury live approvals. */
  failedWindowMs?: number;
}

const DEFAULT_FAILED_WINDOW_MS = 30 * 60_000;

// A terminal agent is "needs me" only while recently failed: within the window
// by completed_at, or with no completion timestamp at all (can't tell — keep it).
function recentlyFailed(agent: AgentInfo, now: number, windowMs: number): boolean {
  if (agent.status !== 'failed' && agent.status !== 'interrupted') return false;
  if (!agent.completed_at) return true;
  const age = now - new Date(agent.completed_at).getTime();
  return !Number.isFinite(age) || age <= windowMs;
}

export function buildAttentionQueue(input: AttentionInput = {}): AttentionQueueView {
  const now = input.now ?? Date.now();
  const windowMs = input.failedWindowMs ?? DEFAULT_FAILED_WINDOW_MS;
  const items: AttentionItem[] = [];

  for (const action of input.pendingActions ?? []) items.push(approvalItem(action, now));
  // Cluster identical open questions so the operator answers once → fan-out.
  const clusters = new Map<string, AgentQuery[]>();
  for (const q of input.agentQueries ?? []) {
    if (q.status === 'answered') continue;
    const key = questionClusterKey(q);
    const group = clusters.get(key);
    if (group) group.push(q); else clusters.set(key, [q]);
  }
  for (const group of clusters.values()) items.push(questionClusterItem(group));
  for (const agent of input.agents ?? []) {
    if (recentlyFailed(agent, now, windowMs)) items.push(failedItem(agent));
    // Stuck is mutually exclusive with blocked (isStuck excludes agents waiting
    // on an approval/question), so this never double-counts a blocked agent that
    // already has its approval/question item in the queue.
    else if (isStuck(agent, now, { pendingActions: input.pendingActions, agentQueries: input.agentQueries })) {
      items.push(stuckItem(agent, now));
    }
  }

  items.sort((a, b) => (b.priority - a.priority) || a.id.localeCompare(b.id));

  const counts: Record<AttentionKind, number> = { approval: 0, question: 0, failed: 0, stuck: 0 };
  for (const it of items) counts[it.kind] += 1;

  return { items, total: items.length, counts };
}
