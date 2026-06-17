import type { AgentInfo, PendingAction } from './types';
import type { AgentQuery } from './api';
import { toConsoleApprovalItem, type ConsoleApprovalItem } from './console-approvals';

// Phase 5 (Mission Control) — one prioritized "what needs me" queue, merging the
// surfaces that today live as separate boxes: pending approvals (act inline),
// agent questions (answer inline), and failed/interrupted agents. The console
// shows one item expanded at a time. Stuck-agent detection joins this in Phase 2
// (the `kind` union is the extension point).

export type AttentionKind = 'approval' | 'question' | 'failed';

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
  queryId?: string;    // question
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

function questionItem(q: AgentQuery): AttentionItem {
  return {
    id: `question:${q.query_id}`,
    kind: 'question',
    priority: P_QUESTION,
    title: 'Agent question',
    detail: q.question,
    agentLabel: q.agent_id,
    queryId: q.query_id,
    options: q.options,
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
  for (const q of input.agentQueries ?? []) {
    if (q.status !== 'answered') items.push(questionItem(q));
  }
  for (const agent of input.agents ?? []) {
    if (recentlyFailed(agent, now, windowMs)) items.push(failedItem(agent));
  }

  items.sort((a, b) => (b.priority - a.priority) || a.id.localeCompare(b.id));

  const counts: Record<AttentionKind, number> = { approval: 0, question: 0, failed: 0 };
  for (const it of items) counts[it.kind] += 1;

  return { items, total: items.length, counts };
}
