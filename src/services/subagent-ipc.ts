// ============================================================
// Overwatch — Sub-agent IPC Contract (P4.2 — scaffold)
//
// Typed protocol over JSON-over-stdio. Each message is one JSON object
// per line (\n-delimited). Direction is encoded by the message kind, not
// by socket choice — both directions share the same wire format.
//
// Parent (engine) → child:
//   - 'assign' once at startup with task/scope/frontier
//   - 'shutdown' to ask the child to wrap up
//
// Child (sub-agent) → parent:
//   - 'register'        : "I'm alive, my task_id is X"
//   - 'get_context'     : ask the engine for graph context (the parent
//                         translates this into engine.getAgentContext
//                         and sends back a 'context_response')
//   - 'report_finding'  : structured Finding
//   - 'log_thought'     : reasoning trace
//   - 'heartbeat'       : liveness ping
//   - 'submit_transcript': final result summary; child should exit shortly after
//
// Parent → child responses:
//   - 'context_response' for a prior 'get_context'
//
// Today this contract is also satisfied IMPLICITLY by the in-process
// path (sub-agents call MCP tools directly). Making it explicit means
// the process-mode runner can be slotted in alongside without contract
// drift, and the same recon-scoping handler can run in either mode.
//
// Per scoping decision: scaffold the IPC, prove it on recon-scoping
// end-to-end. Other roles stay in_process until follow-up work.
// ============================================================

import type { Finding } from '../types.js';

// ---- Types ----

export interface SubAgentAssign {
  kind: 'assign';
  task_id: string;
  agent_id: string;
  engagement_nonce?: string;
  frontier_item_id?: string;
  subgraph_node_ids: string[];
  skill?: string;
}

export interface SubAgentShutdown {
  kind: 'shutdown';
  task_id: string;
  reason?: string;
}

export interface SubAgentRegister {
  kind: 'register';
  task_id: string;
  agent_id: string;
}

export interface SubAgentGetContext {
  kind: 'get_context';
  task_id: string;
  request_id: string;
  hops?: number;
}

export interface SubAgentContextResponse {
  kind: 'context_response';
  task_id: string;
  request_id: string;
  // Free-shape payload — the parent translates engine.getAgentContext()
  // output here. The child treats it as opaque graph state.
  context: Record<string, unknown>;
}

export interface SubAgentReportFinding {
  kind: 'report_finding';
  task_id: string;
  finding: Finding;
}

export interface SubAgentLogThought {
  kind: 'log_thought';
  task_id: string;
  thought: string;
  thought_kind?: string;
  considered_alternatives?: string[];
  related_action_ids?: string[];
  confidence?: number;
}

export interface SubAgentHeartbeat {
  kind: 'heartbeat';
  task_id: string;
}

export interface SubAgentSubmitTranscript {
  kind: 'submit_transcript';
  task_id: string;
  status: 'completed' | 'failed';
  result_summary?: string;
  transcript?: string;
}

export type SubAgentMessage =
  | SubAgentAssign
  | SubAgentShutdown
  | SubAgentRegister
  | SubAgentGetContext
  | SubAgentContextResponse
  | SubAgentReportFinding
  | SubAgentLogThought
  | SubAgentHeartbeat
  | SubAgentSubmitTranscript;

// ---- Wire format helpers ----

/**
 * Encode a single message. Newline-terminated JSON. Always emit a
 * trailing newline so a buffered reader on the other side can split
 * cleanly even if the OS doesn't flush our writes immediately.
 */
export function encodeMessage(msg: SubAgentMessage): string {
  return JSON.stringify(msg) + '\n';
}

/**
 * Decode a buffer of newline-delimited JSON into a list of messages
 * plus any trailing partial-line bytes the caller should keep for the
 * next read. Tolerates malformed lines (skips with no error) so a
 * single corrupted message doesn't block the channel — caller can log
 * the count separately if desired.
 */
export function decodeMessages(buffer: string): { messages: SubAgentMessage[]; remainder: string } {
  const out: SubAgentMessage[] = [];
  const lastNewline = buffer.lastIndexOf('\n');
  if (lastNewline === -1) return { messages: [], remainder: buffer };
  const complete = buffer.slice(0, lastNewline);
  const remainder = buffer.slice(lastNewline + 1);
  for (const line of complete.split('\n')) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object' && typeof parsed.kind === 'string') {
        out.push(parsed as SubAgentMessage);
      }
    } catch {
      // Drop malformed line. Caller can wrap this in a counter for telemetry.
    }
  }
  return { messages: out, remainder };
}
