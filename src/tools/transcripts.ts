// ============================================================
// Overwatch — ingest_transcript tool
// Pull an external chat/IDE transcript JSONL into the engagement
// after the fact. Each turn becomes a compact `transcript_turn_ingested`
// event linked to evidence; tool-call turns extract action_id where
// possible so retrospective analysis can correlate them with live
// graph events.
// ============================================================

import { z } from 'zod';
import { readFileSync, existsSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import {
  parseTranscriptJsonl,
  hashTranscript,
  type ParsedTranscriptTurn,
} from '../services/transcript-parser.js';

// In-memory dedup of already-ingested transcript hashes for the lifetime of
// this engine instance. We also persist a marker by writing a system event
// containing the hash, so a restart can rebuild this set from history.
const INGESTED_HASHES = new WeakMap<GraphEngine, Set<string>>();

function getIngestedSet(engine: GraphEngine): Set<string> {
  let set = INGESTED_HASHES.get(engine);
  if (!set) {
    set = new Set<string>();
    // Rebuild from history: any event of this type with details.transcript_sha256
    for (const e of engine.getFullHistory()) {
      if (e.event_type === 'transcript_turn_ingested') {
        const h = (e.details as any)?.transcript_sha256;
        if (typeof h === 'string') set.add(h);
      }
    }
    INGESTED_HASHES.set(engine, set);
  }
  return set;
}

export function registerTranscriptTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'ingest_transcript',
    {
      title: 'Ingest Transcript',
      description: `Pull an external chat/IDE transcript JSONL into the engagement after the fact.

Each line of the transcript is parsed into a typed turn (user / assistant / tool_call / tool_result / system) and written as a compact \`transcript_turn_ingested\` activity event with \`provenance: 'ingested'\`. Tool-call/result turns extract an \`action_id\` when one is present so retrospective analysis can correlate them with the live graph events.

The full transcript blob is stored in the evidence store (linked from each turn event by \`evidence_id\`); turn events themselves stay short (no full text dumped into \`description\`).

Idempotent: the SHA-256 of the transcript content is recorded; re-ingesting the same blob is skipped and surfaces an \`instrumentation_warning\`. Provide either \`transcript_path\` (read from disk) or \`transcript_jsonl\` (raw content).`,
      inputSchema: {
        transcript_path: z.string().optional().describe('Absolute path to a JSONL transcript file. Mutually exclusive with transcript_jsonl.'),
        transcript_jsonl: z.string().optional().describe('Raw JSONL transcript content. Mutually exclusive with transcript_path.'),
        session_id: z.string().describe('Identifier for the source session (IDE chat session, CLI run, etc.) — used for attribution.'),
        provenance: z.enum(['ingested', 'operator']).default('ingested').describe('Provenance to record on each turn event.'),
        agent_id: z.string().optional().describe('Optional agent_id to associate with these turns (e.g. when the transcript is a sub-agent run).'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('ingest_transcript', async ({ transcript_path, transcript_jsonl, session_id, provenance, agent_id }) => {
      const resolved_provenance: 'ingested' | 'operator' = provenance ?? 'ingested';
      if (!transcript_path && !transcript_jsonl) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'Provide either transcript_path or transcript_jsonl' }, null, 2) }],
          isError: true,
        };
      }
      if (transcript_path && transcript_jsonl) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'Provide only one of transcript_path or transcript_jsonl' }, null, 2) }],
          isError: true,
        };
      }

      let blob: string;
      if (transcript_path) {
        if (!existsSync(transcript_path)) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Transcript file not found: ${transcript_path}` }, null, 2) }],
            isError: true,
          };
        }
        try {
          blob = readFileSync(transcript_path, 'utf-8');
        } catch (err) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Failed to read transcript: ${(err as Error).message}` }, null, 2) }],
            isError: true,
          };
        }
      } else {
        blob = transcript_jsonl as string;
      }

      const transcript_sha256 = await hashTranscript(blob);
      const seen = getIngestedSet(engine);
      if (seen.has(transcript_sha256)) {
        engine.logActionEvent({
          description: `ingest_transcript skipped duplicate (sha256=${transcript_sha256.slice(0, 12)}…) for session ${session_id}`,
          event_type: 'instrumentation_warning',
          category: 'system',
          provenance: 'system',
          details: {
            warning: 'duplicate_transcript_ingest',
            session_id,
            transcript_sha256,
          },
        });
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ingested: false,
              skipped: 'duplicate',
              transcript_sha256,
              session_id,
            }, null, 2),
          }],
        };
      }

      const { turns, parse_errors } = parseTranscriptJsonl(blob);

      // Store full transcript as evidence
      const evidence_id = engine.getEvidenceStore().store({
        evidence_type: 'log',
        filename: `transcript_${session_id}.jsonl`,
        content: blob,
      });

      // Per-turn events (compact)
      const turn_event_ids: string[] = [];
      for (const turn of turns) {
        const description = compactDescription(turn, session_id);
        const details: Record<string, unknown> = {
          session_id,
          transcript_sha256,
          evidence_id,
          turn_index: turn.index,
          role: turn.role,
          summary: turn.summary,
          raw_size: turn.raw_size,
        };
        if (turn.tool_name) details.tool_name = turn.tool_name;
        if (turn.action_id) details.action_id_ref = turn.action_id;

        const event = engine.logActionEvent({
          description,
          event_type: 'transcript_turn_ingested',
          category: 'system',
          provenance: resolved_provenance,
          agent_id,
          // Note: we record action_id in details (not as the entry's action_id)
          // to avoid polluting the actionFrontierMap with externally-sourced refs
          // that may not match a live action.
          details,
        });
        turn_event_ids.push(event.event_id);
      }

      seen.add(transcript_sha256);

      const tool_call_count = turns.filter(t => t.role === 'tool_call').length;
      const tool_result_count = turns.filter(t => t.role === 'tool_result').length;
      const action_id_count = turns.filter(t => !!t.action_id).length;

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ingested: true,
            session_id,
            transcript_sha256,
            evidence_id,
            turn_count: turns.length,
            tool_call_count,
            tool_result_count,
            action_id_linked: action_id_count,
            parse_errors,
            turn_event_ids: turn_event_ids.slice(0, 10),  // sample only — full list available via query_graph
          }, null, 2),
        }],
      };
    }),
  );
}

function compactDescription(turn: ParsedTranscriptTurn, session_id: string): string {
  const head = `[transcript ${session_id} #${turn.index}] ${turn.role}`;
  if (turn.tool_name) {
    const ref = turn.action_id ? ` (action_id=${turn.action_id})` : '';
    return `${head} ${turn.tool_name}${ref}`;
  }
  return `${head}: ${turn.summary}`;
}
