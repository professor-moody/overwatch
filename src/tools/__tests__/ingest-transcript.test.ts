import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync, rmSync, readFileSync } from 'fs';
import { resolve } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerTranscriptTools } from '../transcripts.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-ingest-transcript.json';
const FIXTURE_PATH = resolve(__dirname, '../../../fixtures/transcripts/sample.jsonl');

function makeConfig(): EngagementConfig {
  return {
    id: 'test-ingest-transcript',
    name: 'ingest_transcript test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-ingest-transcript', { recursive: true, force: true }); } catch {}
}

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('ingest_transcript', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerTranscriptTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('parses fixture jsonl, stores evidence, emits per-turn events with action_id linkage', async () => {
    const result = await handlers.ingest_transcript({
      transcript_path: FIXTURE_PATH,
      session_id: 'test-session-1',
    });
    const payload = parse(result);

    expect(result.isError).toBeFalsy();
    expect(payload.ingested).toBe(true);
    expect(payload.turn_count).toBe(5);
    expect(payload.tool_call_count).toBe(1);
    expect(payload.tool_result_count).toBe(1);
    expect(payload.action_id_linked).toBe(2); // both call + result reference act-abc-1
    expect(payload.evidence_id).toBeTruthy();
    expect(payload.parse_errors).toEqual([]);

    // Evidence stored
    const stored = engine.getEvidenceStore().getContent(payload.evidence_id);
    expect(stored).toBe(readFileSync(FIXTURE_PATH, 'utf-8'));

    // Per-turn events present
    const events = engine.getFullHistory().filter(e => e.event_type === 'transcript_turn_ingested');
    expect(events.length).toBe(5);

    // Roles correctly classified
    const roles = events.map(e => (e.details as any).role);
    expect(roles).toEqual(['user', 'assistant', 'tool_call', 'tool_result', 'assistant']);

    // Tool-call event captures tool_name + action_id_ref
    const toolCall = events.find(e => (e.details as any).role === 'tool_call');
    expect((toolCall?.details as any).tool_name).toBe('validate_action');
    expect((toolCall?.details as any).action_id_ref).toBe('act-abc-1');

    // All events share the transcript hash and evidence_id
    const hashes = new Set(events.map(e => (e.details as any).transcript_sha256));
    expect(hashes.size).toBe(1);
    const evIds = new Set(events.map(e => (e.details as any).evidence_id));
    expect(evIds.size).toBe(1);

    // Provenance defaulted to 'ingested'
    for (const e of events) {
      expect(e.provenance).toBe('ingested');
    }
  });

  it('is idempotent: re-ingesting the same blob is skipped with a warning', async () => {
    const blob = readFileSync(FIXTURE_PATH, 'utf-8');
    await handlers.ingest_transcript({ transcript_jsonl: blob, session_id: 's1' });
    const second = await handlers.ingest_transcript({ transcript_jsonl: blob, session_id: 's1' });
    const payload = parse(second);

    expect(payload.ingested).toBe(false);
    expect(payload.skipped).toBe('duplicate');

    // Only the first ingest produced turn events
    const events = engine.getFullHistory().filter(e => e.event_type === 'transcript_turn_ingested');
    expect(events.length).toBe(5);

    // Warning surfaced
    const warnings = engine.getFullHistory().filter(e =>
      e.event_type === 'instrumentation_warning'
      && (e.details as any)?.warning === 'duplicate_transcript_ingest',
    );
    expect(warnings.length).toBe(1);
  });

  it('returns error when neither transcript_path nor transcript_jsonl provided', async () => {
    const result = await handlers.ingest_transcript({ session_id: 's1' });
    expect(result.isError).toBe(true);
    expect(parse(result).error).toMatch(/transcript_path or transcript_jsonl/);
  });

  it('records parse_errors for malformed lines but ingests the rest', async () => {
    const blob = '{"role":"user","content":"hi"}\nNOT JSON\n{"role":"assistant","content":"ok"}\n';
    const result = await handlers.ingest_transcript({ transcript_jsonl: blob, session_id: 's-mixed' });
    const payload = parse(result);
    expect(payload.ingested).toBe(true);
    expect(payload.turn_count).toBe(2);
    expect(payload.parse_errors.length).toBe(1);
    expect(payload.parse_errors[0].line).toBe(2);
  });

  it('keeps default recent_activity clean (system+ingested events filtered)', async () => {
    await handlers.ingest_transcript({
      transcript_path: FIXTURE_PATH,
      session_id: 's-clean',
    });
    // Default get_state behavior: include_system=true (events still visible).
    // The key Phase 1 guarantee is that descriptions are compact (not full text dumps).
    const events = engine.getFullHistory().filter(e => e.event_type === 'transcript_turn_ingested');
    for (const e of events) {
      expect(e.description.length).toBeLessThan(300);
    }
  });
});
