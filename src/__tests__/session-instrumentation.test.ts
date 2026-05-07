// ============================================================
// send_to_session instrumentation (Phase A of the post-foundations
// remediation plan). Sessions used to bypass validateAction, the
// activity-log lifecycle, and evidence persistence; this suite locks
// down the new behavior at the tool boundary.
// ============================================================

import { describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerSessionTools } from '../tools/sessions.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type {
  SessionDefaultValidation,
  SessionMetadata,
  SessionReadResult,
} from '../types.js';
import type { ActivityLogEntry } from '../services/engine-context.js';

interface MockEngineState {
  validate: (action: any) => { valid: boolean; errors: string[]; warnings: string[]; opsec_context: any };
  events: ActivityLogEntry[];
  noiseRecords: any[];
  evidenceWrites: any[];
  nonce?: string;
}

function makeSessionMetadata(overrides: Partial<SessionMetadata> = {}): SessionMetadata {
  const now = new Date().toISOString();
  return {
    id: overrides.id ?? 'session-1',
    kind: overrides.kind ?? 'ssh',
    transport: overrides.transport ?? 'pty',
    state: overrides.state ?? 'connected',
    title: overrides.title ?? 'lab-shell',
    host: overrides.host ?? '10.10.10.7',
    started_at: overrides.started_at ?? now,
    last_activity_at: overrides.last_activity_at ?? now,
    capabilities: overrides.capabilities ?? {
      has_stdin: true,
      has_stdout: true,
      supports_resize: true,
      supports_signals: true,
      tty_quality: 'full',
    },
    buffer_end_pos: overrides.buffer_end_pos ?? 0,
    ...overrides,
  };
}

function buildHarness(opts: {
  session?: SessionMetadata | null;
  sendResult?: SessionReadResult;
  validateOverride?: (action: any) => ReturnType<MockEngineState['validate']>;
  nonce?: string;
} = {}) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const state: MockEngineState = {
    validate: opts.validateOverride ?? ((_a) => ({
      valid: true,
      errors: [],
      warnings: [],
      opsec_context: { global_noise_spent: 0, noise_budget_remaining: 1, recommended_approach: 'normal', defensive_signals: [] },
    })),
    events: [],
    noiseRecords: [],
    evidenceWrites: [],
    nonce: opts.nonce,
  };

  const sendCommand = vi.fn(async () => opts.sendResult ?? {
    session_id: 'session-1',
    start_pos: 0,
    end_pos: 12,
    text: 'mocked stdout',
    truncated: false,
    completion_reason: 'idle' as const,
    timed_out: false,
  });

  const sessionManager = {
    create: vi.fn(),
    list: vi.fn(() => []),
    getSession: vi.fn(() => opts.session ?? null),
    sendCommand,
    update: vi.fn(),
    write: vi.fn(),
    read: vi.fn(),
    resize: vi.fn(),
    signal: vi.fn(),
    close: vi.fn(),
  };

  const engine = {
    getConfig: () => ({
      scope: { cidrs: ['10.10.10.0/24'], domains: ['lab.local'] },
      engagement_nonce: state.nonce,
    }),
    getNode: () => null,
    validateAction: (a: any) => state.validate(a),
    logActionEvent: (entry: any) => {
      const full: ActivityLogEntry = { ...entry, event_id: `evt-${state.events.length + 1}`, timestamp: new Date().toISOString() };
      state.events.push(full);
      return full;
    },
    persist: vi.fn(),
    now: () => '2026-05-07T00:00:00.000Z',
    nextDeterministicSeq: () => 1,
    recordOpsecNoise: (rec: any) => state.noiseRecords.push(rec),
    getEvidenceStore: () => ({
      store: (rec: any) => {
        state.evidenceWrites.push(rec);
        return `evid-${state.evidenceWrites.length}`;
      },
    }),
  } as unknown as GraphEngine;

  registerSessionTools(fakeServer, sessionManager as any, engine);
  return { handlers, sessionManager, sendCommand, state };
}

describe('send_to_session instrumentation', () => {
  it('runs the full lifecycle and persists evidence when default_validation is set', async () => {
    const session = makeSessionMetadata({
      default_validation: { technique: 'lateral_movement', target_ip: '10.10.10.7' } as SessionDefaultValidation,
    });
    const { handlers, sendCommand, state } = buildHarness({ session });

    const result = await handlers.send_to_session({ session_id: 'session-1', command: 'whoami' });

    expect(result.isError).toBeUndefined();
    expect(sendCommand).toHaveBeenCalledOnce();

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toMatch(/^[0-9a-f-]+$/i);
    expect(payload.evidence_id).toBe('evid-1');
    expect(payload.validation_result).toBe('valid');

    const types = state.events.map(e => e.event_type);
    expect(types).toEqual(['action_validated', 'action_started', 'action_completed']);

    const completed = state.events.find(e => e.event_type === 'action_completed')!;
    expect(completed.tool_name).toBe('send_to_session');
    expect(completed.technique).toBe('lateral_movement');
    expect(completed.target_ips).toEqual(['10.10.10.7']);
    expect((completed.details as any).evidence_id).toBe('evid-1');
    expect((completed.details as any).captured_bytes).toBeGreaterThan(0);

    expect(state.evidenceWrites).toHaveLength(1);
    expect(state.evidenceWrites[0].raw_output).toBe('mocked stdout');
    expect(state.evidenceWrites[0].evidence_type).toBe('command_output');
  });

  it('falls back to a generic technique when no default or override is set (uninstrumented-scope path)', async () => {
    // local_pty / scope-less sessions: no operator ceremony required, but
    // the lifecycle still runs with a generic `session_command` technique
    // so the activity log, evidence, and OPSEC noise tracking all work.
    const session = makeSessionMetadata({ default_validation: undefined });
    const { handlers, sendCommand, state } = buildHarness({ session });

    const result = await handlers.send_to_session({ session_id: 'session-1', command: 'whoami' });

    expect(result.isError).toBeUndefined();
    expect(sendCommand).toHaveBeenCalledOnce();
    const started = state.events.find(e => e.event_type === 'action_started')!;
    expect(started.technique).toBe('session_command');
  });

  it('blocks the PTY write when validateAction denies (per-call out-of-scope override)', async () => {
    const session = makeSessionMetadata({
      default_validation: { technique: 'lateral_movement', target_ip: '10.10.10.7' } as SessionDefaultValidation,
    });
    const { handlers, sendCommand, state } = buildHarness({
      session,
      validateOverride: (action) => ({
        valid: action.target_ip === '10.10.10.7',
        errors: action.target_ip === '10.10.10.7' ? [] : [`Target IP is out of scope: ${action.target_ip}`],
        warnings: [],
        opsec_context: { global_noise_spent: 0, noise_budget_remaining: 1, recommended_approach: 'normal', defensive_signals: [] },
      }),
    });

    const result = await handlers.send_to_session({
      session_id: 'session-1',
      command: 'curl https://9.9.9.9/',
      target_ip: '9.9.9.9',
    });

    expect(result.isError).toBe(true);
    expect(sendCommand).not.toHaveBeenCalled();

    const payload = JSON.parse(result.content[0].text);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors[0]).toMatch(/out of scope/);

    const types = state.events.map(e => e.event_type);
    expect(types).toEqual(['action_validated', 'action_failed']);
  });

  it('marks action_failed when the session times out or closes mid-command', async () => {
    const session = makeSessionMetadata({
      default_validation: { technique: 'lateral_movement', target_ip: '10.10.10.7' } as SessionDefaultValidation,
    });
    const { handlers, state } = buildHarness({
      session,
      sendResult: {
        session_id: 'session-1',
        start_pos: 0,
        end_pos: 0,
        text: '',
        truncated: false,
        completion_reason: 'timeout',
        timed_out: true,
      },
    });

    const result = await handlers.send_to_session({ session_id: 'session-1', command: 'sleep 99' });

    expect(result.isError).toBeUndefined(); // mcp response is non-error; lifecycle event is failed
    const completed = state.events.find(e => e.event_type === 'action_failed')!;
    expect(completed).toBeDefined();
    expect((completed.details as any).completion_reason).toBe('timeout');
    expect((completed.details as any).timed_out).toBe(true);
  });

  it('records OPSEC noise when noise_estimate is provided', async () => {
    const session = makeSessionMetadata({
      default_validation: { technique: 'lateral_movement', target_ip: '10.10.10.7' } as SessionDefaultValidation,
    });
    const { handlers, state } = buildHarness({ session });

    await handlers.send_to_session({
      session_id: 'session-1',
      command: 'whoami',
      noise_estimate: 0.25,
    });

    expect(state.noiseRecords).toHaveLength(1);
    expect(state.noiseRecords[0].noise_estimate).toBe(0.25);
  });

  it('per-call technique override takes precedence over the session default', async () => {
    const session = makeSessionMetadata({
      default_validation: { technique: 'lateral_movement', target_ip: '10.10.10.7' } as SessionDefaultValidation,
    });
    const { handlers, state } = buildHarness({ session });

    await handlers.send_to_session({
      session_id: 'session-1',
      command: 'cat /etc/shadow',
      technique: 'post_exploit',
    });

    const started = state.events.find(e => e.event_type === 'action_started')!;
    expect(started.technique).toBe('post_exploit');
  });
});
