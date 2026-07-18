import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { setColorEnabled, isColorEnabled, formatTable, truncate, keyValues } from '../operator/format.js';
import { resolveClientOptions, createClient, ApiError, type ApiClient } from '../operator/client.js';
import { READ_COMMANDS, WRITE_COMMANDS } from '../operator/commands.js';
import { renderStatus, renderApprovals, renderQueries, renderOpsec, renderFindings, renderDeploy, renderDispatch, renderAgents, renderRecovery, renderSessions, renderPlaybooks, renderAgentDuplicates, renderAgentWorkMutation } from '../operator/render.js';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deterministic output: force color off for all assertions.
const initialColorEnabled = isColorEnabled();
beforeEach(() => setColorEnabled(false));
afterEach(() => setColorEnabled(initialColorEnabled));

describe('format', () => {
  it('truncate adds an ellipsis past the limit', () => {
    expect(truncate('abcdef', 4)).toBe('abc…');
    expect(truncate('abc', 4)).toBe('abc');
    expect(truncate('abc', 0)).toBe('');
  });

  it('color helpers are plain when disabled (no ANSI)', () => {
    setColorEnabled(false);
    const out = formatTable(['A', 'B'], [['x', 'y']]);
    // eslint-disable-next-line no-control-regex
    expect(/\x1b\[/.test(out)).toBe(false);
  });

  it('formatTable aligns columns and shows (none) when empty', () => {
    expect(formatTable(['A'], [])).toContain('(none)');
    const out = formatTable(['STATUS', 'ID'], [['running', 'a1'], ['pending', 'a22']]);
    const lines = out.split('\n');
    expect(lines[0]).toMatch(/^STATUS/);
    expect(lines).toHaveLength(3); // header + 2 rows
  });

  it('keyValues right-pads keys', () => {
    const out = keyValues([['a', '1'], ['bbb', '2']]);
    expect(out).toContain('a:');
    expect(out).toContain('bbb:');
  });

  it('renders recovered session ownership from claimed_by', () => {
    const output = renderSessions([{
      id: 'listener-1',
      kind: 'socket',
      state: 'resume_available',
      claimed_by: 'task-owner',
      connection_generation: 2,
    }]);
    expect(output).toContain('task-owner');
    expect(output).toContain('resume_available');
  });

  it('renders ownership for prepared, approval-waiting, and running playbook attempts', () => {
    const statuses = ['claimed', 'awaiting_approval', 'running'];
    const output = renderPlaybooks({ total: 3, runs: statuses.map((status, index) => ({
      run_id: `run-${index + 1}`, schema_version: 1, credential_id: 'cred-1', status, report_status: 'partial',
      definition: { provider: 'aws' },
      steps: [{ status, attempts: [{ status, claimed_by_task_id: `task-${status}`, claimed_via: 'mcp' }] }],
    })) });
    expect(output).toContain('task-claimed');
    expect(output).toContain('task-awaiting_approval');
    expect(output).toContain('task-running');
    expect(output).toContain('partial');
  });
});

describe('client option resolution', () => {
  it('prefers --url/--token flags over env and default', () => {
    const opts = resolveClientOptions(['--url', 'http://host:9/', '--token', 'tok']);
    expect(opts.url).toBe('http://host:9'); // trailing slash stripped
    expect(opts.token).toBe('tok');
  });

  it('falls back to the loopback default with no token', () => {
    const prevUrl = process.env.OVERWATCH_URL; const prevTok = process.env.OVERWATCH_DASHBOARD_TOKEN;
    delete process.env.OVERWATCH_URL; delete process.env.OVERWATCH_DASHBOARD_TOKEN;
    const opts = resolveClientOptions([]);
    expect(opts.url).toBe('http://127.0.0.1:8384');
    expect(opts.token).toBeUndefined();
    if (prevUrl !== undefined) process.env.OVERWATCH_URL = prevUrl;
    if (prevTok !== undefined) process.env.OVERWATCH_DASHBOARD_TOKEN = prevTok;
  });

  it('sends a Bearer header only when a token is set, and never an Origin header', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string | URL, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    try {
      await createClient({ url: 'http://h:8384', token: 'secret123' }).get('/api/state');
      const withTok = (calls[0].init.headers ?? {}) as Record<string, string>;
      expect(withTok.Authorization).toBe('Bearer secret123');
      expect(withTok.Origin).toBeUndefined(); // CLI never sends Origin → server CSRF check is skipped
      calls.length = 0;
      await createClient({ url: 'http://h:8384' }).get('/api/state');
      expect(((calls[0].init.headers ?? {}) as Record<string, string>).Authorization).toBeUndefined();
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('raises an unreachable ApiError when the server cannot be reached', async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => { throw new TypeError('fetch failed'); }) as typeof fetch;
    try {
      const err = await createClient({ url: 'http://127.0.0.1:9' }).get('/api/state').catch(e => e);
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).unreachable).toBe(true);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('retries one failed mutation with the same command identity', async () => {
    const calls: RequestInit[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: string | URL, init: RequestInit) => {
      calls.push(init);
      if (calls.length === 1) throw new TypeError('response connection lost');
      return new Response('{"ok":true}', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'X-Overwatch-Server-Response': '1',
        },
      });
    }) as typeof fetch;
    try {
      await createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 });
      expect(calls).toHaveLength(2);
      expect(calls[1].headers).toEqual(calls[0].headers);
      expect(calls[1].body).toBe(calls[0].body);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('retains a mutation identity across process-like clients until a response arrives', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-cli-pending-'));
    const previousPendingDirectory = process.env.OVERWATCH_CLI_PENDING_DIR;
    process.env.OVERWATCH_CLI_PENDING_DIR = directory;
    const calls: RequestInit[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: string | URL, init: RequestInit) => {
      calls.push(init);
      if (calls.length <= 2) throw new TypeError('daemon unavailable');
      return new Response('{"ok":true}', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'X-Overwatch-Server-Response': '1',
        },
      });
    }) as typeof fetch;
    try {
      await expect(createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 }))
        .rejects.toMatchObject({ unreachable: true });
      const retainedId = (calls[0].headers as Record<string, string>)['X-Overwatch-Command-Id'];

      await createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 });
      expect((calls[2].headers as Record<string, string>)['X-Overwatch-Command-Id'])
        .toBe(retainedId);

      await createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 });
      expect((calls[3].headers as Record<string, string>)['X-Overwatch-Command-Id'])
        .not.toBe(retainedId);
    } finally {
      globalThis.fetch = realFetch;
      if (previousPendingDirectory === undefined) delete process.env.OVERWATCH_CLI_PENDING_DIR;
      else process.env.OVERWATCH_CLI_PENDING_DIR = previousPendingDirectory;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('retains a mutation identity after an unmarked proxy response', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-cli-proxy-pending-'));
    const previousPendingDirectory = process.env.OVERWATCH_CLI_PENDING_DIR;
    process.env.OVERWATCH_CLI_PENDING_DIR = directory;
    const calls: RequestInit[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: string | URL, init: RequestInit) => {
      calls.push(init);
      return calls.length === 1
        ? new Response('{"error":"gateway timeout"}', { status: 504 })
        : new Response('{"ok":true}', {
            status: 200,
            headers: { 'X-Overwatch-Server-Response': '1' },
          });
    }) as typeof fetch;
    try {
      await expect(createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 }))
        .rejects.toMatchObject({ status: 504 });
      const firstId = (calls[0].headers as Record<string, string>)['X-Overwatch-Command-Id'];
      await createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 });
      expect((calls[1].headers as Record<string, string>)['X-Overwatch-Command-Id'])
        .toBe(firstId);
    } finally {
      globalThis.fetch = realFetch;
      if (previousPendingDirectory === undefined) delete process.env.OVERWATCH_CLI_PENDING_DIR;
      else process.env.OVERWATCH_CLI_PENDING_DIR = previousPendingDirectory;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('retains a mutation identity for a durable response-unavailable receipt', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-cli-ambiguous-pending-'));
    const previousPendingDirectory = process.env.OVERWATCH_CLI_PENDING_DIR;
    process.env.OVERWATCH_CLI_PENDING_DIR = directory;
    const calls: RequestInit[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: string | URL, init: RequestInit) => {
      calls.push(init);
      if (calls.length === 1) {
        return new Response('{"error":"command is running"}', {
          status: 409,
          headers: {
            'X-Overwatch-Server-Response': '1',
            'X-Overwatch-Boundary-Command-Id': 'boundary-running',
            'X-Overwatch-Command-Status': 'running',
            'X-Overwatch-Command-Response-Available': '0',
          },
        });
      }
      return new Response('{"ok":true}', {
        status: 200,
        headers: {
          'X-Overwatch-Server-Response': '1',
          'X-Overwatch-Boundary-Command-Id': 'boundary-running',
          'X-Overwatch-Command-Status': 'succeeded',
          'X-Overwatch-Command-Response-Available': '1',
        },
      });
    }) as typeof fetch;
    try {
      await expect(createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 }))
        .rejects.toMatchObject({ status: 409 });
      const retained = (calls[0].headers as Record<string, string>)['X-Overwatch-Command-Id'];
      await createClient({ url: 'http://h:8384' }).post('/api/test', { value: 1 });
      expect((calls[1].headers as Record<string, string>)['X-Overwatch-Command-Id'])
        .toBe(retained);
    } finally {
      globalThis.fetch = realFetch;
      if (previousPendingDirectory === undefined) delete process.env.OVERWATCH_CLI_PENDING_DIR;
      else process.env.OVERWATCH_CLI_PENDING_DIR = previousPendingDirectory;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('accepts explicit command ids for independent identical CLI intents', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-cli-explicit-pending-'));
    const previousPendingDirectory = process.env.OVERWATCH_CLI_PENDING_DIR;
    process.env.OVERWATCH_CLI_PENDING_DIR = directory;
    const calls: RequestInit[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: string | URL, init: RequestInit) => {
      calls.push(init);
      return new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Overwatch-Server-Response': '1' },
      });
    }) as typeof fetch;
    try {
      await createClient({ url: 'http://h:8384', commandId: 'independent-a' })
        .post('/api/test', { value: 1 });
      await createClient({ url: 'http://h:8384', commandId: 'independent-b' })
        .post('/api/test', { value: 1 });
      expect((calls[0].headers as Record<string, string>)['X-Overwatch-Command-Id'])
        .toBe('independent-a');
      expect((calls[1].headers as Record<string, string>)['X-Overwatch-Command-Id'])
        .toBe('independent-b');
    } finally {
      globalThis.fetch = realFetch;
      if (previousPendingDirectory === undefined) delete process.env.OVERWATCH_CLI_PENDING_DIR;
      else process.env.OVERWATCH_CLI_PENDING_DIR = previousPendingDirectory;
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

// Fake client returning canned API payloads keyed by path.
function fakeClient(map: Record<string, unknown>): ApiClient {
  return {
    get: async <T>(p: string) => map[p] as T,
    post: async <T>() => ({}) as T,
  };
}

describe('read commands', () => {
  it('lists filtered durable playbook runs', async () => {
    const payload = { runs: [{ run_id: 'run-1', status: 'pending', steps: [] }], total: 1 };
    const client = fakeClient({ '/api/playbook-runs?credential_id=cred-1&open_only=true': payload });
    const result = await READ_COMMANDS.playbooks.run({ client, args: ['--credential', 'cred-1', '--open'] });
    expect(result.data).toEqual(payload);
    expect(result.text).toContain('run-1');
  });
  it('state migrate --check inspects local files without contacting HTTP', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-cli-state-check-'));
    try {
      const configPath = join(directory, 'engagement.json');
      const statePath = join(directory, 'state-cli-check.json');
      const engagement = {
        id: 'cli-check',
        name: 'CLI check',
        created_at: '2026-07-16T00:00:00.000Z',
        scope: { cidrs: [], domains: [], exclusions: [] },
        objectives: [],
        opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
      };
      writeFileSync(configPath, JSON.stringify(engagement));
      writeFileSync(statePath, JSON.stringify({
        config: engagement,
        graph: { attributes: {}, nodes: [], edges: [] },
        journalSnapshotSeq: 0,
      }));
      const client = fakeClient({});
      const result = await READ_COMMANDS.state.run({
        client,
        args: [
          'migrate',
          '--check',
          '--state-file',
          statePath,
          '--config-file',
          configPath,
        ],
      });
      expect(result.exitCode).toBe(0);
      expect(result.data).toMatchObject({
        status: 'migration_required',
        observed_state_version: 0,
        migration_required: true,
        ready: true,
      });
      expect(result.text).toContain('State migration check');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('state migrate --check uses the same persisted state selection as daemon startup', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-cli-state-profile-'));
    const priorProfile = process.env.OVERWATCH_RUNTIME_PROFILE;
    try {
      const configPath = join(directory, 'engagement.json');
      const statePath = join(directory, 'state-renamed-family.json');
      const profilePath = join(directory, 'profile.json');
      const engagement = {
        id: 'renamed-id',
        name: 'Profile selection',
        created_at: '2026-07-16T00:00:00.000Z',
        scope: { cidrs: [], domains: [], exclusions: [] },
        objectives: [],
        opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
      };
      writeFileSync(configPath, JSON.stringify(engagement));
      writeFileSync(statePath, JSON.stringify({
        config: engagement,
        graph: { attributes: {}, nodes: [], edges: [] },
        journalSnapshotSeq: 0,
      }));
      writeFileSync(profilePath, JSON.stringify({
        schema_version: 1,
        config_path: configPath,
        state_file_path: statePath,
      }));
      process.env.OVERWATCH_RUNTIME_PROFILE = profilePath;

      const result = await READ_COMMANDS.state.run({
        client: fakeClient({}),
        args: ['migrate', '--check'],
      });
      expect(result.exitCode).toBe(0);
      expect(result.data).toMatchObject({ state_file: statePath });
    } finally {
      if (priorProfile === undefined) delete process.env.OVERWATCH_RUNTIME_PROFILE;
      else process.env.OVERWATCH_RUNTIME_PROFILE = priorProfile;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('recovery reads the dedicated degraded-safe endpoint', async () => {
    const payload = { recovery: {
      outcome: 'clean', source: 'state', complete: true, writable: true,
      base_checkpoint: 2, highest_allocated_seq: 2, highest_on_disk_seq: 2,
      highest_allocated_logical_seq: 2, highest_allocated_frame_seq: 8,
      highest_physical_frame_seq: 8,
      highest_contiguous_applied_seq: 2,
      highest_contiguous_applied_logical_seq: 2,
      consecutive_persistence_failures: 0,
      journal: { enabled: true, read: 0, attempted: 0, applied: 0, skipped: 0, failed: 0, malformed: false, preserved: false },
    } };
    const client = fakeClient({ '/api/recovery': payload });
    const result = await READ_COMMANDS.recovery.run({ client, args: [] });
    expect(result.data).toEqual(payload);
    expect(result.text).toContain('Recovery');
    expect(result.text).toContain('physical frames allocated / on-disk');
    expect(result.text).toContain('8/8');
  });

  it('frontier filters by --type and caps with --max', async () => {
    const state = { state: { frontier: [
      { id: 'f1', type: 'network_discovery', description: 'a' },
      { id: 'f2', type: 'incomplete_node', description: 'b' },
      { id: 'f3', type: 'network_discovery', description: 'c' },
    ] } };
    const client = fakeClient({ '/api/state': state });
    const filtered = await READ_COMMANDS.frontier.run({ client, args: ['--type', 'network_discovery'] });
    expect((filtered.data as unknown[]).length).toBe(2);
    const capped = await READ_COMMANDS.frontier.run({ client, args: ['--max', '1'] });
    expect((capped.data as unknown[]).length).toBe(1);
  });

  it('findings filters by --severity', async () => {
    const resp = { total: 2, severity_summary: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      findings: [
        { id: 'a', severity: 'critical', title: 'x', risk_score: 9, affected_assets: ['h1'] },
        { id: 'b', severity: 'high', title: 'y', risk_score: 6, affected_assets: [] },
      ] };
    const client = fakeClient({ '/api/findings': resp });
    const out = await READ_COMMANDS.findings.run({ client, args: ['--severity', 'critical'] });
    expect((out.data as { findings: unknown[] }).findings.length).toBe(1);
  });

  it('approvals returns the pending array as data', async () => {
    const client = fakeClient({ '/api/actions/pending': { pending: [{ action_id: 'a1', description: 'd' }] } });
    const out = await READ_COMMANDS.approvals.run({ client, args: [] });
    expect((out.data as unknown[]).length).toBe(1);
  });
});

// Client that records POST calls + returns a canned response.
function recordingClient(response: unknown = {}): { client: ApiClient; calls: Array<{ path: string; body: unknown }> } {
  const calls: Array<{ path: string; body: unknown }> = [];
  const client: ApiClient = {
    get: async <T>() => ({}) as T,
    post: async <T>(path: string, body?: unknown) => { calls.push({ path, body }); return response as T; },
  };
  return { client, calls };
}

describe('write commands', () => {
  const work = {
    version: 1 as const,
    root_task_id: 'task-root',
    signature: 'a'.repeat(64),
  };
  const task = (id: string) => ({
    id,
    task_id: id,
    agent_id: `agent-${id}`,
    assigned_at: '2026-07-18T00:00:00.000Z',
    status: 'completed' as const,
    subgraph_node_ids: ['node-1'],
    work,
  });

  it('keeps the agent roster at `agents` with no subcommand', async () => {
    const payload = { agents: [{ id: 'task-1', status: 'running', agent_id: 'agent-one' }] };
    const client = fakeClient({ '/api/agents': payload });
    const result = await WRITE_COMMANDS.agents.run({ client, args: [] });
    expect(result.data).toEqual(payload.agents);
    expect(result.text).toContain('task-1');
  });

  it('lists exact duplicate work groups from the shared endpoint', async () => {
    const response = {
      total: 1,
      groups: [{
        signature: 'b'.repeat(64),
        canonical_task_id: 'task-1',
        candidate_task_ids: ['task-1', 'task-2'],
        tasks: [task('task-1'), task('task-2')],
      }],
    };
    const client = fakeClient({ '/api/agents/duplicates': response });
    const result = await WRITE_COMMANDS.agents.run({ client, args: ['duplicates'] });
    expect(result.data).toEqual(response);
    expect(result.text).toContain('task-1');
    expect(result.text).toContain('task-2');
  });

  it('posts a handoff with required successor fields and repeatable key references', async () => {
    const response = {
      operation: 'handoff' as const,
      source_task_id: 'task/source',
      created_tasks: [task('task-next')],
      warnings: [], command_id: 'cmd-1', idempotency_key: 'key-1', replayed: false,
    };
    const { client, calls } = recordingClient(response);
    const result = await WRITE_COMMANDS.agents.run({ client, args: [
      'handoff', 'task/source',
      '--summary', 'Recon is complete; continue validation.',
      '--archetype', 'web_tester',
      '--objective', 'Validate the discovered login path',
      '--agent-label', 'login follow-up',
      '--skill', 'web-testing',
      '--model', 'sonnet',
      '--finding', 'finding-1', '--finding', 'finding-2',
      '--evidence', 'evidence-1', '--event', 'event-1',
    ] });
    expect(calls).toEqual([{
      path: '/api/agents/task%2Fsource/handoff',
      body: {
        summary: 'Recon is complete; continue validation.',
        archetype: 'web_tester',
        objective: 'Validate the discovered login path',
        agent_label: 'login follow-up',
        skill: 'web-testing',
        model: 'sonnet',
        key_finding_ids: ['finding-1', 'finding-2'],
        key_evidence_ids: ['evidence-1'],
        key_event_ids: ['event-1'],
      },
    }]);
    expect(result.text).toContain('task-next');
  });

  it('loads and validates a strict split request from a JSON file', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'overwatch-agent-split-'));
    try {
      const path = join(directory, 'split.json');
      const request = {
        summary: 'Partition by host.',
        key_finding_ids: ['finding-1'],
        children: [
          { archetype: 'recon_scanner', objective: 'Scan node one', target_node_ids: ['node-1'] },
          { archetype: 'recon_scanner', objective: 'Scan node two', target_node_ids: ['node-2'] },
        ],
      };
      writeFileSync(path, JSON.stringify(request));
      const response = {
        operation: 'split' as const,
        source_task_id: 'task-1',
        created_tasks: [task('child-1'), task('child-2')],
        warnings: [], command_id: 'cmd-2', idempotency_key: 'key-2', replayed: false,
      };
      const { client, calls } = recordingClient(response);
      const result = await WRITE_COMMANDS.agents.run({ client, args: ['split', 'task-1', '--file', path] });
      expect(calls).toEqual([{ path: '/api/agents/task-1/split', body: request }]);
      expect(result.text).toContain('child-1');
      expect(result.text).toContain('child-2');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('posts a merge with unique duplicate task IDs and a summary', async () => {
    const response = {
      operation: 'merge' as const,
      canonical_task_id: 'task-canonical',
      updated_tasks: [task('task-canonical'), task('task-2'), task('task-3')],
      warnings: [], command_id: 'cmd-3', idempotency_key: 'key-3', replayed: false,
    };
    const { client, calls } = recordingClient(response);
    const result = await WRITE_COMMANDS.agents.run({ client, args: [
      'merge', 'task-canonical',
      '--duplicate', 'task-2', '--duplicate', 'task-3',
      '--summary', 'The tasks describe the same terminal work.',
    ] });
    expect(calls).toEqual([{
      path: '/api/agents/task-canonical/merge',
      body: {
        summary: 'The tasks describe the same terminal work.',
        duplicate_task_ids: ['task-2', 'task-3'],
      },
    }]);
    expect(result.text).toContain('task-canonical');
    expect(result.text).toContain('2 duplicate tasks');
  });

  it('rejects incomplete or invalid agent work requests before HTTP', async () => {
    const { client, calls } = recordingClient();
    await expect(WRITE_COMMANDS.agents.run({ client, args: [
      'handoff', 'task-1', '--summary', 'continue', '--archetype', 'web_tester',
    ] })).rejects.toThrow(/objective/);
    await expect(WRITE_COMMANDS.agents.run({ client, args: [
      'split', 'task-1', '--file', '/definitely/missing/split.json',
    ] })).rejects.toThrow(/Cannot read JSON request/);
    await expect(WRITE_COMMANDS.agents.run({ client, args: [
      'merge', 'task-1', '--duplicate', 'task-2', '--duplicate', 'task-2', '--summary', 'same',
    ] })).rejects.toThrow(/unique/);
    expect(calls).toHaveLength(0);
  });

  it('prepares and releases playbook attempts without claiming target execution occurred', async () => {
    const prepared = recordingClient({ attempt: { attempt_id: 'attempt-1' }, execution: { command_id: 'exec-1' } });
    const start = await WRITE_COMMANDS.playbook.run({ client: prepared.client, args: ['start', 'run-1', 'step-1'] });
    expect(prepared.calls[0]).toEqual({ path: '/api/playbook-runs/run-1/steps/step-1/start', body: {} });
    expect(start.text).toContain('does not execute');

    const released = recordingClient({ run: { status: 'interrupted' } });
    const interrupt = await WRITE_COMMANDS.playbook.run({ client: released.client, args: ['interrupt', 'run-1', 'step-1', '--reason', 'not running'] });
    expect(released.calls[0]).toEqual({
      path: '/api/playbook-runs/run-1/steps/step-1/interrupt', body: { reason: 'not running' },
    });
    expect(interrupt.text).toContain('Released step-1');
  });
  it('session resume posts to the explicit listener-resume endpoint', async () => {
    const { client, calls } = recordingClient({
      resumed: true,
      metadata: { id: 'listener-1', state: 'pending' },
    });
    const result = await WRITE_COMMANDS.session.run({
      client,
      args: ['resume', 'listener-1'],
    });
    expect(calls).toEqual([{
      path: '/api/sessions/listener-1/resume',
      body: {},
    }]);
    expect(result.text).toContain('listener-1');
    await expect(WRITE_COMMANDS.session.run({ client, args: ['resume'] }))
      .rejects.toThrow(/session-id/);
  });

  it('config reconcile posts the exact inspected hashes', async () => {
    const { client, calls } = recordingClient({ resolved: true });
    await WRITE_COMMANDS.config.run({
      client,
      args: ['reconcile', 'use_state', '--file-hash', 'a'.repeat(64), '--state-hash', 'b'.repeat(64)],
    });
    expect(calls).toEqual([{
      path: '/api/recovery/config/resolve',
      body: {
        resolution: 'use_state',
        expected_file_hash: 'a'.repeat(64),
        expected_state_hash: 'b'.repeat(64),
      },
    }]);
  });

  it('config reconcile supports file authority with the same optimistic hashes', async () => {
    const { client, calls } = recordingClient({ resolved: true });
    await WRITE_COMMANDS.config.run({
      client,
      args: ['reconcile', 'use_file', '--file-hash', 'c'.repeat(64), '--state-hash', 'd'.repeat(64)],
    });
    expect(calls).toEqual([{
      path: '/api/recovery/config/resolve',
      body: {
        resolution: 'use_file',
        expected_file_hash: 'c'.repeat(64),
        expected_state_hash: 'd'.repeat(64),
      },
    }]);
  });

  it('config reconcile rejects unsupported modes or missing and invalid hashes locally', async () => {
    const { client, calls } = recordingClient();
    await expect(WRITE_COMMANDS.config.run({ client, args: ['reconcile', 'guess'] })).rejects.toThrow(/use_file.*use_state/);
    await expect(WRITE_COMMANDS.config.run({ client, args: ['reconcile', 'use_state'] })).rejects.toThrow(/file-hash/);
    await expect(WRITE_COMMANDS.config.run({
      client,
      args: ['reconcile', 'use_state', '--file-hash', 'A'.repeat(64), '--state-hash', 'b'.repeat(64)],
    })).rejects.toThrow(/file-hash/);
    await expect(WRITE_COMMANDS.config.run({
      client,
      args: ['reconcile', 'use_state', '--file-hash', 'a'.repeat(64), '--state-hash', 'short'],
    })).rejects.toThrow(/state-hash/);
    expect(calls).toHaveLength(0);
  });

  it('approve posts to the action approve endpoint', async () => {
    const { client, calls } = recordingClient();
    const out = await WRITE_COMMANDS.approve.run({ client, args: ['a11c'] });
    expect(calls[0].path).toBe('/api/actions/a11c/approve');
    expect(out.text).toContain('Approved a11c');
  });

  it('deny passes --reason in the body', async () => {
    const { client, calls } = recordingClient();
    await WRITE_COMMANDS.deny.run({ client, args: ['a11c', '--reason', 'too noisy'] });
    expect(calls[0].path).toBe('/api/actions/a11c/deny');
    expect(calls[0].body).toEqual({ reason: 'too noisy' });
  });

  it('answer joins the trailing words into the answer body', async () => {
    const { client, calls } = recordingClient({ ok: true });
    await WRITE_COMMANDS.answer.run({ client, args: ['q1', 'stay', 'quiet', 'and', 'pivot'] });
    expect(calls[0].path).toBe('/api/agent-queries/q1/answer');
    expect(calls[0].body).toEqual({ answer: 'stay quiet and pivot' });
  });

  it('deploy reads the positional target even when a value-flag precedes it', async () => {
    const { client, calls } = recordingClient({ dispatched: true, task: { id: 't1', agent_id: 'ag1', archetype: 'recon_scanner' } });
    await WRITE_COMMANDS.deploy.run({ client, args: ['--archetype', 'recon_scanner', '10.0.0.5'] });
    expect(calls[0].path).toBe('/api/agents/quick-deploy');
    expect(calls[0].body).toEqual({ target: '10.0.0.5', archetype: 'recon_scanner' });
  });

  it('dispatch collects repeated --node values', async () => {
    const { client, calls } = recordingClient({ dispatched: true, task: { id: 't1', agent_id: 'ag1' } });
    await WRITE_COMMANDS.dispatch.run({ client, args: ['--node', 'n1', '--node', 'n2', '--skill', 'network-recon'] });
    expect(calls[0].body).toEqual({ target_node_ids: ['n1', 'n2'], skill: 'network-recon', archetype: undefined });
  });

  it('missing required args throw before any request', async () => {
    const { client, calls } = recordingClient();
    await expect(WRITE_COMMANDS.approve.run({ client, args: [] })).rejects.toThrow(/action-id/);
    await expect(WRITE_COMMANDS.dispatch.run({ client, args: [] })).rejects.toThrow(/--node/);
    expect(calls).toHaveLength(0);
  });
});

describe('renderers', () => {
  it('renders empty duplicate detection and mutation warnings clearly', () => {
    expect(renderAgentDuplicates({ total: 0, groups: [] })).toContain('No exact duplicate');
    const output = renderAgentWorkMutation({
      operation: 'handoff', source_task_id: 'source', created_tasks: [{
        id: 'next', task_id: 'next', agent_id: 'agent-next', agent_label: 'agent-next',
        assigned_at: '2026-07-18T00:00:00.000Z', status: 'completed',
        subgraph_node_ids: ['node-1'],
        work: { version: 1, root_task_id: 'source', signature: 'a'.repeat(64) },
      }],
      warnings: ['Frontier was stale; created a node follow-up instead.'],
      reused_existing: false,
      command_id: 'cmd', idempotency_key: 'key', replayed: false,
    });
    expect(output).toContain('source');
    expect(output).toContain('next');
    expect(output).toContain('Frontier was stale');
  });

  it('renderRecovery exposes copyable config observations and revisions', () => {
    const out = renderRecovery({
      recovery: {
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        reason: 'configuration reconciliation required',
        state_recovery: {
          outcome: 'incomplete',
          source: 'state',
          complete: false,
          writable: false,
          reason: 'WAL sequence gap at 5',
        },
        persistence_reason: 'WAL sequence gap at 5',
        last_persistence_error: 'fsync failed before restart',
        base_checkpoint: 1,
        highest_allocated_seq: 1,
        highest_on_disk_seq: 1,
        highest_contiguous_applied_seq: 1,
        consecutive_persistence_failures: 0,
        journal: { enabled: true, path: '/tmp/state.wal.jsonl', read: 0, attempted: 0, applied: 0, skipped: 0, failed: 0, malformed: false, preserved: true },
        runtime_ownership_warnings: [{
          run_id: 'run-reused',
          pid: 4242,
          lifecycle: 'unknown',
          message: 'The recorded PID belongs to a different process.',
        }],
        artifact_recovery: {
          reports: {
            writable: false,
            uncertain_deletion_ids: ['report-ambiguous'],
            reason: 'ambiguous deletion tombstone',
          },
          generation_warnings: [{
            root: '/tmp/operator-reports',
            namespace: 'report',
            message: 'mirror refresh pending',
          }],
        },
        config_recovery: {
          status: 'diverged',
          resolution_required: true,
          intent_present: false,
          file_valid: true,
          file_revision: 4,
          state_revision: 3,
          runtime_revision: 3,
          file_hash: 'a'.repeat(64),
          state_hash: 'b'.repeat(64),
          runtime_hash: 'b'.repeat(64),
          allowed_resolutions: ['use_file', 'use_state'],
          reason: 'file and state differ',
        },
      },
    });
    expect(out).toContain('observed file hash');
    expect(out).toContain('a'.repeat(64));
    expect(out).toContain('durable state hash');
    expect(out).toContain('runtime revision');
    expect(out).toContain('file and state differ');
    expect(out).toContain('persistence reason');
    expect(out).toContain('WAL sequence gap at 5');
    expect(out).toContain('state/WAL health');
    expect(out).toContain('degraded');
    expect(out).toMatch(/base checkpoint:\s+1/);
    expect(out).toMatch(/WAL preserved:\s+yes/);
    expect(out).toMatch(/WAL malformed:\s+no/);
    expect(out).toContain('last persistence error');
    expect(out).toContain('fsync failed before restart');
    expect(out).toContain('/tmp/state.wal.jsonl');
    expect(out).toContain('Runtime ownership warnings');
    expect(out).toContain('run-reused');
    expect(out).toContain('PID 4242');
    expect(out).toContain('belongs to a different process');
    expect(out).toContain('Artifact recovery');
    expect(out).toContain('report-ambiguous');
    expect(out).toContain('/tmp/operator-reports');
  });

  it('renderRecovery identifies a config-only write gate without blaming state or WAL recovery', () => {
    const out = renderRecovery({
      recovery: {
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        reason: 'configuration reconciliation required',
        state_recovery: {
          outcome: 'clean',
          source: 'state',
          complete: true,
          writable: true,
        },
        base_checkpoint: 8,
        highest_allocated_seq: 8,
        highest_on_disk_seq: 8,
        highest_contiguous_applied_seq: 8,
        consecutive_persistence_failures: 0,
        journal: {
          enabled: true,
          read: 0,
          attempted: 0,
          applied: 0,
          skipped: 0,
          failed: 0,
          malformed: false,
          preserved: false,
        },
        config_recovery: {
          status: 'diverged',
          resolution_required: true,
          intent_present: false,
          file_valid: true,
          file_hash: 'a'.repeat(64),
          state_hash: 'b'.repeat(64),
          allowed_resolutions: ['use_file', 'use_state'],
        },
      },
    });

    expect(out).toContain('combined status');
    expect(out).toContain('read-only');
    expect(out).toContain('state/WAL health');
    expect(out).toContain('healthy · writes paused only for configuration reconciliation');
    expect(out).not.toContain('persistence reason');
  });

  it('renderStatus shows name, objective progress, and frontier', () => {
    const out = renderStatus({
      state: {
        engagement: { id: 'eng-1', name: 'Acme Test' },
        graph_summary: { total_nodes: 5, total_edges: 4, confirmed_edges: 3, inferred_edges: 1 },
        objectives: [{ description: 'Get DA', achieved: false }, { description: 'Read flag', achieved: true }],
        frontier: [{ id: 'f1', type: 'network_discovery', description: 'sweep' }],
        agents: [{ id: 'a1', status: 'running', task: 't' }],
      },
      history_count: 12,
    } as never);
    expect(out).toContain('Acme Test');
    expect(out).toContain('1/2 achieved');
    expect(out).toContain('Get DA');
  });

  it('renderStatus shows a compact persistence recovery summary', () => {
    const out = renderStatus({
      state: {
        engagement: { name: 'Recovery Test' },
        persistence_recovery: {
          outcome: 'incomplete',
          source: 'state',
          complete: false,
          writable: false,
          reason: 'sequence gap',
          base_checkpoint: 2,
          highest_allocated_seq: 6,
          highest_allocated_logical_seq: 6,
          highest_allocated_frame_seq: 18,
          highest_on_disk_seq: 6,
          highest_physical_frame_seq: 18,
          highest_contiguous_applied_seq: 4,
          highest_contiguous_applied_logical_seq: 4,
          consecutive_persistence_failures: 0,
          journal: {
            enabled: true,
            read: 4,
            attempted: 2,
            applied: 2,
            skipped: 0,
            failed: 0,
            malformed: false,
            preserved: true,
          },
        },
      },
    });

    expect(out).toContain('recovery');
    expect(out).toContain('incomplete from state');
    expect(out).toContain('frames 18/18');
    expect(out).toContain('seq 4/6');
    expect(out).toContain('read-only');
    expect(out).toContain('sequence gap');
  });

  it('renderAgents fills the TASK column from skill/agent_id (not the nonexistent `task`)', () => {
    const out = renderAgents([
      { id: 'task-1', status: 'running', agent_id: 'network-recon-ab12', skill: 'network-recon', current_action: 'nmap' },
      { id: 'task-2', status: 'running', agent_id: 'osint-cd34' }, // no skill → falls back to agent_id
    ] as never);
    expect(out).toContain('network-recon'); // TASK column populated from skill
    expect(out).toContain('osint-cd34');    // fallback to agent_id when skill absent
  });

  it('empty approvals + queries render friendly messages', () => {
    expect(renderApprovals([])).toContain('No pending approvals');
    expect(renderQueries([])).toContain('No agents waiting');
  });

  it('renderOpsec shows budget + approach', () => {
    const out = renderOpsec({ global_noise_spent: 0.3, noise_budget_remaining: 0.4, max_noise: 0.7, recommended_approach: 'normal' } as never);
    expect(out).toContain('noise spent');
    expect(out).toContain('normal');
  });

  it('renderDeploy/renderDispatch confirm success and surface refusals', () => {
    expect(renderDeploy({ dispatched: true, task: { id: 't1', agent_id: 'ag1', archetype: 'recon_scanner' } } as never, '10.0.0.5'))
      .toMatch(/Deployed.*10\.0\.0\.5.*t1/);
    expect(renderDeploy({ dispatched: false, reason: 'out of scope' } as never, '9.9.9.9')).toContain('out of scope');
    expect(renderDispatch({ dispatched: true, task: { id: 't2', agent_id: 'ag2' } } as never)).toContain('t2');
    expect(renderDispatch({ dispatched: false, reason: 'leased', existing_task_id: 'tX' } as never)).toMatch(/leased.*tX/);
  });

  it('renderFindings shows the severity summary header', () => {
    const out = renderFindings({ total: 1, severity_summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      findings: [{ id: 'a', severity: 'critical', title: 'x', risk_score: 9, affected_assets: ['h1'] }] } as never);
    expect(out).toContain('1 findings');
    expect(out).toContain('1 critical');
  });
});
