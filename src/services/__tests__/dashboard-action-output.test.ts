// ============================================================
// Route tests for the Analysis workspace output endpoints:
//   GET /api/actions/:id/output  — stdout/stderr (head) for an action
//   GET /api/evidence/:id/raw    — bounded, paged raw-evidence read
// Boots a real DashboardServer on an ephemeral loopback port and hits
// the routes via fetch(), asserting status + response shape.
// ============================================================

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import { parseAndMaybeIngest } from '../parse-ingest.js';
import type { EngagementConfig } from '../../types.js';

let dashboard: DashboardServer;
let engine: GraphEngine;
let baseUrl: string;
let tempDir: string;

const ACTION_ID = 'act_outputtest1';
const STDOUT_TEXT = 'PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\n';
const STDERR_TEXT = 'warning: 1 host seems down\n';
let stdoutId: string;
let stderrId: string;

function makeConfig(): EngagementConfig {
  return {
    id: 'action-output',
    name: 'Action Output',
    created_at: '2026-05-09T00:00:00Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [], aws_accounts: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  } as EngagementConfig;
}

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-output-'));
  engine = new GraphEngine(makeConfig(), join(tempDir, 'state.json'));

  const store = engine.getEvidenceStore();
  stdoutId = store.store({ evidence_type: 'command_output', raw_output: STDOUT_TEXT, action_id: ACTION_ID });
  stderrId = store.store({ evidence_type: 'command_output', raw_output: STDERR_TEXT, action_id: ACTION_ID });

  engine.logActionEvent({
    action_id: ACTION_ID,
    event_type: 'action_completed',
    result_classification: 'success',
    tool_name: 'nmap',
    command_repr: 'nmap -sV 10.0.0.5',
    description: 'nmap scan completed',
    target_ips: ['10.0.0.5'],
    linked_finding_ids: ['f-output-1'],
    details: {
      exit_code: 0,
      duration_ms: 1500,
      stdout_evidence_id: stdoutId,
      stderr_evidence_id: stderrId,
      stdout_truncated: false,
      stderr_truncated: false,
      stdout_total_bytes: Buffer.byteLength(STDOUT_TEXT),
      stderr_total_bytes: Buffer.byteLength(STDERR_TEXT),
      command: 'nmap -sV 10.0.0.5',
      binary: 'nmap',
      invoking_tool: 'run_tool',
    },
  });

  dashboard = new DashboardServer(engine, 0, '127.0.0.1');
  const result = await dashboard.start();
  if (!result.started) throw new Error(`dashboard failed to start: ${result.error}`);
  baseUrl = dashboard.address;
});

afterAll(async () => {
  await dashboard.stop().catch(() => {});
  rmSync(tempDir, { recursive: true, force: true });
});

describe('GET /api/actions/:id/output', () => {
  it('returns stdout + stderr and action metadata for a completed action', async () => {
    const res = await fetch(`${baseUrl}/api/actions/${ACTION_ID}/output`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.action_id).toBe(ACTION_ID);
    expect(body.status).toBe('success');
    expect(body.tool_name).toBe('nmap');
    expect(body.command_repr).toBe('nmap -sV 10.0.0.5');
    expect(body.exit_code).toBe(0);
    expect(body.linked_finding_ids).toContain('f-output-1');
    expect(body.stdout.text).toContain('22/tcp');
    expect(body.stdout.evidence_id).toBe(stdoutId);
    expect(body.stdout.head_truncated).toBe(false);
    expect(body.stderr.text).toContain('host seems down');
  });

  it('honors max_bytes and flags head_truncated when the blob is larger', async () => {
    const res = await fetch(`${baseUrl}/api/actions/${ACTION_ID}/output?max_bytes=10`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.max_bytes).toBe(10);
    expect(Buffer.byteLength(body.stdout.text)).toBeLessThanOrEqual(10);
    expect(body.stdout.head_truncated).toBe(true);
    expect(body.stdout.total_bytes).toBe(Buffer.byteLength(STDOUT_TEXT));
  });

  it('404s for an unknown action id', async () => {
    const res = await fetch(`${baseUrl}/api/actions/act_doesnotexist/output`);
    expect(res.status).toBe(404);
  });

  it('reports a running action (only action_started) with metadata from started.details', async () => {
    engine.logActionEvent({
      action_id: 'act_running1',
      event_type: 'action_started',
      tool_name: 'nmap',
      command_repr: 'nmap -p- 10.0.0.6',
      description: 'nmap started',
      details: { command: 'nmap -p- 10.0.0.6', binary: 'nmap', invoking_tool: 'run_tool' },
    });
    const res = await fetch(`${baseUrl}/api/actions/act_running1/output`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('running');
    expect(body.tool_name).toBe('nmap');
    expect(body.command_repr).toBe('nmap -p- 10.0.0.6');
    expect(body.invoking_tool).toBe('run_tool'); // sourced from started.details
    expect(body.stdout).toBeNull();
    expect(body.stderr).toBeNull();
  });

  it('reports a failed action with status failure', async () => {
    const failOut = engine.getEvidenceStore().store({
      evidence_type: 'command_output', raw_output: 'Connection refused\n', action_id: 'act_failed1',
    });
    engine.logActionEvent({
      action_id: 'act_failed1',
      event_type: 'action_failed',
      result_classification: 'failure',
      tool_name: 'curl',
      command_repr: 'curl https://10.0.0.9',
      description: 'curl failed',
      details: { exit_code: 7, stderr_evidence_id: failOut, stderr_total_bytes: 19 },
    });
    const res = await fetch(`${baseUrl}/api/actions/act_failed1/output`);
    const body = await res.json();
    expect(body.status).toBe('failure');
    expect(body.exit_code).toBe(7);
    expect(body.stderr.text).toContain('Connection refused');
  });

  it('flags a capture-failed stream (bytes existed, no evidence id)', async () => {
    engine.logActionEvent({
      action_id: 'act_capfail1',
      event_type: 'action_completed',
      result_classification: 'success',
      tool_name: 'nmap',
      command_repr: 'nmap 10.0.0.10',
      description: 'capture failed mid-run',
      details: {
        stdout_total_bytes: 500,
        // no stdout_evidence_id — capture write failed
        evidence_capture_error: { stdout: 'write EPIPE' },
      },
    });
    const res = await fetch(`${baseUrl}/api/actions/act_capfail1/output`);
    const body = await res.json();
    expect(body.stdout).not.toBeNull();
    expect(body.stdout.evidence_id).toBeNull();
    expect(body.stdout.missing).toBe(true);
    expect(body.stdout.capture_failed).toBe(true);
    expect(body.stdout.total_bytes).toBe(500);
    expect(body.capture_error).toBeTruthy();
  });

  it('uses the last terminal event when an action has more than one', async () => {
    engine.logActionEvent({
      action_id: 'act_multi1', event_type: 'action_completed',
      result_classification: 'failure', description: 'first attempt failed', details: {},
    });
    engine.logActionEvent({
      action_id: 'act_multi1', event_type: 'action_completed',
      result_classification: 'success', description: 'retry succeeded', details: {},
    });
    const res = await fetch(`${baseUrl}/api/actions/act_multi1/output`);
    const body = await res.json();
    expect(body.status).toBe('success'); // last terminal wins
  });
});

describe('GET /api/evidence/:id/raw', () => {
  it('returns the full blob by default with eof set', async () => {
    const res = await fetch(`${baseUrl}/api/evidence/${stdoutId}/raw`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.evidence_id).toBe(stdoutId);
    expect(body.text).toBe(STDOUT_TEXT);
    expect(body.offset).toBe(0);
    expect(body.eof).toBe(true);
    expect(body.total_bytes).toBe(Buffer.byteLength(STDOUT_TEXT));
    expect(body.action_id).toBe(ACTION_ID);
  });

  it('pages with offset + max_bytes', async () => {
    const res = await fetch(`${baseUrl}/api/evidence/${stdoutId}/raw?offset=5&max_bytes=4`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.offset).toBe(5);
    expect(body.bytes_read).toBe(4);
    expect(body.eof).toBe(false);
    expect(body.text).toBe(STDOUT_TEXT.slice(5, 9));
  });

  it('returns an empty eof window for an offset past the end (no 32-bit wrap)', async () => {
    const res = await fetch(`${baseUrl}/api/evidence/${stdoutId}/raw?offset=9999999999&max_bytes=10`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.bytes_read).toBe(0);
    expect(body.text).toBe('');
    expect(body.eof).toBe(true);
  });

  it('404s for an unknown evidence id', async () => {
    const res = await fetch(`${baseUrl}/api/evidence/ev-nope/raw`);
    expect(res.status).toBe(404);
  });
});

const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.acme.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
    </ports>
  </host>
</nmaprun>`;

describe('POST /api/actions/:id/reparse', () => {
  let reEvId: string;

  beforeAll(() => {
    reEvId = engine.getEvidenceStore().store({ evidence_type: 'command_output', raw_output: NMAP_XML, action_id: 'act_reparse1' });
    engine.logActionEvent({
      action_id: 'act_reparse1', event_type: 'action_completed', result_classification: 'success',
      tool_name: 'nmap', command_repr: 'nmap -oX - 10.10.10.5', description: 'nmap',
      details: { stdout_evidence_id: reEvId, stdout_total_bytes: Buffer.byteLength(NMAP_XML) },
    });
  });

  const reparse = (
    actionId: string,
    body: Record<string, unknown>,
    headers: Record<string, string> = {},
  ) =>
    fetch(`${baseUrl}/api/actions/${actionId}/reparse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });

  it('previews a parse without ingesting (ingest:false)', async () => {
    const res = await reparse('act_reparse1', { tool_name: 'nmap', evidence_id: reEvId, ingest: false });
    expect(res.status).toBe(200);
    const b = await res.json();
    expect(b.parse_status).toBe('ok');
    expect(b.parse_outcome).toBe('ok');
    expect(b.nodes_parsed).toBeGreaterThan(0);
    expect(b.ingested).toBeUndefined();
  });

  it('promotes to the graph (ingest:true)', async () => {
    const res = await reparse('act_reparse1', { tool_name: 'nmap', evidence_id: reEvId, ingest: true });
    const b = await res.json();
    expect(b.parse_status).toBe('ok');
    expect(b.ingested.new_nodes).toBeGreaterThan(0);
  });

  it('replays one dashboard parse command and rejects conflicting reuse', async () => {
    const actionId = 'act_reparse_idempotent';
    const evidenceId = engine.getEvidenceStore().store({
      evidence_type: 'command_output',
      raw_output: NMAP_XML,
      action_id: actionId,
    });
    const headers = {
      'X-Overwatch-Command-Id': 'dashboard-reparse-command',
      'Idempotency-Key': 'dashboard-reparse-retry',
    };
    const request = {
      tool_name: 'nmap',
      evidence_id: evidenceId,
      ingest: true,
    };
    const first = await reparse(actionId, request, headers);
    const firstBody = await first.json();
    const second = await reparse(actionId, request, headers);
    const secondBody = await second.json();

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(secondBody).toEqual(firstBody);
    expect(engine.getFullHistory().filter(event =>
      event.action_id === actionId
      && event.event_type === 'parse_output')).toHaveLength(1);

    const conflict = await reparse(
      actionId,
      { ...request, ingest: false },
      headers,
    );
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({
      code: 'IDEMPOTENCY_CONFLICT',
    });
  });

  it('resolves the action stdout evidence when evidence_id is omitted', async () => {
    const res = await reparse('act_reparse1', { tool_name: 'nmap', ingest: false });
    const b = await res.json();
    expect(b.parse_status).toBe('ok');
    expect(b.evidence_id).toBe(reEvId);
  });

  it('returns no_parser for an unknown tool', async () => {
    const res = await reparse('act_reparse1', { tool_name: 'totally-unknown', evidence_id: reEvId });
    const b = await res.json();
    expect(b.parse_status).toBe('no_parser');
    expect(b.parse_outcome).toBe('validation_failed');
    expect(b.isError).toBe(true);
  });

  it('routes invalid context through the canonical parse service', async () => {
    const res = await reparse('act_reparse1', {
      tool_name: 'nmap', evidence_id: reEvId, context: { tenant_id: 42 },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({
      parse_status: 'validation_failed', parse_outcome: 'validation_failed',
      failure_stage: 'context', isError: true,
    });
    expect(body.validation_errors.length).toBeGreaterThan(0);
    expect(engine.getFullHistory().some(entry => entry.event_type === 'parse_output'
      && entry.details?.failure_stage === 'context')).toBe(true);
  });

  it('preserves GitHub repository context through dashboard reparse', async () => {
    const githubEvidence = engine.getEvidenceStore().store({
      evidence_type: 'command_output',
      raw_output: JSON.stringify({ use_default: false, include_claim_keys: ['repo', 'context'] }),
      action_id: 'act_reparse_github',
    });
    const res = await reparse('act_reparse_github', {
      tool_name: 'github-actions-oidc', evidence_id: githubEvidence, ingest: true,
      context: {
        repo_full_name: 'acme/dashboard', branch_name: 'main',
        provider_extension: { nested: { retained: true } },
      },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.parse_outcome).toBe('ok');
    expect(engine.getNodesByType('idp_application').find(node => node.repo_full_name === 'acme/dashboard'))
      .toMatchObject({ branch_name: 'main', oidc_use_default: false });
  });

  it('reuses the durable parser context when dashboard reparse omits context', async () => {
    const actionId = 'act_reparse_stored_context';
    const output = JSON.stringify({ use_default: false, include_claim_keys: ['repo', 'environment'] });
    const preview = parseAndMaybeIngest(engine, {
      tool_name: 'github-actions-oidc', outputText: output, action_id: actionId, ingest: false,
      context: {
        repo_full_name: 'acme/stored-context', branch_name: 'release',
        provider_extension: { nested: { retained: true } },
      },
    });
    expect(preview.parse_outcome).toBe('ok');
    const evidenceId = engine.getEvidenceStore().store({
      evidence_type: 'command_output', raw_output: output, action_id: actionId,
    });

    const res = await reparse(actionId, {
      tool_name: 'github-actions-oidc', evidence_id: evidenceId, ingest: true,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ parse_outcome: 'ok' });
    expect(engine.getNodesByType('idp_application')
      .find(node => node.repo_full_name === 'acme/stored-context'))
      .toMatchObject({ branch_name: 'release', oidc_use_default: false });
  });

  it('400s without a tool_name', async () => {
    const res = await reparse('act_reparse1', { evidence_id: reEvId });
    expect(res.status).toBe(400);
  });

  it('404s when the action has no evidence', async () => {
    const res = await reparse('act_no_evidence', { tool_name: 'nmap' });
    expect(res.status).toBe(404);
  });

  it('404s when the chosen evidence has no raw output (content-only)', async () => {
    const contentOnly = engine.getEvidenceStore().store({ evidence_type: 'log', content: 'note only', action_id: 'act_reparse1' });
    const res = await reparse('act_reparse1', { tool_name: 'nmap', evidence_id: contentOnly });
    expect(res.status).toBe(404);
  });
});
