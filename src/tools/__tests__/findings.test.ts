import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerFindingTools } from '../findings.js';
import type { EngagementConfig } from '../../types.js';

let testDir: string;
let testStateFile: string;

function makeConfig(): EngagementConfig {
  return {
    id: 'test-findings',
    name: 'Findings Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('finding tools', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-findings-'));
    testStateFile = join(testDir, 'state.json');
    engine = new GraphEngine(makeConfig(), testStateFile);
    handlers = {};

    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerFindingTools(fakeServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('report_finding with a simple host node returns finding_id and counts', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-1',
      tool_name: 'nmap',
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', properties: { ip: '10.10.10.1' } },
      ],
      edges: [],
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.finding_id).toBeDefined();
    expect(payload.new_nodes).toBeInstanceOf(Array);
    expect(payload.new_edges).toBeInstanceOf(Array);
    expect(payload.new_nodes).toContain('host-10-10-10-1');
  });

  it('report_finding with evidence returns evidence_id', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-evidence',
      tool_name: 'manual',
      nodes: [
        { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', properties: { ip: '10.10.10.2' } },
      ],
      edges: [],
      evidence: { type: 'command_output', content: 'uid=0(root)' },
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.finding_id).toBeDefined();
    expect(payload.evidence_id).toBeDefined();
  });

  it('keeps blob-first evidence orphaned but does not commit a finding reference when ingest fails', async () => {
    vi.spyOn(engine, 'ingestFinding').mockImplementationOnce(() => {
      throw new Error('synthetic ingest failure');
    });

    const result = await handlers.report_finding({
      agent_id: 'agent-failed-ingest',
      action_id: 'action-failed-ingest',
      tool_name: 'manual',
      nodes: [
        { id: 'host-failed-ingest', type: 'host', label: 'failed ingest', properties: { ip: '10.10.10.44' } },
      ],
      edges: [],
      evidence: { type: 'command_output', content: 'durable orphan candidate' },
    });

    expect(result.isError).toBe(true);
    expect(engine.getEvidenceStore().list({ action_id: 'action-failed-ingest' })).toHaveLength(1);
    expect(engine.getFullHistory().filter(entry =>
      entry.action_id === 'action-failed-ingest'
      && entry.event_type === 'finding_reported'
    )).toHaveLength(0);
  });

  it('get_evidence with valid ID returns content', async () => {
    const finding = await handlers.report_finding({
      agent_id: 'agent-ev',
      tool_name: 'manual',
      nodes: [
        { id: 'host-10-10-10-3', type: 'host', label: '10.10.10.3', properties: { ip: '10.10.10.3' } },
      ],
      edges: [],
      evidence: { type: 'command_output', content: 'test evidence content' },
      raw_output: 'raw output here',
    });

    const findingPayload = JSON.parse(finding.content[0].text);
    const evidenceId = findingPayload.evidence_id;

    const result = await handlers.get_evidence({
      evidence_id: evidenceId,
      list_only: false,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.evidence_id).toBe(evidenceId);
    expect(payload.content).toBe('test evidence content');
    expect(payload.raw_output).toBe('raw output here');
  });

  // M11: get_evidence must bound the raw_output read and expose paging metadata so a
  // large blob (fetched on a poll) cannot pin the daemon.
  it('M11: bounds get_evidence raw_output and pages via next_offset', async () => {
    const big = 'A'.repeat(1000);
    const finding = await handlers.report_finding({
      agent_id: 'agent-big', tool_name: 'manual',
      nodes: [{ id: 'host-10-10-10-9', type: 'host', label: '10.10.10.9', properties: { ip: '10.10.10.9' } }],
      edges: [],
      raw_output: big,
    });
    const evidenceId = JSON.parse(finding.content[0].text).evidence_id;

    const first = JSON.parse((await handlers.get_evidence({ evidence_id: evidenceId, max_bytes: 400 })).content[0].text);
    expect(first.raw_output).toHaveLength(400);
    expect(first.raw_output_truncated).toBe(true);
    expect(first.raw_output_total_bytes).toBe(1000);
    expect(first.next_offset).toBe(400);

    const second = JSON.parse((await handlers.get_evidence({ evidence_id: evidenceId, offset: 400, max_bytes: 400 })).content[0].text);
    expect(second.raw_output).toHaveLength(400);
    expect(second.raw_output_offset).toBe(400);

    const last = JSON.parse((await handlers.get_evidence({ evidence_id: evidenceId, offset: 800, max_bytes: 400 })).content[0].text);
    expect(last.raw_output).toHaveLength(200);
    expect(last.raw_output_truncated).toBe(false);
  });

  it('report_finding persists matched-signal excerpts and backfills evidence_id (3c)', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-ex',
      action_id: 'act-ex',
      tool_name: 'manual',
      nodes: [{ id: 'host-10-10-10-8', type: 'host', label: '10.10.10.8', properties: { ip: '10.10.10.8' } }],
      edges: [],
      evidence: { type: 'command_output', content: 'uid=0(root) gid=0(root)' },
      excerpts: [
        { node_id: 'host-10-10-10-8', byte_start: 0, byte_end: 11, matched_by: 'agent', snippet: 'uid=0(root)' },
        // malformed span — must be dropped with a warning, not persisted.
        { node_id: 'host-10-10-10-8', byte_start: 8, byte_end: 3, matched_by: 'agent' },
      ],
    });
    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);

    const event = engine.getFullHistory().find(e => e.action_id === 'act-ex' && e.event_type === 'finding_reported');
    const excerpts = (event?.details as any)?.excerpts;
    expect(excerpts).toHaveLength(1);
    expect(excerpts[0].byte_start).toBe(0);
    // evidence_id backfilled to the finding's stored blob.
    expect(excerpts[0].evidence_id).toBe(payload.evidence_id);
    expect(payload.warnings?.some((w: string) => /invalid byte range/i.test(w))).toBe(true);
  });

  it('report_finding derives a matched-signal excerpt from raw_output when the agent supplies none (#2 parity)', async () => {
    // The worker-agent path: capture stdout, report a credential finding with
    // raw_output but no explicit excerpts. Derivation must fill in the byte range.
    const raw = 'SMB  10.10.10.9  445  APP  [+] corp\\admin:S3cretP@ssw0rd (Pwn3d!)\n';
    const result = await handlers.report_finding({
      agent_id: 'agent-derive',
      action_id: 'act-derive',
      tool_name: 'nxc',
      nodes: [{
        id: 'cred-x', type: 'credential', label: 'admin',
        properties: {
          cred_value: 'S3cretP@ssw0rd', cred_type: 'plaintext',
          cred_material_kind: 'plaintext_password', cred_user: 'admin',
          cred_domain: 'corp', cred_usable_for_auth: true,
        },
      }],
      edges: [],
      raw_output: raw,
      // NB: no `excerpts` supplied — the generic derivation must produce them.
    });
    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    const event = engine.getFullHistory().find(e => e.action_id === 'act-derive' && e.event_type === 'finding_reported');
    const excerpts = (event?.details as any)?.excerpts;
    expect(excerpts).toHaveLength(1);
    expect(excerpts[0].matched_by).toBe('nxc');
    // A credential value is secret — tagged so the client renderer redacts it.
    expect(excerpts[0].sensitive).toBe(true);
    // evidence_id backfilled to the finding's stored raw blob.
    expect(excerpts[0].evidence_id).toBe(payload.evidence_id);
    // The derived byte range re-reads exactly the leaked secret from that blob.
    const slice = engine.getEvidenceStore().getRawOutputSlice(
      payload.evidence_id, excerpts[0].byte_start, excerpts[0].byte_end - excerpts[0].byte_start,
    );
    expect(slice?.text).toBe('S3cretP@ssw0rd');
  });

  it('report_finding does NOT override the agent\'s explicit excerpts with the generic derivation', async () => {
    const raw = 'user:S3cretP@ssw0rd\n';
    const result = await handlers.report_finding({
      agent_id: 'a', action_id: 'act-explicit', tool_name: 'nxc',
      nodes: [{
        id: 'cred-y', type: 'credential', label: 'u',
        properties: {
          cred_value: 'S3cretP@ssw0rd', cred_type: 'plaintext', cred_material_kind: 'plaintext_password',
          cred_user: 'user', cred_domain: 'corp', cred_usable_for_auth: true,
        },
      }],
      edges: [], raw_output: raw,
      excerpts: [{ node_id: 'cred-y', byte_start: 5, byte_end: 19, matched_by: 'agent', snippet: 'S3cretP@ssw0rd' }],
    });
    const payload = JSON.parse(result.content[0].text);
    const event = engine.getFullHistory().find(e => e.action_id === 'act-explicit' && e.event_type === 'finding_reported');
    const excerpts = (event?.details as any)?.excerpts;
    expect(excerpts).toHaveLength(1);
    expect(excerpts[0].matched_by).toBe('agent');   // explicit wins, not the generic 'nxc'
    expect(excerpts[0].evidence_id).toBe(payload.evidence_id);
  });

  it('get_evidence with invalid ID returns error', async () => {
    const result = await handlers.get_evidence({
      evidence_id: 'nonexistent-evidence-id',
      list_only: false,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('not found');
  });

  it('persists a reported finding to disk synchronously (no debounce window)', async () => {
    // M3: report_finding flushes immediately, so the node is on disk the instant
    // the call returns — a daemon crash in the next moment can't lose it. Under
    // the old debounced persist() the state file would NOT yet contain the node
    // (the write is scheduled ~100ms later), so reading it synchronously here
    // proves the flush happened.
    await handlers.report_finding({
      agent_id: 'agent-durable',
      tool_name: 'nmap',
      nodes: [{ id: 'host-durable-1', type: 'host', label: '10.10.10.9', properties: { ip: '10.10.10.9' } }],
      edges: [],
    });
    const onDisk = readFileSync(testStateFile, 'utf8');
    expect(onDisk).toContain('host-durable-1');
  });
});
