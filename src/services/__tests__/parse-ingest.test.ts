import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { GraphEngine } from '../graph-engine.js';
import { parseAndMaybeIngest } from '../parse-ingest.js';
import {
  ParseCommandService,
  buildParseSourceFingerprint,
} from '../parse-command-service.js';
import { __registerParserForTest } from '../parsers/index.js';
import type { EngagementConfig, Finding } from '../../types.js';

function config(): EngagementConfig {
  return {
    id: 'parse-service-test', name: 'Parse service test', created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
  };
}

function finding(id: string, nodes: Finding['nodes'], extra: Partial<Finding> = {}): Finding {
  return {
    id, agent_id: 'fixture-parser', timestamp: '2026-01-01T00:00:00Z',
    nodes, edges: [], ...extra,
  };
}

describe('parseAndMaybeIngest canonical outcomes', () => {
  let dir: string;
  let engine: GraphEngine;
  const disposers: Array<() => void> = [];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-parse-service-'));
    engine = new GraphEngine(config(), join(dir, 'state.json'));
  });

  afterEach(() => {
    while (disposers.length) disposers.pop()!();
    engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  it.each([
    ['no_data', 'empty-parser', () => finding('empty', [])],
    ['validation_failed', 'invalid-parser', () => finding('invalid', [{
      id: 'cred-invalid', type: 'credential', label: 'invalid', privileged: true,
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    }])],
  ] as const)('returns %s without ingesting', (outcome, name, parser) => {
    disposers.push(__registerParserForTest(name, parser));
    const result = parseAndMaybeIngest(engine, {
      tool_name: name, outputText: 'fixture', action_id: `act-${name}`, ingest: true,
    });
    expect(result.parse_outcome).toBe(outcome);
    expect(result.isError).toBe(true);
    expect(result.ingested).toBe(false);
    expect(engine.exportGraph().nodes).toEqual([]);
  });

  it('carries parser-emitted matched-signal excerpts into the result and the audit event (3c)', () => {
    disposers.push(__registerParserForTest('excerpt-parser', () => finding(
      'finding-excerpt',
      [{ id: 'host-excerpt', type: 'host', label: 'excerpt host', ip: '10.0.0.7', discovered_at: '2026-01-01T00:00:00Z', confidence: 1 }],
      { excerpts: [
        { node_id: 'host-excerpt', byte_start: 10, byte_end: 24, matched_by: 'fixture', snippet: 'open microsoft' },
        // malformed span (end <= start) must be dropped, never surfaced.
        { node_id: 'host-excerpt', byte_start: 5, byte_end: 5, matched_by: 'fixture' },
      ] },
    )));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'excerpt-parser', outputText: 'fixture output open microsoft-ds', action_id: 'act-excerpt', ingest: true,
    });
    expect(result.excerpts).toHaveLength(1);
    expect(result.excerpts?.[0]).toMatchObject({ byte_start: 10, byte_end: 24, matched_by: 'fixture' });
    // Persisted on the parse event so the report chain builder can lift it.
    const event = engine.getFullHistory().find(e => e.action_id === 'act-excerpt' && e.event_type === 'parse_output');
    expect((event?.details as any)?.excerpts).toHaveLength(1);
  });

  it('#2: derives matched-signal excerpts generically from cred_value (real nxc parser, no explicit excerpts)', () => {
    // Exercises the REAL nxc parser: it extracts the credential from this line, and the
    // generic post-parse pass derives the matched-signal excerpt for its cred_value.
    const raw = 'SMB  10.0.0.1  445  APP01  [+] corp\\admin:S3cretP@ssw0rd (Pwn3d!)\n';
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'nxc', outputText: raw, action_id: 'act-cred', ingest: true,
    });
    expect(result.excerpts).toHaveLength(1);
    const ex = result.excerpts![0];
    expect(ex.node_id).toMatch(/^cred/);   // canonicalized credential id
    expect(ex.matched_by).toBe('nxc');
    // The byte range re-reads exactly the leaked secret from the tool output.
    expect(Buffer.from(raw, 'utf8').subarray(ex.byte_start, ex.byte_end).toString('utf8')).toBe('S3cretP@ssw0rd');
  });

  it('#2: derives a matched-signal excerpt from a CVE id for a vulnerability finding', () => {
    const raw = '[critical] [CVE-2021-44228] http://10.0.0.5:8080 log4shell RCE confirmed\n';
    // Realistic scanner shape: host + vuln + VULNERABLE_TO so the vuln actually ingests.
    disposers.push(__registerParserForTest('vuln-parser', () => finding('f-vuln', [
      { id: 'svc-10-0-0-5-8080', type: 'service', label: 'http/8080', port: 8080, discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } as never,
      { id: 'vuln-log4shell', type: 'vulnerability', label: 'Log4Shell', cve: 'CVE-2021-44228', cvss: 10, discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } as never,
    ], { edges: [{ source: 'svc-10-0-0-5-8080', target: 'vuln-log4shell', properties: { type: 'VULNERABLE_TO', confidence: 1, discovered_at: '2026-01-01T00:00:00Z' } }] } as never)));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'vuln-parser', outputText: raw, action_id: 'act-vuln', ingest: true,
    });
    expect(result.excerpts).toHaveLength(1);
    expect(result.excerpts![0].node_id).toBe('vuln-log4shell');
    expect(Buffer.from(raw, 'utf8').subarray(result.excerpts![0].byte_start, result.excerpts![0].byte_end).toString('utf8')).toBe('CVE-2021-44228');
  });

  it('#2: a parser\'s OWN explicit excerpts take precedence over the generic derivation', () => {
    disposers.push(__registerParserForTest('explicit-cred-parser', () => finding('f-x', [
      { id: 'cred-x', type: 'credential', label: 'admin', cred_value: 'Secret123', cred_material_kind: 'plaintext_password', cred_type: 'plaintext', cred_usable_for_auth: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1 } as never,
    ], { excerpts: [{ node_id: 'cred-x', byte_start: 2, byte_end: 8, matched_by: 'explicit' }] })));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'explicit-cred-parser', outputText: 'xxSecret123xx', action_id: 'act-x', ingest: true,
    });
    expect(result.excerpts).toHaveLength(1);
    expect(result.excerpts?.[0].matched_by).toBe('explicit');   // not the generic 't'
  });

  it('distinguishes parser exceptions from zero data', () => {
    disposers.push(__registerParserForTest('throwing-parser', () => {
      throw new Error('fixture parser exploded');
    }));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'throwing-parser', outputText: 'fixture', action_id: 'act-throw', ingest: true,
    });
    expect(result).toMatchObject({
      parsed: false, parse_status: 'parser_exception', parse_outcome: 'parser_exception',
      isError: true, ingested: false,
    });
    expect(result.error).toContain('fixture parser exploded');
  });

  it('replays one atomic parse, ingest, audit, and command after an apply-boundary crash', async () => {
    disposers.push(__registerParserForTest('atomic-parser', () => finding(
      'finding-atomic-parser',
      [{
        id: 'host-atomic-parser',
        type: 'host',
        label: 'atomic parser host',
        ip: '10.0.0.44',
        discovered_at: '2026-01-01T00:00:00Z',
        confidence: 1,
      }],
    )));
    engine.flushNow();
    const statePath = join(dir, 'state.json');
    const descriptor = {
      tool_name: 'atomic-parser',
      source_kind: 'output' as const,
      source_length: 7,
      source_fingerprint: buildParseSourceFingerprint({
        output: 'fixture',
        context: {},
      }),
      context_keys: [],
      action_id: 'action-atomic-parser',
      ingest: true,
    };
    const metadata = {
      command_id: 'parse-atomic-command',
      idempotency_key: 'parse-atomic-retry',
      action_id: 'action-atomic-parser',
    };
    const journal = (engine as any).ctx.mutationJournal;
    const originalAppend = journal.appendTransaction.bind(journal);
    let parses = 0;

    await expect(new ParseCommandService(engine).execute(
      descriptor,
      completion => {
        parses++;
        vi.spyOn(journal, 'appendTransaction').mockImplementationOnce((draft: unknown) => {
          originalAppend(draft);
          throw new Error('synthetic parse apply-boundary crash');
        });
        return parseAndMaybeIngest(engine, {
          tool_name: 'atomic-parser',
          outputText: 'fixture',
          action_id: 'action-atomic-parser',
          ingest: true,
          command_completion: completion,
        });
      },
      metadata,
    )).rejects.toThrow('synthetic parse apply-boundary crash');

    vi.restoreAllMocks();
    engine.dispose();
    engine = new GraphEngine(config(), statePath);
    const replay = await new ParseCommandService(engine).execute(
      descriptor,
      () => {
        parses++;
        throw new Error('must not parse again');
      },
      metadata,
    );

    expect(parses).toBe(1);
    expect(replay).toMatchObject({
      parse_outcome: 'ok',
      finding_id: 'finding-atomic-parser',
    });
    expect(engine.getNode('host-10-0-0-44')).toMatchObject({ type: 'host' });
    expect(engine.getApplicationCommandById(metadata.command_id)).toMatchObject({
      status: 'succeeded',
      action_id: 'action-atomic-parser',
    });
    expect(engine.getFullHistory().filter(event =>
      event.event_type === 'parse_output'
      && event.action_id === 'action-atomic-parser')).toHaveLength(1);
  });

  it('returns the same sanitized parser-exception response on live and replay paths', async () => {
    disposers.push(__registerParserForTest('durable-throwing-parser', () => {
      throw new Error('sensitive parser detail');
    }));
    const descriptor = {
      tool_name: 'durable-throwing-parser',
      source_kind: 'output' as const,
      source_length: 7,
      source_fingerprint: buildParseSourceFingerprint({
        output: 'fixture',
        context: {},
      }),
      context_keys: [],
      action_id: 'action-durable-throw',
      ingest: true,
    };
    const metadata = {
      command_id: 'parse-throw-command',
      idempotency_key: 'parse-throw-retry',
      action_id: 'action-durable-throw',
    };
    const invoke = () => new ParseCommandService(engine).execute(
      descriptor,
      completion => parseAndMaybeIngest(engine, {
        tool_name: descriptor.tool_name,
        outputText: 'fixture',
        action_id: descriptor.action_id,
        ingest: true,
        command_completion: completion,
      }),
      metadata,
    );

    const first = await invoke();
    const replay = await invoke();
    expect(replay).toEqual(first);
    expect(first).toMatchObject({
      parse_outcome: 'parser_exception',
      error: 'Parser exception detail is available through the original input/evidence.',
    });
    expect(JSON.stringify(first)).not.toContain('sensitive parser detail');
  });

  it('rejects a retry key reused for different same-length parse content', async () => {
    disposers.push(__registerParserForTest('content-fingerprint-parser', output =>
      finding(`finding-${output}`, [])));
    const service = new ParseCommandService(engine);
    const metadata = {
      command_id: 'parse-content-command',
      idempotency_key: 'parse-content-retry',
      action_id: 'action-parse-content',
    };
    const invoke = (output: string) => service.execute(
      {
        tool_name: 'content-fingerprint-parser',
        source_kind: 'output',
        source_length: Buffer.byteLength(output),
        source_fingerprint: buildParseSourceFingerprint({ output, context: {} }),
        context_keys: [],
        action_id: 'action-parse-content',
        ingest: true,
      },
      completion => parseAndMaybeIngest(engine, {
        tool_name: 'content-fingerprint-parser',
        outputText: output,
        action_id: 'action-parse-content',
        ingest: true,
        command_completion: completion,
      }),
      metadata,
    );

    await invoke('foo');
    await expect(invoke('bar')).rejects.toMatchObject({
      code: 'IDEMPOTENCY_CONFLICT',
    });
  });

  it('links parser-ingested findings to unique frontier campaigns without duplicates', () => {
    disposers.push(__registerParserForTest('campaign-parser', () => finding('finding-parser-campaign', [{
      id: 'host-parser-campaign', type: 'host', label: 'parser host', ip: '10.0.0.8',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    }])));
    const campaign = engine.createCampaign({
      name: 'Parser campaign', strategy: 'custom', item_ids: ['fi-parser'], abort_conditions: [],
    });
    const first = parseAndMaybeIngest(engine, {
      tool_name: 'campaign-parser', outputText: 'fixture', action_id: 'act-campaign-1',
      frontier_item_id: 'fi-parser', ingest: true,
    });
    const second = parseAndMaybeIngest(engine, {
      tool_name: 'campaign-parser', outputText: 'fixture', action_id: 'act-campaign-2',
      frontier_item_id: 'fi-parser', ingest: true,
    });

    expect(first.campaign_id).toBe(campaign.id);
    expect(second.campaign_id).toBe(campaign.id);
    expect(engine.getCampaign(campaign.id)?.findings).toEqual(['finding-parser-campaign']);
  });

  it('retains legacy no_parser while exposing canonical validation_failed', () => {
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'not-registered', outputText: 'fixture', action_id: 'act-missing', ingest: true,
    });
    expect(result).toMatchObject({
      parse_status: 'no_parser', parse_outcome: 'validation_failed',
      failure_stage: 'parser_selection', isError: true, ingested: false,
    });
  });

  it('rejects malformed known context before parser dispatch', () => {
    let invoked = false;
    disposers.push(__registerParserForTest('context-parser', () => {
      invoked = true;
      return finding('should-not-run', []);
    }));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'context-parser', outputText: 'fixture', action_id: 'act-context', ingest: true,
      context: { tenant_id: 42 } as any,
    });
    expect(result).toMatchObject({
      parse_status: 'validation_failed', parse_outcome: 'validation_failed', failure_stage: 'context',
    });
    expect(invoked).toBe(false);
  });

  it('passes provider extensions through and ingests a complete result as ok', () => {
    disposers.push(__registerParserForTest('extension-parser', (_output, _agent, context) => {
      const tenant = context?.tenant_id;
      const extension = context?.provider_extension as { nested?: { marker?: string } } | undefined;
      return finding('extension', [{
        id: `domain-${tenant}`, type: 'domain', label: String(extension?.nested?.marker),
        domain_name: tenant, discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
      }]);
    }));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'extension-parser', outputText: 'fixture', action_id: 'act-ok', ingest: true,
      context: { tenant_id: 'acme.example', provider_extension: { nested: { marker: 'preserved' } } },
    });
    expect(result).toMatchObject({ parse_status: 'ok', parse_outcome: 'ok', isError: false });
    expect(engine.getNodesByType('domain')[0]?.label).toBe('preserved');
  });

  it('ingests valid artifacts from incomplete input as partial without making node quality sticky', () => {
    disposers.push(__registerParserForTest('partial-parser', () => finding('partial', [{
      id: 'domain-partial', type: 'domain', label: 'partial.example', domain_name: 'partial.example',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    }], { partial: true, partial_reason: 'fixture_truncated' })));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'partial-parser', outputText: 'fixture', action_id: 'act-partial', ingest: true,
    });
    expect(result).toMatchObject({
      parse_status: 'ok', parse_outcome: 'partial', partial: true,
      partial_reason: 'fixture_truncated', isError: false,
    });
    expect(engine.getNodesByType('domain')[0]?.partial).toBeUndefined();
    const event = engine.getFullHistory().find(entry => entry.action_id === 'act-partial' && entry.event_type === 'parse_output');
    expect(event).toMatchObject({ result_classification: 'partial' });
    expect(event?.details).toMatchObject({ parse_outcome: 'partial', partial_reason: 'fixture_truncated' });
  });

  it('does not leave a node permanently partial after a complete reparse', () => {
    let partial = true;
    disposers.push(__registerParserForTest('partial-then-complete', () => finding('quality-transition', [{
      id: 'domain-quality', type: 'domain', label: 'quality.example', domain_name: 'quality.example',
      discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
    }], partial ? { partial: true, partial_reason: 'truncated' } : {})));
    expect(parseAndMaybeIngest(engine, {
      tool_name: 'partial-then-complete', outputText: 'first', action_id: 'act-quality-1', ingest: true,
    }).parse_outcome).toBe('partial');
    partial = false;
    expect(parseAndMaybeIngest(engine, {
      tool_name: 'partial-then-complete', outputText: 'second', action_id: 'act-quality-2', ingest: true,
    }).parse_outcome).toBe('ok');
    expect(engine.getNode('domain-quality')?.partial).toBeUndefined();
  });

  it('keeps zero-yield as no_data while retaining parser pagination metadata', () => {
    disposers.push(__registerParserForTest('empty-next-page', () => finding('empty-next-page', [], {
      partial: true, partial_reason: 'pagination_incomplete',
    })));
    const result = parseAndMaybeIngest(engine, {
      tool_name: 'empty-next-page', outputText: 'fixture', action_id: 'act-empty-next', ingest: true,
    });
    expect(result).toMatchObject({
      parse_status: 'no_data', parse_outcome: 'no_data', isError: true,
      partial: true, partial_reason: 'pagination_incomplete',
    });
  });
});
