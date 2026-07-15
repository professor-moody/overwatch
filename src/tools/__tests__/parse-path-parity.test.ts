import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { parseAndMaybeIngest } from '../../services/parse-ingest.js';
import { __registerParserForTest } from '../../services/parsers/index.js';
import { registerRunBashTool } from '../run-bash.js';
import type { EngagementConfig, Finding } from '../../types.js';

function config(id: string): EngagementConfig {
  return {
    id, name: id, created_at: '2026-01-01T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] }, objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
  };
}

const baseFinding = (id: string, nodes: Finding['nodes'] = [], extra: Partial<Finding> = {}): Finding => ({
  id, agent_id: 'parity-parser', timestamp: '2026-01-01T00:00:00Z', nodes, edges: [], ...extra,
});

describe('inline and direct parser parity', () => {
  let dir: string;
  let directEngine: GraphEngine;
  let inlineEngine: GraphEngine;
  let runBash: (args: any) => Promise<any>;
  const disposers: Array<() => void> = [];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-parse-parity-'));
    directEngine = new GraphEngine(config('direct'), join(dir, 'direct.json'));
    inlineEngine = new GraphEngine(config('inline'), join(dir, 'inline.json'));
    const server = {
      registerTool(_name: string, _meta: unknown, handler: (args: any) => Promise<any>) { runBash = handler; },
    } as unknown as McpServer;
    registerRunBashTool(server, inlineEngine);
  });

  afterEach(() => {
    while (disposers.length) disposers.pop()!();
    directEngine.dispose();
    inlineEngine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  const cases: Array<{
    name: string;
    command: string;
    directInput: string;
    parser: (output: string) => Finding;
    expected: string;
  }> = [
    { name: 'empty-input', command: 'true', directInput: '', parser: () => baseFinding('empty', []), expected: 'no_data' },
    { name: 'zero-yield', command: "printf '%s' fixture", directInput: 'fixture', parser: () => baseFinding('zero', []), expected: 'no_data' },
    {
      name: 'validation-failure', command: "printf '%s' fixture", directInput: 'fixture',
      parser: () => baseFinding('invalid', [{
        id: 'cred-invalid', type: 'credential', label: 'invalid', privileged: true,
        discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
      }]), expected: 'validation_failed',
    },
    {
      name: 'parser-exception', command: "printf '%s' fixture", directInput: 'fixture',
      parser: () => { throw new Error('parity exception'); }, expected: 'parser_exception',
    },
    {
      name: 'partial', command: "printf '%s' fixture", directInput: 'fixture',
      parser: () => baseFinding('partial', [{
        id: 'domain-partial', type: 'domain', label: 'partial.example', domain_name: 'partial.example',
        discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
      }], { partial: true, partial_reason: 'fixture_partial' }), expected: 'partial',
    },
    {
      name: 'success', command: "printf '%s' fixture", directInput: 'fixture',
      parser: () => baseFinding('success', [{
        id: 'domain-success', type: 'domain', label: 'success.example', domain_name: 'success.example',
        discovered_at: '2026-01-01T00:00:00Z', confidence: 1,
      }]), expected: 'ok',
    },
  ];

  for (const scenario of cases) {
    it(`matches for ${scenario.name}`, async () => {
      const parserName = `parity-${scenario.name}`;
      disposers.push(__registerParserForTest(parserName, scenario.parser));
      const direct = parseAndMaybeIngest(directEngine, {
        tool_name: parserName, outputText: scenario.directInput,
        action_id: `direct-${scenario.name}`, ingest: true,
      });
      const inlineResponse = await runBash({
        command: scenario.command, validate: false, parse_with: parserName,
      });
      const inline = JSON.parse(inlineResponse.content[0].text).parse_summary;

      expect(direct.parse_outcome).toBe(scenario.expected);
      expect(inline.parse_outcome).toBe(scenario.expected);
      expect(inline.parse_status).toBe(direct.parse_status);
      expect(inline.nodes_parsed).toBe(direct.nodes_parsed);
      expect(inline.edges_parsed).toBe(direct.edges_parsed);
      expect(inline.isError).toBe(direct.isError);
      expect(Boolean(inlineResponse.isError)).toBe(direct.isError);
    });
  }
});
