import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  EvalArtifactSession,
  redactEvalNdjson,
  redactEvalValue,
  shouldPreserveEvalArtifacts,
  type EvalArtifactManifest,
} from './eval-artifacts.js';

describe('evaluation artifact preservation', () => {
  it('writes private, schema-versioned, checksummed, redacted run evidence', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-eval-artifacts-'));
    try {
      const root = join(sandbox, 'eval-artifacts');
      const session = new EvalArtifactSession({
        kind: 'prompt',
        scenario: 'recon/control',
        model: 'haiku',
        promptVariant: 'control',
        command: {
          binary: '/usr/local/bin/claude',
          args: ['--model', 'haiku', '--token', 'argument-secret', '--api-key=inline-secret', '--max-budget-usd', '0.5'],
          env: { PATH: '/usr/bin', OVERWATCH_MCP_TOKEN: 'token-value' },
        },
        limits: { max_budget_usd: 0.5, max_turns: 8, timeout_ms: 300_000 },
        rootDir: root,
        runId: 'run-1',
        startedAt: '2026-07-18T12:34:56.000Z',
      });
      const manifest = session.finalize({
        outcome: 'completed',
        agentNdjson: `${JSON.stringify({
          type: 'result',
          authorization: 'Bearer abc.def',
          usage: { input_tokens: 2, output_tokens: 3 },
          input: { credential_value: 'super-secret' },
        })}\nAWS_SECRET_ACCESS_KEY=plain-secret`,
        record: { taskStatus: 'completed', token: 'record-token' },
        grade: { overall: 1 },
        usage: {
          input_tokens: 2,
          output_tokens: 3,
          cache_read_input_tokens: 5,
          cache_creation_input_tokens: 7,
          accounting_tokens: 17,
        },
        reportedCostUsd: 0.12,
        graphDelta: { new_node_types: ['service'] },
        toolCalls: [{ tool: 'run_tool', input: { password: 'pw' } }],
        finishedAt: '2026-07-18T12:35:00.000Z',
      });

      expect(statSync(root).mode & 0o777).toBe(0o700);
      expect(statSync(session.directory).mode & 0o777).toBe(0o700);
      for (const name of ['manifest.json', 'agent.ndjson', 'record.json', 'grade.json', 'command.json']) {
        expect(statSync(join(session.directory, name)).mode & 0o777).toBe(0o600);
      }

      const agent = readFileSync(join(session.directory, 'agent.ndjson'), 'utf8');
      const command = readFileSync(join(session.directory, 'command.json'), 'utf8');
      const record = readFileSync(join(session.directory, 'record.json'), 'utf8');
      expect(`${agent}\n${command}\n${record}`).not.toContain('abc.def');
      expect(`${agent}\n${command}\n${record}`).not.toContain('super-secret');
      expect(`${agent}\n${command}\n${record}`).not.toContain('plain-secret');
      expect(`${agent}\n${command}\n${record}`).not.toContain('token-value');
      expect(`${agent}\n${command}\n${record}`).not.toContain('record-token');
      expect(command).not.toContain('argument-secret');
      expect(command).not.toContain('inline-secret');
      expect(agent).toContain('input_tokens');

      const storedManifest = JSON.parse(readFileSync(join(session.directory, 'manifest.json'), 'utf8')) as EvalArtifactManifest;
      expect(storedManifest).toMatchObject({
        schema_version: 1,
        outcome: 'completed',
        eligible_for_baseline: true,
        cost: { reported_usd: 0.12, reserved_usd: 0 },
        usage: { accounting_tokens: 17 },
      });
      for (const [name, descriptor] of Object.entries(manifest.artifacts)) {
        const bytes = readFileSync(join(session.directory, name));
        expect(descriptor.bytes).toBe(bytes.byteLength);
        expect(descriptor.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
      }
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it('redacts sensitive fields without erasing token-accounting categories', () => {
    expect(redactEvalValue({
      access_token: 'secret',
      input_tokens: 11,
      env: { GITHUB_TOKEN: 'secret', PATH: '/bin' },
    })).toEqual({
      access_token: '[REDACTED]',
      input_tokens: 11,
      env: { GITHUB_TOKEN: '[REDACTED]', PATH: '/bin' },
    });
    expect(redactEvalNdjson('Authorization: Bearer visible-secret')).not.toContain('visible-secret');
  });

  it('preserves every real run but keeps fake runs temporary unless requested', () => {
    expect(shouldPreserveEvalArtifacts(false)).toBe(true);
    expect(shouldPreserveEvalArtifacts(true)).toBe(false);
    expect(shouldPreserveEvalArtifacts(true, true)).toBe(true);
  });

  it('never marks a completed-but-incomplete record as baseline eligible', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-eval-artifacts-incomplete-'));
    try {
      const session = new EvalArtifactSession({
        kind: 'prompt',
        scenario: 'incomplete',
        model: 'fake',
        promptVariant: 'control',
        command: { binary: 'fake-claude', args: [] },
        limits: { max_turns: 1, timeout_ms: 1_000 },
        rootDir: sandbox,
      });
      expect(session.finalize({ outcome: 'completed', record: { taskStatus: 'completed' } }))
        .toMatchObject({ eligible_for_baseline: false });
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
