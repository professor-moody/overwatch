import { describe, it, expect } from 'vitest';
import {
  normalizeActionOutput,
  formatBytes,
  streamHasMore,
  type OutputStreamView,
} from '../action-output';
import type { ActionOutputResponse } from '../api';

function baseResponse(over: Partial<ActionOutputResponse> = {}): ActionOutputResponse {
  return {
    action_id: 'act_abc',
    status: 'success',
    max_bytes: 65536,
    stdout: null,
    stderr: null,
    ...over,
  };
}

describe('normalizeActionOutput', () => {
  it('maps a completed action with stdout into a view model', () => {
    const view = normalizeActionOutput(baseResponse({
      tool_name: 'nmap',
      command_repr: 'nmap -sV 10.0.0.5',
      exit_code: 0,
      duration_ms: 1234,
      target_ips: ['10.0.0.5'],
      target_node_ids: ['host-1'],
      agent_id: 'agent-recon-1',
      linked_finding_ids: ['f-1', 'f-2'],
      stdout: {
        evidence_id: 'ev-out',
        text: 'PORT   STATE\n22/tcp open',
        total_bytes: 22,
        truncated: false,
        head_truncated: false,
        dropped_bytes: 0,
      },
    }));

    expect(view.actionId).toBe('act_abc');
    expect(view.status).toBe('success');
    expect(view.isRunning).toBe(false);
    expect(view.tool).toBe('nmap');
    expect(view.command).toBe('nmap -sV 10.0.0.5');
    expect(view.exitCode).toBe(0);
    expect(view.durationMs).toBe(1234);
    expect(view.targets).toEqual(['host-1', '10.0.0.5']);
    expect(view.agentId).toBe('agent-recon-1');
    expect(view.findingIds).toEqual(['f-1', 'f-2']);
    expect(view.stdout.text).toContain('22/tcp open');
    expect(view.stdout.isEmpty).toBe(false);
    expect(view.stderr.isEmpty).toBe(true);
    expect(view.isEmpty).toBe(false);
  });

  it('falls back to invoking_tool when tool_name is absent', () => {
    const view = normalizeActionOutput(baseResponse({ invoking_tool: 'run_bash' }));
    expect(view.tool).toBe('run_bash');
  });

  it('treats a running action with no streams as running + empty', () => {
    const view = normalizeActionOutput(baseResponse({ status: 'running', stdout: null, stderr: null }));
    expect(view.isRunning).toBe(true);
    expect(view.isEmpty).toBe(true);
    expect(view.exitCode).toBeNull();
    expect(view.command).toBeNull();
  });

  it('carries truncation, drop, and capture-error signals', () => {
    const view = normalizeActionOutput(baseResponse({
      capture_error: { stdout: 'disk full' },
      stdout: {
        evidence_id: 'ev-out',
        text: 'head…',
        total_bytes: 5_000_000,
        truncated: true,
        head_truncated: true,
        dropped_bytes: 4096,
      },
    }));
    expect(view.hasCaptureError).toBe(true);
    expect(view.stdout.capturedTruncated).toBe(true);
    expect(view.stdout.headTruncated).toBe(true);
    expect(view.stdout.droppedBytes).toBe(4096);
    expect(streamHasMore(view.stdout)).toBe(true);
  });

  it('flags a missing evidence blob', () => {
    const view = normalizeActionOutput(baseResponse({
      stdout: {
        evidence_id: 'ev-gone', text: '', total_bytes: 100,
        truncated: false, head_truncated: false, dropped_bytes: 0, missing: true,
      },
    }));
    expect(view.stdout.missing).toBe(true);
    expect(view.stdout.isEmpty).toBe(true);
    expect(view.stdout.captureFailed).toBe(false);
  });

  it('flags a capture-failed stream (output existed but bytes were lost)', () => {
    const view = normalizeActionOutput(baseResponse({
      capture_error: { stdout: 'write EPIPE' },
      stdout: {
        evidence_id: null, text: '', total_bytes: 4096,
        truncated: false, head_truncated: false, dropped_bytes: 0,
        missing: true, capture_failed: true,
      },
    }));
    expect(view.stdout.captureFailed).toBe(true);
    expect(view.stdout.missing).toBe(true);
    expect(view.stdout.evidenceId).toBeNull();
    expect(view.hasCaptureError).toBe(true);
  });

  it('defaults gracefully when optional numeric fields are absent', () => {
    const view = normalizeActionOutput(baseResponse({}));
    expect(view.exitCode).toBeNull();
    expect(view.durationMs).toBeNull();
    expect(view.timedOut).toBe(false);
    expect(view.findingIds).toEqual([]);
    expect(view.targets).toEqual([]);
  });
});

describe('formatBytes', () => {
  it('formats common magnitudes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(-5)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KiB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MiB');
  });
});

describe('streamHasMore', () => {
  it('is true only when the head was truncated', () => {
    const more: OutputStreamView = {
      evidenceId: 'e', text: 'x', totalBytes: 100, capturedTruncated: false,
      headTruncated: true, droppedBytes: 0, missing: false, captureFailed: false, isEmpty: false,
    };
    const complete: OutputStreamView = { ...more, headTruncated: false };
    expect(streamHasMore(more)).toBe(true);
    expect(streamHasMore(complete)).toBe(false);
  });
});
