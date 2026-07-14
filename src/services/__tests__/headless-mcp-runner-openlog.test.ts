import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, rmSync, mkdtempSync, type WriteStream } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { ProcessTracker } from '../process-tracker.js';
import { HeadlessProcessRegistry } from '../headless-process-registry.js';
import { HeadlessMcpRunner } from '../headless-mcp-runner.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-headless-openlog.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-openlog',
    name: 'openlog test',
    created_at: new Date().toISOString(),
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('HeadlessMcpRunner.openLog', () => {
  afterEach(() => {
    try { if (existsSync(TEST_STATE_FILE)) rmSync(TEST_STATE_FILE); } catch { /* ignore */ }
  });

  it('attaches an error listener so an async log-stream error cannot crash the daemon', () => {
    const logDir = mkdtempSync(join(tmpdir(), 'ow-openlog-'));
    const runner = new HeadlessMcpRunner(
      new GraphEngine(makeConfig(), TEST_STATE_FILE),
      new HeadlessProcessRegistry(),
      new ProcessTracker(),
      { logDir },
    );
    // openLog is private; the log stream is best-effort internal state.
    const stream = (runner as unknown as { openLog(id: string): WriteStream | null }).openLog('task-1');
    expect(stream).toBeTruthy();
    // The async-error path: createWriteStream emits 'error' asynchronously. Without an
    // 'error' listener, that event is unhandled and crashes the process. Assert the
    // listener is present AND that emitting 'error' is swallowed (not re-thrown).
    expect(stream!.listenerCount('error')).toBeGreaterThan(0);
    expect(() => stream!.emit('error', new Error('disk full'))).not.toThrow();

    stream!.destroy();
    try { rmSync(logDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });
});
