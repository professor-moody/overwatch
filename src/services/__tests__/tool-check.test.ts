import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const execFileMock = vi.fn();

vi.mock('child_process', () => ({
  execFile: execFileMock,
}));

// Re-import after mock is in place
const { checkToolByName } = await import('../tool-check.js');

describe('tool-check', () => {
  beforeEach(() => {
    execFileMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('version line regex extracts lines containing semver-like versions', () => {
    const versionRegex = /\d+\.\d+/;

    expect(versionRegex.test('Nmap version 7.94SVN ( https://nmap.org )')).toBe(true);
    expect(versionRegex.test('gobuster v3.6.0')).toBe(true);
    expect(versionRegex.test('Python 3.11.4')).toBe(true);
    expect(versionRegex.test('Usage: nmap [options] target')).toBe(false);
    expect(versionRegex.test('no version here')).toBe(false);
  });

  it('extracts first version-bearing line and trims to 120 chars', () => {
    const lines = [
      'Some preamble text',
      'Tool version 1.2.3 - released 2026-01-01',
      'More output here',
    ];
    const versionLine = lines.find(l => /\d+\.\d+/.test(l));
    expect(versionLine).toBe('Tool version 1.2.3 - released 2026-01-01');
    expect(versionLine!.slice(0, 120).trim()).toBe('Tool version 1.2.3 - released 2026-01-01');
  });

  it('returns null for unknown tool name via checkToolByName', async () => {
    const result = await checkToolByName('nonexistent-tool-xyz');
    expect(result).toBeNull();
  });

  it('checkToolByName returns installed: false when which fails', async () => {
    execFileMock.mockImplementation(
      (_cmd: string, _args: string[], opts: unknown, cb?: (err: Error | null, result: { stdout: string; stderr: string }) => void) => {
        const callback = cb || opts;
        if (typeof callback === 'function') {
          (callback as (err: Error | null, result: { stdout: string; stderr: string }) => void)(
            new Error('not found'), { stdout: '', stderr: '' },
          );
        }
      },
    );

    const result = await checkToolByName('nmap');
    expect(result).not.toBeNull();
    expect(result!.installed).toBe(false);
  });

  it('version extraction handles multiline output correctly', () => {
    const output = `nmap version 7.94 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
Compiled with: nmap-liblua-5.4.4 openssl-3.0.8`;

    const lines = output.trim().split('\n');
    const versionLine = lines.find(l => /\d+\.\d+/.test(l));
    expect(versionLine).toBeDefined();
    expect(versionLine!.slice(0, 120).trim()).toBe('nmap version 7.94 ( https://nmap.org )');
  });

  it('version extraction returns undefined when no version line exists', () => {
    const output = 'Usage: sometool [options]\nNo version info available';
    const lines = output.trim().split('\n');
    const versionLine = lines.find(l => /\d+\.\d+/.test(l));
    expect(versionLine).toBeUndefined();
  });
});
