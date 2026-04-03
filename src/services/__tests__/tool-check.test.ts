import { describe, it, expect, vi, beforeEach } from 'vitest';
// Build a callback-style mock that has a proper custom promisify symbol
// so that util.promisify returns { stdout, stderr } like the real execFile.
let execImpl: (cmd: string, args: string[], opts: any) => { stdout: string; stderr: string };

function makeExecFileMock() {
  const cbFn: any = (cmd: string, args: string[], opts: any, cb: Function) => {
    try {
      const result = execImpl(cmd, args, opts);
      cb(null, result.stdout, result.stderr);
    } catch (err) {
      cb(err, '', '');
    }
  };
  // Attach custom promisify so util.promisify returns { stdout, stderr }
  cbFn[Symbol.for('nodejs.util.promisify.custom')] = async (
    cmd: string,
    args: string[],
    opts: any,
  ) => execImpl(cmd, args, opts);
  return cbFn;
}

vi.mock('child_process', () => ({
  execFile: makeExecFileMock(),
}));

// Re-import after mock is in place (module-level promisify captures mock)
const { checkAllTools, checkToolByName } = await import('../tool-check.js');

describe('Tool Check', () => {
  beforeEach(() => {
    // Default: all tools not found
    execImpl = () => { throw new Error('not found'); };
  });

  describe('checkAllTools', () => {
    it('returns a ToolStatus array with one entry per known tool', async () => {
      const results = await checkAllTools();
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThanOrEqual(10);
      expect(results.every(r => r.name && typeof r.installed === 'boolean')).toBe(true);
    });

    it('marks tools as installed when which succeeds', async () => {
      execImpl = (cmd) => {
        if (cmd === 'which') return { stdout: '/usr/bin/nmap\n', stderr: '' };
        return { stdout: 'Nmap version 7.94\n', stderr: '' };
      };

      const results = await checkAllTools();
      const nmap = results.find(r => r.name === 'nmap');
      expect(nmap?.installed).toBe(true);
      expect(nmap?.path).toBe('/usr/bin/nmap');
      expect(nmap?.version).toContain('7.94');
    });

    it('marks tools as not installed when which fails', async () => {
      const results = await checkAllTools();
      expect(results.every(r => r.installed === false)).toBe(true);
    });
  });

  describe('checkToolByName', () => {
    it('returns null for unknown tool name', async () => {
      const result = await checkToolByName('nonexistent-tool-xyz');
      expect(result).toBeNull();
    });

    it('returns ToolStatus for known tool', async () => {
      execImpl = (cmd) => {
        if (cmd === 'which') return { stdout: '/usr/bin/nmap\n', stderr: '' };
        return { stdout: 'Nmap version 7.94\n', stderr: '' };
      };

      const result = await checkToolByName('nmap');
      expect(result).not.toBeNull();
      expect(result!.name).toBe('nmap');
      expect(result!.installed).toBe(true);
    });

    it('handles version flag failure gracefully', async () => {
      execImpl = (cmd) => {
        if (cmd === 'which') return { stdout: '/usr/bin/nmap\n', stderr: '' };
        throw new Error('version failed');
      };

      const result = await checkToolByName('nmap');
      expect(result!.installed).toBe(true);
      expect(result!.version).toBeUndefined();
    });
  });
});
