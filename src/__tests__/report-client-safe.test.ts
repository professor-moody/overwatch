// ============================================================
// Phase I — generate_report client-safe mode.
//
// The operator-internal report stays evidence-rich (passwords, hashes,
// stdout, operator paths). When the same report is sent to a client,
// `client_safe: true` strips the secret material while keeping enough
// metadata that the report still tells the engagement story.
// ============================================================

import { describe, expect, it } from 'vitest';
import {
  redactBlob,
  redactCredentialValue,
  redactInlineCredentials,
  redactOperatorPaths,
  redactSecretKeys,
  sanitizeCommandForClient,
} from '../services/report-redaction.js';

describe('report-redaction primitives', () => {
  it('redactBlob replaces content with size+sha256 placeholder when client_safe is true', () => {
    const out = redactBlob('hunter2', { client_safe: true });
    expect(out).toMatch(/^<redacted: 0\.0 KB blob, sha256:[0-9a-f]+…>$/);

    // Operator default: pass-through.
    expect(redactBlob('hunter2', { client_safe: false })).toBe('hunter2');
  });

  it('redactCredentialValue replaces value with hashed handle and preserves type', () => {
    const out = redactCredentialValue('aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0', 'nt_hash');
    expect(out).toMatch(/^<redacted: nt_hash, sha256:[0-9a-f]+…>$/);
    expect(redactCredentialValue('hunter2', 'password', { client_safe: false })).toBe('hunter2');
  });

  it('redactOperatorPaths strips /Users, /home, C:\\\\Users paths', () => {
    const text = 'logs at /Users/operator/projects/loot/notes.md and /home/op/scan.txt';
    const out = redactOperatorPaths(text, { client_safe: true });
    expect(out).not.toContain('/Users/operator');
    expect(out).not.toContain('/home/op');
    expect(out).toContain('<operator-path>');
  });

  it('redactSecretKeys deep-walks an object and redacts known secret + blob keys', () => {
    const input = {
      finding_id: 'f-1',
      severity: 'high',
      credentials: [
        { username: 'svc-sql', cred_value: 'PASSWORD123!', type: 'password' },
        { username: 'admin', nt_hash: 'aad3b4:31d6cf', type: 'ntlm' },
      ],
      evidence: [
        { evidence_id: 'ev-1', raw_output: 'plaintext stdout with secrets' },
      ],
      operator_path: '/Users/op/.claude/state.json',
      preserved: { count: 5, label: 'finding count' },
    };

    const out = redactSecretKeys(input, { client_safe: true });
    expect((out as any).credentials[0].cred_value).toMatch(/<redacted/);
    expect((out as any).credentials[0].cred_value).not.toContain('PASSWORD123!');
    expect((out as any).credentials[1].nt_hash).toMatch(/<redacted/);
    expect((out as any).evidence[0].raw_output).toMatch(/<redacted: .* KB blob/);
    expect((out as any).operator_path).toBe('<operator-path>');
    // Non-secret structure preserved
    expect((out as any).finding_id).toBe('f-1');
    expect((out as any).severity).toBe('high');
    expect((out as any).preserved.count).toBe(5);
  });

  it('client_safe=false leaves objects untouched', () => {
    const input = { cred_value: 'PASSWORD123!', count: 5 };
    const out = redactSecretKeys(input, { client_safe: false });
    expect(out).toBe(input);
  });

  // ==== command-string credential redaction (review P1) ====

  describe('sanitizeCommandForClient', () => {
    it('redacts -p / --password values (space and = forms)', () => {
      const a = sanitizeCommandForClient('nxc smb 10.0.0.1 -u admin -p Summer2024!');
      expect(a).not.toContain('Summer2024!');
      expect(a).toContain('-p <redacted>');
      const b = sanitizeCommandForClient('tool --password=hunter2 --host x');
      expect(b).not.toContain('hunter2');
      expect(b).toContain('--password=<redacted>');
    });

    it('is quote-aware (redacts a password containing spaces)', () => {
      const out = sanitizeCommandForClient("sshpass -p 'pass with spaces' ssh u@h");
      expect(out).not.toContain('pass with spaces');
      expect(out).toContain('-p <redacted>');
    });

    it('redacts --hashes / pass-the-hash material', () => {
      const out = sanitizeCommandForClient('secretsdump.py corp/a@10.0.0.1 --hashes aad3b4:31d6cf');
      expect(out).not.toContain('aad3b4:31d6cf');
      expect(out).toContain('--hashes <redacted>');
    });

    it('redacts user%password (smbclient / nxc) keeping the user', () => {
      const out = sanitizeCommandForClient('smbclient //h/share -U corp\\\\admin%P@ssw0rd');
      expect(out).not.toContain('P@ssw0rd');
      expect(out).toContain('%<redacted>');
      expect(out).toContain('corp\\\\admin');
    });

    it('redacts inline credentials in connection strings and bearer headers', () => {
      const out = sanitizeCommandForClient("psql postgres://svc:s3cret@db:5432/x ; curl -H 'Authorization: Bearer eyJhbG.tok.zzz'");
      expect(out).not.toContain('s3cret');
      expect(out).toContain('svc:<redacted>@');
      expect(out).not.toContain('eyJhbG.tok.zzz');
    });

    it('passes through unchanged when client_safe is false', () => {
      const cmd = 'nxc smb 10.0.0.1 -u admin -p Summer2024!';
      expect(sanitizeCommandForClient(cmd, { client_safe: false })).toBe(cmd);
    });

    it('sanitizes a command rendered inside a markdown bash fence', () => {
      // Mirrors what scrubMarkdownForClient does over the whole client document.
      const md = '```bash\nnxc smb 10.0.0.1 -u admin -p Summer2024!\n```';
      const out = sanitizeCommandForClient(md);
      expect(out).not.toContain('Summer2024!');
    });
  });

  it('redactInlineCredentials redacts user:pass@host and Bearer tokens in any string', () => {
    const out = redactInlineCredentials('connect mysql://root:R00tPass@10.0.0.5 with Bearer abcdef0123456789');
    expect(out).not.toContain('R00tPass');
    expect(out).toContain('root:<redacted>@');
    expect(out).not.toContain('abcdef0123456789');
  });

  it('redactSecretKeys redacts credentials embedded in a command field (not just secret keys)', () => {
    const input = {
      evidence: [{ claim: 'auth', command: 'nxc smb 10.0.0.1 -u admin -p Secret123' }],
      proof_cards: [{ command: 'curl -H "Authorization: Bearer tok.en.value" https://api' }],
    };
    const out = redactSecretKeys(input, { client_safe: true }) as any;
    expect(out.evidence[0].command).not.toContain('Secret123');
    expect(out.evidence[0].command).toContain('-p <redacted>');
    expect(out.proof_cards[0].command).not.toContain('tok.en.value');
  });
});
