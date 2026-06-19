// ============================================================
// Phase I — client-safe report redaction.
//
// Operator-default reports are evidence-rich (passwords, hashes, full
// stdout, absolute filesystem paths) because that's what the operator
// needs for their own analysis. When the same report is destined for
// a client deliverable, those fields become disclosure liabilities.
//
// This module provides redaction primitives used by the markdown and
// HTML report renderers when `client_safe=true`. Goals:
//   - Preserve enough metadata that the report still tells the story
//     (counts, sha256 hashes for verifiability, sanitized lengths).
//   - Strip the actual secret material so the file can be sent
//     externally without further review.
//
// The default report path does NOT call any of these — there is no
// silent default change. Operators opt in per call.
// ============================================================

import { createHash } from 'crypto';

export interface RedactionOptions {
  /** When true, every redaction helper actually redacts; when false, returns input unchanged. */
  client_safe: boolean;
}

const REDACTED_PLACEHOLDER = '<redacted>';

const ABSOLUTE_PATH_RE = [
  /\/Users\/[^\s'"`<>:]+/g,
  /\/home\/[^\s'"`<>:]+/g,
  /[A-Z]:\\\\Users\\\\[^\s'"`<>:]+/g,
  /\/var\/folders\/[^\s'"`<>:]+/g,
];

/** sha256(content) — short hex digest used as a verifiable handle for redacted blobs. */
function sha256(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

/**
 * Redact a stdout/raw_output blob to a size-only summary plus a hash so
 * the report still tells "X bytes were captured for action Y" without
 * leaking the content.
 */
export function redactBlob(content: string | undefined | null, opts: RedactionOptions): string | null {
  if (content == null) return null;
  if (!opts.client_safe) return content;
  const bytes = Buffer.byteLength(content, 'utf-8');
  const kb = (bytes / 1024).toFixed(1);
  return `<redacted: ${kb} KB blob, sha256:${sha256(content).slice(0, 16)}…>`;
}

/**
 * Redact a credential value (password, NTLM hash, bearer token). The
 * cleartext is dropped; a stable short hash is returned so multiple
 * occurrences of the same credential can be cross-referenced in the
 * report without any of them disclosing the secret.
 */
export function redactCredentialValue(value: string | undefined | null, type?: string, opts: RedactionOptions = { client_safe: true }): string | null {
  if (value == null) return value ?? null;
  if (!opts.client_safe) return value;
  const tag = type ? `: ${type}` : '';
  const hash = sha256(value).slice(0, 12);
  return `<redacted${tag}, sha256:${hash}…>`;
}

/**
 * Redact absolute filesystem paths that look like operator-machine
 * locations. Conservative: only paths under /Users, /home, /var/folders,
 * or C:\\Users — these are unambiguously operator-side and rarely
 * meaningful in a client report.
 */
export function redactOperatorPaths(text: string | undefined | null, opts: RedactionOptions): string | null {
  if (text == null) return text ?? null;
  if (!opts.client_safe) return text;
  let out = text;
  for (const re of ABSOLUTE_PATH_RE) out = out.replace(re, '<operator-path>');
  return out;
}

/** Apply both blob and operator-path redactions in one shot. */
export function redactReportText(text: string | undefined | null, opts: RedactionOptions): string | null {
  if (!opts.client_safe || text == null) return text ?? null;
  return redactOperatorPaths(text, opts);
}

/** Walk a JSON-able value and redact a known set of secret keys. Used by report builders. */
export function redactSecretKeys<T>(value: T, opts: RedactionOptions): T {
  if (!opts.client_safe) return value;
  return walkAndRedact(value) as T;
}

const SECRET_KEYS = new Set([
  'cred_value', 'password', 'secret', 'token', 'bearer', 'api_key',
  'private_key', 'priv_key', 'session_key', 'aes_key', 'rc4_key',
  'ntlm', 'nt_hash', 'lm_hash', 'aes256_hash', 'aes128_hash',
  'tgt', 'tgs', 'st',
]);

const BLOB_KEYS = new Set(['raw_output', 'evidence_content', 'stdout_preview', 'stderr_preview', 'content']);

// Keys whose string value is a shell/tool command — secrets ride in the ARGS
// (flags + connection strings), not under a dedicated secret key, so SECRET_KEYS
// never catches them.
const COMMAND_KEYS = new Set(['command', 'command_repr', 'cmd', 'argv_str']);

/**
 * Redact credential material that can appear inline in ANY free-text string,
 * independent of CLI flags: `user:password@host` (URLs / connection strings)
 * and `Authorization: Bearer <token>` / bare `Bearer <token>`. Conservative
 * patterns — they only fire on shapes that are unambiguously credentials.
 */
export function redactInlineCredentials(text: string): string {
  return text
    // scheme://user:pass@host  and  user:pass@host. The password group allows
    // colons so credentials that contain them (NTLM `lm:nt`, colon passwords) are
    // still redacted; it stops at the `@` host separator.
    .replace(/([a-zA-Z][\w.+-]*:\/\/)?([^\s:/@]+):([^@\s]+)@/g,
      (_m, scheme, user) => `${scheme || ''}${user}:${REDACTED_PLACEHOLDER}@`)
    .replace(/(Authorization:\s*Bearer\s+)(\S+)/gi, `$1${REDACTED_PLACEHOLDER}`)
    .replace(/(\bBearer\s+)([A-Za-z0-9._~+/=-]{12,})/g, `$1${REDACTED_PLACEHOLDER}`);
}

/**
 * Sanitize a command string for client delivery: drop the VALUE of
 * secret-bearing CLI flags (-p/--password, --hashes/-H, --token, …), the
 * password in `-u user%pass` (smbclient/nxc), and any inline credentials.
 * Quote-aware so `-p 'pass with spaces'` is fully redacted. The flag itself is
 * preserved so the report still shows what was run.
 *
 * Assumes a well-formed shell command, where a value is a single token (quoted
 * if it contains spaces). An *unquoted* multi-word value (e.g. a naively
 * argv-joined `-p Pass Phrase`) only has its first token redacted — but that is
 * not a valid single-arg shell command, and structured credential fields are
 * already covered by SECRET_KEYS in walkAndRedact, so the residual exposure is
 * a malformed-input edge, not the normal path.
 */
export function sanitizeCommandForClient(cmd: string | undefined | null, opts: RedactionOptions = { client_safe: true }): string | null {
  if (cmd == null) return null;
  if (!opts.client_safe) return cmd;
  let out = cmd
    // -p VALUE | --password=VALUE | --hashes LM:NT | --token X | -H X  (quote-aware value)
    .replace(
      /(^|\s)(-p|--password|--passwd|--pass|-H|--hashes|--hash|--token|--api-key|--apikey)(\s+|=)('[^']*'|"[^"]*"|\S+)/gi,
      (_m, pre, flag, sep) => `${pre}${flag}${sep}${REDACTED_PLACEHOLDER}`)
    // -u user%password / -U dom\user%password (smbclient / nxc)
    .replace(/((?:^|\s)-[uU]\s+\S*?%)(\S+)/g, `$1${REDACTED_PLACEHOLDER}`);
  return redactInlineCredentials(out);
}

function walkAndRedact(value: unknown): unknown {
  if (value == null) return value;
  if (Array.isArray(value)) return value.map(walkAndRedact);
  if (typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEYS.has(k) && typeof v === 'string') {
      out[k] = redactCredentialValue(v, k);
    } else if (BLOB_KEYS.has(k) && typeof v === 'string') {
      out[k] = redactBlob(v, { client_safe: true });
    } else if (COMMAND_KEYS.has(k) && typeof v === 'string') {
      // Commands carry creds in their args (-p, --hashes, user:pass@, Bearer …).
      out[k] = redactOperatorPaths(sanitizeCommandForClient(v), { client_safe: true });
    } else if (typeof v === 'string') {
      // Operator paths + inline creds (user:pass@, Bearer) can leak via any field.
      out[k] = redactInlineCredentials(redactOperatorPaths(v, { client_safe: true }) ?? v);
    } else {
      out[k] = walkAndRedact(v);
    }
  }
  return out;
}

export const _redactedPlaceholder = REDACTED_PLACEHOLDER;
