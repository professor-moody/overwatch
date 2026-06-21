# Report Redaction (`client_safe`)

Operator-default reports are **evidence-rich** — passwords, hashes, full tool
stdout, absolute filesystem paths — because that's what the operator needs for
their own analysis. When the same report becomes a **client deliverable**, those
fields turn into disclosure liabilities. Passing `client_safe: true` to
[`generate_report`](../tools/generate-report.md) runs the report through the
redaction primitives in `src/services/report-redaction.ts`.

The goal is to **preserve the story** (counts, sha256 hashes for verifiability,
sanitized lengths) while **stripping the secret material**, so the file can be
sent externally without a further manual review pass.

!!! note "Opt-in, never silent"
    The default report path does **not** call any redaction helper — there is no
    silent default change. Operators opt in per call with `client_safe: true`.
    Redacted values are replaced with the literal placeholder `<redacted>`.

## What gets redacted

| Category | Examples | Treatment |
|----------|----------|-----------|
| **Secret-bearing fields** | `cred_value`, `password`, `secret`, `token`, `bearer`, `api_key`, `private_key`, `session_key`, `ntlm` / `nt_hash` / `lm_hash`, `aes256_hash`, `tgt` / `tgs` / `st` | Value replaced with `<redacted>` (a stable short hash may be kept so the same secret can be cross-referenced without disclosure). |
| **Raw output blobs** | `raw_output`, `evidence_content`, `stdout_preview`, `stderr_preview`, `content` | Replaced with a size-only summary plus a `sha256` of the content — the report still says "X KB captured for action Y" and the hash proves provenance, without leaking the bytes. |
| **Command strings** | `command`, `command_repr`, `cmd`, `argv_str` | Secret-bearing flags are sanitized in place (`-p`/`--password`, `--hashes`, `--token`, `-u user%pass`, …) — the flag is preserved so the report still shows *what ran*, the value is redacted. Quote-aware. |
| **Inline credentials (any field)** | `user:pass@host` connection strings, `Authorization: Bearer …`, bare `Bearer <token>` | Redacted wherever they appear in free text, not just under a known secret key. |
| **Operator filesystem paths** | absolute `/Users/…`, `/home/…`, `/root/…`, `/tmp/…` paths | Stripped so the deliverable doesn't leak the operator's machine layout. |

## What is preserved

- Finding structure, severity, attack narratives, and per-objective attack paths.
- Evidence **counts**, byte sizes, and **`sha256` content hashes** (verifiability
  without the content).
- Sanitized command lines (the tool + flags that ran, minus secret values).

## Notes & edge cases

- **Unquoted multi-word values.** A naively argv-joined `-p secret phrase` (no
  quotes) only redacts the first token — but that isn't a valid single-arg shell
  command, and the same secret is already covered by the secret-key path, so the
  residual exposure is a malformed-input edge, not the normal path. Quoted
  multi-word secrets (`-p 'secret phrase'`) are fully redacted.
- **Operator-internal vs deliverable.** Keep the default (evidence-rich) report
  for your own analysis; generate a second `client_safe: true` copy only for the
  hand-off. The two are produced from the same finding set, so they can't drift.

See also: [`generate_report`](../tools/generate-report.md),
[Runtime Model](../runtime-model.md).
