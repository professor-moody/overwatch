# test_webapp_credential

Test a credential already in the graph against a web application in a single call, and record the result so credential coverage retires and authenticated re-scan fires.

**Read-only:** No

## Description

Complements [`validate_token_credential`](token-credential.md) (which only covers IdP / cloud SSO providers — Entra, Okta, AWS STS, GitHub) by handling **ordinary web auth**: form logins, HTTP Basic, generic bearer / API-key headers, and session-cookie replay.

The auth attempt runs as a scope-checked `curl` through the standard instrumented lifecycle (`validate → approval → action_started → spawn → evidence → action_completed → parse`). The engine never makes outbound calls itself; scope is enforced on the request URL **before** spawn.

The secret (password / token / cookie value) is **never** written to the activity log — `command_repr` carries only a `sha256:` fingerprint, and the raw argv is withheld from the persisted events + tool response (via the runner's `redact_args_in_log`). The raw secret is used solely to spawn curl. If a target reflects the secret back in its response body, it's scrubbed from the tool's returned output, and the stored evidence blob is `client_safe`-redacted in reports.

## Methods

| `method` | What it does |
|----------|--------------|
| `form`   | POSTs `username`/`password` to `login_path` (fields overridable with `username_field` / `password_field`). |
| `basic`  | HTTP Basic (`-u cred_user:secret`) against `target_url`. |
| `bearer` | `Authorization: Bearer <token>`. Set `header_name` (e.g. `X-API-Key`) to send the raw value under a custom header instead. |
| `cookie` | `Cookie: <name>=<value>` replay. `header_name` is the cookie name (default `session`). |

## Success detection

You **must** pass a `success` criterion — there is no status-only default, because every status-only heuristic (a form `302`, an API `200`, even a Basic `2xx` on a path that ignores the header) is target-controlled and can't distinguish real access from a benign or crafted response.

- `status` — a code or list of codes that mean success.
- `body_contains` — substring that must appear in the body.
- `body_excludes` — substring whose presence means **failure** even if the status matched (e.g. `"Invalid password"` — keep it a specific phrase, not `"error"`).
- `redirect_contains` — substring the `Location` header must contain.

Pick a positive signal the authenticated response has and an unauthenticated one doesn't: `redirect_contains` for a form login (the post-login landing path — a specific path, not `/`), `body_contains` for an API (a field only an authed response returns), `success.status` for a strictly protected endpoint.

Criteria are **ANDed**. When `success.status` is omitted, `redirect_contains` implies a `3xx` and `body_contains` implies a `<400` status (safety gates); so don't combine a redirect landing with `body_contains`, or set `success.status` to override those gates.

Anti-spoofing properties (the credential-test target is untrusted by construction):

- **Status** is read only from curl's `-w` marker, which carries a **per-call random nonce** — a target can't fake a success status by echoing a marker in its response body.
- **Headers** are parsed by curl's block structure: interim `1xx` blocks (incl. status-shaped header lines a target plants inside them) are skipped whole, and the real response is the first non-`1xx` block — so a target can't forge the status line / `Location` header by injecting an `HTTP/…` block, and a benign body containing an `HTTP/…` line doesn't corrupt header parsing.
- A **malformed response** (junk framing / no header terminator) is scored **inconclusive**, never a confirmed success.
- A **reflected secret** (a target echoing the submitted credential in its response) is scrubbed from the captured stdout/stderr in the tool response and the live dashboard tee (including a secret split across an output-truncation marker); the parser never emits it into the finding.
- The **response body is target-controlled**, so `body_contains` / `body_excludes` / `redirect_contains` are meaningful only against honest targets — a target that deliberately returns a success-shaped response for a wrong credential can't be distinguished from a real success (the value is confirming credentials against the actual app under test, not defending against a target that lies about auth). Status (nonce) and headers (block-structure) are the injection-resistant parts.

## Outcomes

| Verdict | What it stamps |
|---------|----------------|
| **Success** | `AUTHENTICATED_AS` (credential → webapp) — fires `rule-authenticated-rescan`; `VALID_ON` (credential → service) — retires the `credential_test` item; plus the backing `host → service → webapp` chain. |
| **Failure** (`401`/`403`, an unmet explicit criterion, or a `body_excludes` hit) | `TESTED_CRED` (credential → service) — retires the pair **without** claiming access, so it isn't re-suggested forever. |
| **Inconclusive** (unreachable / curl killed / no success criterion supplied) | Nothing — the pair stays on the frontier to retry with a criterion. |

The parser never re-emits the credential node (that would either trip `credential_material_missing` and drop the whole finding, or shallow-merge over the live credential's label/confidence) — validity is carried entirely by the edges.

## Usage Notes

- Use for `credential_test` frontier items on http/https services, or any time you want to confirm a provided/discovered web credential.
- Password reuse falls out for free: the same plaintext credential is also surfaced against any in-scope non-web services (SMB/SSH/RDP) it pairs with.
- For IdP / cloud SSO tokens (Entra, Okta, AWS STS, GitHub), prefer [`validate_token_credential`](token-credential.md) — it knows each provider's API and stamps `VALID_FOR_APP` / `ASSUMES_ROLE`.

## Example

> **"Test the `dev@acme.com` login against `https://app.acme.com` — it's a form POST to `/login`, success is a redirect to `/dashboard`."**

```jsonc
{
  "credential_id": "cred-plaintext-...",
  "target_url": "https://app.acme.com",
  "method": "form",
  "login_path": "/login",
  "success": { "redirect_contains": "/dashboard" }
}
```
