# Web Assessment

**Scenario:** you're handed a set of **subdomains**, **IP addresses**, and **test credentials** in scope, and asked to assess the web attack surface. This guide takes you from that hand-off to a driven, credential-aware engagement.

!!! tip "New to Overwatch?"
    Do the [Quick Start](../getting-started.md#quick-start-5-minutes) first (install, wire into Claude Code, launch). This guide picks up once `claude` is connected and the dashboard is open.

!!! note "Tools you'll want"
    `httpx`, `nuclei`, `nikto`, a dir bruteforcer (`gobuster`/`feroxbuster`/`ffuf`), `sqlmap`, `wpscan`, `testssl.sh`, plus `curl`. Install the web group from [Prerequisites](../prerequisites.md), then confirm with the `check_tools` MCP tool.

---

## 1. Scope it

A web assessment is scoped by **URL patterns** (and optionally domains/CIDRs for the hosts behind them). Start from the `external-assessment` template — it sets `profile: web_app`, an "initial access" objective, and conservative OPSEC with full approval gates:

```bash
npm run setup -- --template external-assessment --name "Acme Web" --domain acme.com --cidr 203.0.113.0/24
```

Then fill in the scope with the subdomains and IPs you were given:

```jsonc
{
  "profile": "web_app",
  "scope": {
    "url_patterns": [
      "https://app.acme.com/**",       // ** = any depth; * = one path segment
      "https://api.acme.com/**",
      "https://*.acme.com/**"           // a subdomain wildcard, one label deep
    ],
    "domains": ["acme.com"],            // apex, for subdomain enumeration
    "cidrs": ["203.0.113.0/28"],        // the IPs you were given, if any
    "exclusions": ["https://app.acme.com/admin/**"]   // carve-outs
  }
}
```

!!! important "Scope is the egress boundary"
    Every target-facing tool call (`nuclei`, `sqlmap`, `curl`, …) is checked against this scope before it runs — an out-of-scope URL/host is **rejected before spawn**. `*` matches one path/host segment, `**` matches any depth. Get the patterns right and the guard does the rest. See [Configuration](../configuration.md) for the matching rules.

To update the running assessment conversationally, tell Claude: *"Add
app.acme.com, api.acme.com, and 203.0.113.0/28 to the current scope; add the
objective 'initial access'; use quiet OPSEC."* It uses the active
`update_scope`, `add_objective`, and `set_opsec` paths. Calling
`create_engagement` would instead create another inactive config without
switching the running daemon.

## 2. Seed the targets you were given

Get your subdomains and IPs into the graph so the frontier has something to work. Two ways:

- **Probe them** (recommended — enriches the graph): have Claude run `httpx` over the in-scope hosts and pipe the result through `parse_output`. httpx now emits the full `host → service(http/https) → webapp` chain, so each live web target lands as a real node the frontier and credential coverage can see.

    > **"Run httpx over the in-scope subdomains and ingest the results, then work the frontier."**

- **Declare them directly** (when you already have the list): `ingest_json` maps a JSON/CSV list of hosts or subdomains into nodes without a scan.

    > **"Ingest these subdomains as nodes: app.acme.com, api.acme.com, legacy.acme.com."**

!!! tip "Dangling CNAMEs surface for free"
    Resolving subdomains with `dnsx -a -cname` (keep A-record resolution on) captures each `CNAME` alongside its addresses; a subdomain whose CNAME points at a **claimable provider** (S3, GitHub Pages, Heroku, …) but resolves to **no address** is flagged `takeover_candidate` — the classic subdomain-takeover signal. The `rule-subdomain-takeover` inference rule then surfaces it as a `PATH_TO_OBJECTIVE` (so it shows up in frontier scoring + attack-path analysis). Run a `nuclei` takeover template against flagged names to confirm.

From here, `nuclei` tech-detection and a dir bruteforcer fill in `technology`, `framework`, `auth_type`, and discovered paths (`has_login_form` on the service).

## 3. Add your test credentials

Provided credentials are added the same way captured ones are — as `credential` nodes. Use `ingest_json` for a batch, or just describe them and let Claude call `report_finding`:

> **"Add a test credential: web login `dev@acme.com` / `Passw0rd!` valid on the app portal, and an API bearer token for api.acme.com."**

The credential node carries the fields that drive downstream logic:

| Field | Meaning |
|-------|---------|
| `cred_user` | username / principal (`dev@acme.com`) |
| `cred_value` | the secret (redacted in client reports) |
| `cred_type` / `cred_material_kind` | `plaintext` / `plaintext_password`, `token` / `oidc_access_token`, `session_cookie`, `pat`, … |
| `cred_evidence_kind` | set `manual` for operator-provided creds |
| `cred_audience` | for a bearer/API token — the API it's valid for |

`ingest_json` example (a small JSON list of test logins):

```jsonc
{"mappings": [{
  "node_type": "credential",
  "id_field": "user",
  "label_field": "user",
  "property_fields": [
    {"from": "user", "to": "cred_user"},
    {"from": "pass", "to": "cred_value"},
    {"from": "kind", "to": "cred_material_kind"}
  ]
}]}
```

## 4. Enumerate WITH the credentials

Once a credential and a web target are both in the graph, the **credential-coverage frontier** surfaces the pairing to test — `get_state` (or `next_task`) lists `credential_test` items like *"Test dev@acme.com against app.acme.com (https)"*. Http/https targets are first-class here, so your test logins get real frontier pressure, not just AD creds.

> **"What credential tests are on the frontier? Run the top ones."**

How each credential type is tested:

- **IdP / cloud SSO tokens** (Entra / Microsoft Graph, Okta, AWS STS, GitHub — captured or provided) → the `validate_token_credential` tool replays the token against that **provider's** API. Pass the `provider` (one of `microsoft_graph`, `aws_sts`, `okta`, `github`) and optionally override the `endpoint` within it; on success it updates the credential's status and stamps a `VALID_FOR_APP` edge (or `ASSUMES_ROLE` for AWS STS), feeding the OIDC federation-pivot inference. It does **not** handle arbitrary third-party APIs.

    > **"Validate the captured Entra access token with `validate_token_credential`."**

- **Generic web-app API tokens / session cookies** (a custom `api.acme.com` bearer, a `PHPSESSID`) → the `test_webapp_credential` tool with `method: bearer` (or `cookie`). It sends the scope-checked request, redacts the secret from the activity log, and on success stamps `AUTHENTICATED_AS` + `VALID_ON` — retiring the coverage item and firing authenticated re-scan. Give it a `success` criterion (e.g. `body_contains` a field only an authenticated response has) since a bare `200` is ambiguous for APIs. Set `header_name` for a custom API-key header or cookie name.

    > **"Test the `api.acme.com` bearer token against `https://api.acme.com/v1/me`, success = body contains my username."**

- **Web form logins (username/password)** → the same `test_webapp_credential` tool with `method: form`. Point it at the login endpoint (`login_path`) and give it a `success` criterion — a redirect target or a body string — so a 200-that-re-renders-the-login-page isn't mistaken for a win.

    > **"Test `dev@acme.com` against `https://app.acme.com`, form POST to `/login`, success is a redirect to `/dashboard`."**

- **Reused AD/service passwords** → the same plaintext credential is also tested against any in-scope non-web services (SMB/SSH/RDP) it pairs with — password-reuse falls out of the coverage matrix for free.

On a successful authenticated session, re-scan post-auth — the `web_app` profile prioritizes authenticated re-scan → auth bypass / IDOR → SQLi / RCE.

## 5. Discover and exploit

Drive the scanners and ingest everything through `parse_output`:

- `nuclei` / `nikto` → `vulnerability` nodes (CVE IDs, severity) + `VULNERABLE_TO` edges. A `nuclei` **takeover** result (`takeover` tag) becomes a `subdomain_takeover` vulnerability (classified CWE-16) and flags the affected `subdomain` node `takeover_candidate`.
- `sqlmap` on a confirmed injection → dumps **credential** nodes (feed them back to step 4 — spray loop)
- `wpscan` → WordPress users + plugin/theme CVEs
- `testssl.sh` → TLS/cert weaknesses
- `trufflehog` over the app's JS → **credential** nodes for hardcoded secrets (verified ones become spray-loop candidates); LinkFinder → `api_endpoint` nodes. trufflehog scans files/git, so pull the bundles down first (e.g. `wget`/`curl`), scan the directory, and pass the app URL as `source_host` so findings attach to the webapp.
- An **OpenAPI/Swagger** doc (`/openapi.json`, `/swagger.json`) or a **GraphQL introspection** dump → `api_endpoint` nodes (method, `auth_required`, `response_type`) via `parse_output` (`openapi` / `graphql`). This maps the API surface — unauthenticated endpoints and mutations to probe next.
- **Response headers** (`curl -sI <url>`, or an httpx `-json` line) → `parse_output` (`security-headers`) surfaces `cors_misconfig` (permissive `Access-Control-Allow-Origin`) and `missing_security_header` (HSTS/CSP/X-Frame-Options/…) as `vulnerability` nodes on the webapp. For raw `curl -I` text, pass the app URL as `source_host` (the header dump carries no URL).
- **Screenshots** (`gowitness scan …` / `aquatone`) → `parse_output` (`gowitness` / `aquatone`) enriches each webapp with its title, status, technology, and a `screenshot_path` reference — a fast visual triage of the web estate. To make the captures **viewable in the dashboard**, run the `ingest_screenshots` tool on the report dir (it stores the PNG bytes as evidence and stamps `screenshot_evidence_id` on the webapp).
- **Authenticated crawl** — log in with `test_webapp_credential` passing a `session_jar_id` (the response `Set-Cookie` is saved to `session-jars/<id>.jar`, a plaintext Netscape cookie file), then crawl the app **with that session** and ingest the result:
    > **"Log in to app.acme.com with `test_webapp_credential` (session_jar_id `acme`), then crawl it authenticated and ingest the endpoints."**

    The successful login's response prints the jar **path**. Carry the session into the crawler through `run_tool` (scope + OPSEC gated) — point a Netscape-jar-aware tool at that path (`wget --load-cookies '<jar-path>' --recursive --level=2 --spider --no-verbose https://app.acme.com`), or read the cookie out of the jar and pass it to katana (`katana -u https://app.acme.com -H "Cookie: <name>=<value>" -jsonl`). Then `parse_output` (`katana`) → an `api_endpoint` per discovered URL under the webapp (kept to the same registrable domain — sibling subdomains stay, off-site CDNs/trackers are dropped). This surfaces the **post-login** surface that unauthenticated dir-enum misses.

    > **"Fetch app.acme.com/openapi.json and ingest it as `openapi`; then run introspection on /graphql and ingest as `graphql`."**

    > **"Download app.acme.com's JS bundles, run `trufflehog filesystem` over them and ingest with source_host https://app.acme.com; then LinkFinder for endpoints."**

Inference rules chain these automatically (SQLi→RCE, login-form→spray-candidate, admin-panel default-creds, authenticated-rescan). Ask for a path when you want the picture:

> **"Show me a path from any tested credential to the 'initial access' objective."**

## 6. Report

> **"Generate a client-safe report for this engagement."**

`generate_report` renders findings + attack paths. In `client_safe` mode, credential values, tokens, and operator paths are redacted (a `sha256:` fingerprint is kept so repeated secrets can be cross-referenced without disclosure).

---

## Note: web auth tools {#note-web-form-auth}

Overwatch has two first-class credential-test tools for the web tier:

- [`validate_token_credential`](../tools/token-credential.md) — live replay for **IdP / cloud SSO tokens** (Entra/Microsoft Graph, AWS STS, Okta, GitHub). Knows each provider's API; stamps `VALID_FOR_APP` / `ASSUMES_ROLE`.
- [`test_webapp_credential`](../tools/test-webapp-credential.md) — **ordinary web auth** in one call: `form` (POST login), `basic`, `bearer` (incl. custom API-key headers), and `cookie` (session replay) against any in-scope web app. Stamps `AUTHENTICATED_AS` + `VALID_ON` on a confirmed success, retiring coverage and firing authenticated re-scan.

Between them, form logins, generic API tokens, and session cookies are all tested with a single scope-checked call — no hand-assembled `curl` step required. (Deeper post-auth work — authenticated crawl with a session jar, headless-Chromium screenshots — is still driven manually.)

## See also

- [Internal AD / Network Assessment](internal-ad-network.md) — for the AD/network side of a hybrid scope
- [parse_output vs report_finding](../playbook/parse-vs-report.md) — when to use which ingest path
- [End-to-End Walkthrough](../playbook/walkthrough.md) — a fully narrated engagement
- [Configuration](../configuration.md) — full scope + profile schema
