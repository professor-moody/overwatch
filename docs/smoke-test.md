# Smoke Test: Credential Playbooks + Reporting

End-to-end walkthrough of the credential playbooks (A.1–A.4) and reporting deliverable (B.1–B.4) shipped in the credential-driven E2E plan. Use this to dogfood the flow before running it on a real engagement.

The smoke seed pre-populates the graph with five captured credentials (AWS, GitHub PAT, CI/CD OIDC, Entra refresh + access tokens), the supporting federation graph, an objective targeting an AWS PowerUser role, and an ADMIN_TO edge so the attack-path analyzer has a starting point. Cross-tier inference fires during seed, so an inferred ASSUMES_ROLE edge is already in place — the playbooks confirm it through replay rather than discovering it from scratch.

**No real cloud APIs are called.** All commands return canned fixtures the operator pipes through `parse_output`.

---

## 0. Prerequisites

```bash
# In the overwatch checkout:
npm run build               # builds backend + dashboard
```

For the optional PDF check:
```bash
# Linux / Kali:
apt-get install chromium
# macOS: Chrome at /Applications/Google Chrome.app/Contents/MacOS/Google Chrome works.
```

---

## 1. Seed the engagement

```bash
rm -rf smoke-engagement     # idempotent — script will also wipe
npx tsx scripts/smoke-engagement.ts
```

You should see:
```
Smoke engagement seeded:
  Engagement dir: ./smoke-engagement/
  Config file:    smoke-engagement/config.json
  State file:     smoke-engagement/state.json
  Engagement id:  smoke-credential-playbooks
Seeded credentials:
  cred-aws-power    AWS poweruser temp creds (oidc_access_token shape)
  cred-gh-pat       GitHub PAT for svc-deploy
  cred-oidc-gha     Captured GHA OIDC token (audience: sts.amazonaws.com)
  cred-entra-rt     Entra refresh token for alice@acme.local
  cred-entra-at     Entra access token for alice@acme.local (post-MFA)
```

## 2. Start the MCP server pointed at the smoke engagement

```bash
OVERWATCH_CONFIG=smoke-engagement/config.json \
  OVERWATCH_STATE_FILE=smoke-engagement/state.json \
  node dist/index.js
```

The server starts on stdio (for MCP) and the dashboard on `http://localhost:8384`.

## 3. Open the dashboard

`http://localhost:8384`

**Confirm before going further:**
- **Sidebar shows the new Findings tab** (ShieldAlert icon, between Attack Paths and Settings).
- **AttackPaths tab** lists at least one path: `host-jumpbox → cred-oidc-gha → cloud-id-poweruser`.
- **Identity tab** shows the `acme-corp` (github_org) and `acme.onmicrosoft.com` (entra) IdPs with their applications.
- **Findings tab** is initially empty (no parsed findings yet) and shows the "Generate Report" button.

If any of these are missing, hard-refresh the page (Cmd-Shift-R / Ctrl-F5) — Vite serves hashed JS bundles and a stale index.html keeps loading old assets.

---

## 4. Walk the AWS playbook

In your MCP-connected Claude Code session (or via any MCP client):

```jsonc
{ "tool": "expand_aws_credential",
  "args": { "credential_id": "cred-aws-power", "use_ambient_credentials": true } }
```

The smoke walk does not execute the AWS command; `use_ambient_credentials: true` explicitly exercises the ambient-binding plan path. In a real engagement, set it only when the active AWS environment/default chain is known to represent this selected credential. Otherwise supply a bound `aws_profile`, or use an `aws_session_credentials` credential and populate the returned `run_bash.env.OVERWATCH_AWS_SESSION_CREDENTIALS` binding with its actual JSON value.

You should get back a durable `run_id` and a dependency-aware plan starting with a ready `aws sts get-caller-identity` step. The remaining descriptors are blocked, have `ready: false`, and intentionally use `command: null` until caller attribution exists. Run creation does not stamp or retire the credential.

Inspect the run with `get_playbook_run`, then claim only the ready caller-identity step with `start_playbook_step`. Preserve the returned `playbook_run_id`, `playbook_step_id`, `playbook_attempt_id`, `command_id`, and `idempotency_key` when sending its descriptor to `run_bash`. Preparing a step does not execute it; if you do not run it, call `interrupt_playbook_attempt` so another terminal or dashboard agent is not left blocked. Never execute a blocked/null descriptor; honor each ready descriptor's returned runner and environment binding.

Now drive step 1 with a canned response. Pipe the fixture below through `parse_output`:

**Fixture: `aws sts get-caller-identity` output**
```json
{
  "UserId": "AROAEXAMPLE:smoke-session",
  "Account": "111122223333",
  "Arn": "arn:aws:sts::111122223333:assumed-role/PowerUser/smoke-session"
}
```

Call:
```jsonc
{ "tool": "parse_output",
  "args": {
    "tool_name": "aws-sts-identity",
    "output": "<paste the JSON above>",
    "agent_id": "smoke-aws",
    "playbook_run_id": "<run_id from start_playbook_step>",
    "playbook_step_id": "<step_id from start_playbook_step>",
    "playbook_attempt_id": "<attempt_id from start_playbook_step>",
    "context": {
      "source_credential_id": "cred-aws-power",
      "cloud_provider": "aws",
      "credential_execution_binding": "ambient:explicit"
    }
  }}
```

**Expected:** a new `cloud_identity` for the assumed-role session lands in the graph; an `OWNS_CRED` edge connects it to `cred-aws-power`. Refresh the Identity tab — the new principal appears.

Call `expand_aws_credential` again with the same execution binding:

```jsonc
{ "tool": "expand_aws_credential",
  "args": { "credential_id": "cred-aws-power", "use_ambient_credentials": true } }
```

It now resolves the STS bindings, selects the role-policy branch, and returns executable account-summary, attached-policy, CloudFox, S3, and Lambda steps. Pass each returned `parser_context`, `parse_with`, and `parse_stream` through unchanged.

**Fixture: `aws iam get-account-summary`**
```json
{
  "SummaryMap": {
    "Users": 12, "Groups": 4, "Roles": 30, "Policies": 17,
    "AccountMFAEnabled": 1, "MFADevices": 8, "AccessKeysPerUserQuota": 2
  }
}
```

Pipe through `parse_output` with `tool_name: "aws-iam-summary"` and the `parser_context` returned for the account-summary step (it includes the account, caller ARN, and target cloud-identity id).

**Expected:** the confirmed caller `cloud_identity` carries `account_summary` + `account_summary_observed_at`.

(The remaining steps use dedicated `aws-iam-attached-policies`, `aws-s3-list-buckets`, and `aws-lambda-list-functions` parsers. The CloudFox step reads CloudFox's generated JSON files and emits a normalized JSON envelope; it does not parse CloudFox console text.)

---

## 5. Walk the GitHub playbook

```jsonc
{ "tool": "expand_github_credential", "args": { "credential_id": "cred-gh-pat", "include_orgs": true } }
```

Returns a 3-step plan (validate → /user/orgs → /user/repos). Pre-expand a single repo for full coverage:

```jsonc
{ "tool": "expand_github_credential",
  "args": {
    "credential_id": "cred-gh-pat",
    "candidate_repos": [
      { "repo_full_name": "acme-corp/webapp", "default_branch": "main" }
    ]
  } }
```

You'll get the 4 per-repo steps too (secrets, branch protection, deploy keys, OIDC trust customization). Each uses `runner: "run_bash"`; real execution must populate `run_bash.env.OVERWATCH_GITHUB_TOKEN` with the selected token value from the returned `env_from_credential` mapping.

The legacy string form (`"acme-corp/webapp"`) is still accepted. If the graph does not already know its default branch, it emits a ready repo-details descriptor and a blocked branch-protection descriptor with `command: null`; ingest repo details and re-expand before branch inspection.

**Fixture: `gh api /user/orgs --paginate --slurp`**
```json
[
  [
    { "login": "acme-corp", "id": 1001, "url": "https://api.github.com/orgs/acme-corp" }
  ]
]
```

`--slurp` produces one valid JSON array containing the paginated page arrays; the parser flattens them. `parse_output` with `tool_name: "gh-api-orgs"`, context `{ source_credential_id: "cred-gh-pat" }`.

**Fixture: `gh api /repos/acme-corp/webapp/branches/main/protection` (unprotected)**
```json
{ "message": "Branch not protected" }
```

`parse_output` with `tool_name: "gh-api-branch-protection"`, context `{ repo_full_name: "acme-corp/webapp", branch_name: "main" }`.

**Expected:** the `acme-corp/webapp` idp_application gets stamped with `branch_protection_gaps: [...]` and `finding_severity: "high"`. Visit Findings tab and refresh — a new high-severity finding should appear once `/api/findings` next polls (8s) or after you click around.

**Fixture: `gh api /repos/acme-corp/webapp/keys`**
```json
[
  { "id": 1, "key": "ssh-rsa AAAAFAKEKEY1...write", "title": "ci-deploy", "read_only": false, "created_at": "2025-08-01T00:00:00Z" }
]
```

`parse_output` with `tool_name: "gh-api-deploy-keys"`, context `{ repo_full_name: "acme-corp/webapp" }`.

**Expected:** new credential node `<...ci-deploy>` with `deploy_key_write_access: true` and `finding_severity: "high"`.

---

## 6. Walk the OIDC capture playbook

```jsonc
{ "tool": "expand_oidc_capture", "args": { "credential_id": "cred-oidc-gha" } }
```

The smoke seed already has the federation graph in place, so you should see:
```
candidates_considered: 1
step_count: 1
steps: [{ tool: "validate_token_credential", args: { ..., target_role_arn: "arn:aws:iam::111122223333:role/PowerUser" }, ... }]
```

If `candidates_considered: 0`, the seed didn't run — re-run step 1.

You don't have to actually run the replay (no real STS endpoint). The plan-output is what the playbook ships.

---

## 7. Walk the Entra playbook

```jsonc
{ "tool": "exchange_refresh_token",
  "args": { "credential_id": "cred-entra-rt", "client_id": "1950a258-227b-4e31-a9cf-717495945fc2" } }
```

Returns a single `run_bash` curl POST step against `https://login.microsoftonline.com/acme.onmicrosoft.com/oauth2/v2.0/token`. The refresh-token value is referenced via `$OVERWATCH_ENTRA_REFRESH_TOKEN`; check `payload.command` does not contain the literal value. At real execution, resolve `env_from_credential` and place the selected refresh-token value in `run_bash.env.OVERWATCH_ENTRA_REFRESH_TOKEN`.

```jsonc
{ "tool": "expand_entra_credential",
  "args": { "credential_id": "cred-entra-at", "include_groups": true } }
```

Returns a 5-step plan (`/me`, `/users`, `/applications`, `/servicePrincipals`, `/groups`). The seeded credential already has a concrete tenant, so all five commands are ready; real execution binds its selected access-token value through `run_bash.env.OVERWATCH_ENTRA_TOKEN`. If a credential has no concrete tenant, only `/me` is ready—ingest it and re-expand before executing the other null-command descriptors.

**Fixture: `/v1.0/users?$top=999`**
```json
{
  "value": [
    { "id": "u-1", "userPrincipalName": "alice@acme.local", "displayName": "Alice", "mail": "alice@acme.local", "accountEnabled": true },
    { "id": "u-2", "userPrincipalName": "bob@acme.local", "displayName": "Bob", "accountEnabled": true }
  ]
}
```

`parse_output` with `tool_name: "msgraph-users"`, context `{ tenant_id: "acme.onmicrosoft.com" }`.

**Fixture: `/v1.0/servicePrincipals` (scopes and app-role metadata)**
```json
{
  "value": [
    {
      "id": "sp-priv", "appId": "app-priv", "displayName": "Risky-Consent-App",
      "servicePrincipalType": "Application",
      "oauth2PermissionScopes": [
        { "id": "s1", "value": "Mail.ReadWrite", "type": "User" },
        { "id": "s2", "value": "Files.ReadWrite.All", "type": "Admin" }
      ],
      "appOwnerOrganizationId": "external-tenant"
    }
  ]
}
```

`parse_output` with `tool_name: "msgraph-serviceprincipals"`, context `{ tenant_id: "acme.onmicrosoft.com" }`.

**Expected:** the service-principal node lands with `app_kind: "entra_service_principal"` and `exposed_oauth_scopes: ["Mail.ReadWrite", "Files.ReadWrite.All"]`. This parser records the API metadata without asserting an inferred finding. If a response contains `@odata.nextLink`, fetch and ingest each subsequent page before treating the tenant inventory as complete.

---

## 8. Generate the report

In the dashboard, click **Findings → Generate Report**. The modal lets you pick:

- **Format:** start with `markdown` (fast smoke). Try `pdf` if you have chromium installed.
- **Theme:** `light` for HTML/PDF.
- **Client-safe redaction:** off for the operator pass; on for the second pass.
- **Include Attack Paths:** on (default).
- **Include compliance mapping:** on.
- **Include retrospective:** off (not relevant for smoke).

Click **Render & Save**. After ~1 sec, the modal closes and the **Reports archive** section under the findings list shows the new entry. Click **Download** to verify the file.

**What to look for in the markdown:**
1. `## Findings Summary` — counts reflect everything you ingested.
2. `## Attack Paths` — should contain a numbered chain:
   ```
   1. jumpbox.acme.local `(host)`
      → `OWNS_CRED` (confirmed, conf 1.00)
   2. gha-oidc-token-prod-deploy `(credential)`
      → `ASSUMES_ROLE` (inferred by `oidc_federation_pivot`, conf 0.75)
   3. arn:aws:iam::111122223333:role/PowerUser `(cloud_identity)`
   ```
3. `## Credential Chains` (if step 4 added a temp cred via parse).
4. `## Recommendations` — touches the high-severity findings the GitHub deploy-key + branch-protection parsers stamped.

**For PDF:** download the `.pdf`, open it. Should be a styled multi-page render. If you get an error like `No Chromium / Chrome binary found`, install one (see prerequisites) or fall back to HTML.

---

## 9. Sanity checks (what should be true at the end)

Run via direct curl (no MCP needed):

```bash
# Findings populated
curl -s http://localhost:8384/api/findings | jq '.severity_summary, .total'

# Reports archive shows your render
curl -s http://localhost:8384/api/reports | jq '.total, .reports[0]'

# Engagement state has all 5 credentials
curl -s http://localhost:8384/api/state | jq '.state.graph_summary.nodes_by_type.credential'

# Attack paths panel has the OIDC pivot chain
curl -s http://localhost:8384/api/paths/obj-aws-admin | jq '.count, .paths[].nodes'
```

Expected:
- `severity_summary` shows `high >= 2` (deploy-key + branch-protection) once the GitHub steps ran.
- `reports.total >= 1`.
- `nodes_by_type.credential` is at least 5 (more if you ran the deploy-keys + secrets fixtures).
- `paths` returns at least one chain.

---

## 10. What to flag back if anything looks rough

- Plan steps that reference parsers / context fields that don't exist
- Approval prompts for steps that should auto-approve (or vice versa)
- Findings that the classifier mis-categorizes
- Attack-path chains rendered with wrong direction or missing edges
- PDF formatting issues (missing sections, broken page breaks, Unicode)
- Anything you expected to be in the report but isn't

Once the smoke passes cleanly here, the same flow works against a real engagement — just swap the fixture JSON for actual `aws ...` / `gh api ...` / `curl ... graph.microsoft.com` outputs.
