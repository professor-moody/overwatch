# Cloud and Token Playbooks

Generate replay and enumeration plans for captured cloud, SaaS, and CI/CD credentials.

**Read-only:** Plan execution is not read-only. Expanding creates or resumes durable run state; the returned target-facing step still uses the normal validation, approval, evidence, and parsing path.

The playbook tools create or resume a matching durable run. Calling an expansion tool still does not execute a target-facing step or stamp the credential as expanded. A run retains its immutable plan revisions, dependency state, attempts, action/evidence/finding references, and truthful restart outcome.

## Tools

| Tool | Purpose |
|------|---------|
| `expand_aws_credential` | Build a dependency-aware AWS plan from an access key, STS session, or assumed-role credential. |
| `expand_github_credential` | Build a paginated GitHub plan from a captured token, optionally including repository-specific checks. |
| `expand_entra_credential` | Build a tenant-bound Microsoft Graph / Entra ID plan. |
| `exchange_refresh_token` | Build an approval-gated Entra refresh-token exchange step. |
| `expand_oidc_capture` | Build direct `validate_token_credential` calls for captured CI/CD OIDC tokens and candidate cloud roles. |

## Executing a returned plan

- A repeated expansion with the same credential and normalized inputs resumes the matching logical run. If newly discovered bindings materialize changed work, a previously terminal run reopens with a new immutable plan revision; an unchanged terminal run remains terminal. Pass `new_run: true` only when a separate run is intentional.
- Claim exactly one ready step with `start_playbook_step`. Use `retry_playbook_step` after a failed or interrupted attempt; retries append and never overwrite earlier evidence.
- Preserve `playbook_run_id`, `playbook_step_id`, and `playbook_attempt_id` through the indicated runner. `run_bash`, `run_tool`, and token replay finalize linked attempts automatically; `complete_playbook_attempt` is the explicit fallback after an instrumented execution crossed its durable boundary.
- Treat `status: "blocked"`, `ready: false`, or `command: null` as non-executable. Run the prerequisite, ingest its output, and call the generator again so it can resolve the missing binding.
- Honor the returned execution surface. A command descriptor names `runner: "run_bash"` or `runner: "run_tool"`; a direct-tool descriptor names `tool` and `args`. Do not assume every playbook step is a `run_tool` call.
- `env_from_credential` maps an environment-variable name to a credential node ID. Resolve that node and put its actual selected credential value in `run_bash.env`; the credential ID itself is not the environment-variable value. Commands fail closed before network access when a required binding is absent.
- Forward `parse_with`, `parser_context`, and `parse_stream` exactly as returned. These fields carry attribution such as the source credential, tenant, repository, account, caller ARN, and target identity.
- Restart converts an in-flight attempt to `interrupted`; use `resume_playbook_run`, then retry the selected step. Open runs and prior attempts remain visible through MCP, HTTP, the terminal CLI, WebSocket state, and the Credentials dashboard.

## AWS

`expand_aws_credential` requires an explicit execution binding before it emits an executable caller-identity command. Use one of:

- `aws_profile` for a profile known to represent the selected credential;
- `session_credentials_env_var` (default `OVERWATCH_AWS_SESSION_CREDENTIALS`) for an `aws_session_credentials` JSON credential, resolved into `run_bash.env`; or
- `use_ambient_credentials: true` only when the current AWS environment/default chain is known to contain the selected AWS-marked credential.

Without one of those bindings, caller identity and every dependent descriptor are blocked with null commands. With a binding, run and ingest `aws sts get-caller-identity` first, then call `expand_aws_credential` again with the same binding options. The second plan binds `account_id`, `caller_arn`, `principal_kind`, and the target identity server-side; selects user-policy versus role-policy enumeration; and makes the applicable IAM summary, attached-policy, CloudFox, S3, and Lambda steps ready. Unsupported or ambiguous principal bindings remain blocked instead of being guessed.

AWS steps use `runner: "run_bash"` because their commands include fail-closed guards and, where needed, shell setup. CloudFox is parsed from its generated JSON files, not its console output. The resource steps use the dedicated `aws-iam-attached-policies`, `aws-s3-list-buckets`, and `aws-lambda-list-functions` parsers.

## GitHub

GitHub steps bind the selected token through `run_bash.env.OVERWATCH_GITHUB_TOKEN` by default; override the name with `token_env_var`. Organization, repository, Actions-secret, and deploy-key list commands use `gh api --paginate --slurp`, so their parsers receive complete JSON arrays rather than concatenated page objects.

`candidate_repos` accepts either legacy `"owner/repo"` strings or records shaped like:

```json
{ "repo_full_name": "owner/repo", "default_branch": "main" }
```

The record form makes branch-protection inspection ready immediately. For a legacy string with no `default_branch` already in the graph, the plan emits a ready repository-details step and a blocked branch-protection step with `command: null`. Ingest repository details, then re-expand the credential to resolve the default branch.

## Entra ID

`exchange_refresh_token` uses `run_bash.env.OVERWATCH_ENTRA_REFRESH_TOKEN` by default (override with `refresh_token_env_var`). `expand_entra_credential` uses `run_bash.env.OVERWATCH_ENTRA_TOKEN` by default (override with `token_env_var`). In both cases, resolve `env_from_credential` to the actual selected token and keep the returned parser context unchanged.

When no concrete tenant is available, only `/me` is ready. The `/users`, `/applications`, `/servicePrincipals`, and `/groups` descriptors are blocked with null commands until `/me` is ingested and the credential is re-expanded. Each collection descriptor requests one page with `$top=999`; follow and ingest every `@odata.nextLink` for complete coverage. The service-principal parser records exposed scopes, app roles, and ownership metadata without asserting an inferred finding.

## CI/CD OIDC

`expand_oidc_capture` emits direct `validate_token_credential` invocations (`tool` plus `args`), not shell commands. A successful AWS STS replay creates temporary AWS session credentials; pass that resulting credential to `expand_aws_credential` and provide its returned execution binding before enumeration.
