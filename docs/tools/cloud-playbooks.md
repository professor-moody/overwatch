# Cloud and Token Playbooks

Generate replay and enumeration plans for captured cloud, SaaS, and CI/CD credentials.

**Read-only:** No

These tools generally produce structured plans rather than running the whole chain themselves. Execute emitted commands through [`run_tool`](run-tool.md) or [`run_bash`](run-bash.md) so validation, approval, evidence, and parser ingestion stay intact.

## Tools

| Tool | Purpose |
|------|---------|
| `expand_aws_credential` | Build an AWS recon plan from an access key, STS session, or assumed-role credential. |
| `expand_github_credential` | Build a GitHub recon plan from a captured token. |
| `expand_entra_credential` | Build a Microsoft Graph / Entra ID recon plan. |
| `exchange_refresh_token` | Produce an approval-gated refresh-token exchange step; the operator supplies `REFRESH_TOKEN` at execution time. |
| `expand_oidc_capture` | Build validation/replay steps for captured CI/CD OIDC tokens and candidate cloud roles. |

## Usage Notes

- Playbook output includes technique labels, commands, parser hints, and expected graph shapes.
- `expand_entra_credential` emits single-page Graph requests; handle pagination during execution when a tenant has more results.
- `exchange_refresh_token` does not persist the raw refresh token.
