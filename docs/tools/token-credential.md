# validate_token_credential

Replay a captured token credential against a provider API.

**Read-only:** No

## Description

Validates whether a token-shaped credential still works by replaying it against a provider-specific API or CLI path. Supported providers include Microsoft Graph, AWS STS, Okta, and GitHub.

Sensitive token values are not logged directly. Evidence and reports redact token material.

## Usage Notes

- Use this for `credential_test` frontier items or when a captured token needs live reachability confirmation.
- Successful validation can emit edges such as application validity or cloud role assumption, depending on provider and response.
- Prefer the cloud playbook tools for multi-step follow-on enumeration.
