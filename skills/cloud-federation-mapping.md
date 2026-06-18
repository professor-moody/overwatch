# Cloud & Identity Federation Mapping

tags: cloud, federation, oidc, saml, assume-role, aws, entra, github, cross-account, identity, expand, pivots

## Objective
Map how captured cloud/identity credentials federate into access: which roles they
can assume, which resources that unlocks, and where cloud bridges to on-prem (or one
account bridges to another). Expand credentials with the `expand_*` playbooks, run
the resulting recon through the approval gate, and land everything as graph nodes/edges
— never leave reach only in prose.

## Tools
- `expand_aws_credential` / `expand_entra_credential` / `expand_github_credential` /
  `expand_oidc_capture` — numbered recon playbooks per credential kind.
- `validate_token_credential` / `exchange_refresh_token` — confirm + refresh tokens.
- `validate_action` → `run_tool`/`run_bash` → `parse_output`/`report_finding` — execute
  the playbook steps through the gate and record results.

## Federation patterns to map
- **Direct role assumption** (`ASSUMES_ROLE`) — an identity/role whose trust policy
  lets it assume another role (often cross-account). Walk the trust chain to the
  highest-privilege role reachable.
- **OIDC trust** — a CI/workload identity (GitHub Actions, GitLab, EKS IRSA) federated
  into a cloud role via an OIDC provider. `expand_oidc_capture` emits a
  `validate_token_credential` step per candidate role; a successful replay mints temp
  cloud creds — chain into `expand_aws_credential` on the resulting session.
- **SAML / IdP federation** (`FEDERATES_WITH`) — an IdP (Okta/Entra) federated to a
  cloud account or domain; a captured IdP session/cookie may be `VALID_FOR_APP`.
- **Cloud → on-prem bridges** — a cloud secret/SSM param holding a domain credential,
  a managed instance with a domain join, a backup role reaching on-prem data.

## Methodology

### 1. Expand the captured credential
Run the right `expand_*` playbook for the credential kind (AWS key/STS → aws;
GH PAT/OIDC → github/oidc; Entra refresh/access → entra). Each step goes through
`validate_action` + the approval gate.

### 2. Walk the trust edges
After identity inventory lands, follow `ASSUMES_ROLE` / `ISSUES_TOKENS_FOR` /
`HAS_POLICY` edges. For each assumable role, record what its policies allow
(`POLICY_ALLOWS` → resources) as findings.

### 3. Chain federation hops
A CI OIDC token → DeployRole → (assumes) AdminRole is a 3-hop chain; record each hop
as an edge so the path is in the graph, not just your head. Replay validated tokens
to mint the next session, then expand THAT.

### 4. Surface the bridges
Flag any cloud→on-prem or cross-account reach as a finding with severity reflecting
the blast radius (a backup role reading payroll = high).

## Escalation / done
- **Ask the operator** before assuming a production role or exchanging a refresh
  token if it would create loud CloudTrail/sign-in events near the noise ceiling.
- **Done** when each cloud credential's reachable resources, assumable roles, and
  federation edges are recorded as graph findings (or it's recorded as no-further-reach).

## Anti-patterns
- Re-deriving the recon chain by hand instead of using the `expand_*` playbooks.
- Recording reach in prose without the `ASSUMES_ROLE`/`POLICY_ALLOWS` edges.
- Replaying tokens loudly when the OPSEC budget is nearly spent.
