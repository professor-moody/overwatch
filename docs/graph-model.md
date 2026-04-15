# Graph Model

Overwatch models engagements as directed property graphs using [graphology](https://graphology.github.io/). Every discovery — a host, a credential, an access relationship — is a node or edge in the graph.

## Node Types

| Type | Description | Key Properties |
|------|-------------|----------------|
| `host` | A target machine | `ip`, `hostname`, `os`, `alive`, `domain_joined` |
| `service` | A network service on a host | `port`, `protocol`, `service_name`, `version`, `banner` |
| `domain` | An Active Directory domain | `domain_name`, `functional_level`, `password_policy`, `lockout_policy` |
| `user` | A domain or local user | `username`, `sid`, `enabled`, `privileged`, `pwd_last_set` |
| `group` | A security group | `sid`, `member_of` |
| `credential` | Authentication material | `cred_type`, `cred_value`, `cred_domain`, `cred_user`, `credential_status` |
| `share` | A network share | `share_name`, `share_path`, `readable`, `writable` |
| `certificate` | An X.509 certificate | `template_name`, `eku` |
| `ca` | A Certificate Authority | `ca_name`, `ca_kind` (`enterprise_ca`, `root_ca`, `aia_ca`) |
| `cert_template` | An AD CS certificate template | `template_name`, `ca_name`, `eku`, `enrollee_supplies_subject` |
| `pki_store` | A PKI store | `pki_store_kind` (`ntauth_store`, `issuance_policy`) |
| `gpo` | A Group Policy Object | `label` |
| `ou` | An Organizational Unit | `label` |
| `subnet` | A network subnet | `subnet_cidr` |
| `objective` | An engagement objective | `objective_description`, `objective_achieved` |
| `webapp` | A web application | `url`, `technology`, `framework`, `auth_type` |
| `vulnerability` | A discovered vulnerability | `cve`, `cvss`, `vuln_type`, `exploitable` |
| `cloud_identity` | Cloud IAM principal (user, role, service account) | `provider`, `arn`, `principal_type`, `mfa_enabled` |
| `cloud_resource` | Cloud resource (S3 bucket, EC2, Lambda, etc.) | `resource_type`, `region`, `public`, `encrypted` |
| `cloud_policy` | Cloud IAM policy or RBAC role assignment | `policy_name`, `effect`, `actions`, `resources` |
| `cloud_network` | Cloud network construct (VPC, security group) | `network_type`, `ingress_rules`, `egress_rules` |
| `api_endpoint` | A web API endpoint | `path`, `method`, `auth_required`, `response_type` |

### Common Node Properties

Every node has these base properties:

| Property | Type | Description |
|----------|------|-------------|
| `id` | `string` | Unique node identifier |
| `type` | `NodeType` | One of the types above |
| `label` | `string` | Human-readable display label |
| `confidence` | `number` | 0.0 (hypothesis) to 1.0 (confirmed) |
| `discovered_by` | `string` | Agent ID that found this node |
| `discovered_at` | `string` | ISO timestamp of discovery |
| `first_seen_at` | `string` | First direct observation time |
| `last_seen_at` | `string` | Most recent direct observation time |
| `sources` | `string[]` | Unique agents that contributed to this node |

### Credential Types

| `cred_type` | Description |
|-------------|-------------|
| `plaintext` | Cleartext password |
| `cleartext` | Cleartext password (alias for `plaintext`) |
| `ntlm` | NTLM hash |
| `ntlmv2_challenge` | Captured NTLMv2 challenge-response |
| `aes256` | AES-256 Kerberos key |
| `kerberos_tgt` | Kerberos TGT |
| `kerberos_tgs` | Kerberos TGS (Kerberoast) |
| `certificate` | X.509 certificate |
| `token` | Authentication token |
| `ssh_key` | SSH private key |

### Credential Lifecycle Properties

| Property | Type | Description |
|----------|------|-------------|
| `credential_status` | `string` | `active`, `stale`, `expired`, or `rotated` |
| `valid_until` | `string` | ISO timestamp — expiry for time-limited creds (TGT/TGS, tokens, certs) |
| `rotated_at` | `string` | ISO timestamp — when credential was observed as changed |
| `stale_at` | `string` | ISO timestamp — when credential became stale |
| `cred_domain_inferred` | `boolean` | Whether `cred_domain` was set by graph inference |
| `cred_domain_source` | `string` | `explicit`, `graph_inference`, or `parser_context` |
| `dump_source_host` | `string` | Host from which the credential was dumped |

Stale or expired credentials have their outbound `POTENTIAL_AUTH` edges degraded (confidence × 0.5, clamped at 0.1). Frontier items sourced from stale/expired credentials are deprioritized (confidence × 0.1).

### Identity Properties

| Property | Type | Description |
|----------|------|-------------|
| `identity_status` | `string` | `canonical`, `unresolved`, or `superseded` |
| `identity_family` | `string` | Family grouping for related identities |
| `canonical_id` | `string` | ID of the canonical node (if superseded) |
| `identity_markers` | `string[]` | Matching markers (hostname variants, SIDs, credential fingerprints) |
| `superseded_by` | `string` | Node ID that superseded this one |

Identity resolution runs automatically on ingest. Alias nodes sharing identity markers are merged into canonicals — edges are retargeted and properties merged.

### Host Enrichment Properties (Linux)

| Property | Type | Description |
|----------|------|-------------|
| `suid_checked` | `boolean` | Whether SUID binaries have been enumerated |
| `has_suid_root` | `boolean` | Dangerous SUID root binaries found |
| `suid_binaries` | `string[]` | List of SUID root binary paths |
| `cron_checked` | `boolean` | Whether cron jobs have been enumerated |
| `cron_jobs` | `string[]` | Discovered cron job entries |
| `capabilities_checked` | `boolean` | Whether capabilities have been checked |
| `interesting_capabilities` | `string[]` | Capabilities of interest |
| `docker_socket_accessible` | `boolean` | Docker socket is accessible |
| `kernel_version` | `string` | Kernel version string |

### Web Application Properties

| Property | Type | Description |
|----------|------|-------------|
| `url` | `string` | Application URL |
| `technology` | `string` | Detected technology stack |
| `framework` | `string` | Web framework (e.g., Django, Rails) |
| `auth_type` | `string` | Authentication type (form, basic, oauth) |
| `has_api` | `boolean` | Exposes an API |
| `cms_type` | `string` | CMS type (WordPress, Drupal, etc.) |

### Vulnerability Properties

| Property | Type | Description |
|----------|------|-------------|
| `cve` | `string` | CVE identifier |
| `cvss` | `number` | CVSS score (0.0–10.0) |
| `vuln_type` | `string` | Vulnerability class (e.g., `sqli`, `xss`, `ssrf`, `rce`) |
| `exploitable` | `boolean` | Whether the vulnerability is exploitable |
| `exploit_available` | `boolean` | Public exploit exists |
| `affected_component` | `string` | Affected software component |

### Cloud Identity Properties

| Property | Type | Description |
|----------|------|-------------|
| `provider` | `string` | `aws`, `azure`, or `gcp` |
| `arn` | `string` | Amazon Resource Name (AWS) or equivalent identifier |
| `principal_type` | `string` | `user`, `role`, `service_account`, `managed_identity`, `app` |
| `policies` | `string[]` | Attached policy names |
| `mfa_enabled` | `boolean` | Multi-factor authentication status |
| `last_used` | `string` | ISO timestamp of last use |
| `cloud_account` | `string` | Account/subscription/project ID |
| `policies_enumerated` | `boolean` | Whether policies have been fully enumerated |

### Cloud Resource Properties

| Property | Type | Description |
|----------|------|-------------|
| `resource_type` | `string` | e.g., `s3_bucket`, `ec2_instance`, `lambda_function`, `azure_vm` |
| `region` | `string` | Cloud region |
| `public` | `boolean` | Publicly accessible |
| `encrypted` | `boolean` | Encryption at rest enabled |
| `tags` | `object` | Cloud resource tags |
| `imdsv2_required` | `boolean` | IMDSv2 enforcement (EC2) |

### Cloud Policy Properties

| Property | Type | Description |
|----------|------|-------------|
| `policy_name` | `string` | Policy display name |
| `effect` | `string` | `allow` or `deny` |
| `actions` | `string[]` | Allowed/denied API actions (e.g., `s3:*`, `iam:PassRole`) |
| `resources` | `string[]` | Resource ARN patterns |
| `conditions` | `string[]` | Policy conditions |

### Cloud Network Properties

| Property | Type | Description |
|----------|------|-------------|
| `network_type` | `string` | `vpc`, `security_group`, `subnet`, `firewall_rule` |
| `ingress_rules` | `string[]` | Inbound access rules |
| `egress_rules` | `string[]` | Outbound access rules |

### API Endpoint Properties

| Property | Type | Description |
|----------|------|-------------|
| `path` | `string` | URL path (e.g., `/api/users`) |
| `method` | `string` | HTTP method (`GET`, `POST`, etc.) |
| `auth_required` | `boolean` | Whether the endpoint requires authentication |
| `response_type` | `string` | Response content type (e.g., `json`, `html`) |

### Domain Policy Properties

| Property | Type | Description |
|----------|------|-------------|
| `password_policy` | `object` | Domain password policy: `minLength`, `maxAge` (ISO 8601 duration), `complexity`, `history` |
| `lockout_policy` | `object` | Account lockout policy: `threshold`, `duration` (ISO 8601), `observation_window` (ISO 8601) |

### User Temporal Properties

| Property | Type | Description |
|----------|------|-------------|
| `pwd_last_set` | `string` | ISO timestamp — when the user's password was last changed. Used with domain `password_policy.maxAge` to estimate credential expiry |

## Edge Types

### Network

| Edge | Description |
|------|-------------|
| `REACHABLE` | Network reachability between hosts |
| `RUNS` | Host runs a service |

### Domain Membership

| Edge | Description |
|------|-------------|
| `MEMBER_OF` | User, group, or cloud identity is member of a group |
| `MEMBER_OF_DOMAIN` | Object belongs to a domain |
| `TRUSTS` | Domain trust relationship |
| `SAME_DOMAIN` | Objects share a domain |

### Access

| Edge | Description |
|------|-------------|
| `ADMIN_TO` | Administrative access to a host |
| `HAS_SESSION` | Session on a host. `session_live=true` means an active runtime session exists; `session_live=false` means historical proof of access (session closed or server restarted). Only live sessions contribute to `access_summary.compromised_hosts`. |
| `CAN_RDPINTO` | RDP access to a host |
| `CAN_PSREMOTE` | PSRemoting/WinRM access |

### Credentials

| Edge | Description |
|------|-------------|
| `VALID_ON` | Credential is valid on a host or service |
| `OWNS_CRED` | User owns a credential |
| `POTENTIAL_AUTH` | Credential might authenticate (hypothesis) |
| `DERIVED_FROM` | Credential derived from another (e.g., cracked from hash) |
| `DUMPED_FROM` | Credential dumped from a host |

### AD Attack Paths

| Edge | Description |
|------|-------------|
| `CAN_DCSYNC` | DCSync rights |
| `DELEGATES_TO` | Delegation relationship |
| `CAN_DELEGATE_TO` | Constrained delegation to a target service |
| `WRITEABLE_BY` | Object is writable by another |
| `GENERIC_ALL` | GenericAll permission |
| `GENERIC_WRITE` | GenericWrite permission |
| `WRITE_OWNER` | WriteOwner permission |
| `WRITE_DACL` | WriteDACL permission |
| `ADD_MEMBER` | Can add members to a group |
| `FORCE_CHANGE_PASSWORD` | Can force password change |
| `ALLOWED_TO_ACT` | Resource-based constrained delegation |
| `CAN_READ_LAPS` | LAPS password readable via ACL |
| `CAN_READ_GMSA` | gMSA password readable via ACL |
| `RBCD_TARGET` | Resource-based constrained delegation target |

### Roasting

| Edge | Description |
|------|-------------|
| `AS_REP_ROASTABLE` | User is AS-REP roastable (pre-auth disabled) |
| `KERBEROASTABLE` | User is Kerberoastable (has SPN) |

### ADCS

| Edge | Description |
|------|-------------|
| `CAN_ENROLL` | Can enroll in a certificate template |
| `ESC1` – `ESC4` | ADCS escalation paths 1–4 |
| `ESC5` | ADCS escalation path 5 (vulnerable CA ACL) |
| `ESC6` | ADCS escalation path 6 |
| `ESC7` | ADCS escalation path 7 (CA agent approval bypass) |
| `ESC8` | ADCS escalation path 8 (web enrollment relay) |
| `ESC9` | ADCS escalation path 9 (no security extension) |
| `ESC10` | ADCS escalation path 10 (weak certificate mapping) |
| `ESC11` | ADCS escalation path 11 (certificate relay to AD CS) |
| `ESC12` | ADCS escalation path 12 (shell access to CA with YubiHSM) |
| `ESC13` | ADCS escalation path 13 (issuance policy OID abuse) |

### Lateral Movement

| Edge | Description |
|------|-------------|
| `RELAY_TARGET` | NTLM relay target |
| `NULL_SESSION` | Null session access |
| `TESTED_CRED` | Credential tested against a service (with result) |
| `SHARED_CREDENTIAL` | Credential shared across multiple users/services |

### Web Application Surface

| Edge | Description |
|------|-------------|
| `HOSTS` | Service hosts a web application |
| `HAS_ENDPOINT` | Web application exposes an API endpoint |
| `AUTHENTICATED_AS` | Web application authenticated as a user/identity |
| `VULNERABLE_TO` | Web application, service, or cloud resource is vulnerable to a vulnerability |
| `AUTH_BYPASS` | Vulnerability enables authentication bypass on a web application or API endpoint |
| `EXPLOITS` | Vulnerability exploits a host, credential, or web application |

### Cloud Infrastructure

| Edge | Description |
|------|-------------|
| `ASSUMES_ROLE` | Cloud identity can assume a role (cross-account or same-account) |
| `HAS_POLICY` | Cloud identity has an attached policy |
| `POLICY_ALLOWS` | Cloud policy allows actions on a resource |
| `EXPOSED_TO` | Cloud resource is exposed to a network/internet |
| `RUNS_ON` | Cloud resource runs on infrastructure (e.g., Lambda on VPC) |
| `MANAGED_BY` | Cloud resource is managed by an identity (managed identity, service account) |

### Objective

| Edge | Description |
|------|-------------|
| `PATH_TO_OBJECTIVE` | Computed path toward an engagement objective |

### Generic

| Edge | Description |
|------|-------------|
| `RELATED` | Uncategorized relationship (unconstrained). Generic relationship (no endpoint type constraints) |

### Edge Properties

Every edge has these base properties:

| Property | Type | Description |
|----------|------|-------------|
| `type` | `EdgeType` | One of the types above |
| `confidence` | `number` | 0.0 (hypothesis) to 1.0 (confirmed) |
| `discovered_by` | `string` | Agent ID |
| `discovered_at` | `string` | ISO timestamp |
| `tested` | `boolean` | Whether this edge has been tested |
| `test_result` | `string` | `success`, `failure`, `partial`, `error` |
| `opsec_noise` | `number` | 0.0 (silent) to 1.0 (loud) |
| `inferred_by_rule` | `string` | Rule ID if this edge was inferred |
| `confirmed_at` | `string` | Timestamp when confidence raised to 1.0 |

## Inference Rules

Fifty-five built-in declarative rules fire automatically when matching nodes are ingested. Many rules use **edge-triggered inference** — they require a matching inbound edge (`requires_edge` field) in addition to the node property match. When a new or updated edge arrives, inference re-evaluates its endpoints.

#### AD & Service Rules (21)

| Rule | Trigger | Produces |
|------|---------|----------|
| Kerberos → Domain | Service with `service_name: kerberos` | `MEMBER_OF_DOMAIN` to matching domain (hostname suffix) |
| Host Runs Service | Service node linked to a host | `RUNS` edge from host to service |
| SMB Signing → Relay | Service with `smb_signing: false` | `RELAY_TARGET` from compromised hosts |
| MSSQL + Domain | MSSQL service on domain host | `POTENTIAL_AUTH` from domain credentials |
| Credential Fanout | New credential node | `POTENTIAL_AUTH` to compatible services in same domain |
| Login Spray Candidate | Service with auth (SMB, RDP, WinRM, SSH, HTTP) | `POTENTIAL_AUTH` from credentials with matching username |
| Unconstrained Delegation | Host with `unconstrained_delegation: true` | `DELEGATES_TO` from domain admins and session holders (confidence 0.7) |
| AS-REP Roastable | User with `asrep_roastable: true` | `AS_REP_ROASTABLE` to user's own domain (confidence 0.85) |
| Kerberoastable | User with `has_spn: true` | `KERBEROASTABLE` to user's own domain (confidence 0.85) |
| Constrained Delegation | Host with `constrained_delegation: true` | `CAN_DELEGATE_TO` to delegation targets from `allowed_to_delegate_to` SPN list (confidence 0.8) |
| LAPS Readable | Host with `laps: true` + inbound `GENERIC_ALL` | `CAN_READ_LAPS` from edge peers |
| gMSA Readable | User with `gmsa: true` + inbound `GENERIC_ALL` | `CAN_READ_GMSA` from edge peers |
| RBCD Target | Host with `maq_gt_zero: true` + inbound `WRITEABLE_BY` | `RBCD_TARGET` from edge peers |
| WriteDACL Escalation | User with inbound `WRITE_DACL` | `ESCALATION_PATH` from edge peers (confidence 0.8) |
| WriteOwner Escalation | User with inbound `WRITE_OWNER` | `ESCALATION_PATH` from edge peers (confidence 0.8) |
| ForceChangePassword | User with inbound `FORCE_CHANGE_PASSWORD` | `ESCALATION_PATH` from edge peers (confidence 0.85) |
| Shadow Credentials | User/host with inbound `WRITE_MSDS_ALLOWEDTOACTONBEHALFOFOTHERIDENTITY` | `ESCALATION_PATH` from edge peers (confidence 0.8) |
| GPO Abuse | GPO with inbound `WRITE_PROPERTY` | `ESCALATION_PATH` from edge peers to linked hosts (confidence 0.75) |
| DCSync | User with inbound `CAN_DCSYNC` edge | `CAN_DCSYNC` to user's own domain (confidence 0.9) |
| Session → Admin Persistence | Host with `HAS_SESSION` + `ADMIN_TO` | `ADMIN_TO` persistence reinforcement |
| Shared Credential | Credential used by multiple users | `SHARED_CREDENTIAL` edges between users |
| User Owns Credential | User with associated credential | `OWNS_CRED` edge from user to credential |

#### ADCS Rules (14)

| Rule | Trigger | Produces |
|------|---------|----------|
| ADCS ESC1 | cert_template with enrollee-supplied subject + client auth EKU | `ESC1` from enrollable users (confidence 0.75) |
| ADCS ESC2 | cert_template with Any Purpose or no EKU restriction | `ESC2` from enrollable users (confidence 0.7) |
| ADCS ESC3 | cert_template with enrollment agent EKU | `ESC3` from enrollable users (confidence 0.7) |
| ADCS ESC4 | cert_template with low-privilege write access | `ESC4` from writeable-by peers (confidence 0.75) |
| ADCS ESC5 (Template) | cert_template with vulnerable template ACLs | `ESC5` from relevant users/groups |
| ADCS ESC5 (CA) | CA with vulnerable CA ACLs | `ESC5` from manage-CA peers |
| ADCS ESC6 | CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` flag | `ESC6` from enrollable users (confidence 0.75) |
| ADCS ESC7 | CA with manage CA + manage certificates | `ESC7` from manage-CA peers (confidence 0.75) |
| ADCS ESC8 | CA with HTTP enrollment endpoint | `ESC8` from HTTP services via CA (confidence 0.7) |
| ADCS ESC9 | cert_template with no security extension | `ESC9` from enrollable users (confidence 0.7) |
| ADCS ESC10 | cert_template with weak certificate mapping | `ESC10` from enrollable users (confidence 0.7) |
| ADCS ESC11 | CA with certificate relay to AD CS | `ESC11` from CA host compromised peers (confidence 0.7) |
| ADCS ESC12 | CA with shell access + YubiHSM key storage | `ESC12` from CA host compromised peers (confidence 0.7) |
| ADCS ESC13 | cert_template with issuance policy OID | `ESC13` from enrollable users with issuance policy (confidence 0.7) |

#### Linux Privilege Escalation Rules

| Rule | Trigger | Produces |
|------|---------|----------|
| SUID Privesc | Host with `has_suid_root: true` + `HAS_SESSION` | `ADMIN_TO` from session holders (confidence 0.6) |
| SSH Key Reuse | Credential with `cred_type: ssh_key` | `POTENTIAL_AUTH` to SSH services on related hosts (confidence 0.5) |
| Docker Escape | Host with `docker_socket_accessible: true` + `HAS_SESSION` | `ADMIN_TO` from session holders (confidence 0.8) |
| NFS Root Squash | Host with `no_root_squash: true` + `HAS_SESSION` | `ADMIN_TO` from session holders (confidence 0.7) |
| Sudo NOPASSWD | Host with `sudoers_nopasswd: true` + `HAS_SESSION` | `ADMIN_TO` from session holders (confidence 0.7) |
| Dangerous Capabilities | Host with `has_dangerous_capabilities: true` + `HAS_SESSION` | `ADMIN_TO` from session holders (confidence 0.55) |
| Writable Cron/Systemd | Host with `writable_cron_or_systemd: true` + `HAS_SESSION` | `ADMIN_TO` from session holders (confidence 0.65) |

#### Web Application Rules (8)

| Rule | Trigger | Produces |
|------|---------|----------|
| Web Login Form | Service with `has_login_form: true` | `POTENTIAL_AUTH` from domain credentials |
| Webapp Login Spray | Webapp with `has_login_form: true` | `POTENTIAL_AUTH` from all credentials (confidence 0.3) |
| Authenticated Rescan | Webapp with `AUTHENTICATED_AS` edge | Frontier: re-scan with authenticated session |
| Default Credentials | Webapp with `technology` matching known defaults | `POTENTIAL_AUTH` edges with default cred pairs |
| CMS Exploitation | Webapp with `cms_type` set | Frontier: version-specific exploit checks |
| SQLi → Credential Extraction | Vulnerability with `vuln_type=sqli` | `EXPLOITS` edge + potential `credential` nodes |
| SQLi → RCE Escalation | Vulnerability with `vuln_type=sqli` + stacked queries | `EXPLOITS` edge to parent host |
| Token → Webapp Auth | Credential with `cred_type=token` + `AUTHENTICATED_AS` edge on webapp | `VALID_ON` edge from credential to webapp service (confidence 0.75) |
| Auth Bypass Escalation | Vulnerability with `AUTH_BYPASS` edge to webapp | `EXPLOITS` edge from vulnerability to webapp host (confidence 0.8) |

#### MSSQL Rules (2)

| Rule | Trigger | Produces |
|------|---------|----------|
| MSSQL Linked Server | MSSQL service with `linked_servers` | `REACHABLE` edges to linked hosts (confidence 0.8) |

#### Cloud Rules

| Rule | Trigger | Produces |
|------|---------|----------|
| Overprivileged Policy | Cloud policy with wildcard actions (`iam:*`, `s3:*`, `*:*`) | `PATH_TO_OBJECTIVE` to nearest objective (confidence 0.7) |
| Public Bucket | Cloud resource (`s3_bucket`, `public: true`) | `PATH_TO_OBJECTIVE` to nearest objective (confidence 0.8) |
| Cross-Account Role | Cloud identity with `ASSUMES_ROLE` crossing accounts | `REACHABLE` to cross-account roles (confidence 0.7) |

Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md).

### Selector Reference

Selectors resolve graph context when inference rules fire:

| Selector | Resolves To |
|----------|-------------|
| `trigger_node` | The node that triggered the rule |
| `trigger_service` | Same as `trigger_node` |
| `parent_host` | Host running the triggering service |
| `orphan_service_host` | Host for a service node without an existing `RUNS` edge |
| `domain_nodes` | All domain nodes |
| `domain_users` | All domain-joined user nodes |
| `domain_credentials` | All NTLM/Kerberos/AES reusable credentials |
| `domain_admins_and_session_holders` | Session holders on trigger host + admin group members; falls back to all domain users |
| `all_compromised` | Hosts with `HAS_SESSION` or `ADMIN_TO` edges at confidence >= 0.7 |
| `compatible_services` | Services accepting the credential type |
| `compatible_services_same_domain` | Like `compatible_services` but filtered to same domain as credential |
| `matching_domain` | Domain nodes matching host hostname suffix |
| `matching_user_domain` | Domain nodes the trigger user belongs to (via `MEMBER_OF_DOMAIN` edge or `domain_name` property) |
| `matching_user_for_cred` | User nodes matching a credential's `cred_user` field |
| `edge_peers` | Peer nodes from the rule's `requires_edge` (for edge-triggered rules) |
| `writeable_by_peers` | Peer nodes with `WRITEABLE_BY` edges to the trigger node |
| `enrollable_users` | All user nodes (for ADCS rules) |
| `enrollable_users_if_client_auth` | All users, but only when the trigger cert_template has Client Authentication EKU |
| `enrollable_users_if_issuance_policy` | All users, but only when the trigger cert_template has issuance policy OID |
| `session_holders_on_host` | Users/groups with `HAS_SESSION` (confidence >= 0.7) to the triggering host |
| `ssh_services` | All services with `service_name: ssh` |
| `ssh_services_related` | SSH services on hosts where the credential owner has existing access |
| `delegation_targets` | Hosts/services resolved from `allowed_to_delegate_to` SPN list; falls back to domain nodes |
| `linked_server_hosts` | Hosts matching the `linked_servers` array by hostname/label |
| `target_user_credentials` | Credentials associated with a target user |
| `credentials_same_username` | Credentials matching the same `cred_user` as the trigger credential |
| `gpo_linked_hosts` | Hosts linked to the GPO via `APPLIES_TO` or group membership |
| `web_form_credentials` | Plaintext non-default credentials for webapp spray |
| `all_usable_credentials` | All credentials usable for authentication |
| `ca_for_template` | CA nodes that issue the trigger cert_template |
| `manage_ca_peers` | Identities with manage-CA permissions |
| `ca_host_compromised_peers` | Session holders on host running the CA |
| `http_services_via_ca` | HTTP services reachable from CA enrollment endpoints |
| `nearest_objective` | Objective nodes (for cloud rules with wildcard action gating) |
| `cross_account_roles` | Cloud identities in different accounts reachable via `ASSUMES_ROLE` |
| `default_credential_candidates` | Webapps with technology matching known default credential databases |
| `cms_credentials` | Plaintext credentials for CMS-type web applications |
| `hosted_webapps` | Webapps hosted on the triggering service (via `HOSTS` edges) |
| `vulnerable_webapps` | Webapps with at least one `VULNERABLE_TO` edge |
