# Graph Model

Overwatch models engagements as directed property graphs using [graphology](https://graphology.github.io/). Every discovery — a host, a credential, an access relationship — is a node or edge in the graph.

## Node Types

| Type | Description | Key Properties |
|------|-------------|----------------|
| `host` | A target machine | `ip`, `hostname`, `os`, `alive`, `domain_joined` |
| `service` | A network service on a host | `port`, `protocol`, `service_name`, `version`, `banner` |
| `domain` | An Active Directory domain | `domain_name`, `functional_level` |
| `user` | A domain or local user | `username`, `sid`, `enabled`, `privileged` |
| `group` | A security group | `sid`, `member_of` |
| `credential` | Authentication material | `cred_type`, `cred_value`, `cred_domain`, `cred_user`, `credential_status` |
| `share` | A network share | `share_name`, `share_path`, `readable`, `writable` |
| `certificate` | An X.509 certificate | `template_name`, `eku` |
| `ca` | A Certificate Authority | `ca_name`, `ca_kind` (`enterprise_ca`, `root_ca`, `aia_ca`) |
| `cert_template` | An AD CS certificate template | `template_name`, `ca_name`, `eku`, `enrollee_supplies_subject` |
| `pki_store` | A PKI store | `pki_store_kind` (`ntauth_store`, `issuance_policy`) |
| `gpo` | A Group Policy Object | `label` |
| `ou` | An Organizational Unit | `label` |
| `subnet` | A network subnet | `label` |
| `objective` | An engagement objective | `objective_description`, `objective_achieved` |

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

## Edge Types

### Network

| Edge | Description |
|------|-------------|
| `REACHABLE` | Network reachability between hosts |
| `RUNS` | Host runs a service |

### Domain Membership

| Edge | Description |
|------|-------------|
| `MEMBER_OF` | User/group is member of a group |
| `MEMBER_OF_DOMAIN` | Object belongs to a domain |
| `TRUSTS` | Domain trust relationship |
| `SAME_DOMAIN` | Objects share a domain |

### Access

| Edge | Description |
|------|-------------|
| `ADMIN_TO` | Administrative access to a host |
| `HAS_SESSION` | Active session on a host |
| `CAN_RDPINTO` | RDP access to a host |
| `CAN_PSREMOTE` | PSRemoting/WinRM access |

### Credentials

| Edge | Description |
|------|-------------|
| `VALID_ON` | Credential is valid on a service |
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
| `ESC6` | ADCS escalation path 6 |
| `ESC8` | ADCS escalation path 8 (web enrollment relay) |

### Lateral Movement

| Edge | Description |
|------|-------------|
| `RELAY_TARGET` | NTLM relay target |
| `NULL_SESSION` | Null session access |

### Objective

| Edge | Description |
|------|-------------|
| `PATH_TO_OBJECTIVE` | Computed path toward an engagement objective |

### Generic

| Edge | Description |
|------|-------------|
| `RELATED` | Uncategorized relationship (unconstrained) |

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

Thirteen built-in rules fire automatically when matching nodes are ingested:

| Rule | Trigger | Produces |
|------|---------|----------|
| Kerberos → Domain | Service with `service_name: kerberos` | `MEMBER_OF_DOMAIN` to matching domain (hostname suffix) |
| SMB Signing → Relay | Service with `smb_signing: false` | `RELAY_TARGET` from compromised hosts |
| MSSQL + Domain | MSSQL service on domain host | `POTENTIAL_AUTH` from domain credentials |
| Credential Fanout | New credential node | `POTENTIAL_AUTH` to compatible services in same domain |
| ADCS ESC1 | cert_template with enrollee-supplied subject | `ESC1` from enrollable users |
| Unconstrained Delegation | Host with `unconstrained_delegation: true` | `DELEGATES_TO` from domain users |
| AS-REP Roastable | User with `asrep_roastable: true` | `AS_REP_ROASTABLE` to domain nodes |
| Kerberoastable | User with `has_spn: true` | `KERBEROASTABLE` to domain nodes |
| Constrained Delegation | Host with `constrained_delegation: true` | `CAN_DELEGATE_TO` to domain nodes |
| Web Login Form | Service with `has_login_form: true` | `POTENTIAL_AUTH` from domain credentials |
| LAPS Readable | Host with `laps: true` + inbound `GENERIC_ALL` | `CAN_READ_LAPS` from edge peers |
| gMSA Readable | User with `gmsa: true` + inbound `GENERIC_ALL` | `CAN_READ_GMSA` from edge peers |
| RBCD Target | Host with `maq_gt_zero: true` + inbound `WRITEABLE_BY` | `RBCD_TARGET` from edge peers |

The last three rules use **edge-triggered inference** — they require a matching inbound edge (`requires_edge` field) in addition to the node property match. When a new edge arrives, inference also re-evaluates its endpoints.

Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md).

### Selector Reference

Selectors resolve graph context when inference rules fire:

| Selector | Resolves To |
|----------|-------------|
| `trigger_node` | The node that triggered the rule |
| `trigger_service` | Same as `trigger_node` |
| `parent_host` | Host running the triggering service |
| `domain_nodes` | All domain nodes |
| `domain_users` | All domain user nodes |
| `domain_credentials` | All NTLM/Kerberos/AES credentials |
| `all_compromised` | Hosts with confirmed access |
| `compatible_services` | Services accepting the credential type |
| `compatible_services_same_domain` | Like `compatible_services` but filtered to same domain as credential |
| `matching_domain` | Domain nodes matching host hostname suffix |
| `edge_peers` | Peer nodes from the rule’s `requires_edge` (for edge-triggered rules) |
| `enrollable_users` | All user nodes (for ADCS rules) |
