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
| `credential` | Authentication material | `cred_type`, `cred_value`, `cred_domain`, `cred_user` |
| `share` | A network share | `share_name`, `share_path`, `readable`, `writable` |
| `certificate` | An ADCS certificate template | `template_name`, `ca_name`, `eku`, `enrollee_supplies_subject` |
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
| `ntlm` | NTLM hash |
| `ntlmv2_challenge` | Captured NTLMv2 challenge-response |
| `aes256` | AES-256 Kerberos key |
| `kerberos_tgt` | Kerberos TGT |
| `kerberos_tgs` | Kerberos TGS (Kerberoast) |
| `certificate` | X.509 certificate |
| `token` | Authentication token |
| `ssh_key` | SSH private key |

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

### AD Attack Paths

| Edge | Description |
|------|-------------|
| `CAN_DCSYNC` | DCSync rights |
| `DELEGATES_TO` | Delegation relationship |
| `WRITEABLE_BY` | Object is writable by another |
| `GENERIC_ALL` | GenericAll permission |
| `GENERIC_WRITE` | GenericWrite permission |
| `WRITE_OWNER` | WriteOwner permission |
| `WRITE_DACL` | WriteDACL permission |
| `ADD_MEMBER` | Can add members to a group |
| `FORCE_CHANGE_PASSWORD` | Can force password change |
| `ALLOWED_TO_ACT` | Resource-based constrained delegation |

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

Built-in rules fire automatically when matching nodes are ingested:

| Rule | Trigger | Produces |
|------|---------|----------|
| Kerberos → Domain | Service with `service_name: kerberos` | `MEMBER_OF_DOMAIN` edge to domain nodes |
| SMB Signing → Relay | Service with `smb_signing: false` | `RELAY_TARGET` edges from compromised hosts |
| MSSQL + Domain | MSSQL service on domain host | `POTENTIAL_AUTH` from domain credentials |
| Credential Fanout | New credential node | `POTENTIAL_AUTH` to all compatible services |
| ADCS ESC1 | Certificate with enrollee-supplied subject | `ESC1` from enrollable users |
| Unconstrained Delegation | Host with unconstrained delegation | `DELEGATES_TO` from domain users |

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
| `enrollable_users` | All user nodes (for ADCS rules) |
