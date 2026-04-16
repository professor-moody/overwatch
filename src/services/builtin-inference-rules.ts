import type { InferenceRule } from '../types.js';

export const BUILTIN_RULES: InferenceRule[] = [
  {
    id: 'rule-kerberos-domain',
    name: 'Kerberos implies domain membership',
    description: 'Host running Kerberos (port 88) is likely a domain controller — matched by hostname suffix',
    trigger: { node_type: 'service', property_match: { service_name: 'kerberos' } },
    produces: [{
      edge_type: 'MEMBER_OF_DOMAIN',
      source_selector: 'parent_host',
      target_selector: 'matching_domain',
      confidence: 0.95
    }],
    self_confirming: true
  },
  {
    id: 'rule-smb-signing-relay',
    name: 'SMB signing disabled implies relay target',
    description: 'Hosts with SMB signing disabled are relay targets',
    trigger: { node_type: 'service', property_match: { service_name: 'smb', smb_signing: false } },
    produces: [{
      edge_type: 'RELAY_TARGET',
      source_selector: 'all_compromised',
      target_selector: 'parent_host',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-mssql-domain-auth',
    name: 'Domain-joined MSSQL accepts domain creds',
    description: 'MSSQL on domain-joined host likely accepts domain authentication',
    trigger: {
      node_type: 'service',
      property_match: { service_name: 'mssql' },
      requires_edge: { type: 'RUNS', direction: 'inbound', peer_match: { domain_joined: true } },
    },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'domain_credentials',
      target_selector: 'trigger_service',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-cred-fanout',
    name: 'New credential tests against compatible services',
    description: 'When a new credential is found, create POTENTIAL_AUTH edges to compatible services in the same domain',
    trigger: { node_type: 'credential' },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'trigger_node',
      target_selector: 'compatible_services_same_domain',
      confidence: 0.4
    }]
  },
  {
    id: 'rule-adcs-esc1',
    name: 'ADCS enrollment + subject supply = ESC1 candidate',
    description: 'Certificate template allowing enrollee-supplied subject name with client auth EKU',
    trigger: { node_type: 'cert_template', property_match: { enrollee_supplies_subject: true } },
    produces: [{
      edge_type: 'ESC1',
      source_selector: 'enrollable_users_if_client_auth',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-unconstrained-delegation',
    name: 'Unconstrained delegation target',
    description: 'Hosts with unconstrained delegation can capture TGTs from authenticating principals',
    trigger: { node_type: 'host', property_match: { unconstrained_delegation: true } },
    produces: [{
      edge_type: 'DELEGATES_TO',
      source_selector: 'domain_admins_and_session_holders',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-asrep-roastable',
    name: 'AS-REP Roastable user',
    description: 'User with Kerberos pre-auth disabled is AS-REP roastable in its domain',
    trigger: { node_type: 'user', property_match: { asrep_roastable: true } },
    produces: [{
      edge_type: 'AS_REP_ROASTABLE',
      source_selector: 'trigger_node',
      target_selector: 'matching_user_domain',
      confidence: 0.85
    }]
  },
  {
    id: 'rule-kerberoastable',
    name: 'Kerberoastable user',
    description: 'User with SPN set is kerberoastable in its domain',
    trigger: { node_type: 'user', property_match: { has_spn: true } },
    produces: [{
      edge_type: 'KERBEROASTABLE',
      source_selector: 'trigger_node',
      target_selector: 'matching_user_domain',
      confidence: 0.85
    }]
  },
  {
    id: 'rule-constrained-delegation',
    name: 'Constrained delegation target',
    description: 'Host with constrained delegation can impersonate users to target services',
    trigger: { node_type: 'host', property_match: { constrained_delegation: true } },
    produces: [{
      edge_type: 'CAN_DELEGATE_TO',
      source_selector: 'trigger_node',
      target_selector: 'delegation_targets',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-web-login-form',
    name: 'Web login form discovered',
    description: 'HTTP service with login form is a candidate for credential testing',
    trigger: { node_type: 'service', property_match: { has_login_form: true } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'domain_credentials',
      target_selector: 'trigger_service',
      confidence: 0.5
    }]
  },
  {
    id: 'rule-laps-readable',
    name: 'LAPS password readable via ACL',
    description: 'Host with LAPS enabled and inbound GENERIC_ALL from a principal allows LAPS password read',
    trigger: {
      node_type: 'host',
      property_match: { laps: true },
      requires_edge: { type: 'GENERIC_ALL', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'CAN_READ_LAPS',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-gmsa-readable',
    name: 'gMSA password readable via ACL',
    description: 'gMSA service account with inbound GENERIC_ALL from a principal allows gMSA password read',
    trigger: {
      node_type: 'user',
      property_match: { gmsa: true },
      requires_edge: { type: 'GENERIC_ALL', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'CAN_READ_GMSA',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-rbcd-target',
    name: 'RBCD eligible target',
    description: 'Host writable by a principal is an RBCD target when MachineAccountQuota > 0',
    trigger: {
      node_type: 'host',
      property_match: { maq_gt_zero: true },
      requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'RBCD_TARGET',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-suid-privesc',
    name: 'SUID root binary enables privilege escalation',
    description: 'Host with dangerous SUID root binaries allows session holders to escalate to root',
    trigger: { node_type: 'host', property_match: { has_suid_root: true } },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'session_holders_on_host',
      target_selector: 'trigger_node',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-ssh-key-reuse',
    name: 'SSH key reuse across services',
    description: 'SSH key credential can authenticate to SSH services on hosts where the owner has access',
    trigger: { node_type: 'credential', property_match: { cred_type: 'ssh_key' } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'trigger_node',
      target_selector: 'ssh_services_related',
      confidence: 0.5
    }]
  },
  {
    id: 'rule-docker-escape',
    name: 'Docker socket enables container escape',
    description: 'Host with accessible Docker socket allows session holders to escape to root',
    trigger: { node_type: 'host', property_match: { docker_socket_accessible: true } },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'session_holders_on_host',
      target_selector: 'trigger_node',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-nfs-root-squash',
    name: 'NFS no_root_squash enables privilege escalation',
    description: 'Host with NFS no_root_squash allows session holders to escalate via NFS write',
    trigger: { node_type: 'host', property_match: { no_root_squash: true } },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'session_holders_on_host',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-login-spray-candidate',
    name: 'Webapp login form is a credential spray target',
    description: 'Web application with a login form should be tested with all known credentials',
    trigger: { node_type: 'webapp', property_match: { has_login_form: true } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'web_form_credentials',
      target_selector: 'trigger_node',
      confidence: 0.3
    }]
  },
  {
    id: 'rule-sqli-credential-extraction',
    name: 'SQL injection may yield database credentials',
    description: 'Confirmed SQLi vulnerability on a webapp host is a candidate for credential extraction via database dump',
    trigger: { node_type: 'vulnerability', property_match: { vuln_type: 'sqli', exploitable: true } },
    produces: [{
      edge_type: 'EXPLOITS',
      source_selector: 'trigger_node',
      target_selector: 'parent_host',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-authenticated-rescan',
    name: 'Authenticated webapp warrants deeper scanning',
    description: 'Webapp with authenticated access should be re-scanned for post-auth vulnerabilities',
    trigger: {
      node_type: 'webapp',
      requires_edge: { type: 'AUTHENTICATED_AS', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.4
    }]
  },
  {
    id: 'rule-default-credentials',
    name: 'Known technology has default credentials',
    description: 'Web application running a technology with well-known defaults should be tested for default credentials',
    trigger: { node_type: 'webapp' },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'default_credential_candidates',
      target_selector: 'trigger_node',
      confidence: 0.3
    }]
  },
  {
    id: 'rule-cms-exploitation',
    name: 'CMS webapp is a target for version-specific exploits',
    description: 'Web application with a known CMS type should be tested for CMS-specific vulnerabilities and default credentials',
    trigger: { node_type: 'webapp' },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'cms_credentials',
      target_selector: 'trigger_node',
      confidence: 0.3
    }]
  },
  {
    id: 'rule-sqli-to-rce',
    name: 'SQL injection on capable DBMS may enable RCE',
    description: 'SQLi on MySQL (INTO OUTFILE), MSSQL (xp_cmdshell), or PostgreSQL (COPY TO) can lead to OS command execution',
    trigger: { node_type: 'vulnerability', property_match: { vuln_type: 'sqli' } },
    produces: [{
      edge_type: 'EXPLOITS',
      source_selector: 'trigger_node',
      target_selector: 'parent_host',
      confidence: 0.4
    }]
  },
  {
    id: 'rule-mssql-linked-server',
    name: 'MSSQL linked server implies host reachability',
    description: 'MSSQL service with linked servers implies network reachability to the linked host',
    trigger: { node_type: 'service', property_match: { service_name: 'mssql' } },
    produces: [{
      edge_type: 'REACHABLE',
      source_selector: 'parent_host',
      target_selector: 'linked_server_hosts',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-overprivileged-policy',
    name: 'Overprivileged cloud policy is a high-value target',
    description: 'Cloud policy with wildcard actions (iam:*, s3:*, *:*) is high-value — identity holders can escalate',
    trigger: { node_type: 'cloud_policy' },
    produces: [{
      edge_type: 'PATH_TO_OBJECTIVE',
      source_selector: 'policy_holders',
      target_selector: 'nearest_objective',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-public-bucket',
    name: 'Public S3 bucket is a data exfiltration target',
    description: 'S3 bucket with public access is a direct objective candidate',
    trigger: { node_type: 'cloud_resource', property_match: { resource_type: 's3_bucket', public: true } },
    produces: [{
      edge_type: 'PATH_TO_OBJECTIVE',
      source_selector: 'trigger_node',
      target_selector: 'nearest_objective',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-cross-account-role',
    name: 'Cross-account role assumption enables lateral movement',
    description: 'ASSUMES_ROLE edge crossing cloud account boundaries indicates lateral movement opportunity',
    trigger: {
      node_type: 'cloud_identity',
      requires_edge: { type: 'ASSUMES_ROLE', direction: 'outbound' }
    },
    produces: [{
      edge_type: 'REACHABLE',
      source_selector: 'trigger_node',
      target_selector: 'cross_account_roles',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-imds-credential-theft',
    name: 'IMDS credential theft via IMDSv1',
    description: 'EC2 instance without IMDSv2 enforcement allows SSRF-based credential theft from metadata service',
    trigger: { node_type: 'cloud_resource', property_match: { resource_type: 'ec2', imdsv2_required: false } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'trigger_node',
      target_selector: 'imds_managed_identity',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-cross-account-role-chain',
    name: 'Transitive cross-account role chaining enables deep lateral movement',
    description: 'Multi-hop ASSUMES_ROLE chains crossing account boundaries open lateral movement into distant accounts',
    trigger: {
      node_type: 'cloud_identity',
      requires_edge: { type: 'ASSUMES_ROLE', direction: 'outbound' }
    },
    produces: [{
      edge_type: 'REACHABLE',
      source_selector: 'trigger_node',
      target_selector: 'transitive_assumed_roles',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-lambda-iam-escalation',
    name: 'Lambda execution role enables privilege escalation',
    description: 'Lambda function with an attached IAM role can be invoked to escalate privileges via the role',
    trigger: {
      node_type: 'cloud_resource',
      property_match: { resource_type: 'lambda' }
    },
    produces: [{
      edge_type: 'ASSUMES_ROLE',
      source_selector: 'trigger_node',
      target_selector: 'lambda_attached_role',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-s3-bucket-exposed',
    name: 'S3 bucket with cross-account or public exposure is a data exfiltration vector',
    description: 'S3 bucket exposed via bucket policy or ACL to external principals enables data access',
    trigger: {
      node_type: 'cloud_resource',
      property_match: { resource_type: 's3_bucket' },
      requires_edge: { type: 'EXPOSED_TO', direction: 'outbound' }
    },
    produces: [{
      edge_type: 'REACHABLE',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-write-dacl-escalation',
    name: 'WriteDACL implies effective GenericAll',
    description: 'Principal with WriteDACL on an object can grant themselves GenericAll',
    trigger: {
      requires_edge: { type: 'WRITE_DACL', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'GENERIC_ALL',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-write-owner-escalation',
    name: 'WriteOwner implies effective GenericAll',
    description: 'Principal with WriteOwner on an object can set themselves as owner, then modify DACL to gain GenericAll',
    trigger: {
      requires_edge: { type: 'WRITE_OWNER', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'GENERIC_ALL',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-force-change-password',
    name: 'ForceChangePassword enables credential takeover',
    description: 'Principal with ForceChangePassword on a user can reset the password and take over the account',
    trigger: {
      node_type: 'user',
      requires_edge: { type: 'FORCE_CHANGE_PASSWORD', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'OWNS_CRED',
      source_selector: 'edge_peers',
      target_selector: 'target_user_credentials',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-shadow-credentials',
    name: 'GenericWrite on computer enables Shadow Credentials takeover',
    description: 'Principal with GenericWrite on a computer can add msDS-KeyCredentialLink for PKINIT auth',
    trigger: {
      node_type: 'host',
      requires_edge: { type: 'GENERIC_WRITE', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.65
    }]
  },
  {
    id: 'rule-gpo-abuse',
    name: 'GPO write access enables host compromise',
    description: 'Principal with write access to a GPO can modify it to execute code on linked hosts',
    trigger: {
      node_type: 'gpo',
      requires_edge: { type: 'GENERIC_WRITE', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'edge_peers',
      target_selector: 'gpo_linked_hosts',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-dcsync',
    name: 'DCSync capable principal',
    description: 'User with outbound CAN_DCSYNC edge is a high-value target — path to domain compromise',
    trigger: {
      node_type: 'user',
      requires_edge: { type: 'CAN_DCSYNC', direction: 'outbound' }
    },
    produces: [{
      edge_type: 'PATH_TO_OBJECTIVE',
      source_selector: 'trigger_node',
      target_selector: 'nearest_objective',
      confidence: 0.9
    }]
  },
  {
    id: 'rule-sudo-nopasswd',
    name: 'Sudoers NOPASSWD enables privilege escalation',
    description: 'Host with NOPASSWD sudoers entries allows session holders to escalate to root',
    trigger: { node_type: 'host', property_match: { sudoers_nopasswd: true } },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'session_holders_on_host',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-dangerous-capabilities',
    name: 'Dangerous Linux capabilities enable privilege escalation',
    description: 'Host with dangerous capabilities (cap_setuid, cap_dac_override, etc.) allows session holders to escalate',
    trigger: { node_type: 'host', property_match: { has_dangerous_capabilities: true } },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'session_holders_on_host',
      target_selector: 'trigger_node',
      confidence: 0.55
    }]
  },
  {
    id: 'rule-writable-cron-systemd',
    name: 'Writable cron/systemd enables code execution',
    description: 'Host with writable cron jobs or systemd service files allows session holders to execute as the service owner',
    trigger: { node_type: 'host', property_match: { writable_cron_or_systemd: true } },
    produces: [{
      edge_type: 'ADMIN_TO',
      source_selector: 'session_holders_on_host',
      target_selector: 'trigger_node',
      confidence: 0.65
    }]
  },
  // --- ADCS ESC rules (Phase 2) ---
  {
    id: 'rule-adcs-esc2',
    name: 'ADCS ESC2 — Any Purpose EKU template',
    description: 'Certificate template with Any Purpose or no EKU allows certificate abuse for authentication',
    trigger: { node_type: 'cert_template', property_match: { any_purpose: true } },
    produces: [{
      edge_type: 'ESC2',
      source_selector: 'enrollable_users_if_client_auth',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-adcs-esc3',
    name: 'ADCS ESC3 — Enrollment agent template',
    description: 'Certificate template with Certificate Request Agent EKU allows enrolling on behalf of others',
    trigger: { node_type: 'cert_template', property_match: { enrollment_agent: true } },
    produces: [{
      edge_type: 'ESC3',
      source_selector: 'enrollable_users',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-adcs-esc4',
    name: 'ADCS ESC4 — Writable certificate template',
    description: 'Certificate template writable by a principal can be modified to enable ESC1-style abuse',
    trigger: {
      node_type: 'cert_template',
      requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'ESC4',
      source_selector: 'edge_peers',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-adcs-esc6',
    name: 'ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA',
    description: 'CA with SAN flag enabled allows requesters to specify arbitrary SANs',
    trigger: { node_type: 'ca', property_match: { san_flag_enabled: true } },
    produces: [{
      edge_type: 'ESC6',
      source_selector: 'enrollable_users',
      target_selector: 'trigger_node',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-adcs-esc7',
    name: 'ADCS ESC7 — CA management abuse',
    description: 'Principal with ManageCA or ManageCertificates on a CA can issue arbitrary certificates',
    trigger: {
      node_type: 'ca',
      requires_edge: { type: 'GENERIC_ALL', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'ESC7',
      source_selector: 'manage_ca_peers',
      target_selector: 'trigger_node',
      confidence: 0.75
    }]
  },
  {
    id: 'rule-adcs-esc8',
    name: 'ADCS ESC8 — NTLM relay to AD CS HTTP endpoint',
    description: 'CA with HTTP enrollment endpoint is vulnerable to NTLM relay (PetitPotam/DFSCoerce)',
    trigger: { node_type: 'ca', property_match: { http_enrollment: true } },
    produces: [{
      edge_type: 'ESC8',
      source_selector: 'all_compromised',
      target_selector: 'trigger_node',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-adcs-esc5-template',
    name: 'ADCS ESC5 — Vulnerable PKI object ACL (certificate template)',
    description: 'Principal with write-type ACL on a PKI object (cert template) can modify it to enable certificate abuse',
    trigger: {
      node_type: 'cert_template',
      requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'ESC5',
      source_selector: 'writeable_by_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-adcs-esc5-ca',
    name: 'ADCS ESC5 — Vulnerable PKI object ACL (CA)',
    description: 'Principal with write-type ACL on a CA object can modify CA configuration to enable certificate abuse',
    trigger: {
      node_type: 'ca',
      requires_edge: { type: 'WRITEABLE_BY', direction: 'inbound' }
    },
    produces: [{
      edge_type: 'ESC5',
      source_selector: 'writeable_by_peers',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  {
    id: 'rule-adcs-esc9',
    name: 'ADCS ESC9 — No security extension (CT_FLAG_NO_SECURITY_EXTENSION)',
    description: 'Template with CT_FLAG_NO_SECURITY_EXTENSION flag allows bypassing strong certificate binding when StrongCertificateBindingEnforcement < 2',
    trigger: { node_type: 'cert_template', property_match: { ct_flag_no_security_extension: true } },
    produces: [{
      edge_type: 'ESC9',
      source_selector: 'enrollable_users',
      target_selector: 'trigger_node',
      confidence: 0.65
    }]
  },
  {
    id: 'rule-adcs-esc10',
    name: 'ADCS ESC10 — Weak certificate mapping (UPN mapping abuse)',
    description: 'Template with enrollee-supplied subject and weak certificate mapping methods allows impersonation via UPN mapping',
    trigger: { node_type: 'cert_template', property_match: { enrollee_supplies_subject: true } },
    produces: [{
      edge_type: 'ESC10',
      source_selector: 'enrollable_users',
      target_selector: 'trigger_node',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-adcs-esc11',
    name: 'ADCS ESC11 — NTLM relay to ICPR (RPC without encryption)',
    description: 'CA without IF_ENFORCEENCRYPTICERTREQUEST allows NTLM relay to RPC certificate enrollment endpoint',
    trigger: { node_type: 'ca', property_match: { enforce_encrypt_icert_request: false } },
    produces: [{
      edge_type: 'ESC11',
      source_selector: 'all_compromised',
      target_selector: 'trigger_node',
      confidence: 0.55
    }]
  },
  {
    id: 'rule-adcs-esc12',
    name: 'ADCS ESC12 — Shell access to CA server',
    description: 'Compromised host running the CA allows direct certificate authority abuse (key extraction, arbitrary issuance)',
    trigger: { node_type: 'ca' },
    produces: [{
      edge_type: 'ESC12',
      source_selector: 'ca_host_compromised_peers',
      target_selector: 'trigger_node',
      confidence: 0.8
    }]
  },
  {
    id: 'rule-adcs-esc13',
    name: 'ADCS ESC13 — Issuance policy linked to group',
    description: 'Template with an issuance policy OID linked to a universal group grants group membership upon enrollment',
    trigger: { node_type: 'cert_template' },
    produces: [{
      edge_type: 'ESC13',
      source_selector: 'enrollable_users_if_issuance_policy',
      target_selector: 'trigger_node',
      confidence: 0.7
    }]
  },
  // --- Credential reuse ---
  {
    id: 'rule-shared-credential',
    name: 'Credential reuse across accounts',
    description: 'Credentials with the same username likely share the same password — common in AD environments',
    trigger: { node_type: 'credential' },
    produces: [{
      edge_type: 'SHARED_CREDENTIAL',
      source_selector: 'trigger_node',
      target_selector: 'credentials_same_username',
      confidence: 0.7
    }]
  },
  // --- Lateral movement chaining ---
  {
    id: 'rule-session-admin-persistence',
    name: 'Session + admin on same host implies persistence',
    description: 'User with both HAS_SESSION and ADMIN_TO on the same host has persistent access — high-value path',
    trigger: {
      node_type: 'user',
      requires_edge: { type: 'ADMIN_TO', direction: 'outbound' }
    },
    produces: [{
      edge_type: 'PATH_TO_OBJECTIVE',
      source_selector: 'trigger_node',
      target_selector: 'nearest_objective',
      confidence: 0.6
    }]
  },
  // --- Auto-inference for parser-discovered relationships ---
  {
    id: 'rule-host-runs-service',
    name: 'Host runs discovered service',
    description: 'Service nodes should have a RUNS edge from their parent host — infer when missing',
    trigger: { node_type: 'service' },
    produces: [{
      edge_type: 'RUNS',
      source_selector: 'orphan_service_host',
      target_selector: 'trigger_node',
      confidence: 0.9
    }]
  },
  {
    id: 'rule-user-owns-credential',
    name: 'User owns matching credential',
    description: 'Credential with cred_user matching a known user implies OWNS_CRED relationship',
    trigger: { node_type: 'credential' },
    produces: [{
      edge_type: 'OWNS_CRED',
      source_selector: 'matching_user_for_cred',
      target_selector: 'trigger_node',
      confidence: 0.85
    }]
  },
  {
    id: 'rule-token-webapp-auth',
    name: 'Token credential authenticates to webapp via service',
    description: 'A token credential valid on a service that hosts a webapp implies AUTHENTICATED_AS on the webapp',
    trigger: { node_type: 'credential', property_match: { cred_type: 'token' } },
    produces: [{
      edge_type: 'AUTHENTICATED_AS',
      source_selector: 'trigger_node',
      target_selector: 'hosted_webapps',
      confidence: 0.6
    }]
  },
  {
    id: 'rule-auth-bypass-escalation',
    name: 'Auth bypass vulnerability enables unauthenticated access',
    description: 'A vulnerability with auth_bypass or idor type on a webapp creates an AUTH_BYPASS edge',
    trigger: { node_type: 'vulnerability', property_match: { vuln_type: 'auth_bypass' } },
    produces: [{
      edge_type: 'AUTH_BYPASS',
      source_selector: 'trigger_node',
      target_selector: 'vulnerable_webapps',
      confidence: 0.5
    }]
  },
  {
    id: 'rule-api-endpoint-discovery',
    name: 'Webapp with API requires endpoint enumeration',
    description: 'A webapp with has_api=true is a candidate for API endpoint discovery and enumeration',
    trigger: { node_type: 'webapp', property_match: { has_api: true } },
    produces: [{
      edge_type: 'POTENTIAL_AUTH',
      source_selector: 'default_credential_candidates',
      target_selector: 'trigger_node',
      confidence: 0.3
    }]
  },
];
