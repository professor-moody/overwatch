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
      confidence: 0.7
    }]
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
      source_selector: 'trigger_node',
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
    id: 'rule-dcsync',
    name: 'DCSync capable principal',
    description: 'User/group with Replicating Directory Changes rights can perform DCSync against the domain',
    trigger: { node_type: 'user', property_match: { can_dcsync: true } },
    produces: [{
      edge_type: 'CAN_DCSYNC',
      source_selector: 'trigger_node',
      target_selector: 'matching_user_domain',
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
];
