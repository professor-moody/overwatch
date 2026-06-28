// ============================================================
// Node Display — ported from legacy node-display.js
// ============================================================

export const FRIENDLY_TYPE_LABELS: Record<string, string> = {
  host: 'Hosts',
  service: 'Services',
  domain: 'Domains',
  user: 'Users',
  group: 'Groups',
  credential: 'Credentials',
  share: 'Shares',
  certificate: 'Certificates',
  ca: 'CAs',
  cert_template: 'Templates',
  pki_store: 'PKI Stores',
  gpo: 'GPOs',
  ou: 'OUs',
  subnet: 'Subnets',
  objective: 'Objectives',
  webapp: 'Web Apps',
  vulnerability: 'Vulnerabilities',
  cloud_identity: 'Cloud Identities',
  cloud_resource: 'Cloud Resources',
  cloud_policy: 'Cloud Policies',
  cloud_network: 'Cloud Networks',
  idp: 'Identity Providers',
  idp_application: 'IdP Applications',
  idp_principal: 'IdP Principals',
  api_endpoint: 'API Endpoints',
  subdomain: 'Subdomains',
  asn: 'ASNs',
  organization: 'Organizations',
  email: 'Emails',
  mock_service: 'Mock Services',
};

export function getFriendlyNodeTypeLabel(type: string): string {
  return FRIENDLY_TYPE_LABELS[type] || `${type}s`;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getNodeDisplayLabel(props: Record<string, any> = {}, fallbackId = ''): string {
  const type = props.type || 'host';
  if (type === 'host') return props.hostname || props.ip || props.label || fallbackId;
  if (type === 'service') return props.label || [props.service_name, props.port].filter(Boolean).join('/') || fallbackId;
  if (type === 'domain') return props.domain_name || props.label || fallbackId;
  if (type === 'user') return props.label || [props.domain_name, props.username].filter(Boolean).join('\\') || props.username || fallbackId;
  if (type === 'group') return props.label || props.group_name || fallbackId;
  if (type === 'credential') return props.label || [props.cred_domain, props.cred_user].filter(Boolean).join('\\') || props.cred_user || fallbackId;
  if (type === 'share') return props.label || props.share_name || fallbackId;
  if (type === 'certificate') return props.label || props.template_name || fallbackId;
  if (type === 'ca') return props.ca_name || props.label || fallbackId;
  if (type === 'cert_template') return props.template_name || props.label || fallbackId;
  if (type === 'pki_store') return props.label || props.pki_store_kind || fallbackId;
  if (type === 'gpo') return props.label || props.display_name || fallbackId;
  if (type === 'ou') return props.label || props.name || fallbackId;
  if (type === 'subnet') return props.cidr || props.label || fallbackId;
  if (type === 'objective') return props.objective_description || props.label || fallbackId;
  if (type === 'webapp') return props.url || props.label || fallbackId;
  if (type === 'vulnerability') return props.cve || props.vuln_type || props.label || fallbackId;
  if (type === 'cloud_identity') return props.arn || props.principal_name || props.label || fallbackId;
  if (type === 'cloud_resource') return props.resource_name || props.arn || props.label || fallbackId;
  if (type === 'cloud_policy') return props.policy_name || props.label || fallbackId;
  if (type === 'cloud_network') return props.network_name || props.cidr || props.label || fallbackId;
  if (type === 'mock_service') return props.label || [props.mock_purpose, `${props.bind_host || ''}:${props.bind_port || ''}`].filter(Boolean).join(' ') || fallbackId;
  if (type === 'subdomain') return props.subdomain_name || props.label || fallbackId;
  if (type === 'asn') return props.label || (props.asn_number ? `AS${props.asn_number}` : props.asn_org) || fallbackId;
  if (type === 'organization') return props.org_name || props.label || fallbackId;
  if (type === 'email') return props.email_address || props.label || fallbackId;
  return props.label || fallbackId;
}

export interface IdentityEntry {
  key: string;
  value: string | number | boolean;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getNodeIdentityEntries(props: Record<string, any> = {}, fallbackId = ''): IdentityEntry[] {
  const type = props.type || 'host';
  const entries: IdentityEntry[] = [];

  function push(key: string, value: unknown) {
    if (value === undefined || value === null || value === '') return;
    entries.push({ key, value: value as string | number | boolean });
  }

  push('id', fallbackId);

  if (type === 'host') {
    push('hostname', props.hostname);
    push('ip', props.ip);
    push('os', props.os);
  } else if (type === 'service') {
    push('service_name', props.service_name);
    push('port', props.port);
    push('protocol', props.protocol);
  } else if (type === 'domain') {
    push('domain_name', props.domain_name || props.label);
    push('functional_level', props.functional_level);
  } else if (type === 'user') {
    push('username', props.username);
    push('domain_name', props.domain_name);
    push('display_name', props.display_name);
  } else if (type === 'group') {
    push('label', props.label);
    push('domain_name', props.domain_name);
  } else if (type === 'credential') {
    push('cred_user', props.cred_user);
    push('cred_domain', props.cred_domain);
    push('cred_type', props.cred_type);
  } else if (type === 'share') {
    push('share_name', props.share_name);
    push('share_path', props.share_path);
  } else if (type === 'certificate') {
    push('template_name', props.template_name);
    push('ca_name', props.ca_name);
  } else if (type === 'ca') {
    push('ca_name', props.ca_name || props.label);
    push('ca_kind', props.ca_kind);
  } else if (type === 'cert_template') {
    push('template_name', props.template_name || props.label);
    push('ca_name', props.ca_name);
  } else if (type === 'pki_store') {
    push('pki_store_kind', props.pki_store_kind);
    push('label', props.label);
  } else if (type === 'webapp') {
    push('url', props.url);
    push('technology', props.technology);
    push('cms_type', props.cms_type);
    push('auth_type', props.auth_type);
  } else if (type === 'vulnerability') {
    push('cve', props.cve);
    push('cvss', props.cvss);
    push('vuln_type', props.vuln_type);
    push('affected_component', props.affected_component);
  } else if (type === 'gpo' || type === 'ou' || type === 'subnet' || type === 'objective') {
    push(type === 'subnet' ? 'cidr' : 'label', props.cidr || props.label || props.objective_description);
  } else if (type === 'cloud_identity') {
    push('arn', props.arn);
    push('principal_name', props.principal_name);
    push('account', props.cloud_account);
    push('provider', props.cloud_provider);
    push('region', props.cloud_region);
  } else if (type === 'cloud_resource') {
    push('arn', props.arn);
    push('resource_name', props.resource_name);
    push('resource_type', props.resource_type);
    push('account', props.cloud_account);
    push('region', props.cloud_region);
    push('public', props.public_access);
  } else if (type === 'cloud_policy') {
    push('policy_name', props.policy_name);
    push('arn', props.arn);
    push('account', props.cloud_account);
  } else if (type === 'cloud_network') {
    push('network_name', props.network_name);
    push('cidr', props.cidr);
    push('vpc_id', props.vpc_id);
    push('account', props.cloud_account);
    push('region', props.cloud_region);
  } else if (type === 'mock_service') {
    push('purpose', props.mock_purpose);
    push('bind', `${props.bind_host || ''}:${props.bind_port || ''}`);
    push('protocol', props.protocol);
    push('opsec_loud', props.opsec_loud);
    push('started_at', props.started_at);
    push('stopped_at', props.stopped_at);
    push('bound_session_id', props.bound_session_id);
  }

  if (props.canonical_id && props.canonical_id !== fallbackId) {
    push('canonical_id', props.canonical_id);
  }
  if (props.identity_status && props.identity_status !== 'canonical') {
    push('identity_status', props.identity_status);
  }

  return entries;
}
