// ============================================================
// Overwatch Dashboard — Shared Node Display Contract
// ============================================================

const FRIENDLY_TYPE_LABELS = {
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
};

function getNodeDisplayLabel(props = {}, fallbackId = '') {
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
  return props.label || fallbackId;
}

function getNodeIdentityEntries(props = {}, fallbackId = '') {
  const type = props.type || 'host';
  const entries = [];

  function push(key, value) {
    if (value === undefined || value === null || value === '') return;
    entries.push({ key, value });
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
  } else if (type === 'gpo' || type === 'ou' || type === 'subnet' || type === 'objective') {
    push(type === 'subnet' ? 'cidr' : 'label', props.cidr || props.label || props.objective_description);
  }

  if (props.canonical_id && props.canonical_id !== fallbackId) {
    push('canonical_id', props.canonical_id);
  }
  if (props.identity_status && props.identity_status !== 'canonical') {
    push('identity_status', props.identity_status);
  }

  return entries;
}

function getFriendlyNodeTypeLabel(type) {
  return FRIENDLY_TYPE_LABELS[type] || `${type}s`;
}

window.OverwatchNodeDisplay = {
  getNodeDisplayLabel,
  getNodeIdentityEntries,
  getFriendlyNodeTypeLabel,
};
