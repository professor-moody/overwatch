// ============================================================
// Graph Constants — ported from legacy graph.js
// ============================================================

export const NODE_COLORS: Record<string, string> = {
  host: '#6e9eff',
  service: '#5dcaa5',
  credential: '#f0b54a',
  user: '#afa9ec',
  group: '#ed93b1',
  domain: '#97c459',
  objective: '#f07b6e',
  certificate: '#85b7eb',
  ca: '#79b9f2',
  cert_template: '#c69bf7',
  pki_store: '#8f95a8',
  share: '#e0a86e',
  gpo: '#d08770',
  ou: '#7fb1a8',
  subnet: '#8fabb8',
  webapp: '#4ecdc4',
  vulnerability: '#e05555',
  cloud_identity: '#59b8e6',
  cloud_resource: '#e6a459',
  cloud_policy: '#a8d65c',
  cloud_network: '#8fabb8',
  // Identity tier (SSO / IdP).
  idp: '#9b8cf0',
  idp_application: '#b89af2',
  idp_principal: '#c9b3f5',
  api_endpoint: '#3fb5a8',
  // OSINT / external-recon tier (Phase 2).
  subdomain: '#b5d97a',
  asn: '#7a9cc6',
  organization: '#c0a35e',
  email: '#8fd6c4',
  mock_service: '#d97706',
};

export const NODE_BASE_SIZES: Record<string, number> = {
  host: 8,
  service: 5,
  credential: 7,
  user: 6,
  group: 7,
  domain: 14,
  objective: 10,
  certificate: 6,
  ca: 8,
  cert_template: 7,
  pki_store: 5,
  share: 5,
  gpo: 5,
  ou: 5,
  subnet: 5,
  webapp: 7,
  vulnerability: 6,
  cloud_identity: 7,
  cloud_resource: 7,
  cloud_policy: 5,
  cloud_network: 6,
  // Identity tier (SSO / IdP).
  idp: 10,
  idp_application: 6,
  idp_principal: 6,
  api_endpoint: 4,
  // OSINT / external-recon tier (Phase 2).
  subdomain: 7,
  asn: 9,
  organization: 11,
  email: 5,
  mock_service: 7,
};

export const EDGE_CATEGORIES: Record<string, string> = {
  // Network
  REACHABLE: '#6e9eff', RUNS: '#6e9eff',
  // Access
  ADMIN_TO: '#5dcaa5', HAS_SESSION: '#5dcaa5', CAN_RDPINTO: '#5dcaa5', CAN_PSREMOTE: '#5dcaa5',
  // Credentials
  VALID_ON: '#f0b54a', OWNS_CRED: '#f0b54a', POTENTIAL_AUTH: '#f0b54a', TESTED_CRED: '#f0b54a',
  // AD Attack Paths
  CAN_DCSYNC: '#f07b6e', WRITEABLE_BY: '#f07b6e',
  GENERIC_ALL: '#f07b6e', GENERIC_WRITE: '#f07b6e', WRITE_OWNER: '#f07b6e',
  WRITE_DACL: '#f07b6e', ADD_MEMBER: '#f07b6e', FORCE_CHANGE_PASSWORD: '#f07b6e',
  ALLOWED_TO_ACT: '#f07b6e',
  // ADCS
  CAN_ENROLL: '#afa9ec', ESC1: '#afa9ec', ESC2: '#afa9ec', ESC3: '#afa9ec',
  ESC4: '#afa9ec', ESC5: '#afa9ec', ESC6: '#afa9ec', ESC7: '#afa9ec', ESC8: '#afa9ec',
  ESC9: '#afa9ec', ESC10: '#afa9ec', ESC11: '#afa9ec', ESC13: '#afa9ec',
  ISSUED_BY: '#6b6977', OPERATES_CA: '#6b6977',
  // Delegation
  DELEGATES_TO: '#7c6cf0', CAN_DELEGATE_TO: '#7c6cf0',
  // Roasting
  AS_REP_ROASTABLE: '#e68a50', KERBEROASTABLE: '#e68a50',
  // Lateral movement
  RELAY_TARGET: '#ed93b1', NULL_SESSION: '#ed93b1',
  // Credential derivation / provenance
  DERIVED_FROM: '#ff8c42', DUMPED_FROM: '#ff8c42',
  // Credential reuse
  SHARED_CREDENTIAL: '#ff8c42',
  // ACL-derived
  CAN_READ_LAPS: '#f07b6e', CAN_READ_GMSA: '#f07b6e', RBCD_TARGET: '#f07b6e',
  // Domain
  MEMBER_OF: '#6b6977', MEMBER_OF_DOMAIN: '#6b6977', TRUSTS: '#97c459',
  SAME_DOMAIN: '#6b6977',
  // Web application surface
  HOSTS: '#6e9eff', AUTHENTICATED_AS: '#f0b54a',
  VULNERABLE_TO: '#e05555', EXPLOITS: '#e05555',
  // Cloud infrastructure
  ASSUMES_ROLE: '#59b8e6', HAS_POLICY: '#59b8e6',
  POLICY_ALLOWS: '#a8d65c', MANAGED_BY: '#a8d65c',
  EXPOSED_TO: '#6e9eff', RUNS_ON: '#6e9eff',
  // Objective
  PATH_TO_OBJECTIVE: '#f0b54a',
  // Operator-controlled infrastructure
  OPERATED_BY: '#d97706', BAITED: '#d97706', RELAYED_VIA: '#d97706',
  // Generic
  RELATED: '#6b6977',
};

export const DEFAULT_EDGE_COLOR = 'rgba(110,158,255,0.25)';
export const INFERRED_EDGE_COLOR = 'rgba(175,169,236,0.25)';

export const HIGH_SIGNAL_NODE_TYPES = new Set([
  'domain', 'host', 'objective', 'credential', 'certificate', 'ca', 'subnet', 'cert_template',
]);

export const DETAIL_NODE_TYPES = new Set(['service', 'share']);

export const SUPPORTING_NODE_TYPES = new Set([
  'user', 'group', 'ou', 'gpo', 'pki_store',
]);

export const ZOOM_REVEAL_THRESHOLDS = {
  detail: 0.24,
  supporting: 0.12,
} as const;

export const LAYOUT_MAX_ITERATIONS = 600;
export const LAYOUT_ITERS_PER_FRAME = 5;
export const DRAG_THRESHOLD_PX = 6;

export const FILTER_PRESETS: Record<string, string[]> = {
  host: ['host', 'domain', 'objective', 'credential', 'certificate'],
  domain: ['domain', 'host', 'objective', 'credential', 'certificate', 'user'],
  objective: ['objective', 'host', 'domain', 'credential'],
  credential: ['credential', 'user', 'host', 'domain', 'objective', 'certificate'],
  certificate: ['certificate', 'credential', 'host', 'domain', 'objective'],
  ca: ['ca', 'cert_template', 'certificate', 'domain', 'host', 'objective'],
  cert_template: ['cert_template', 'ca', 'certificate', 'domain', 'user', 'group'],
  pki_store: ['pki_store', 'ca', 'cert_template', 'domain'],
  service: ['service', 'host', 'domain', 'objective', 'share'],
  share: ['share', 'host', 'domain', 'objective', 'service'],
  user: ['user', 'credential', 'domain', 'host', 'objective', 'group'],
  group: ['group', 'user', 'domain', 'host', 'objective'],
  ou: ['ou', 'domain', 'group', 'user'],
  gpo: ['gpo', 'ou', 'domain', 'host', 'user'],
  subnet: ['subnet', 'host', 'domain', 'objective'],
};

export interface FocusPreset {
  nodeTypes: string[];
  edgeHighlight: Set<string>;
}

export const FOCUS_PRESETS: Record<string, FocusPreset> = {
  'AD Attack Surface': {
    nodeTypes: ['domain', 'host', 'user', 'group', 'credential', 'objective'],
    edgeHighlight: new Set([
      'ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE',
      'CAN_DCSYNC', 'WRITEABLE_BY', 'GENERIC_ALL', 'GENERIC_WRITE',
      'WRITE_OWNER', 'WRITE_DACL', 'ADD_MEMBER', 'FORCE_CHANGE_PASSWORD',
      'ALLOWED_TO_ACT', 'CAN_READ_LAPS', 'CAN_READ_GMSA', 'RBCD_TARGET',
      'DELEGATES_TO', 'CAN_DELEGATE_TO',
    ]),
  },
  'Credential Chain': {
    nodeTypes: ['credential', 'user', 'host', 'service', 'domain'],
    edgeHighlight: new Set([
      'VALID_ON', 'OWNS_CRED', 'DERIVED_FROM', 'DUMPED_FROM',
      'SHARED_CREDENTIAL', 'HAS_SESSION', 'TESTED_CRED', 'POTENTIAL_AUTH',
    ]),
  },
  'ADCS/PKI': {
    nodeTypes: ['ca', 'cert_template', 'domain', 'user', 'group', 'certificate', 'pki_store'],
    edgeHighlight: new Set([
      'CAN_ENROLL', 'ISSUED_BY', 'OPERATES_CA',
      'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8',
      'ESC9', 'ESC10', 'ESC11', 'ESC13',
    ]),
  },
  'Cloud Identity': {
    nodeTypes: ['cloud_identity', 'cloud_resource', 'cloud_policy', 'cloud_network', 'host', 'service'],
    edgeHighlight: new Set([
      'ASSUMES_ROLE', 'HAS_POLICY', 'POLICY_ALLOWS',
      'EXPOSED_TO', 'RUNS_ON', 'MANAGED_BY',
    ]),
  },
};
