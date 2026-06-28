// ============================================================
// Overwatch — Core Type Definitions
// ============================================================

import { z } from 'zod';
import { isValidCidr } from './services/cidr.js';

// --- Node Types ---

export const NODE_TYPES = [
  'host', 'service', 'domain', 'user', 'group', 'credential',
  'share', 'certificate', 'ca', 'cert_template', 'pki_store', 'gpo', 'ou', 'subnet', 'objective',
  'webapp', 'vulnerability', 'api_endpoint',
  'cloud_identity', 'cloud_resource', 'cloud_policy', 'cloud_network',
  // Identity tier (Phase 1 of enterprise readiness — SSO / IdP modeling).
  // These are first-class so SSO-fed engagements can model the auth surface
  // distinctly from cloud_identity (which models AWS IAM / Azure RBAC).
  'idp', 'idp_application', 'idp_principal',
  'mock_service',
  // OSINT / external-recon tier (Phase 2A). Passive external surface modeled
  // distinctly from the internal/AD topology: DNS names, netblocks, the owning
  // organization, and harvested email/people. `email` is the person anchor
  // (person_name is an optional field); breaches are evidence, not nodes.
  'subdomain', 'asn', 'organization', 'email'
] as const;
export type NodeType = typeof NODE_TYPES[number];
export const nodeTypeSchema = z.enum(NODE_TYPES);
const nonEmptyString = z.string().min(1);

export interface NodeProperties {
  // Common
  id: string;
  type: NodeType;
  label: string;
  discovered_by?: string;       // agent id that found this
  discovered_at: string;        // ISO timestamp
  first_seen_at?: string;       // first direct observation time
  last_seen_at?: string;        // most recent direct observation time
  confirmed_at?: string;        // node-level direct confirmation time
  sources?: string[];           // unique agents that contributed to this node
  confidence: number;           // 0.0 - 1.0
  notes?: string;
  identity_status?: 'canonical' | 'unresolved' | 'superseded';
  identity_family?: string;
  canonical_id?: string;
  identity_markers?: string[];
  superseded_by?: string;

  // Host
  ip?: string;
  hostname?: string;
  os?: string;
  os_version?: string;
  alive?: boolean;
  edr?: string;
  domain_joined?: boolean;
  // Linux host enrichment
  users_enumerated?: boolean;
  suid_checked?: boolean;
  has_suid_root?: boolean;
  suid_binaries?: string[];
  cron_checked?: boolean;
  cron_jobs?: string[];
  capabilities_checked?: boolean;
  interesting_capabilities?: string[];
  docker_socket_accessible?: boolean;
  kernel_version?: string;
  writable_paths?: string[];

  // Service
  port?: number;
  protocol?: string;            // tcp/udp
  service_name?: string;        // smb, http, ldap, kerberos, mssql, etc.
  version?: string;
  banner?: string;
  linked_servers?: string[];    // MSSQL linked server hostnames
  // P2: CVE research bookkeeping. Set by the research_cve tool when a versioned
  // service has been researched (even if nothing was found), so the cve_research
  // frontier item stops regenerating. cve_check_summary holds the agent's note.
  cve_checked_at?: string;
  cve_check_summary?: string;

  // Domain
  domain_name?: string;
  functional_level?: string;
  password_policy?: { min_pwd_age?: number; max_pwd_age?: number; pwd_history_length?: number; complexity_enabled?: boolean; min_pwd_length?: number };
  lockout_policy?: { lockout_threshold?: number; lockout_duration?: number; lockout_observation_window?: number };

  // User / Group
  username?: string;
  display_name?: string;
  enabled?: boolean;
  privileged?: boolean;
  sid?: string;
  member_of?: string[];         // group IDs
  pwd_last_set?: string;        // ISO timestamp — last password change (from LDAP pwdLastSet)

  // Credential
  cred_type?: 'plaintext' | 'cleartext' | 'ntlm' | 'ntlmv1_challenge' | 'ntlmv2_challenge' | 'aes256' | 'kerberos_tgt' | 'kerberos_tgs' | 'kerberos_asrep' | 'certificate' | 'token' | 'ssh_key' | 'oidc_token' | 'saml' | 'oauth_secret' | 'pat' | 'app_password' | 'session_cookie';
  cred_value?: string;          // hash or redacted reference
  cred_hash?: string;           // normalized hash material for cracked/captured creds
  cred_user?: string;           // associated user node id
  cred_domain?: string;
  cred_domain_inferred?: boolean;
  cred_domain_source?: 'explicit' | 'graph_inference' | 'parser_context';
  cred_material_kind?:
    | 'plaintext_password' | 'ntlm_hash' | 'ntlmv1_challenge' | 'ntlmv2_challenge'
    | 'aes256_key' | 'kerberos_tgt' | 'kerberos_tgs' | 'kerberos_asrep'
    | 'certificate' | 'token' | 'ssh_key'
    // Phase 1 (enterprise): SSO / OIDC / SAML / OAuth / session-cookie tokens.
    // Each carries different semantics from a password (audience-bound,
    // scope-bound, sometimes refreshable). Treat them distinctly so coverage,
    // expiry, and MFA reasoning are honest.
    | 'oidc_id_token' | 'oidc_access_token' | 'oidc_refresh_token'
    | 'saml_assertion' | 'oauth_client_secret' | 'pat' | 'app_password' | 'session_cookie';
  cred_usable_for_auth?: boolean;
  cred_evidence_kind?: 'capture' | 'crack' | 'dump' | 'spray_success' | 'manual';
  cred_is_default_guess?: boolean;
  observed_from_ip?: string;
  valid_until?: string;         // ISO timestamp — expiry for time-limited creds (TGT/TGS, tokens, certs)
  rotated_at?: string;          // ISO timestamp — when credential was observed as changed
  stale_at?: string;            // ISO timestamp — when credential became stale
  credential_status?: 'active' | 'stale' | 'expired' | 'rotated';
  dump_source_host?: string;
  // Token-specific (Phase 1 enterprise readiness): bearer / OIDC / SAML
  // tokens are audience-bound and scope-bound — a token valid for the
  // Microsoft Graph API isn't valid for AWS STS even if both sit behind
  // the same IdP. Track these so coverage, frontier, and inference rules
  // can reason about token boundaries instead of treating every token
  // like a password.
  /** Token `aud` claim or comparable: which API/app the token authenticates against. */
  cred_audience?: string;
  /** OAuth scopes / SAML attributes the token grants. */
  cred_scopes?: string[];
  /** Token `iss` claim or back-reference to an `idp` node id. */
  cred_issuer?: string;
  /** Token-specific expiry (`exp` claim) — distinct from `valid_until` so
   *  legacy creds don't lose their existing semantics. */
  cred_token_expires_at?: string;
  /** True when the IdP / app requires MFA to use this credential. */
  cred_mfa_required?: boolean;
  /** True when MFA pass-through has been observed (AiTM-captured cookie,
   *  step-up auth completed, …). When `cred_mfa_required` is true and this
   *  is false, the credential is NOT usable_for_auth even if all other
   *  fields say it should be. */
  cred_mfa_satisfied?: boolean;

  // Share
  share_name?: string;
  share_path?: string;
  readable?: boolean;
  writable?: boolean;
  no_root_squash?: boolean;

  // Certificate
  template_name?: string;
  ca_name?: string;
  ca_kind?: 'enterprise_ca' | 'root_ca' | 'aia_ca';
  pki_store_kind?: 'ntauth_store' | 'issuance_policy';
  eku?: string[];
  enrollee_supplies_subject?: boolean;
  any_purpose?: boolean;
  enrollment_agent?: boolean;
  san_flag_enabled?: boolean;
  http_enrollment?: boolean;
  ct_flag_no_security_extension?: boolean;
  strong_cert_binding_enforcement?: number;
  certificate_mapping_methods?: string[];
  enforce_encrypt_icert_request?: boolean;
  issuance_policy_oid?: string;
  issuance_policy_group_link?: string;

  // Service — TLS enrichment
  tls_version?: string;
  cipher_suites?: string[];
  cert_subject?: string;
  cert_expiry?: string;
  cert_issuer?: string;

  // Subnet
  subnet_cidr?: string;

  // Cloud resource metadata
  provider_resource_id?: string;
  public_access_block_incomplete?: boolean;

  // Webapp
  url?: string;
  technology?: string;
  framework?: string;
  auth_type?: string;
  has_api?: boolean;
  cms_type?: string;

  // API Endpoint
  path?: string;
  method?: string;
  auth_required?: boolean;
  response_type?: string;

  // Vulnerability
  cve?: string;
  cvss?: number;
  vuln_type?: string;
  exploitable?: boolean;
  exploit_available?: boolean;
  affected_component?: string;

  // Cloud Identity (IAM user, role, service account, managed identity)
  provider?: 'aws' | 'azure' | 'gcp';
  arn?: string;
  principal_type?: 'user' | 'role' | 'service_account' | 'managed_identity' | 'app' | 'service' | 'federated' | 'canonical' | 'wildcard';
  /** AWS-specific principal classification preserved from the trust policy
   * (Principal.AWS / Service / Federated / CanonicalUser / "*"). */
  principal_kind?: 'aws' | 'service' | 'federated' | 'canonical' | 'wildcard';
  /** Raw principal value when it isn't a real ARN (e.g. lambda.amazonaws.com). */
  principal_value?: string;
  policies?: string[];
  mfa_enabled?: boolean;
  last_used?: string;
  cloud_account?: string;
  policies_enumerated?: boolean;

  // Cloud Resource (S3 bucket, EC2, Lambda, Azure VM, etc.)
  resource_type?: string;
  region?: string;
  public?: boolean;
  encrypted?: boolean;
  tags?: Record<string, string>;
  imdsv2_required?: boolean;

  // Cloud Policy (IAM policy, RBAC role assignment)
  policy_name?: string;
  effect?: 'allow' | 'deny';
  actions?: string[];
  resources?: string[];
  conditions?: string[];

  // Cloud Network (VPC, security group, subnet, firewall rule)
  network_type?: 'vpc' | 'security_group' | 'subnet' | 'firewall_rule';
  ingress_rules?: string[];
  egress_rules?: string[];

  // Objective
  objective_description?: string;
  objective_achieved?: boolean;
  objective_achieved_at?: string;

  // High-Value Target (populated by BloodHoundPathEnricher)
  hvt?: boolean;
  hvt_reason?: string;

  // ============================================================
  // Identity tier (Phase 1 of enterprise readiness)
  // ============================================================
  //
  // `idp` — top-level identity provider (Okta org, Entra tenant, …).
  // `idp_application` — registered application within an IdP.
  // `idp_principal` — federated user/group/service identity at the IdP.
  //
  // These are deliberately distinct from `cloud_identity`. cloud_identity
  // models AWS IAM, Azure RBAC, GCP IAM principals — entities that hold
  // policies and ASSUMES_ROLE edges. idp_* models the SSO surface that
  // ISSUES_TOKENS_FOR cloud_identity (and federates with on-prem `domain`).

  /** IdP node: which kind of provider this is. */
  idp_kind?: 'okta' | 'entra' | 'auth0' | 'ping' | 'generic_oidc' | 'generic_saml' | 'ci_github_actions' | 'ci_gitlab' | 'ci_circleci' | 'github_org';
  /** IdP node: tenant / org identifier (e.g. Okta org subdomain, Entra tenant GUID). */
  tenant_id?: string;
  /** IdP node: OIDC issuer URL (https://login.microsoftonline.com/<tenant>/v2.0). */
  issuer_url?: string;
  /** IdP node: how the IdP was discovered (parser name, manual report, …). */
  discovered_via?: string;
  /** IdP node: federation summary (PHS / PTA / federated, on-prem sync state). */
  federation_mode?: 'cloud_only' | 'password_hash_sync' | 'pass_through_auth' | 'federated';

  /** idp_application: OIDC client_id. */
  client_id?: string;
  /** idp_application: human-readable app name. */
  app_name?: string;
  /** idp_application: count of assigned principals (sized by enumeration). */
  assigned_user_count?: number;
  /** idp_application: OAuth grant types the app supports. */
  grant_types?: string[];
  /** idp_application: token `aud` claim / allowed audiences. */
  audience?: string;
  /** idp_application: redirect URIs registered with the IdP. */
  redirect_uris?: string[];
  /** idp_application: parent IdP node id (back-reference). */
  idp_id?: string;
  /** idp_application: scopes the app is allowed to request. */
  app_scopes?: string[];
  /** idp_application: requires MFA for sign-in (from conditional access / sign-on policy). */
  app_mfa_required?: boolean;
  /**
   * CI/OIDC trust subject claim pattern. For GitHub Actions this is
   * the value of the `token.actions.githubusercontent.com:sub`
   * StringLike/StringEquals condition in the IAM trust policy
   * (e.g. `repo:acme/webapp:ref:refs/heads/main` or `repo:acme/*`).
   * Wildcards outside a domain-bounded position (e.g. `repo:*`) are
   * flagged as overly broad by the CI_TRUST_WILDCARD inference rule.
   */
  sub_claim_pattern?: string;

  /** idp_principal: IdP-internal user/group identifier. */
  idp_user_id?: string;
  /** idp_principal: principal kind at the IdP. */
  idp_principal_kind?: 'user' | 'group' | 'service_principal' | 'app_role';
  /** idp_principal: configured MFA factors (totp, webauthn, sms, push, …). */
  mfa_methods?: string[];
  /** idp_principal: MFA enforced on this principal by IdP policy. */
  mfa_required?: boolean;
  /** idp_principal: app ids this principal is assigned to / can sign into. */
  assigned_apps?: string[];
  /** idp_principal: UPN / email claim used to correlate with on-prem AD. */
  upn?: string;

  // Mock service (operator-controlled decoy / listener / relay)
  mock_purpose?: 'fake_ldap' | 'responder' | 'ntlmrelayx' | 'redirector' | 'reverse_shell_catcher' | 'http_capture' | 'smb_capture' | 'other';
  bind_host?: string;
  bind_port?: number;
  bound_session_id?: string;
  bound_process_id?: number;
  started_at?: string;
  stopped_at?: string;
  opsec_loud?: boolean;

  // OSINT / external-recon tier (Phase 2A)
  // subdomain
  subdomain_name?: string;
  parent_domain?: string;
  resolved_ips?: string[];
  dns_records?: string[];
  wildcard?: boolean;
  takeover_candidate?: boolean;
  // asn (netblock)
  asn_number?: number;
  asn_org?: string;
  cidr_ranges?: string[];
  registry?: string;
  // organization
  org_name?: string;
  domains_owned?: string[];
  industry?: string;
  // email (person anchor; breaches recorded as evidence, not nodes)
  email_address?: string;
  person_name?: string;
  email_source?: 'breach' | 'harvest' | 'dork' | 'manual' | 'other';
  breach_names?: string[];
  email_verified?: boolean;

  // Extensible
  [key: string]: unknown;
}

// --- Edge Types ---

export const EDGE_TYPES = [
  // Network
  'REACHABLE', 'RUNS',
  // Domain membership
  'MEMBER_OF', 'MEMBER_OF_DOMAIN',
  // Access
  'ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE',
  // Credential relationships
  'VALID_ON', 'OWNS_CRED', 'DERIVED_FROM', 'DUMPED_FROM',
  // AD attack paths
  'CAN_DCSYNC', 'CAN_GET_CHANGES', 'CAN_GET_CHANGES_ALL',
  'DELEGATES_TO', 'WRITEABLE_BY', 'GENERIC_ALL', 'OWNS',
  'GENERIC_WRITE', 'WRITE_OWNER', 'WRITE_DACL', 'ADD_MEMBER',
  'FORCE_CHANGE_PASSWORD', 'ALLOWED_TO_ACT',
  // ADCS
  'CAN_ENROLL', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC10', 'ESC11', 'ESC12', 'ESC13', 'ESC15',
  'ISSUED_BY', 'OPERATES_CA', 'MANAGE_CA', 'MANAGE_CERTIFICATES',
  // Trust
  'TRUSTS', 'SAME_DOMAIN',
  // Roasting
  'AS_REP_ROASTABLE', 'KERBEROASTABLE',
  // Delegation
  'CAN_DELEGATE_TO', 'CAN_CAPTURE_TGT_FROM',
  // ACL-derived
  'CAN_READ_LAPS', 'CAN_READ_GMSA', 'RBCD_TARGET',
  // Credential reuse
  'SHARED_CREDENTIAL',
  // Lateral movement
  'RELAY_TARGET', 'NULL_SESSION', 'POTENTIAL_AUTH', 'TESTED_CRED',
  // Web application surface
  'HOSTS', 'AUTHENTICATED_AS', 'VULNERABLE_TO', 'EXPLOITS', 'HAS_ENDPOINT', 'AUTH_BYPASS',
  // Cloud infrastructure
  'ASSUMES_ROLE', 'HAS_POLICY', 'POLICY_ALLOWS', 'EXPOSED_TO', 'RUNS_ON', 'MANAGED_BY',
  // Cloud identity relationships
  // SERVICE_PRINCIPAL_FOR: SP node → app-registration node it represents.
  // This is a directory binding, NOT an RBAC role assumption (which is
  // what ASSUMES_ROLE implies). Modeling it separately keeps attack-path
  // scoring honest about what a service principal can actually do.
  'SERVICE_PRINCIPAL_FOR',
  // Identity tier (Phase 1 enterprise readiness). Distinct from cloud
  // identity: these model SSO / IdP topology rather than IAM/RBAC.
  // FEDERATES_WITH:        idp ↔ domain  (Okta org federates with on-prem AD)
  // AUTHENTICATES_VIA:     webapp / cloud_resource → idp_application
  // ASSIGNED_TO_APP:       idp_principal → idp_application
  // MFA_REQUIRED_FOR:      idp_principal → idp_application (CA / sign-on policy)
  // ISSUES_TOKENS_FOR:     idp_application → cloud_identity (OIDC federation)
  // BACKED_BY:             webapp → cloud_resource (cross-tier app/backend link)
  // CAN_REACH:             webapp → cloud_resource (inferred reachability,
  //                        e.g. SSRF reaching IMDS); intentionally weaker than
  //                        BACKED_BY which is a declared linkage.
  // VALID_FOR_APP:         credential → idp_application (token works for app)
  // VALID_FOR_IDP_PRINCIPAL: credential → idp_principal (cred grants access
  //                        to a federated principal — hybrid identity pivot).
  'FEDERATES_WITH', 'AUTHENTICATES_VIA', 'ASSIGNED_TO_APP',
  'MFA_REQUIRED_FOR', 'ISSUES_TOKENS_FOR',
  'BACKED_BY', 'CAN_REACH',
  'VALID_FOR_APP', 'VALID_FOR_IDP_PRINCIPAL',
  // Operator-controlled infrastructure (mock_service / decoy listeners)
  'OPERATED_BY', 'BAITED', 'RELAYED_VIA',
  // OSINT / external recon (Phase 2A). External-surface relationships:
  // SUBDOMAIN_OF:   subdomain → domain (DNS hierarchy)
  // RESOLVES_TO:    subdomain → host  (DNS A/AAAA resolution)
  // IN_NETBLOCK:    host → asn        (IP falls in an announced netblock)
  // OWNS_ASSET:     organization → domain | asn  (distinct from the AD `OWNS`)
  // AFFILIATED_WITH: email → organization (harvested person/email ↔ org)
  'SUBDOMAIN_OF', 'RESOLVES_TO', 'IN_NETBLOCK', 'OWNS_ASSET', 'AFFILIATED_WITH',
  // Objective
  'PATH_TO_OBJECTIVE',
  // Generic
  'RELATED'
] as const;
export type EdgeType = typeof EDGE_TYPES[number];
export const edgeTypeSchema = z.enum(EDGE_TYPES);

export interface EdgeProperties {
  type: EdgeType;
  confidence: number;           // 0.0 = hypothesis, 1.0 = confirmed
  discovered_by?: string;
  discovered_at: string;
  tested?: boolean;
  tested_at?: string;
  test_result?: 'success' | 'failure' | 'partial' | 'error';
  opsec_noise?: number;         // 0.0 (silent) to 1.0 (extremely loud)
  notes?: string;
  // Inference lifecycle tracking
  inferred_by_rule?: string;    // rule ID that created this edge
  inferred_at?: string;         // ISO timestamp when inferred
  confirmed_at?: string;        // ISO timestamp when confidence raised to 1.0
  // Web attack path annotations
  auth_bypass?: boolean;        // AUTHENTICATED_AS edge bypasses normal auth
  session_type?: string;        // session/cookie/bearer token type
  // Pivot tracking
  via_pivot?: string;           // node ID of principal enabling pivot (on REACHABLE edges)
  [key: string]: unknown;
}

// --- Parser Context ---

export interface ParseContext {
  domain?: string;
  source_host?: string;
  domain_aliases?: Record<string, string>;
  // Cloud context (Sprint 11+)
  cloud_account?: string;
  cloud_region?: string;
  // Network context (Sprint 9+)
  network_zone?: string;
  [key: string]: unknown;
}

// --- Engagement Config ---

export interface EngagementObjective {
  id: string;
  description: string;
  target_node_type?: NodeType;
  target_criteria?: Record<string, unknown>;  // match against node props
  achievement_edge_types?: EdgeType[];        // custom edge types that count as "obtained" (default: HAS_SESSION, ADMIN_TO, OWNS_CRED)
  achieved: boolean;
  achieved_at?: string;
}

export type ApprovalMode = 'auto-approve' | 'approve-critical' | 'approve-all';

export interface OpsecProfile {
  name: string;                  // 'ctf' | 'pentest' | 'redteam' | 'assumed_breach'
  enabled?: boolean;             // default false — when false, all OPSEC enforcement (vetoes, blacklist, noise budget, prompt sections) is skipped
  max_noise: number;             // hard ceiling, 0.0-1.0 (only enforced when enabled)
  time_window?: {
    start_hour: number;          // 0-23
    end_hour: number;
  };
  blacklisted_techniques?: string[];
  notes?: string;
  approval_mode?: ApprovalMode;
  approval_timeout_ms?: number;  // default: 300000 (5 min)
}

/**
 * Compiled operator policy — durable, inspectable rules the approval gate +
 * dispatcher consult, instead of operator preferences living as prose in the
 * system prompt (which evaporate on compaction and can't be audited). Lives on
 * EngagementConfig; editable from the dashboard Settings panel.
 *
 * Invariant: policy may only TIGHTEN, never weaken, what phase∪engagement already
 * require (see getEffectiveApprovalConfig — a looser rule is ignored). Scope is
 * engagement-GLOBAL this phase (a per-/24 cap is about target blast radius, which
 * doesn't care which campaign is hammering the subnet).
 */
export interface ApprovalRule {
  match: {
    host_class?: 'in_scope' | 'unverified' | 'excluded';
    network?: string;    // CIDR; matched against the action's target IP
    technique?: string;
  };
  require: ApprovalMode;
}

export interface OperatorPolicy {
  version: 1;
  /** Ordered; the STRICTEST matching rule wins (never weakens phase/engagement). */
  approval_rules?: ApprovalRule[];
  dispatch_limits?: {
    /** Max concurrently-running target-facing agents per /24 (0/undefined = unlimited). */
    max_per_subnet?: number;
    /** Max concurrently-running target-facing agents per resolved host IP. */
    max_per_target?: number;
    /** Override which archetypes count as "target-facing" (default: those with the EXECUTE surface). */
    target_facing_archetypes?: string[];
  };
}

export interface EngagementConfig {
  id: string;
  name: string;
  created_at: string;
  template?: string;
  profile?: LabProfile;
  scope: {
    cidrs: string[];
    domains: string[];
    exclusions: string[];
    hosts?: string[];
    aws_accounts?: string[];
    azure_subscriptions?: string[];
    gcp_projects?: string[];
    url_patterns?: string[];   // glob-like: "*.example.com", "app.corp.io/api/*"
    /**
     * Phase 3 (enterprise): explicit cross-tier linkage. When the operator
     * knows which cloud account / IdP backs a given app, declaring the
     * link here lets CrossTierCorrelator emit BACKED_BY / AUTHENTICATES_VIA
     * edges automatically. Without it, the correlator stays silent — we
     * never invent linkage that wasn't explicitly declared.
     */
    cross_tier_links?: Array<{
      url_pattern?: string;             // glob over webapp URL
      aws_account?: string;             // AWS account id
      azure_subscription?: string;      // Azure subscription id
      gcp_project?: string;             // GCP project id
      cloud_resource_prefix?: string;   // e.g. "arn:aws:lambda:us-east-1:123:function:client-api-*"
      idp_kind?: 'okta' | 'entra' | 'auth0' | 'ping' | 'generic_oidc' | 'generic_saml' | 'ci_github_actions' | 'ci_gitlab' | 'ci_circleci' | 'github_org';
      tenant_id?: string;
      notes?: string;
    }>;
  };
  objectives: EngagementObjective[];
  opsec: OpsecProfile;
  community_resolution?: number;  // Louvain resolution (default 1.0, lower → fewer/larger communities)
  failure_patterns?: { technique: string; target_pattern?: string; warning: string }[];  // Retrospective feedback for validation
  phases?: EngagementPhase[];     // ordered engagement phases with entry/exit criteria
  max_prompt_tokens?: number;     // Token budget for system prompt generation (default 8000)
  iam_assume_depth?: number;      // Max ASSUMES_ROLE hops for IAM simulation (default 5)
  hash_chain_enabled?: boolean;   // Enable tamper-evident hash chain over agent/system events (default TRUE for new engagements; legacy engagements without the flag set keep their original behavior)
  /** Optional signing key identifier used to sign chain checkpoints. Implementation stub today. */
  engagement_signing_key_id?: string;
  /**
   * P1.2: per-engagement nonce (32 random bytes hex-encoded). Generated
   * once at engagement creation; persisted; never rotated. Presence of
   * this field flips action_id generation from uuidv4 to a deterministic
   * sha256-derived form, which is what makes byte-reproducible replay
   * possible. Legacy engagements that pre-date P1.2 leave this undefined
   * and continue to use uuidv4 forever (strict migration).
   */
  engagement_nonce?: string;
  /**
   * P4.2: where sub-agents run.
   *  - 'in_process' (default) — current behavior: sub-agents share memory
   *    with the engine and call MCP tools directly.
   *  - 'process' — sub-agents run in a child Node process and communicate
   *    over JSON-over-stdio per `subagent-ipc.ts`. Per the scoping
   *    decision, this is scaffolded and proven on the recon-scoping
   *    role; other roles fall back to in_process even when the flag
   *    is set, until follow-up work fills out coverage.
   */
  subagent_isolation?: 'in_process' | 'process';
  /**
   * P2: CVE research. When enabled (default), `cve_research` frontier items are
   * dispatched to a headless web-research sub-agent. Air-gapped engagements set
   * `enabled: false` to forbid web egress — those items then route to `manual`.
   */
  cve_research?: {
    enabled?: boolean;
  };
  /** In-process JSON-RPC tape recorder. Off by default. */
  tape?: {
    enabled?: boolean;
    dir?: string;
    file?: string;
  };
  /**
   * Redacted DSN recorded for display purposes only. The live connection is
   * session-scoped (in-process pool); re-run connect_postgres after restart.
   * Never contains credentials — a redacted placeholder is stored here.
   */
  postgres_dsn?: string;
  /** Compiled operator policy: durable approval/dispatch rules the engine consults. */
  operator_policy?: OperatorPolicy;
}

export const engagementObjectiveSchema = z.object({
  id: nonEmptyString,
  description: nonEmptyString,
  target_node_type: nodeTypeSchema.optional(),
  target_criteria: z.record(z.unknown()).optional(),
  achievement_edge_types: z.array(edgeTypeSchema).optional(),
  achieved: z.boolean(),
  achieved_at: z.string().optional(),
});

export const opsecProfileSchema = z.object({
  name: nonEmptyString,
  enabled: z.boolean().optional(),
  max_noise: z.number().min(0).max(1),
  time_window: z.object({
    start_hour: z.number().int().min(0).max(23),
    end_hour: z.number().int().min(0).max(23),
  }).optional(),
  blacklisted_techniques: z.array(z.string()).optional(),
  notes: z.string().optional(),
  approval_mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional(),
  approval_timeout_ms: z.number().int().min(1000).optional(),
});

/**
 * Strict, partial variant of opsecProfileSchema used by routes that accept
 * partial updates from clients (e.g. the dashboard SettingsPanel). Strict
 * mode rejects unknown keys with a 400 — this caught the long-standing
 * dashboard drift where the client sent `approval_timeout_seconds` and
 * `time_window: {start, end}` and the server silently dropped them.
 */
export const opsecPartialUpdateSchema = opsecProfileSchema.partial().strict();

export const operatorPolicySchema = z.object({
  version: z.literal(1),
  approval_rules: z.array(z.object({
    match: z.object({
      host_class: z.enum(['in_scope', 'unverified', 'excluded']).optional(),
      network: z.string().optional(),
      technique: z.string().optional(),
    }).strict(),
    require: z.enum(['auto-approve', 'approve-critical', 'approve-all']),
  }).strict()).optional(),
  dispatch_limits: z.object({
    max_per_subnet: z.number().int().min(1).optional(),
    max_per_target: z.number().int().min(1).optional(),
    target_facing_archetypes: z.array(z.string()).optional(),
  }).strict().optional(),
}).strict();

/** Strict variant for the config PATCH route — rejects unknown keys with a 400. */
export const operatorPolicyUpdateSchema = operatorPolicySchema;

const campaignStrategySchema = z.enum(['credential_spray', 'enumeration', 'post_exploitation', 'network_discovery', 'custom']);

const phaseCriterionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('always') }),
  z.object({ type: z.literal('phase_completed'), phase_id: nonEmptyString }),
  z.object({ type: z.literal('objective_achieved'), objective_id: nonEmptyString }),
  z.object({ type: z.literal('node_count'), node_type: nodeTypeSchema, min: z.number().int().min(1) }),
  z.object({ type: z.literal('access_level'), min_level: z.enum(['user', 'local_admin', 'domain_admin']) }),
]);

const engagementPhaseSchema = z.object({
  id: nonEmptyString,
  name: nonEmptyString,
  order: z.number().int().min(0),
  strategies: z.array(campaignStrategySchema).default([]),
  entry_criteria: z.array(phaseCriterionSchema).default([]),
  exit_criteria: z.array(phaseCriterionSchema).default([]),
  // P4.1: per-phase policy overrides. When the engagement is in a phase
  // that supplies an override, validateAction and the approval queue
  // prefer the override over the engagement-level config. Use sparingly:
  // tighter ceilings during exploitation, looser auto-approve during recon.
  opsec_overrides: opsecProfileSchema.partial().optional(),
  approval_overrides: z.object({
    mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional(),
    blacklisted_techniques: z.array(z.string()).optional(),
  }).optional(),
});

export const engagementConfigSchema = z.object({
  id: nonEmptyString,
  name: nonEmptyString,
  created_at: z.string().min(1).refine(
    (val) => !isNaN(Date.parse(val)),
    { message: 'created_at must be a valid ISO-8601 date string' },
  ),
  template: z.string().optional(),
  profile: z.enum(['goad_ad', 'single_host', 'network', 'web_app', 'cloud', 'hybrid']).optional(),
  community_resolution: z.number().min(0.1).max(10).optional(),
  failure_patterns: z.array(z.object({
    technique: z.string(),
    target_pattern: z.string().optional(),
    warning: z.string(),
  })).optional(),
  scope: z.object({
    cidrs: z.array(z.string().refine(
      isValidCidr,
      { message: 'Each CIDR must be valid IPv4 X.X.X.X/N with octets 0-255 and mask 0-32' },
    )).default([]),
    domains: z.array(z.string()),
    exclusions: z.array(z.string()),
    hosts: z.array(z.string()).optional(),
    aws_accounts: z.array(z.string()).optional(),
    azure_subscriptions: z.array(z.string()).optional(),
    gcp_projects: z.array(z.string()).optional(),
    url_patterns: z.array(z.string()).optional(),
    cross_tier_links: z.array(z.object({
      url_pattern: z.string().optional(),
      aws_account: z.string().optional(),
      azure_subscription: z.string().optional(),
      gcp_project: z.string().optional(),
      cloud_resource_prefix: z.string().optional(),
      idp_kind: z.enum(['okta', 'entra', 'auth0', 'ping', 'generic_oidc', 'generic_saml', 'ci_github_actions', 'ci_gitlab', 'ci_circleci']).optional(),
      tenant_id: z.string().optional(),
      notes: z.string().optional(),
    })).optional(),
  }),
  objectives: z.array(engagementObjectiveSchema),
  opsec: opsecProfileSchema,
  phases: z.array(engagementPhaseSchema).optional(),
  max_prompt_tokens: z.number().int().min(1000).max(100000).optional(),
  iam_assume_depth: z.number().int().min(0).max(20).optional(),
  // P0.2: hash chain default-on for newly-parsed engagement configs. Legacy
  // engagements that were already serialized with the field omitted keep
  // their old behavior; the runtime distinguishes "explicit false" from
  // "explicit true" both intentional, while undefined-after-parse defaults
  // to true. Tests that bypass schema parsing (cast `as any`) keep undefined
  // and therefore the legacy off-by-default behavior.
  hash_chain_enabled: z.boolean().default(true),
  engagement_signing_key_id: z.string().optional(),
  // P1.2: engagement nonce. Optional in the schema so legacy parses don't
  // throw, but engagement creation will populate it for new engagements.
  // 64-char hex (32 bytes). The runtime treats absence as "stay on UUIDs."
  engagement_nonce: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  // P4.2: sub-agent isolation mode. Default keeps the in-process path
  // every existing engagement uses today.
  subagent_isolation: z.enum(['in_process', 'process']).default('in_process'),
  // P2: CVE research toggle. Default enabled; set false for air-gapped engagements.
  cve_research: z.object({ enabled: z.boolean().optional() }).optional(),
  /**
   * In-process JSON-RPC tape recorder. When `enabled: true` the MCP server
   * captures every wire frame (both directions) into a JSONL tape and
   * auto-registers it with the engagement on startup. Off by default; can
   * also be toggled at runtime via dashboard or env vars.
   */
  tape: z.object({
    enabled: z.boolean().default(false),
    /** Directory for auto-named tape files. Defaults to ./tapes. */
    dir: z.string().optional(),
    /** Explicit tape file path. Overrides `dir` when set. */
    file: z.string().optional(),
  }).optional(),
  /**
   * Redacted Postgres DSN recorded for display only. Live Postgres pools remain
   * session-scoped and must be reconnected after restart.
   */
  postgres_dsn: z.string().optional(),
  operator_policy: operatorPolicySchema.optional(),
});

export interface ExportedGraphNode {
  id: string;
  properties: NodeProperties;
}

export interface ExportedGraphEdge {
  id?: string;
  source: string;
  target: string;
  properties: EdgeProperties;
}

export interface ExportedGraph {
  nodes: ExportedGraphNode[];
  edges: ExportedGraphEdge[];
  // P3.2: hosts that landed in the cold-store during ingest are not part
  // of the live graphology graph but are still part of the engagement's
  // discovered inventory. Surface them in exports so reports, exports,
  // and downstream tooling don't lose them. Each record is the minimal
  // ColdNodeRecord shape.
  cold_nodes?: ColdNodeRecord[];
}

export interface ColdNodeRecord {
  id: string;
  type: string;
  label: string;
  ip?: string;
  hostname?: string;
  discovered_at: string;
  last_seen_at: string;
  subnet_cidr?: string;
  provenance?: string;
  alive?: boolean;
  confidence?: number;
  finding_id?: string;
  action_id?: string;
}

// --- Frontier + Scoring ---

export interface FrontierItem {
  id: string;
  type:
    | 'incomplete_node' | 'untested_edge' | 'inferred_edge'
    | 'network_discovery' | 'network_pivot' | 'credential_test'
    // Phase 1 (enterprise): SSO-aware frontier surfaces.
    // - `idp_enumeration`: an `idp` node is in scope but no principals
    //   have been enumerated yet (Okta/Entra org dump candidate).
    // - `mfa_bypass_candidate`: a credential exists for a principal but
    //   `cred_mfa_required && !cred_mfa_satisfied` — surface AiTM /
    //   token-theft / consent-phishing attempts.
    // - `cross_tier_pivot`: a cross-tier edge has been inferred but
    //   not yet acted on (e.g. webapp BACKED_BY cloud_resource).
    | 'idp_enumeration' | 'mfa_bypass_candidate' | 'cross_tier_pivot'
    // P2: a service has a known version but no CVE/exploit research yet.
    | 'cve_research';
  node_id?: string;
  edge_source?: string;
  edge_target?: string;
  edge_type?: EdgeType;
  target_cidr?: string;
  missing_properties?: string[];
  via_pivot?: string;           // principal node ID enabling pivot
  pivot_host_id?: string;       // host with session enabling pivot
  credential_id?: string;       // credential node ID for credential_test items
  description: string;
  graph_metrics: {
    hops_to_objective: number | null;
    fan_out_estimate: number;
    node_degree: number;
    /**
     * Per-item priority/score. Despite the historical name, this is NOT a
     * probability bounded to [0,1] — it's a multiplier composed of edge
     * confidence × credential weight × KB success-rate boost × chain
     * boost, so values can legitimately exceed 1.0 when knowledge-base
     * hit-rates or attack-chain heuristics promote an item. Treat it as
     * a relative ordering signal, not a calibrated probability.
     */
    confidence: number;
  };
  opsec_noise: number;
  staleness_seconds: number;
  stale_credential?: boolean;
  scope_unverified?: boolean;
  community_id?: number;
  community_unexplored_count?: number;
  // Chain scoring (populated by ChainScorer for credential/auth edges)
  chain_id?: string;                 // groups edges in the same attack chain
  chain_depth?: number;              // hop position in the chain (0 = first hop)
  chain_length?: number;             // total hops in the chain
  chain_completion_pct?: number;     // fraction of chain already confirmed (0.0-1.0)
  chain_score?: number;              // composite chain value score
  chain_target_objective?: boolean;  // chain terminates at an objective-adjacent node
  chain_template?: string;           // matched attack path template name (e.g., 'acl-takeover')
  // P3.1: CIDR truncation tracking on network_discovery items. When the
  // CIDR is larger than the per-scan host cap, `truncated: true` signals
  // that the frontier item represents a chunk of an incomplete discovery,
  // not the entire range. `total_hosts` is the full estimate, `expanded_count`
  // is how many have been discovered so far.
  truncated?: boolean;
  total_hosts?: number;
  expanded_count?: number;
}

export interface ScoredTask {
  frontier_item: FrontierItem;
  llm_score?: number;            // 1-10 from LLM
  llm_reasoning?: string;
  llm_suggested_action?: string;
  validated: boolean;
  validation_errors?: string[];
}

// --- Agent Types ---

export interface AgentTask {
  id: string;
  agent_id: string;
  assigned_at: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'interrupted';
  frontier_item_id?: string;
  campaign_id?: string;
  subgraph_node_ids: string[];
  skill?: string;
  completed_at?: string;
  result_summary?: string;
  // P0.3: heartbeat-based liveness for long-running sub-agents. The agent
  // calls `agent_heartbeat({task_id})` periodically; the watchdog walks
  // running tasks and marks any whose `heartbeat_at` is older than
  // `heartbeat_ttl_seconds` as 'interrupted'. Tasks without a heartbeat
  // field never time out — preserves the legacy behavior for tools that
  // don't yet heartbeat.
  heartbeat_at?: string;
  heartbeat_ttl_seconds?: number;
  // Execution backend that should run this task. Resolved by TaskExecutionService:
  //  - 'scripted'     : in-process deterministic runner (credential_test, token validation)
  //  - 'headless_mcp' : a headless `claude -p` reasoning sub-agent (Phase 1B; no-op until then)
  //  - 'manual'       : a human operator drives it; no automated execution
  // Defaults to 'scripted' when unset (preserves legacy behavior).
  backend?: TaskBackend;
  // P2: agent role, which selects the headless tool profile. 'default' = full
  // Overwatch toolset; 'research' = web search + graph tools, no target execution;
  // 'planner' = read-only graph + propose_plan, never executes (3A.2 NL cockpit).
  role?: AgentRole;
  // Phase 5c: the agent archetype id ("agent type") — a data-driven bundle of
  // {role + tool surface + backend + default skill/objective + scope strategy},
  // resolved via agent-archetypes.ts. When set it takes precedence over `role`
  // for the headless tool allowlist + prompt framing; legacy tasks (role only)
  // still resolve correctly. Kept as a string here to avoid a types→services
  // import cycle; the registry validates/narrows it.
  archetype?: string;
  // 3A.2: free-text objective handed to a headless agent at launch (embedded in
  // its bootstrap prompt). The 'planner' role carries the operator's free-form
  // command + a snapshot of steerable state here so it can propose a plan.
  objective?: string;
}

export type TaskBackend = 'scripted' | 'headless_mcp' | 'manual';
export type AgentRole = 'default' | 'research' | 'planner';

// --- Agent directives (operator steering) ---

/**
 * A steering instruction issued to a running sub-agent. Delivered on the
 * agent_heartbeat response and acknowledged by the agent. Control vs process:
 * the engine only RECORDS directives; `stop` is EXECUTED by TaskExecutionService
 * (which owns the process registry). `pause`/`resume`/steering kinds are pure
 * state the agent reads and honors.
 */
export type AgentDirectiveKind =
  | 'pause'        // stop taking new actions; keep heartbeating; wait for resume
  | 'resume'       // continue after a pause
  | 'stop'         // wrap up + exit; the service kills the process
  | 'narrow_scope' // restrict work to node_ids
  | 'skip_types'   // ignore frontier items of frontier_types
  | 'prioritize'   // do frontier_types first
  | 'instruct';    // free-text operator instruction in `note` — agent reads + honors it

export interface AgentDirective {
  id: string;
  task_id: string;
  kind: AgentDirectiveKind;
  /** narrow_scope: the node ids the agent should restrict itself to. */
  node_ids?: string[];
  /** skip_types / prioritize: the frontier item types to skip or prioritize. */
  frontier_types?: string[];
  note?: string;
  issued_by: string;       // operator id or 'primary'
  issued_at: string;
  status: 'pending' | 'acknowledged' | 'superseded';
  acknowledged_at?: string;
}

// --- Finding (reported by agents) ---

export interface Finding {
  id: string;
  agent_id: string;
  timestamp: string;
  action_id?: string;
  tool_name?: string;
  frontier_item_id?: string;
  target_node_ids?: string[];
  nodes: Array<Partial<NodeProperties> & { id: string; type: NodeType }>;
  edges: Array<{
    source: string;
    target: string;
    properties: Partial<EdgeProperties> & { type: EdgeType };
  }>;
  evidence?: {
    type: 'screenshot' | 'log' | 'file' | 'command_output';
    content: string;
    filename?: string;
  };
  raw_output?: string;
}

// --- Engagement Phases ---

export type PhaseStatus = 'locked' | 'active' | 'completed';

export type PhaseCriterion =
  | { type: 'always' }
  | { type: 'phase_completed'; phase_id: string }
  | { type: 'objective_achieved'; objective_id: string }
  | { type: 'node_count'; node_type: NodeType; min: number }
  | { type: 'access_level'; min_level: 'user' | 'local_admin' | 'domain_admin' };

export interface EngagementPhase {
  id: string;
  name: string;
  order: number;
  strategies: CampaignStrategy[];
  entry_criteria: PhaseCriterion[];
  exit_criteria: PhaseCriterion[];
  /** P4.1: per-phase OPSEC override. Validation prefers this over the
   *  engagement-level config when set. */
  opsec_overrides?: Partial<OpsecProfile>;
  /** P4.1: per-phase approval override (mode + extra blacklisted techniques). */
  approval_overrides?: {
    mode?: ApprovalMode;
    blacklisted_techniques?: string[];
  };
}

// --- Campaign Types ---

export type CampaignStrategy = 'credential_spray' | 'enumeration' | 'post_exploitation' | 'network_discovery' | 'custom';
export type CampaignStatus = 'draft' | 'active' | 'paused' | 'completed' | 'aborted';

export interface AbortCondition {
  type: 'consecutive_failures' | 'total_failures_pct' | 'opsec_noise_ceiling' | 'time_limit_seconds';
  threshold: number;
}

export interface CampaignProgress {
  total: number;
  completed: number;
  succeeded: number;
  failed: number;
  consecutive_failures: number;
}

export interface Campaign {
  id: string;
  name: string;
  strategy: CampaignStrategy;
  status: CampaignStatus;
  items: string[];               // frontier item IDs
  /**
   * Per-item terminal state, keyed by frontier_item_id. Items absent from
   * the map are implicitly `pending`. dispatchCampaignAgents() skips items
   * whose status is `succeeded` or `failed` so completed work isn't reissued
   * on a follow-up dispatch. Updated by updateCampaignProgress() which
   * also gates progress counters for idempotency.
   */
  item_status?: Record<string, 'succeeded' | 'failed'>;
  abort_conditions: AbortCondition[];
  progress: CampaignProgress;
  chain_id?: string;             // links to ChainScorer chain for spray campaigns
  phase_id?: string;             // links campaign to an engagement phase
  parent_id?: string;            // links child campaign to parent
  created_at: string;
  started_at?: string;
  completed_at?: string;
  findings: string[];            // finding node IDs from campaign execution
}

// --- Graph State Summary (returned by get_state) ---

export interface EngagementState {
  config: EngagementConfig;
  graph_summary: {
    total_nodes: number;
    nodes_by_type: Record<string, number>;
    total_edges: number;
    edges_by_type: Record<string, number>;
    confirmed_edges: number;
    inferred_edges: number;
    community_count: number;
    largest_community_size: number;
    unexplored_community_count: number;
    cold_node_count: number;
    cold_nodes_by_subnet?: Record<string, number>;
  };
  objectives: EngagementObjective[];
  frontier: FrontierItem[];
  active_agents: AgentTask[];
  /** All agent tasks regardless of status (running, completed, failed, interrupted). The dashboard reads this for the AgentsPanel; `active_agents` stays running-only for the prompt-generator's per-agent context. */
  agents: AgentTask[];
  recent_activity: Array<{
    event_id: string;
    timestamp: string;
    description: string;
    agent_id?: string;
    action_id?: string;
    event_type?: string;
    tool_name?: string;
    result_classification?: string;
  }>;
  access_summary: {
    compromised_hosts: string[];
    valid_credentials: string[];
    current_access_level: string;
  };
  warnings: HealthSummary;
  lab_readiness: LabReadinessSummary;
  scope_suggestions: ScopeSuggestion[];
  phases: Array<{
    id: string;
    name: string;
    order: number;
    status: PhaseStatus;
    strategies: CampaignStrategy[];
    entry_criteria_met: boolean;
    exit_criteria_met: boolean;
  }>;
  current_phase?: string;        // ID of the lowest-order active phase
  inference_rule_effectiveness?: InferenceRuleEffectiveness[];
  credential_coverage?: CredentialCoverage;
}

export interface CredentialCoverage {
  total_credentials: number;
  total_targets: number;
  tested_pairs: number;
  total_pairs: number;
  coverage_pct: number;
  top_untested: Array<{ credential: string; target: string; priority: number; service?: string }>;
}

export interface InferenceRuleEffectiveness {
  rule_id: string;
  total: number;
  confirmed: number;
  unconfirmed: number;
  confirmation_rate: number;
}

// --- Scope Suggestions (surfaced by get_state for operator review) ---

export interface ScopeSuggestion {
  suggested_cidr: string;
  out_of_scope_ips: string[];
  node_ids: string[];
  first_seen_at: string;
  source_descriptions: string[];
}

export type LabProfile = 'goad_ad' | 'single_host' | 'network' | 'web_app' | 'cloud' | 'hybrid';

export function inferProfile(config: EngagementConfig): LabProfile {
  if (config.profile) return config.profile;
  const hasCloud = !!(config.scope.aws_accounts?.length
    || config.scope.azure_subscriptions?.length
    || config.scope.gcp_projects?.length);
  const hasDomains = config.scope.domains.length > 0;
  const hasUrls = !!(config.scope.url_patterns?.length);
  if (hasCloud && hasDomains) return 'hybrid';
  if (hasCloud) return 'cloud';
  if (hasUrls) return 'web_app';
  if (hasDomains) return 'goad_ad';
  return 'single_host';
}
export type LabReadinessStatus = 'ready' | 'warning' | 'blocked';

export interface LabReadinessCheck {
  name: string;
  status: 'pass' | 'warning' | 'fail';
  message: string;
  details?: Record<string, unknown>;
}

export interface LabReadinessSummary {
  status: LabReadinessStatus;
  top_issues: string[];
}

export interface LabPreflightReport {
  profile: LabProfile;
  status: LabReadinessStatus;
  graph_stage: 'empty' | 'seeded' | 'mid_run';
  checks: LabReadinessCheck[];
  missing_required_tools: string[];
  warnings: string[];
  recommended_next_steps: string[];
  dashboard: {
    enabled: boolean;
    running: boolean;
    address?: string;
  };
}

export type HealthSeverity = 'warning' | 'critical';
export type HealthStatus = 'healthy' | 'warning' | 'critical';

export interface HealthIssue {
  severity: HealthSeverity;
  check: string;
  message: string;
  node_ids?: string[];
  edge_ids?: string[];
  details?: Record<string, unknown>;
}

export interface HealthReport {
  status: HealthStatus;
  counts_by_severity: Record<HealthSeverity, number>;
  issues: HealthIssue[];
}

export interface HealthSummary {
  status: HealthStatus;
  counts_by_severity: Record<HealthSeverity, number>;
  top_issues: HealthIssue[];
}

// --- Inference Rule ---

export interface InferenceRule {
  id: string;
  name: string;
  description: string;
  trigger: {
    node_type?: NodeType;
    edge_type?: EdgeType;
    property_match?: Record<string, unknown>;
    requires_edge?: {
      type: EdgeType | EdgeType[];
      direction: 'inbound' | 'outbound';
      peer_match?: Record<string, unknown>;
    };
  };
  produces: {
    edge_type: EdgeType;
    source_selector: string;     // e.g. 'trigger_node', 'domain_nodes'
    target_selector: string;
    confidence: number;
    properties?: Record<string, unknown>;
  }[];
  self_confirming?: boolean;     // skip low-performance check (e.g. kerberos domain membership)
}

// --- Graph Query (for query_graph tool) ---

export interface GraphQuery {
  // Find nodes matching criteria
  node_type?: NodeType;
  node_filter?: Record<string, unknown>;
  // Find edges matching criteria
  edge_type?: EdgeType;
  edge_filter?: Record<string, unknown>;
  // Traverse from a specific node
  from_node?: string;
  direction?: 'outbound' | 'inbound' | 'both';
  max_depth?: number;
  // Return options
  include_properties?: boolean;
  limit?: number;
}

export interface GraphQueryResult {
  nodes: Array<{ id: string; properties: NodeProperties }>;
  edges: Array<{ source: string; target: string; properties: EdgeProperties }>;
  paths?: Array<{ nodes: string[]; edges: EdgeType[]; total_confidence: number }>;
}

export type GraphCorrectionOperation =
  | {
      kind: 'drop_edge';
      source_id: string;
      edge_type: EdgeType;
      target_id: string;
    }
  | {
      kind: 'replace_edge';
      source_id: string;
      edge_type: EdgeType;
      target_id: string;
      new_source_id?: string;
      new_edge_type?: EdgeType;
      new_target_id?: string;
      confidence?: number;
      properties?: Record<string, unknown>;
    }
  | {
      kind: 'patch_node';
      node_id: string;
      set_properties?: Record<string, unknown>;
      unset_properties?: string[];
    };

// --- Retrospective Types ---

export interface InferenceRuleSuggestion {
  rule: InferenceRule;
  evidence: string;
  occurrences: number;
}

export interface SkillGapReport {
  unused_skills: string[];
  missing_skills: string[];
  failed_techniques: string[];
  mentioned_techniques: string[];
  skill_usage_counts: Record<string, number>;
}

export type AnalysisConfidence = 'low' | 'medium' | 'high';

export interface FrontierObservation {
  area: string;
  observation: string;
  evidence_count: number;
  confidence: AnalysisConfidence;
}

export interface ContextGap {
  area: string;
  gap: string;
  recommendation: string;
  severity: 'warning' | 'critical';
  confidence: AnalysisConfidence;
}

export interface OpsecObservation {
  observation: string;
  recommendation: string;
  confidence: AnalysisConfidence;
}

export interface LoggingQualityReport {
  status: 'good' | 'mixed' | 'weak';
  issues: string[];
  observations?: string[];
  recommendation: string;
}

export interface ContextImprovementReport {
  frontier_observations: FrontierObservation[];
  context_gaps: ContextGap[];
  opsec_observations: OpsecObservation[];
  logging_quality: LoggingQualityReport;
  recommendations: string[];
  success_by_frontier_type: Record<string, { total: number; successful: number }>;
}

export interface RLVRTrace {
  step: number;
  timestamp: string;
  state_summary: { nodes: number; edges: number; access_level: string; objectives_achieved: number };
  action: { type: string; target?: string; technique?: string; tool?: string };
  outcome: { new_nodes: number; new_edges: number; objective_achieved: boolean };
  reward: number;
  confidence: AnalysisConfidence;
  derived_from: 'structured' | 'text_heuristic' | 'mixed';
}

export interface TraceQualityReport {
  status: 'good' | 'mixed' | 'weak';
  issues: string[];
  total_actions: number;
  structured_count: number;
  mixed_count: number;
  heuristic_count: number;
}

export interface RetrospectiveResult {
  inference_suggestions: InferenceRuleSuggestion[];
  skill_gaps: SkillGapReport;
  context_improvements: ContextImprovementReport;
  report_markdown: string;
  training_traces: RLVRTrace[];
  trace_quality: TraceQualityReport;
  tool_telemetry?: import('./services/tool-telemetry.js').TelemetrySummary;
  summary: string;
}

// ============================================================
// Session Manager Types
// ============================================================

export type SessionKind = 'ssh' | 'local_pty' | 'socket';
export type SessionState = 'pending' | 'connected' | 'closed' | 'error';
export type TtyQuality = 'none' | 'dumb' | 'partial' | 'full';

export interface SessionCapabilities {
  has_stdin: boolean;
  has_stdout: boolean;
  supports_resize: boolean;
  supports_signals: boolean;
  tty_quality: TtyQuality;
  /** When this session is bound to an operator-controlled mock service
   * (e.g. socket listener, fake LDAP, responder, reverse-shell catcher),
   * this points back at the mock_service node id so the dashboard /
   * retrospectives can pivot session ↔ listener bidirectionally. */
  serves_mock_service_id?: string;
}

/**
 * Validation metadata carried by a session. When set at open time, every
 * `send_to_session` call for that session inherits this as its default
 * (per-call overrides still apply). Lets the session lifecycle run
 * `validateAction` on each command without forcing the caller to repeat
 * scope/technique on every send.
 */
export interface SessionDefaultValidation {
  technique: string;
  target_ip?: string;
  target_url?: string;
  target_node?: string;
  allow_unverified_scope?: boolean;
  agent_id?: string;
}

export interface SessionMetadata {
  id: string;
  kind: SessionKind;
  transport: string;
  state: SessionState;
  mode?: 'connect' | 'listen';
  bind_host?: string;
  advertise_host?: string;
  accept_mode?: 'single' | 'rearm';
  reachability_warnings?: string[];
  auth_status?: 'shell_confirmed' | 'connected_unconfirmed' | 'auth_prompt' | 'auth_failed';
  title: string;
  host?: string;
  user?: string;
  port?: number;
  pid?: number;
  agent_id?: string;
  target_node?: string;
  principal_node?: string;
  credential_node?: string;
  action_id?: string;
  frontier_item_id?: string;
  claimed_by?: string;
  started_at: string;
  last_activity_at: string;
  closed_at?: string;
  capabilities: SessionCapabilities;
  buffer_end_pos: number;
  notes?: string;
  /**
   * Baseline scope/technique for instrumented `send_to_session`. When
   * present, every send runs `validateAction` against the merged
   * (per-call > default) metadata, logs `action_started`/`action_completed`,
   * and persists evidence for the captured output window. When absent,
   * `send_to_session` requires per-call metadata.
   */
  default_validation?: SessionDefaultValidation;
}

export interface SessionReadResult {
  session_id: string;
  start_pos: number;
  end_pos: number;
  text: string;
  truncated: boolean;
  /**
   * Why the read returned. Lets callers distinguish "command finished and
   * the prompt came back" (`wait_for` / `idle`) from "we gave up waiting"
   * (`timeout`) or "the session went away" (`session_closed`).
   * Optional for backwards compatibility — older callers and the plain
   * `read()` (non-waiting) variant don't set it.
   */
  completion_reason?: 'wait_for' | 'idle' | 'timeout' | 'session_closed';
  /** Convenience boolean: true iff completion_reason === 'timeout'. */
  timed_out?: boolean;
}

export interface AdapterHandle {
  pid?: number;
  capabilities: SessionCapabilities;
  write(data: string): void;
  resize?(cols: number, rows: number): void;
  kill?(signal?: string): void;
  close(): void;
  onData(cb: (chunk: string) => void): void;
  onExit(cb: (info: { exitCode?: number; signal?: number }) => void): void;
  onDisconnect?(cb: (info?: { reason?: string }) => void): void;
}
