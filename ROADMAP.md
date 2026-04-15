# Overwatch Roadmap

Last updated: 2026-04-15

This roadmap captures planned capabilities organized into prioritized phases. Items within each phase are roughly ordered by expected impact. Phase ordering reflects dependencies and strategic priority, not strict sequencing — work can overlap across phases.

---

## Phase 1 — Attack Chain Intelligence & Campaign Planning

> **Goal:** Turn the 1,400+ untested inferred edges into efficient, batched campaigns instead of one-at-a-time frontier items.

### 1.1 Credential Chain Scorer ✅

**Priority: Critical** · Depends on: —

The frontier computes per-edge scores, but doesn't evaluate multi-hop credential chains as a unit. A chain scorer should:

- Rank POTENTIAL_AUTH edges by depth-to-objective using `PathAnalyzer` (Dijkstra already supports confidence/stealth/balanced weighting)
- Score credential spray *campaigns* — "this credential against these N services" — as a batch, not N independent frontier items
- Factor in chain completion: if 2 of 3 hops are confirmed, the last hop is more valuable than an isolated edge
- Integrate with `find_paths()` to surface chains that terminate at objective-adjacent nodes

**Implementation scope:**
- New `ChainScorer` service in `src/services/chain-scorer.ts`
- Extend `FrontierItem` with `chain_id`, `chain_depth`, `chain_completion_pct`
- Modify `frontier.ts` to group and batch-score POTENTIAL_AUTH edges by credential source
- Expose chain context in `next_task()` output so the model can reason about campaigns

### 1.2 Campaign Planner ✅

**Priority: Critical** · Depends on: 1.1

Group related frontier items into coherent campaigns:

- **Credential spray campaigns** — one credential against all compatible services, ordered by likelihood
- **Enumeration campaigns** — "enumerate all DCs" or "version-scan all HTTP services" as a single dispatchable unit
- **Post-exploitation campaigns** — run standard checks on each compromised host
- Campaign-level progress tracking (completion %, findings so far, time spent)
- Campaign abort conditions (all spray attempts failing → stop early)

**Implementation scope:**
- New `CampaignPlanner` service that wraps frontier output into campaign objects
- New `Campaign` type with `items: FrontierItem[]`, `strategy`, `abort_conditions`
- Modify `next_task()` to optionally return campaigns instead of individual items
- Campaign state persisted in activity log for retrospective analysis

### 1.3 Multi-Agent Campaign Orchestration ✅

**Priority: High** · Depends on: 1.2

Extend `dispatch_subnet_agents` pattern to other parallel workloads:

- **Credential spray agents** — one per domain or credential batch, parallel across compatible services
- **ADCS enumeration agents** — one per CA, checking all ESC paths
- **Post-exploitation agents** — one per compromised host, running enumeration in parallel
- Agent result aggregation that triggers inference rules and feeds new campaigns
- Campaign-aware agent dispatch: `dispatch_campaign_agents(campaign_id)`

**Implementation scope:**
- New dispatch tool `dispatch_campaign_agents` in `src/tools/agents.ts`
- Agent scoping uses campaign items instead of (or in addition to) node IDs
- Result aggregation in `agent-manager.ts` triggers `findingIngestion` and re-evaluates campaigns

### 1.4 Console: Campaign Management UI ✅

**Priority: High** · Depends on: 1.2

Web UI for designing, launching, and monitoring campaigns:

- **Campaign builder**: Select frontier items or node groups → assemble into a campaign with strategy, abort conditions, and agent allocation
- **Campaign dashboard**: Live progress view with completion %, active agents, findings stream, time elapsed per campaign
- **Launch / pause / abort controls**: Start a campaign, pause mid-execution (agents finish current task then hold), abort with cleanup
- **Campaign templates**: Save campaign patterns (e.g., "full credential spray against domain X") for reuse
- **Drag frontier items** between campaigns or reorder priority within a campaign

**Implementation scope:**
- New `src/dashboard/campaigns.js` module — campaign list, builder, progress panels
- REST endpoints in `dashboard-server.ts`:
  - `POST /api/campaigns` — create campaign from frontier items
  - `GET /api/campaigns` — list active/completed campaigns
  - `PATCH /api/campaigns/:id` — pause/resume/abort
  - `POST /api/campaigns/:id/dispatch` — launch agents for campaign
- WebSocket events: `campaign_update` (progress, findings, agent status changes)
- Campaign state stored in `CampaignPlanner` service (1.2), exposed via API

---

## Phase 2 — Adaptive Reasoning & OPSEC

> **Goal:** Make the model reason about defensive posture and resource budgets, not just attack opportunity.

### 2.1 Adaptive OPSEC Profiling ✅

**Priority: High** · Depends on: —

Replace static noise ceiling with a dynamic model:

- Track cumulative noise budget across the engagement (total noise spent vs. ceiling)
- Auto-shift technique selection: noisy recon early → quiet lateral movement as budget depletes
- Detect defensive response signals: account lockouts, connection resets, honeypot indicators
- Feed dynamic noise modifier into `validate_action()` alongside static OPSEC profile
- Time-window awareness: if OPSEC profile has `time_window`, factor remaining window into urgency

**Implementation scope:**
- New `OpsecTracker` service in `src/services/opsec-tracker.ts`
- Track cumulative noise per host, per domain, and globally
- Extend `validate_action()` response with `noise_budget_remaining`, `recommended_approach`
- New OPSEC fields in activity log for retrospective noise auditing

### 2.2 Credential Lifecycle Intelligence ✅

**Priority: High** · Depends on: —

Extend credential node model beyond current `isCredentialStaleOrExpired()`:

- ✅ TGT/TGS expiry tracking: surface "credential expires in N minutes" in frontier scoring
- ✅ Automatic re-validation reminders for time-sensitive credentials
- ✅ Password policy enrichment from LDAP (`minPwdAge`, `maxPwdAge`, `lockoutThreshold`) stored on domain nodes
- ✅ Predict rotation windows from policy and warn before credentials age out
- ✅ Track credential provenance chain: captured → cracked → used → expired

**Implementation scope:**
- ✅ `estimateCredentialExpiry()`, `timeToExpiry()`, `getCredentialProvenance()` in `credential-utils.ts`
- ✅ New domain node properties: `password_policy`, `lockout_policy` in `types.ts`
- ✅ Graduated frontier scoring: <30m → 0.3×, <2h → 0.7×, stale → 0.1× in `frontier.ts`
- ✅ Graduated chain-scorer: healthy=3pts, expiring<2h=2pts, expiring<30m=1pt
- ✅ LDAP parser extracts password policy attributes and `pwdLastSet` on users

### 2.3 Defensive Posture Estimation

**Priority: Medium** · Depends on: —

Add graph-level signals about defensive posture:

- EDR/AV presence detection from service banners, process lists, `linpeas` output
- Store `edr` property on host nodes (already in `NodeProperties` — populate it)
- "Defense density" metric per community (Louvain cluster)
- Feed posture into `validate_action()` so model avoids techniques likely to trigger
- Common evasion hints: if CrowdFalcon detected, suggest known bypass approaches in skill content

**Implementation scope:**
- Extend `linpeas` parser to extract EDR/AV presence → `edr` host property
- New `nxc` parser enrichment for AV product detection
- Defense density computed in `community-detection.ts` alongside Louvain pass
- Extend `validate_action()` response with `defense_context` field

### 2.4 BloodHound-Native Attack Path Computation ✅

**Priority: Medium** · Depends on: —

Post-ingest enrichment layer for BloodHound/AzureHound data:

- After `ingest_bloodhound`, compute BH-style shortest paths (owned → DA via DACL chain)
- Pre-compute "high value targets" set based on group membership
- Surface pre-computed paths as frontier items with full chain context
- Attack path templates: "GenericAll → ForceChangePassword → ADMIN_TO" as named chains

**Implementation scope:**
- New `BloodHoundPathEnricher` in `src/services/bloodhound-paths.ts`
- Post-ingest hook in `bloodhound-ingest.ts` that runs enrichment
- Named attack path patterns stored as config, matched against ingested graph
- Results surfaced via `find_paths()` or as enriched frontier items

### 2.5 Console: Approval Gates & Action Control ✅

**Priority: High** · Depends on: 2.1

Operator can approve or reject actions before the model executes:

- Engagement-level toggle: `auto-approve` / `approve-critical` / `approve-all`
- `validate_action()` extended with async approval mode — puts action into pending queue instead of immediately returning
- Console shows pending actions with full context (target, technique, OPSEC noise, defensive posture)
- Operator approves / denies / modifies parameters, model receives the resolution
- Timeout with configurable auto-approve fallback so the model doesn't hang if no operator is watching

**Implementation scope:**
- New `PendingActionQueue` service in `src/services/pending-action-queue.ts`
- Extend `validate_action()` in `src/tools/scoring.ts` with approval mode
- REST: `GET /api/actions/pending`, `POST /api/actions/:id/approve`, `POST /api/actions/:id/deny`
- WebSocket events: `action_pending`, `action_resolved`
- Console panel showing pending actions with approve/deny buttons and context

### 2.6 Console: Session Terminal Multiplexer ✅

**Priority: Critical** · Depends on: —

xterm.js-based terminal emulation in the browser, bridging to the existing session manager:

- WebSocket bridge per session (`/ws/session/:id`) — server reads from existing `RingBuffer`, writes to existing session adapter
- Tab / split-pane layout for multiple concurrent sessions
- Click-to-attach: claim unclaimed sessions or force-attach to an agent's session
- Session list panel: owner, state, TTY quality, active command indicator
- Visual state indicators: connected (green), pending (amber), closed (gray)

**Implementation scope:**
- New `src/dashboard/terminal.js` module — xterm.js integration, tab management
- `xterm.js` + `xterm-addon-fit` + `xterm-addon-webgl` as vendor dependencies
- New WebSocket route `/ws/session/:id` in `dashboard-server.ts`
- Session list panel in `ui.js` with real-time state updates

### 2.7 Console: Agent Supervision Panel ✅

**Priority: High** · Depends on: —

Live supervision of dispatched sub-agents:

- Agent task list: status, progress, assigned scope, elapsed time
- Click an agent → view its scoped subgraph rendered inline (what `get_agent_context` returns)
- Kill / cancel stuck agents with confirmation
- Real-time findings stream per agent as they call `report_finding`
- Re-dispatch a failed agent with modified parameters

**Implementation scope:**
- New `src/dashboard/agents-panel.js` module
- REST: `GET /api/agents`, `POST /api/agents/:id/cancel`
- Extended `agent_update` WebSocket event payload with findings stream

---

## Phase 3 — Web & Cloud Attack Surfaces

> **Goal:** Bring web application and cloud attack graphs to the same maturity as the AD/infrastructure surface.

### 3.1 Web Application Attack Graph

**Priority: Critical** · Depends on: —

The graph model already has `webapp`, `vulnerability`, `AUTHENTICATED_AS`, `VULNERABLE_TO`, `EXPLOITS` edges. Build the toolchain to populate them.

#### 3.1.1 New Parsers ✅

| Parser | Tool | Output → Graph Mapping | Status |
|--------|------|----------------------|--------|
| Burp Suite XML | Burp Suite Pro | `vulnerability` nodes with CVE/CVSS, `webapp → VULNERABLE_TO → vulnerability` edges | ✅ Done |
| ZAP XML | OWASP ZAP | Same as Burp — different XML schema, same graph output | ✅ Done |
| SQLMap | sqlmap | `vulnerability` nodes (SQLi type, DBMS, technique), `service → VULNERABLE_TO → vulnerability`, credential extraction → `credential` nodes | ✅ Done |
| WPScan JSON | WPScan | Plugin/theme vulnerabilities, user enumeration → `user` nodes | ✅ Done |

**Implementation scope:** ✅ Complete
- `src/services/parsers/burp.ts` — Burp Suite XML report parser ✅
- `src/services/parsers/zap.ts` — ZAP XML report parser ✅
- `src/services/parsers/sqlmap.ts` — sqlmap text/JSON output parser ✅
- `src/services/parsers/wpscan.ts` — WPScan JSON parser ✅
- Registered all in `src/services/parsers/index.ts` ✅
- 43 new tests in `output-parsers.test.ts` — all passing ✅

#### 3.1.2 Web Attack Inference Rules ✅

| Rule | Trigger | Produces | Status |
|------|---------|----------|--------|
| SQLi → credential extraction | `vulnerability` node with `vuln_type=sqli` | `EXPLOITS` edge + potential `credential` nodes | ✅ Done |
| Authenticated scan escalation | `webapp` with `AUTHENTICATED_AS` edge | Frontier: re-scan with authenticated session | ✅ Done |
| Default credentials | `webapp` with `technology` matching known defaults | `POTENTIAL_AUTH` edges with default cred pairs | ✅ Done |
| API endpoint discovery | `webapp` with `has_api=true` | Frontier: enumerate API endpoints | Deferred (3.1.3) |
| CMS exploitation | `webapp` with `cms_type` set | Frontier: version-specific exploit checks | ✅ Done |
| SQLi → RCE escalation | `vulnerability` with `vuln_type=sqli` + stacked queries | `EXPLOITS` edge to parent host | ✅ Done (bonus) |

**Implementation scope:** ✅ Complete
- 5 rules added to `builtin-inference-rules.ts` ✅
- `rule-sqli-credential-extraction`, `rule-authenticated-rescan`, `rule-default-credentials`, `rule-cms-exploitation`, `rule-sqli-to-rce`

#### 3.1.3 Web Attack Path Modeling ✅

- ✅ IDOR/auth bypass paths as `AUTH_BYPASS` edges with `auth_bypass=true`
- ✅ Session token relationships: inference rule `rule-token-webapp-auth` (token → AUTHENTICATED_AS → hosted_webapps)
- ✅ API endpoint enumeration as `api_endpoint` child nodes under `webapp` (HAS_ENDPOINT edges)
- ✅ Auth bypass escalation: inference rule `rule-auth-bypass-escalation`
- ✅ New selectors: `default_credential_candidates`, `cms_credentials`, `hosted_webapps`, `vulnerable_webapps`
- Multi-step web chains: "SQLi → file read → config → credentials → lateral movement" (deferred)

### 3.2 Cloud Attack Graph Deepening

**Priority: Critical** · Depends on: —

Skills exist for AWS/Azure/GCP, parsers for Pacu/Prowler, AzureHound ingest. Deepen the graph model.

#### 3.2.1 New Parsers ✅

| Parser | Tool | Output → Graph Mapping | Status |
|--------|------|----------------------|--------|
| ScoutSuite JSON | ScoutSuite | Multi-cloud: `cloud_identity`, `cloud_resource`, `cloud_policy`, `cloud_network` nodes | ✅ `src/services/parsers/scoutsuite.ts` |
| Steampipe JSON | Steampipe | Same scope as ScoutSuite, different schema | ⬜ |
| CloudFox | CloudFox | AWS privilege escalation paths → edges | ✅ `src/services/parsers/cloudfox.ts` |
| Enumerate-IAM | enumerate-iam | AWS IAM permission enumeration → `cloud_policy` nodes | ✅ `src/services/parsers/cloud.ts` |
| ROADtools | ROADtools | Azure AD enumeration (extends existing AzureHound ingest) | ⬜ |
| Terraform state | terraform | Infrastructure-as-code recon → all cloud node types | ✅ `src/services/parsers/terraform.ts` |

**Implementation scope:**
- ✅ `src/services/parsers/scoutsuite.ts` — multi-cloud parser: IAM users/roles with trust policies, EC2, S3 (public flag), Lambda (MANAGED_BY), security groups, findings → vulnerability nodes
- ✅ `src/services/parsers/cloudfox.ts` — RoleTrust → ASSUMES_ROLE, Permissions → HAS_POLICY + POLICY_ALLOWS, inventory → MANAGED_BY
- ✅ `src/services/parsers/terraform.ts` — raw `.tfstate` and `terraform show -json` formats; maps EC2/IAM/S3/Lambda/SG resources
- ✅ `src/services/parsers/cloud.ts` — `parseEnumerateIam()` added: text output → cloud_identity + cloud_policy with confirmed actions

#### 3.2.2 Cloud Inference Rules ✅

Extend the 3 existing cloud rules (overprivileged policy, public bucket, cross-account role):

| Rule | Trigger | Produces | Status |
|------|---------|----------|--------|
| IMDS credential theft | `cloud_resource` with `imdsv2_required=false` | `POTENTIAL_AUTH` from resource to instance role | ✅ `rule-imds-credential-theft` |
| Cross-account role chaining | `cloud_identity(role)` with `ASSUMES_ROLE` | Transitive `REACHABLE` chains (BFS, max 5 hops) | ✅ `rule-cross-account-role-chain` |
| Lambda → IAM escalation | `cloud_resource(lambda)` with attached role | `ASSUMES_ROLE` edges to execution role | ✅ `rule-lambda-iam-escalation` |
| S3 bucket exposed | `cloud_resource(s3)` with `EXPOSED_TO` edge | `REACHABLE` from exposed network | ✅ `rule-s3-bucket-exposed` |
| Service account key reuse | `cloud_identity` with `last_used` > threshold | Frontier: check for key rotation | ⬜ |
| Managed identity pivot | Azure `cloud_identity(managed_identity)` on compromised VM | `POTENTIAL_AUTH` edge | ✅ Imperative: `inferManagedIdentityPivot` |

**New selectors:** `transitive_assumed_roles`, `imds_managed_identity`, `lambda_attached_role`
**Schema extensions:** REACHABLE (cloud_identity ↔ cloud_resource), POTENTIAL_AUTH (cloud_resource → cloud_identity), ASSUMES_ROLE (cloud_resource → cloud_identity)

#### 3.2.3 IAM Policy Simulation ✅

- ✅ Given principal + action + resource, determine if policy allows it
- ✅ Traverse principal → HAS_POLICY → cloud_policy + group memberships
- ✅ Explicit deny detection (deny overrides allow) — all 3 providers
- Permission boundary / SCP / resource policy intersection (deferred)

**Implementation scope:**
- ✅ `evaluateIAM()` in `src/services/iam-simulator.ts`
- ✅ AWS: explicit deny → allow → implicit deny semantics
- ✅ Azure RBAC: scope hierarchy matching (subscription → resource group)
- ✅ GCP IAM: deny policy precedence, service account detection

### 3.3 ADCS Full ESC Coverage ✅

**Priority: High** · Depends on: —

All 13 ADCS ESC attack paths now have inference rules and community-detection weights:

| ESC | Rule ID | Trigger | Status |
|-----|---------|---------|--------|
| ESC1 | `rule-adcs-esc1` | `cert_template` + `enrollee_supplies_subject: true` | ✅ Done |
| ESC2 | `rule-adcs-esc2` | `cert_template` + `any_purpose: true` | ✅ Done |
| ESC3 | `rule-adcs-esc3` | `cert_template` + `enrollment_agent: true` | ✅ Done |
| ESC4 | `rule-adcs-esc4` | `cert_template` + inbound `WRITEABLE_BY` | ✅ Done |
| ESC5 | `rule-adcs-esc5-template`, `rule-adcs-esc5-ca` | PKI object + any write-ACL edge | ✅ Done |
| ESC6 | `rule-adcs-esc6` | `ca` + `san_flag_enabled: true` | ✅ Done |
| ESC7 | `rule-adcs-esc7` | `ca` + inbound `GENERIC_ALL` | ✅ Done |
| ESC8 | `rule-adcs-esc8` | `ca` + `http_enrollment: true` | ✅ Done |
| ESC9 | `rule-adcs-esc9` | `cert_template` + `ct_flag_no_security_extension: true` | ✅ Done |
| ESC10 | `rule-adcs-esc10` | `cert_template` + `enrollee_supplies_subject: true` (UPN mapping) | ✅ Done |
| ESC11 | `rule-adcs-esc11` | `ca` + `enforce_encrypt_icert_request: false` | ✅ Done |
| ESC12 | `rule-adcs-esc12` | `ca` + compromised host (via `ca_host_compromised_peers`) | ✅ Done |
| ESC13 | `rule-adcs-esc13` | `cert_template` + `issuance_policy_oid` + `issuance_policy_group_link` | ✅ Done |

**Implementation scope:** ✅ Complete
- 14 rules in `builtin-inference-rules.ts` (ESC5 has 2: template + CA) ✅
- 6 new `NodeProperties` for ESC detection ✅
- `ESC12` edge type added to graph schema + community-detection weights ✅
- Certipy parser enriched for ESC9/ESC11/ESC13 property extraction ✅
- `ca_host_compromised_peers` selector for ESC12 ✅
- `enrollable_users_if_issuance_policy` selector for ESC13 ✅
- 22 new tests (inference + parser + schema) ✅

---

## Phase 4 — Reporting & Analysis

> **Goal:** Produce client-ready deliverables and close the retrospective learning loop.

### 4.1 Report Generation Improvements ✅

**Priority: Critical** · Depends on: — · **Status: Complete**

Extend `report-generator.ts` and `report-html.ts`:

- ✅ **Finding categorization**: Auto-map findings to NIST 800-53 controls, OWASP Top 10 (2021), and PCI DSS v4.0 based on CWE
- ✅ **CVSS auto-scoring**: Full CVSS v3.1 base score computation from graph topology context; explicit CVSS from vuln nodes preferred
- ✅ **Executive summary**: Risk heatmap (severity × category matrix), business impact narrative
- ✅ **Remediation priority ranking**: Weighted by CVSS × 4 + blast_radius × 0.3 + cred_exposure × 1.5 (capped at 100)
- ✅ **Attack narrative**: Existing chronological story tracing critical path from initial access to objective
- ✅ **Compliance mapping**: CWE → OWASP Top 10, NIST 800-53, PCI DSS mapping tables
- ✅ **Multi-format export**: Markdown, self-contained HTML, JSON (new — structured findings with classifications + Navigator layer)
- ✅ **MITRE ATT&CK**: Technique tagging on findings, ATT&CK Navigator v4.5 JSON layer export

**Implemented:**
- `FindingClassifier` service (`src/services/finding-classifier.ts`) — CWE → NIST/OWASP/PCI mapping, edge/vuln/category → ATT&CK technique mapping
- `CvssCalculator` utility (`src/services/cvss-calculator.ts`) — full CVSS v3.1 base score computation + context estimation from graph
- Extended `report-generator.ts` — enriched `ReportFinding` with classification/CVSS, new sections: Risk Heatmap, Remediation Priority Ranking, Compliance Mapping, MITRE ATT&CK Techniques, `buildRemediationRanking()` function
- Extended `report-html.ts` — CVSS score badges, ATT&CK/OWASP/CWE badges on findings, 5 new section renderers, updated CSS
- Extended `tools/reporting.ts` — JSON format, `include_compliance` and `include_attack_navigator` parameters, Navigator layer export
- 49 new tests (17 classifier + 16 CVSS + 16 report integration) — 2020 total tests passing
- **Not implemented (deferred):** PDF via headless Chrome, DOCX via pandoc (requires external dependencies)

### 4.2 Evidence Chain Visualization (Partial ✅)

**Priority: High** · Depends on: —

Extend the dashboard (`src/dashboard/`):

- ✅ Backend API: `/api/evidence-chains/:nodeId` — activity history referencing a node
- ✅ Backend API: `/api/paths/:objectiveId` — find paths to objective with limit/optimize params
- Click-through from credential → authentication → shell → loot chain (frontend — deferred)
- Timeline view showing attack progression (frontend — deferred)
- Finding cards with evidence snippets (frontend — deferred)
- Export to MITRE ATT&CK Navigator layer (deferred to 5.4)
- Path highlight mode (frontend — deferred)

**Implementation scope:**
- ✅ Two new REST endpoints in `dashboard-server.ts`
- New `timeline.js` dashboard module (deferred)
- Extend `graph.js` with path-trace mode and evidence popover (deferred)

### 4.3 Retrospective-Driven Self-Improvement Loop ✅

**Priority: High** · Depends on: —

Close the loop from retrospective findings to system improvements:

- ✅ Auto-apply inference rule suggestions meeting quality thresholds (occurrences ≥ 5)
- ✅ Skill annotation system with use_count/success_count/failure_count/success_rate
- ✅ Per-technique success priors from RLVR traces (computeTechniquePriors)
- Track per-technique success rate across engagements (requires 5.2)

**Implementation scope:**
- ✅ `applyInferenceSuggestions()` in `src/services/retrospective-hooks.ts`
- ✅ `updateSkillAnnotations()` with full lifecycle tracking
- ✅ `computeTechniquePriors()`, `getTechniquePrior()` in `src/services/technique-priors.ts`

### 4.4 Console: Graph Interaction

**Priority: Medium** · Depends on: 4.2

Safe graph mutation through the console. All writes route through `correct_graph` — validated, transactional, fully audited. No direct graphology API calls from the console.

- **Read-only by default**, explicit "Edit Mode" toggle with confirmation
- Right-click context menu on nodes: annotate, mark as honeypot, mark out-of-scope, add notes
- Manual edge creation ("I tested this — credential X works on service Y") — wraps `correct_graph` `add_edge`
- Visual scope editor: highlight in-scope / excluded ranges, add/remove via `update_scope` API wrapper
- Undo support: each `correct_graph` operation stored with its reverse for undo stack

**Safety model:**
- All mutations wrapped in `correct_graph` (existing, tested, transactional)
- Server validates every operation before applying
- Full audit trail in activity log with operator attribution (`source: 'console'`)
- Optimistic UI with server-side validation and rollback on error

**Implementation scope:**
- Extend `graph.js` with context menu system and Edit Mode toggle
- REST: `POST /api/graph/correct` (wraps `correct_graph` tool), `POST /api/scope` (wraps `update_scope`)
- Undo stack stored client-side with reverse operation payloads
- New CSS for context menus, edit mode indicator

---

## Phase 5 — Platform & Infrastructure

> **Goal:** Templates, cross-engagement learning, and operational polish.

### 5.1 Engagement Templating and Profiles ✅

**Priority: Medium** · Depends on: —

Pre-built engagement configs:

| Template | Focus | OPSEC | Pre-loaded Skills | Special Rules |
|----------|-------|-------|-------------------|---------------|
| `internal-pentest` | AD + infrastructure | medium (0.7) | AD, credential, lateral movement | Full credential fanout |
| `external-assessment` | Web + cloud perimeter | high (0.4) | Web, DNS, cloud | Conservative spray limits |
| `red-team` | Full kill chain | critical (0.2) | All | Time-window, low-and-slow |
| `cloud-assessment` | Multi-account cloud | medium (0.6) | AWS, Azure, GCP | Cloud-specific inference |
| `assumed-breach` | Post-compromise | low (0.8) | Privesc, lateral, persistence | Skip initial recon |
| `ctf` | Lab/CTF | none (1.0) | All | No OPSEC constraints |

**Implementation scope:**
- `engagement-templates/` directory with JSON configs
- `create_engagement` tool or CLI flag: `--template internal-pentest`
- Template inheritance: custom config overrides template defaults

### 5.2 Multi-Engagement Knowledge Base ✅

**Priority: Medium** · Depends on: 4.3

Cross-engagement store for institutional learning:

- Per-technique success rate (e.g., "password spraying works 40% of the time against this OPSEC profile")
- Common host fingerprints and service signatures
- Credential pattern dictionary (default creds by service, common password patterns)
- Defense-vs-technique matrix: which techniques succeed against which EDR/AV products
- Privacy-preserving: store statistics and patterns, not client data

**Implementation scope:**
- New `knowledge-base.ts` service with SQLite backing store
- Import/export for sharing across installations
- Integration with `validate_action()` to surface historical success rates
- Integration with `get_skill()` to enrich skill content with empirical data

### 5.3 Parser Coverage Expansion (Partial ✅)

**Priority: Medium** · Depends on: —

Fill gaps identified by retrospectives and extend existing parsers:

| Parser | Gap | Priority | Status |
|--------|-----|----------|--------|
| **nxc modules** | `--sam`, `--lsa`, `spider_plus`, `--shares` output not fully parsed | High | ✅ |
| **Impacket suite** | Only `secretsdump` covered. Add: `getTGT`, `getST`, `GetNPUsers`, `GetUserSPNs`, `smbclient.py`, `wmiexec`, `psexec` | High | ✅ |
| **CertSync/ADReaper** | ADCS tools beyond certipy | Medium | |
| **SharpHound v5/BOF** | Post-exploitation collector output variants | Medium | |
| **Chisel/ligolo** | Pivot tunnel status parsing | Low | |
| **Metasploit** | `msfconsole` session/loot/cred output | Medium | |
| **Cobalt Strike** | Beacon log parsing (if applicable) | Low | |

**Implementation scope:**
- ✅ Extended `src/services/parsers/nxc.ts`: SAM dump, LSA secrets, spider_plus file listings
- ✅ New `src/services/parsers/impacket-suite.ts`: 7 parsers (GetNPUsers, GetUserSPNs, getTGT, getST, smbclient, wmiexec, psexec)
- ✅ 14 new parser aliases registered in `parsers/index.ts`
- New `src/services/parsers/metasploit.ts` (deferred)

### 5.4 MITRE ATT&CK Integration ✅

**Priority: Medium** · Depends on: 4.1

- Tag findings with ATT&CK technique IDs (T-codes) from graph context
- Auto-map edge types to techniques (e.g., `CAN_DCSYNC` → T1003.006, `KERBEROASTABLE` → T1558.003)
- Export ATT&CK Navigator layer JSON for engagement coverage visualization
- ATT&CK-based gap analysis: "these techniques were not tested"

**Implementation scope:**
- ATT&CK mapping table: edge type → technique ID
- Navigator layer export in `report-generator.ts`
- Skill files annotated with ATT&CK technique IDs for searchability

---

## Cross-Cutting Concerns

These apply across all phases and should be addressed continuously.

### Console Infrastructure

Shared foundation for all console items (1.4, 2.5, 2.6, 2.7, 4.4):

- **Auth & Security**: Extend existing `OVERWATCH_DASHBOARD_TOKEN` to all REST write endpoints. CSRF protection on mutations. Rate limiting. Non-loopback binding requires token. All console write operations get audit trail.
- **Frontend**: Vanilla JS (consistent with existing dashboard, no framework migration). xterm.js for terminals. New CSS modules per panel. Keyboard shortcuts for common operations.
- **WebSocket protocol**: Extend existing types (`graph_update`, `agent_update`, `objective_update`, `full_state`) with `campaign_update`, `action_pending`, `action_resolved`, `session_data`, `session_state_change`.
- **REST conventions**: All writes via POST/PATCH/DELETE. JSON request/response. Standard error envelope `{ error: string, details?: any }`. Mutations return updated object.
- **Audit**: Console write operations logged with `source: 'console'` attribution, distinct from model-originated activity.

### Logging Quality

The GOAD retrospective flagged weak logging. Every phase should enforce:

- `action_id` threaded through `validate_action()` → `log_action_event()` → `parse_output()` → `report_finding()`
- `frontier_item_id` from `next_task()` threaded through all downstream calls
- Explicit `event_type` fields (`action_started`, `action_completed`, `action_failed`) — not just descriptions
- Prompt-level enforcement: `get_system_prompt()` should emphasize logging discipline

### Testing

- Each new parser gets a test file with real-world sample output
- Each new inference rule gets test coverage in `inference-engine.test.ts`
- Campaign planner and chain scorer need integration tests with realistic graphs
- Cloud and web parsers need schema validation tests

### Documentation

- Each new parser documented in `docs/tools/parse-output.md` supported parsers table
- Each new inference rule documented in `docs/graph-model.md` rule reference
- New services get architecture docs
- Engagement templates get getting-started guide entries

---

## Summary & Priority Matrix

| # | Item | Phase | Priority | Depends On | Status |
|---|------|-------|----------|------------|--------|
| 1.1 | Credential Chain Scorer | 1 | Critical | — | ✅ |
| 1.2 | Campaign Planner | 1 | Critical | 1.1 | ✅ |
| 1.3 | Multi-Agent Campaign Orchestration | 1 | High | 1.2 | ✅ |
| 1.4 | Console: Campaign Management UI | 1 | High | 1.2 | ✅ |
| 2.1 | Adaptive OPSEC Profiling | 2 | High | — | ✅ |
| 2.2 | Credential Lifecycle Intelligence | 2 | High | — | ✅ |
| 2.3 | Defensive Posture Estimation | 2 | Medium | — |
| 2.4 | BloodHound-Native Attack Paths | 2 | Medium | — | ✅ |
| 2.5 | Console: Approval Gates | 2 | High | 2.1 | ✅ |
| 2.6 | Console: Session Terminals | 2 | Critical | — | ✅ |
| 2.7 | Console: Agent Supervision | 2 | High | — | ✅ |
| 3.1 | Web Application Attack Graph | 3 | Critical | — | Partial ✅ |
| 3.2 | Cloud Attack Graph Deepening | 3 | Critical | — | Partial ✅ |
| 3.3 | ADCS Full ESC Coverage | 3 | High | — | ✅ |
| 4.1 | Report Generation Improvements | 4 | Critical | — | ✅ |
| 4.2 | Evidence Chain Visualization | 4 | High | — | Partial ✅ |
| 4.3 | Retrospective Self-Improvement Loop | 4 | High | — | ✅ |
| 4.4 | Console: Graph Interaction | 4 | Medium | 4.2 | |
| 5.1 | Engagement Templates | 5 | Medium | — | ✅ |
| 5.2 | Multi-Engagement Knowledge Base | 5 | Medium | 4.3 | ✅ |
| 5.3 | Parser Coverage Expansion | 5 | Medium | — | Partial ✅ |
| 5.4 | MITRE ATT&CK Integration | 5 | Medium | 4.1 | ✅ |

### Recommended execution order (parallelizable tracks)

```
Track A (Core reasoning):   1.1 → 1.2 → 1.3 → 2.1 → 2.2 → 2.5
Track B (Attack surfaces):  3.1 → 3.2 → 3.3
Track C (Reporting):        4.1 → 4.2 → 4.3 → 4.4
Track D (Platform):         5.1 → 5.3 → 5.2 → 5.4
Track E (Defensive intel):  2.3 → 2.4 (can start anytime)
Track F (Console):          2.6 → 2.7 → 1.4 → 2.5 → 4.4
```

Tracks A and B are the highest-leverage work. Track C can start immediately since it has no dependencies on A or B. Track D is ongoing polish. Track F is the console spine — starts with session terminals (no dependencies, highest standalone value, infrastructure 80% built), then agent supervision, then campaign UI (needs 1.2), then approval gates (needs 2.1), then graph interaction last (lowest risk tolerance).
