# Overwatch MCP Server — Tier 2 Security Tool Review

**Date:** 2026-04-13
**Reviewer:** Automated deep review
**Scope:** Full codebase architecture, parsers, graph engine, session management, tools

## 1. Executive Summary

Overwatch is a **graph-based offensive security engagement orchestrator** — an MCP server that acts as the persistent state and reasoning substrate for LLM-powered penetration testing. It does not directly execute exploits against targets; rather, it **parses output from ~20 offensive tools, maintains a property graph of engagement state, runs inference rules to suggest attack paths, manages interactive sessions (SSH, PTY, socket), and generates reports**.

The codebase is well-structured, extensively tested, and shows clear evidence of iterative refinement through real engagements (GOAD AD lab, Dante ProLab, etc.). The architecture is sound — TypeScript/Node.js, graphology for the property graph, Zod for input validation, vitest for testing, MCP SDK for transport.

**Would I trust this tool's output on an engagement tomorrow?** Mostly yes. The graph modeling, inference engine, and parser library are mature. The **critical finding** is a bug in the Responder parser that silently misclassifies NTLMv1 captures. A handful of other reliability issues could cause silent incomplete results or misleading operator feedback in edge cases. None are engagement-breaking, but several warrant fixes before relying on the tool for high-stakes AD engagements.

---

## 2. Findings

### P0 — Critical

#### F01: Responder Parser NTLMv1 vs NTLMv2 Classification Bug

**Location:** `src/services/parsers/responder.ts:101-102`
**Operational Impact:** When Responder captures NTLMv1 challenges, both `credType` and `materialKind` are set to `'ntlmv2_challenge'` regardless of actual version. The conditional expressions are identical on both branches:

```typescript
const credType = stanza.version === 'ntlmv1' ? 'ntlmv2_challenge' : 'ntlmv2_challenge';
const materialKind = stanza.version === 'ntlmv1' ? 'ntlmv2_challenge' : 'ntlmv2_challenge';
```

This is a copy-paste error. NTLMv1 captures are far more valuable than NTLMv2 (they can be cracked significantly faster or relayed in different ways). Misclassifying them as NTLMv2 means:
- The operator sees "NTLMv2" label but gets NTLMv1 material
- Downstream hashcat parsing and credential lifecycle logic may process them incorrectly
- The graph's credential node misrepresents the actual cryptographic strength of the captured hash
- Inference rules dependent on `cred_material_kind` will make wrong decisions

**Pre-existing:** Yes — present since parser was written.
**Suggested Remediation:** The NTLMv1 branch should use a distinct `cred_type` value (e.g., `'ntlmv1_challenge'` or keep `'ntlmv2_challenge'` but at minimum label it properly). This also needs a corresponding entry in `getCredentialMaterialKind()` and `isCredentialUsableForAuth()`.

---

### P1 — High

#### F02: `parse_output` File Path Not Validated — Arbitrary File Read

**Location:** `src/tools/parse-output.ts:105`
**Operational Impact:** The `parse_output` tool accepts a `file_path` parameter and reads it with `readFileSync(file_path!, 'utf8')` without any path validation or sandboxing. While the MCP server is designed to run on the operator's machine (so the threat model is primarily about the LLM agent, not external attackers), this means a prompt injection or confused-agent scenario could read any file on the filesystem that the Node.js process can access (e.g., `/etc/shadow`, SSH keys, engagement configs for other clients).

**Evidence:** Line 105 reads the raw user-provided path with no path traversal check, no allowlist, no chroot.
**Pre-existing:** Yes.
**Suggested Remediation:** Validate `file_path` is within the engagement working directory or an explicit artifact directory. Reject absolute paths or paths containing `..`.

#### F03: NXC Parser Drops Failed Auth Results Silently

**Location:** `src/services/parsers/nxc.ts:156`
**Operational Impact:** NXC `[-]` (failure) status lines are matched but produce no output — no edge, no node, no log entry. This means the operator gets no visibility into failed authentication attempts. In a password spray scenario, knowing which accounts *failed* is essential for:
- Tracking password policy lockout risk
- Distinguishing "account doesn't exist" from "password wrong"
- Avoiding re-spraying already-tested combinations

The parser silently discards this information, making it impossible for the operator to assess spray coverage from parsed output alone.
**Pre-existing:** Yes.
**Suggested Remediation:** At minimum, log or annotate the finding with a count of failed attempts. Ideally, create `VALID_ON` edges with `test_result: 'failure'` or add a summary to the finding metadata.

#### F04: Cold Store Can Lose Host Discovery Provenance

**Location:** `src/services/finding-ingestion.ts:94-109`
**Operational Impact:** When a host is classified as "cold" (bare ping-sweep response with no services), it goes to the cold store instead of the hot graph. If the host is later promoted, the `discovered_by` agent attribution is preserved, but the original `finding_id` and `action_id` are not. This breaks the evidence chain for that host — the report generator cannot trace back to the specific scan that discovered it.

In large network sweeps (e.g., scanning a /16), hundreds of hosts may pass through cold storage. If a later pivot makes them operationally relevant, the evidence chain shows a promotion event but not the original discovery.
**Pre-existing:** Yes.
**Suggested Remediation:** Store `finding_id` and `action_id` in `ColdNodeRecord` and restore them on promotion.

---

### P2 — Medium

#### F05: Hashcat Parser Empty Password Accepted

**Location:** `src/services/parsers/hashcat.ts:89`
**Operational Impact:** The guard `if (!plaintext || plaintext.length === 0) continue;` correctly rejects empty strings but doesn't reject whitespace-only passwords. A hashcat potfile line like `hash:   ` (hash followed by spaces) would create a credential node with `cred_value: '   '`, which would be marked `cred_usable_for_auth: true`. This is unlikely in practice but could produce a misleading graph node.
**Pre-existing:** Yes.
**Suggested Remediation:** Trim plaintext and reject whitespace-only values.

#### F06: Certipy Parser Falls Back to Basic Line Parsing on Non-JSON Input

**Location:** `src/services/parsers/certipy.ts:112-126`
**Operational Impact:** When Certipy output is not valid JSON, the fallback text parser only extracts template names — no CAs, no ESC edges, no enrollment permissions. This means if the LLM passes Certipy text-mode output (or if Certipy's JSON output included a non-JSON preamble), the parser silently produces a massively incomplete result. The operator sees "certipy parsed successfully" with template nodes but no vulnerability assessments.
**Pre-existing:** Yes.
**Suggested Remediation:** At minimum, emit a warning when falling back to text parsing. The text-mode parser should also attempt to extract ESC vulnerability classifications from the text output format.

#### F07: State Persistence Not Atomic on Windows

**Location:** `src/services/state-persistence.ts:29-37`
**Operational Impact:** The persist logic writes to a `.tmp` file then uses `renameSync` for atomic replacement, which is atomic on POSIX but **not guaranteed atomic on Windows** (NTFS rename can fail if the target is open by another process, and Node.js `renameSync` on Windows uses `MoveFileEx` which has different guarantees). A crash during persistence on Windows could corrupt the state file.
**Pre-existing:** Yes.
**Suggested Remediation:** On Windows, use write-then-rename with `MOVEFILE_REPLACE_EXISTING` flag, or implement a write-ahead log. Document the limitation for Windows users.

#### F08: Socket Adapter `spawnConnect` Early Buffer Race Condition

**Location:** `src/services/session-adapters.ts:291-300`
**Operational Impact:** The `spawnConnect` method uses an `earlyBuffer` array to capture data arriving before `onData` is registered by the caller. The condition `if (earlyBuffer.length >= 0 && dataCallbacks[0] !== cb)` is always true (array length is always >= 0), which means it clears all callbacks on every `onData` registration. This removes the early buffer callback correctly on first call, but if `onData` is called twice (e.g., by both the caller and the session buffer wiring), the first real callback gets dropped.

In practice, session-manager wires `onData` once, so this mostly works. But the logic is fragile and incorrect.
**Pre-existing:** Yes.
**Suggested Remediation:** Use a boolean flag `earlyBufferActive` instead of the length check. Set it to false after first real registration.

#### F09: Kerbrute Parser Silently Rejects Single-Char Passwords After Domain

**Location:** `src/services/parsers/kerbrute.ts:95-103`
**Operational Impact:** `parseKerbruteLogin` correctly uses first-colon splitting for domain:password, but the guard `colonIndex === remainder.length - 1` rejects single-character passwords (where the colon is the last character before the password). This is an edge case but could silently drop a valid spray success.
**Pre-existing:** Yes — minor edge case.

---

### P3 — Low

#### F10: Snapshot Files Accumulate in Working Directory

**Location:** Root directory contains 80+ `state-*.snap-*.json` files.
**Operational Impact:** Snapshot rotation is per-engagement-ID (`MAX_SNAPSHOTS = 5`), but the working directory contains many debug/test state files that are not cleaned up. On a long engagement, the operator's directory becomes cluttered. Not a reliability issue, but impacts operator experience.
**Pre-existing:** Yes.

#### F11: `node-pty` Binary Dependency

**Location:** `package.json:31` — `"node-pty": "^1.1.0"`
**Operational Impact:** `node-pty` requires native compilation during `npm install`. This can fail on Kali machines with missing build tools, in Docker containers without the right development headers, or on Apple Silicon with Rosetta issues. It's essential for the session management feature. The README doesn't mention this dependency requirement.
**Pre-existing:** Yes.
**Suggested Remediation:** Document the build-tools requirement (`build-essential` on Debian, Xcode CLI tools on macOS). Consider a graceful fallback that disables session tools when node-pty fails to load.

#### F12: No Lockfile Integrity Verification

**Location:** `package.json`, `package-lock.json` present.
**Operational Impact:** CI uses `npm ci` (good), dependencies use `^` semver ranges (standard). No supply chain verification beyond npm's built-in signature checks. Not a practical risk for this use case, but worth noting that `npm audit` isn't in the CI pipeline.
**Pre-existing:** Yes.

---

### Info — Informational

#### F13: Parser Registry Uses Case-Insensitive Keys But Tool Names May Not Match

The `PARSERS` registry in `src/services/parsers/index.ts:43-75` maps tool names to parsers, and `parseOutput` lowercases the lookup. However, some entries like `'linpeas.sh'` include file extensions while the tool description advertises `linpeas`. Both work, but the inconsistency could confuse operators reading the supported parser list.

#### F14: BloodHound Ingest Handles Both Classic and CE Formats

The BloodHound ingestion in `src/services/bloodhound-ingest.ts` includes format detection for SharpHound CE vs classic format. This is a notable strength — many tools only handle one format.

#### F15: Graph Edge Constraint Validation Is Comprehensive

`src/services/graph-schema.ts` defines source/target type constraints for every edge type. This prevents graph corruption from malformed findings and provides auto-fix suggestions.

---

## 3. Notable Strengths

1. **Robust Identity Resolution.** The identity resolution system canonicalizes nodes from different sources into stable IDs. This solves the real-world problem of the same host appearing as `10.10.10.5`, `dc01`, and `DC01.acme.local` from different tools.
2. **Cold Store Graph Compaction.** The hot/cold split keeps the graphology graph performant during large network sweeps by moving bare ping-sweep hosts to a lightweight store, promoting them only when interesting edges arrive.
3. **Parser Library Depth.** 17+ parsers covering the core offensive tool landscape. The parsers handle real-world output variability well.
4. **Inference Engine.** Declarative rules + imperative handlers cover wide attack surface: Kerberoasting, AS-REP roasting, SMB relay targets, ADCS ESC1-ESC13, pivot reachability, default credentials, IMDS SSRF, etc.
5. **Error Boundary Pattern.** Every MCP tool handler is wrapped in `withErrorBoundary()` which catches exceptions and returns structured error responses instead of crashing the server.
6. **Credential Lifecycle Tracking.** Credential status (active/stale/expired/rotated), material kind, and usability for authentication. Expired credentials are automatically degraded in the frontier.
7. **Finding Validation Before Ingestion.** `prepareFindingForIngest()` validates edge type constraints and credential material completeness *before* graph mutation, with actionable error messages and fix suggestions.
8. **Session Manager with Auth Detection.** SSH sessions auto-detect auth success/failure/prompts and integrate results back into the graph.

---

## 4. Residual Risk Areas

1. **Parser Fidelity vs. Tool Updates.** All 17+ parsers are snapshot-tested against specific output formats. Real tools change output formats between versions. No version-awareness in parsers.
2. **Single-Threaded Node.js.** Large graph operations could block the event loop, making the MCP server unresponsive during computations.
3. **Evidence Store Growth.** Evidence files are written to disk individually but never pruned.
4. **Trust-on-Ingestion.** The `report_finding` and `parse_output` tools validate graph schema constraints but not semantic correctness.

---

## 5. Target Coverage Matrix

| Tool / Parser | Graph Modeling | Inference Rules | Test Coverage | Confidence |
|---|---|---|---|---|
| Nmap XML | Host + Service + RUNS | Kerberos→domain, service fan-out | Strong (8+ test cases) | High |
| NXC / NetExec | Host + SMB + User + Share + MSSQL linked | SMB relay, null session, cred fanout | Strong (12+ test cases) | High |
| Secretsdump | Credential + User + OWNS_CRED + DUMPED_FROM | Domain cred reuse | Strong | High |
| Certipy | CA + CertTemplate + ESC1-ESC13 | ADCS enrollment + subject supply | Moderate | Medium (text fallback weak) |
| Kerbrute | User + Domain + Credential | Kerberoastable, AS-REP roastable | Moderate | High |
| Hashcat | Credential (cracked plaintext) | Cred fanout, domain auth | Moderate | High |
| Responder | Credential + User + Host (captured) | — | **Low** (v1/v2 bug) | **Low** |
| LDAP / ldapdomaindump | User + Group + Host + Domain + UAC flags | Kerberoast, AS-REP, group memberships | Moderate | High |
| Enum4linux | Host + SMB + User + Group + Share | Null session | Moderate | Medium |
| Rubeus | User + Credential (TGS/ASREP/TGT) | Kerberoast, AS-REP | Moderate | High |
| Web Dir Enum | Service enrichment + login detection | Web login form → cred testing | Moderate | Medium |
| Linpeas | Host enrichment (SUID, caps, cron, docker) | SUID privesc | Good | High |
| Nuclei | Webapp + Vulnerability + VULNERABLE_TO | SSRF → IMDSv1 chain | Good | High |
| Testssl / sslscan | Service TLS + Vulnerability | — | Moderate | Medium |
| Nikto | Service + Vulnerability | — | Moderate | Medium |
| Pacu (AWS) | CloudIdentity + CloudResource + CloudPolicy | Role assumption, policy analysis | Moderate | Medium |
| Prowler (AWS) | CloudResource + Vulnerability | — | Basic | Medium |
| BloodHound JSON | Full AD graph (SharpHound v4/v5/CE) | All AD attack paths | Strong | High |
| AzureHound | Azure AD + cloud identity | Cloud identity paths | Moderate | Medium |

---

## 6. Next Inspection Targets

1. **Live integration testing with current tool versions.** Run each parser against output from latest tool versions and verify no parsing regressions.
2. ~~**Retrospective system review.**~~ Completed — see Section 7.
3. ~~**Dashboard WebSocket security.**~~ Completed — see Section 8.
4. ~~**Concurrency under HTTP transport.**~~ Completed — see Section 9.

---

## 7. Retrospective System Review

**Scope:** `src/services/retrospective.ts` (1339 lines), `src/services/report-generator.ts` (1163 lines), `src/services/report-html.ts` (579 lines), `src/tools/retrospective.ts` (104 lines), `src/tools/reporting.ts` (212 lines), `src/cli/retrospective.ts` (~100 lines), plus test files.

### 7.1 Architecture Summary

The retrospective system has five analysis passes:

1. **Inference Gap Analysis** — Finds repeated edge patterns (≥3 occurrences) not covered by existing inference rules. Flags low-performing rules (confirmation rate < 10%). Includes self-loop and schema validation filters.
2. **Skill Gap Analysis** — Cross-references engagement history, agent tasks, and skill tags against the skill library. Identifies unused skills, missing coverage, and failed techniques.
3. **Context Improvement Analysis** — Tracks frontier item yield (success by frontier type), identifies graph enrichment gaps (OS, service detail), assesses logging quality, detects OPSEC violations, evaluates unconfirmed inference edges.
4. **RLVR Training Trace Export** — Produces state→action→outcome triplets with reward computation, derived-from classification (structured/mixed/text_heuristic), and confidence scoring.
5. **Attack Path Report** — Markdown report with executive summary, scope, objectives, discovery stats, compromised assets, credential chains, activity timeline, recommendations.

The report generator has a parallel `generateFullReport()` function that produces a client-deliverable pentest report with per-finding sections, evidence chains, attack narrative, and auto-generated remediation.

The HTML renderer (`report-html.ts`) produces a self-contained HTML document with CSS embedded, dark/light theme support, expandable evidence sections, and print-optimized styles.

### 7.2 Findings

#### F16 (P2): `output_dir` in `generate_report` and `run_retrospective` Not Validated — Arbitrary File Write

**Location:** `src/tools/reporting.ts:177-183`, `src/tools/retrospective.ts:82-88`
**Operational Impact:** Same class as F02. When `write_to_disk` is true, `output_dir` is user-provided and passed to `join()` then `mkdirSync(recursive: true)` and `writeFileSync()` without path validation. An LLM agent could be instructed to write reports to arbitrary filesystem locations (e.g., `output_dir: '/etc/cron.d/'` or `output_dir: '~/.ssh/'`).

The `config.id` component sanitizes nothing — it's also user-provided in the engagement config.

**Suggested Remediation:** Validate `output_dir` is relative and within the CWD. Reject absolute paths and paths containing `..`.

#### F17 (P3): Credential Chain Walker Resets `visited` Per Start Node

**Location:** `src/services/retrospective.ts:1313`
**Operational Impact:** `buildCredentialChains()` clears `visited` for each start node, which means the same sub-chain can appear in multiple credential chains if reachable from different roots. This produces duplicate chain entries in the report. Not a correctness issue (chains are still valid), but clutters the report for engagements with many derived credentials.

**Suggested Remediation:** Accumulate `visited` across starts, or deduplicate chains after collection.

#### F18 (P3): Training Trace Reward Skew for Large Findings

**Location:** `src/services/retrospective.ts:1035-1040`
**Operational Impact:** The reward formula `newNodes * 0.5 + newEdges * 0.3` scales linearly with finding size. A single nmap scan returning 50 hosts gets reward 25.0, while achieving a domain admin objective gets reward 5.0. This produces training traces where large enumeration steps dwarf strategic actions in reward signal. If used for actual model training, this would reinforce enumeration-heavy strategies.

**Suggested Remediation:** Cap per-action discovery reward (e.g., `min(newNodes * 0.5, 5.0)`) or use log-scale.

#### F19 (Info): `generateFullReport` and Retrospective's `generateReport` Are Separate Functions with Duplicated Logic

**Location:** `src/services/report-generator.ts` (`generateFullReport`) vs `src/services/retrospective.ts` (`generateReport`)
**Operational Impact:** Two separate markdown report generators exist with overlapping but different output structures. `generateFullReport` produces a richer client-deliverable report (per-finding sections, evidence, narrative), while `generateReport` in the retrospective produces a simpler engagement report. Both duplicate scope rendering, objective tables, discovery summary, credential chain building, and timeline formatting. Changes to one aren't reflected in the other.

Not a bug — both serve different purposes — but increases maintenance burden. The `generate_report` tool correctly uses `generateFullReport`, and the `run_retrospective` tool uses the simpler `generateReport`.

#### F20 (Info): HTML Report `trace_quality` Data Not Fully Populated

**Location:** `src/tools/reporting.ts:164-165`
**Operational Impact:** When building `HtmlReportData` in the `generate_report` tool handler, `trace_quality` is stubbed with zeros:
```typescript
trace_quality: retrospective.trace_quality ? {
  total_actions: 0, with_frontier_id: 0, with_action_id: 0, coverage_pct: 0,
} : undefined,
```
The retrospective `TraceQualityReport` type has `status` and `issues` fields, not the numeric fields the HTML type expects. The HTML renderer shows zeros for trace quality when retrospective is included.

### 7.3 Strengths

1. **Logging Quality Self-Assessment.** The `analyzeLoggingQuality()` function explicitly measures structured-vs-heuristic coverage and adjusts confidence ratings across the entire retrospective. This is a sophisticated meta-analysis — the retrospective knows when its own conclusions are unreliable.
2. **Structured Action Lifecycle Tracking.** Action IDs thread through validation, execution, finding ingestion, and completion. The system prefers structured attribution (action_id → finding linkage) and explicitly flags when it falls back to text heuristics.
3. **Comprehensive Test Coverage.** ~30+ test cases covering edge cases: self-loop prevention, schema-invalid suggestions, low-performing rule flagging, structured vs heuristic confidence, OPSEC violation detection.
4. **HTML XSS Protection.** All user-controlled content in the HTML renderer passes through `esc()` before insertion. The `inlineMarkdownToHtml()` function escapes between markdown markers. Test coverage explicitly verifies `<script>` injection is blocked.
5. **Graceful Degradation.** Empty graph, empty history, and partially structured history all produce valid output without crashing.

---

## 8. Dashboard WebSocket Security Review

**Scope:** `src/services/dashboard-server.ts` (~370 lines), `src/services/delta-accumulator.ts` (44 lines), tests.

### 8.1 Architecture Summary

The dashboard server provides:
- **HTTP API** at `/api/state`, `/api/graph`, `/api/history` for polling
- **WebSocket** (via `ws` library on top of the HTTP server) for real-time push
- **Static file serving** for the dashboard UI
- **Delta accumulation** with debounced broadcast (500ms) to avoid flooding clients

### 8.2 Findings

#### F21 (P2): WebSocket Has No Authentication

**Location:** `src/services/dashboard-server.ts:60-75`
**Operational Impact:** Any WebSocket client connecting to the dashboard port receives the full engagement state on connect (graph, objectives, history count). No authentication token, no session validation, no header check. While the server defaults to `127.0.0.1` binding, if `OVERWATCH_DASHBOARD_HOST` is set to `0.0.0.0` (which operators may do for remote access), **any network client can connect and receive real-time engagement state**, including:
- All discovered hosts, services, credentials, and users
- Attack graph topology
- Engagement objectives and achievement status
- Action history

The HTTP endpoints have CORS checks, but CORS doesn't apply to WebSocket connections — browsers enforce CORS for HTTP but the WebSocket handshake bypasses it.

**Suggested Remediation:** Implement a token-based WebSocket auth check. The `ws` library supports a `verifyClient` callback in `WebSocketServer` options that can check for a token in the URL query string or HTTP headers during the upgrade handshake.

#### F22 (P3): CORS Check Origin Regex May Not Cover All Localhost Variants

**Location:** `src/services/dashboard-server.ts:222-226`
**Operational Impact:** The CORS regex `/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/` only matches `localhost` and `127.0.0.1`. It doesn't match `[::1]` (IPv6 loopback), `0.0.0.0`, or `127.0.0.x` (other loopback addresses). This is a minor gap — the fallback `new URL(origin).hostname === allowedHost` handles the env-override case.

#### F23 (P3): Static File Path Traversal Check Is Correct but Could Be Stricter

**Location:** `src/services/dashboard-server.ts:252-258`, `265-270`
**Operational Impact:** The static file server has two traversal checks:
1. `filePath.includes('..')` — rejects any path with `..`
2. `relative(dashDir, fullPath).startsWith('..')` — validates resolved path is within dashboard dir

Both checks are correct. The double-check is defense-in-depth. However, encoded traversal attempts (e.g., `%2e%2e`) could bypass the string check if Express/Node normalizes URLs after the check. In practice, Node's `http.IncomingMessage.url` does NOT decode percent-encoding automatically, so `%2e%2e` stays literal and gets caught by the `relative()` check. **No actual vulnerability**, but worth documenting.

### 8.3 Strengths

1. **Localhost-only default binding.** `127.0.0.1` binding prevents accidental exposure.
2. **Zero-client short-circuit.** `onGraphUpdate` skips expensive graph export when no clients are connected.
3. **Debounced delta broadcasting.** Prevents flooding clients during rapid graph mutations.
4. **Clean shutdown.** `stop()` closes all clients, clears cache, drains accumulator.

---

## 9. HTTP Transport Concurrency Review

**Scope:** `src/app.ts` (lines 224-350), HTTP transport setup.

### 9.1 Architecture Summary

HTTP transport mode creates a new `McpServer` per HTTP session but all sessions share:
- The same `GraphEngine` instance
- The same `SkillIndex`
- The same `SessionManager`
- The same `ProcessTracker`
- The same `DashboardServer`

Session tracking uses a `transports` record keyed by UUID. Max sessions are capped at 50 (configurable).

### 9.2 Findings

#### F24 (P2): No Concurrency Protection on Shared GraphEngine

**Location:** `src/app.ts:241-242`
**Operational Impact:** Multiple HTTP sessions can invoke graph-mutating tools (`report_finding`, `parse_output`, `correct_graph`, `ingest_bloodhound`) concurrently. The `GraphEngine` uses synchronous graph operations (graphology is not thread-safe, but Node.js is single-threaded), so **JavaScript-level race conditions are impossible** — each `await` point could interleave, but the graph mutations themselves are atomic within a single event loop tick.

However, **logical races are possible**: Two sessions could both read the graph state, independently decide to add conflicting edges, and both succeed — producing a graph state that neither session intended. For example:
- Session A reads: host has no admin access
- Session B reads: host has no admin access
- Session A adds: ADMIN_TO via credential X
- Session B adds: ADMIN_TO via credential Y (duplicate, or conflicting)

The identity resolution and dedup logic in `graph-engine.ts` mitigates most cases (duplicate node/edge detection), but it doesn't prevent all logical inconsistencies.

**Practical Impact:** Low. In practice, only one LLM agent uses the MCP server at a time (the primary operator session), with sub-agents dispatched sequentially. The HTTP transport is primarily used for testing. But if multi-agent concurrent access is planned, this needs attention.

**Suggested Remediation:** For now, document that concurrent write sessions are not tested. If multi-agent writes are needed, implement a lightweight write queue or use the action lifecycle (validate → execute → report) as a serialization boundary.

#### F25 (P3): Session Cleanup on HTTP Transport Disconnect

**Location:** `src/app.ts:288-291`
**Operational Impact:** When a transport closes (`transport.onclose`), the session is deleted from the `transports` record. But if the McpServer has pending tool invocations when the transport closes, those invocations continue executing against the shared GraphEngine. The results are lost (no transport to send them through), but any side effects (graph mutations, file writes, session operations) still complete.

This is standard behavior for server-side cleanup, but it means a disconnected client's tool calls aren't cancelled. For long-running operations (like parsing a large BloodHound JSON), this could tie up resources.

#### F26 (Info): HTTP and Dashboard Bind to Different Ports

The MCP HTTP transport (default port 3000) and the dashboard server (default port 8384) run independently. The HTTP transport binds via Express, while the dashboard uses raw `http.createServer` + `ws`. Both default to `127.0.0.1`. This is clean separation, but operators need to configure two ports if running both behind a reverse proxy.

### 9.3 Strengths

1. **Session cap.** `MAX_HTTP_SESSIONS = 50` prevents resource exhaustion.
2. **Proper session lifecycle.** UUID-based session IDs, clean delete on disconnect.
3. **Localhost-only default.** Both HTTP transport and dashboard default to `127.0.0.1`.
4. **SDK-standard transport.** Uses `StreamableHTTPServerTransport` from the official MCP SDK.

---

## 10. Inference Engine Deep Review

**Files:** `src/services/inference-engine.ts` (~600 lines), `src/services/builtin-inference-rules.ts` (~460 lines, 31 rules), `src/services/imperative-inference.ts` (~300 lines), `src/tools/inference.ts` (~120 lines), `src/services/credential-utils.ts` (~100 lines)

### 10.1 Architecture

The inference engine has two layers:
1. **Declarative rules** (`InferenceEngine` class) — 31 builtin rules with trigger-based matching and selector-resolved edge production. Custom rules addable at runtime via `suggest_inference_rule`.
2. **Imperative handlers** — Complex graph traversals that can't be expressed declaratively: pivot reachability, default credentials, IMDSv1 SSRF chains, managed identity pivots, credential degradation.

Rules fire on node ingestion (`runRules(nodeId)`). The selector system resolves source/target node sets via ~25 named selectors (e.g., `compatible_services_same_domain`, `domain_admins_and_session_holders`, `gpo_linked_hosts`).

### 10.2 Findings

#### F27 (P2): Inference Selector Fallback Creates Spurious Global Edges

**Location:** `inference-engine.ts`, `resolveSelector()` — cases `matching_user_domain` (~L395), `delegation_targets` (~L460), `domain_admins_and_session_holders` (~L275)

Several selectors fall back to returning ALL nodes of a type when specific matches fail:

- `matching_user_domain`: If a user has no domain info (no `MEMBER_OF_DOMAIN` edges, no `domain_name`), returns **every domain node**. Used by `rule-asrep-roastable` and `rule-kerberoastable` — creates `AS_REP_ROASTABLE`/`KERBEROASTABLE` edges to every domain.
- `delegation_targets`: If `allowed_to_delegate_to` is empty, returns **every domain node**. A misconfigured constrained delegation host gets `CAN_DELEGATE_TO` edges to all domains.
- `domain_admins_and_session_holders`: Falls back to **all domain users** when no admin/session-holder matches found. This creates massive edge sets in early-stage graphs before sessions are established.

**Impact:** Combinatorial edge explosion, graph pollution, false attack paths in frontier. In a graph with 100 users and 5 domains, a single user node without domain info triggers 5 false edges per rule. With 50 such users × 3 selector-using rules × 5 domains = 750 spurious edges.

**Recommendation:** Return `[]` instead of falling back to global scope. The builtin rule `compatible_services_same_domain` already does this correctly — it returns `[]` when no authoritative domain info exists.

#### F28 (P3): Custom Rule Properties Spread Can Override Edge Fields

**Location:** `inference-engine.ts`, `applyRuleProductions()`, ~L164

```typescript
const { id: edgeId } = this.addEdge(src, tgt, {
  type: production.edge_type,
  confidence: production.confidence,
  ...  // fixed fields set first
  ...production.properties as Record<string, unknown>  // spread AFTER
});
```

The `production.properties` object is spread after `type`, `confidence`, `tested`, and `discovered_by`, allowing it to override any of these. A rule with `properties: { confidence: 1.0, tested: true }` would override the declared confidence and mark untested edges as tested.

**Mitigation Status:** The `suggest_inference_rule` tool doesn't expose `properties` in its schema, so only code-controlled builtin rules can set this. No builtin rules use `properties`.

**Recommendation:** Spread `properties` BEFORE the fixed fields, or strip reserved keys from `properties` before merging.

#### F29 (P3): Cold Store Promotion Sets Confidence to 1.0

**Location:** `imperative-inference.ts:inferPivotReachability()` ~L82, `scope-manager.ts:updateScope()` ~L105

Both promotion paths set `confidence: 1.0` on promoted nodes:
```typescript
host.addNode({
  ...coldRecord,
  confidence: 1.0,  // <-- unconditionally full confidence
});
```

Cold store records don't preserve their original confidence. A host that was originally discovered at `confidence: 0.3` (e.g., inferred from DNS) gets promoted to `1.0` as if it were directly confirmed.

**Impact:** Inflated confidence misleads offensive analysis and corrupts confidence-gated logic (e.g., `HAS_SESSION` edges require `confidence >= 0.7` for session-holder resolution).

**Recommendation:** Preserve original confidence in the cold store record structure. Fall back to `0.5` if unavailable.

#### F30 (Info): Expired Credential Edges Never Fully Degrade

**Location:** `imperative-inference.ts:degradeExpiredCredentialEdges()` ~L275

`Math.max(0.1, attrs.confidence * 0.5)` floors at 0.1 — expired credentials maintain low-confidence POTENTIAL_AUTH edges indefinitely. This is intentional (allows re-checking stale creds), but means the frontier perpetually includes expired credential test candidates.

### 10.3 Strengths

1. **Selector whitelist on custom rules.** `suggest_inference_rule` validates selectors against a 9-entry whitelist, preventing access to dangerous selectors like `all_compromised` or `gpo_linked_hosts`.
2. **Domain-scoped credential fanout.** `compatible_services_same_domain` correctly suppresses global fanout when only non-authoritative domain hints exist (parser_context).
3. **Duplicate edge prevention.** `applyRuleProductions` checks for existing edges before creating new ones.
4. **Comprehensive AD attack path coverage.** 31 rules covering Kerberos, ADCS, delegation, ACL abuse, GPO, cloud IAM, Linux privesc, web app attacks.
5. **Credential lifecycle gates.** `isCredentialUsableForAuth()` and `isCredentialStaleOrExpired()` properly check `valid_until`, `credential_status`, and `cred_usable_for_auth`.

---

## 11. Identity Resolution Review

**Files:** `src/services/identity-resolution.ts` (~460 lines)

### 11.1 Architecture

Identity resolution canonicalizes node IDs across data sources: `resolveNodeIdentity()` maps partial node data to deterministic canonical IDs using type-specific strategies (IP for hosts, qualified account for users/groups, ARN for cloud resources, material+fingerprint+account for credentials).

`getIdentityMarkers()` produces secondary matching keys for cross-source deduplication (SID, hostname variants, short-domain FQDN matches).

### 11.2 Findings

#### F31 (Info): Identity Resolution — Verified Sound

No bugs found. Key observations:

- **Canonical ID generation is deterministic.** Same input always produces same ID. Uses `normalizeKeyPart()` (lowercase, sanitized) for all components.
- **FQDN ↔ short hostname matching via markers.** `host:name:braavos` added alongside `host:name:braavos.essos.local` enables cross-parser deduction.
- **Unresolved identity handling.** Opaque identifiers (SIDs, UUIDs) create `bh-{type}-{id}` nodes with `identity_status: 'unresolved'`, allowing later resolution when authoritative data arrives.
- **`classifyPrincipalIdentity` defaults to user type.** Ambiguous principals (no clear user/group signal) default to `nodeType: 'user'` with `ambiguous: true` flag. This is acceptable — most AD principals in pentest contexts are users.

---

## 12. Config, Skill, Evidence, Scope Subsystems

**Files:** `src/config.ts` (~35 lines), `src/services/skill-index.ts` (~250 lines), `src/services/evidence-store.ts` (~130 lines), `src/services/scope-manager.ts` (~150 lines), `src/tools/scope.ts` (~120 lines)

### 12.1 Findings

#### F32 (Info): Evidence Store Path Traversal — Mitigated by Manifest Check

**Location:** `evidence-store.ts:getContent()` / `getRawOutput()`

`join(this.dir, evidenceId + '.content')` uses user-supplied `evidence_id`. Path traversal (e.g., `../../etc/passwd`) is theoretically possible. However, the `get_evidence` tool always checks `store.getRecord(evidence_id)` first — a manifest lookup against UUID v4 IDs generated internally. Traversal strings never match the manifest, so this is safe as currently wired.

**Note:** If `getContent()`/`getRawOutput()` are ever called with unsanitized input outside the tool handler path, this becomes exploitable. Add path component validation as defense-in-depth.

#### F33 (P3): Scope Manager Confirmation Gate is Soft

**Location:** `tools/scope.ts`, `confirm` parameter

Scope changes require `confirm: true`. This is a UX-level gate that depends on the LLM respecting the two-step pattern (preview first, then confirm). The MCP trust model treats tool callers as authorized, so this isn't a security boundary, but it provides no protection against tool calls from automated agents that skip the preview step.

#### F34 (Info): Skill Index — Clean Local TF-IDF

**Location:** `skill-index.ts`

Loads `.md` files from a configured directory using `readdirSync` (no symlink traversal risk). TF-IDF scoring with stemming stoplist for security terms. No external network calls, no vector DB dependency. Auto-creates `./skills` directory if it doesn't exist. Clean implementation.

---

## 13. Prompt Generator Security

**Files:** `src/services/prompt-generator.ts` (~350 lines)

### 13.1 Findings

#### F35 (Info): System Prompt Embeds Graph/Config Data Verbatim

**Location:** `prompt-generator.ts`, `generateIdentitySection()`, `generateStateSnapshotSection()`

Engagement config values (name, scope CIDRs, domains, OPSEC profile) and graph state metrics (node counts, compromised hosts, credential counts) are embedded directly into the system prompt. If an adversary can influence graph node labels or engagement config values (e.g., via honeypot output that gets parsed and displayed), they could theoretically inject prompt instructions.

This is inherent to the architecture — the system prompt must contain engagement context. The risk is proportional to the trust placed in parsed tool output, which is validated by Zod schemas at ingestion.

### 13.2 Strengths

1. **Sub-agent tool scoping.** Sub-agents get a restricted 16-tool subset — no access to `update_scope`, `suggest_inference_rule`, `generate_report`, etc.
2. **State-driven prompt.** System prompt is regenerated from graph state each time, so compacted sessions get fresh context.
3. **OPSEC constraints in prompt.** Blacklisted techniques and noise level surfaced in key principles section.
