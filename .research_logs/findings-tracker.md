# Overwatch Code Review — Findings Tracker

**Review Date:** 2026-04-13 – ongoing
**Full Review:** [code-review-2026-04-13.md](code-review-2026-04-13.md)
**Fix rounds:** P0–P2 completed 2026-04-14, P3 completed 2026-04-14, Info closed 2026-04-14

## Summary

| Severity | Count | Fixed | Remaining |
|----------|-------|-------|-----------|
| P0       | 1     | 1     | 0         |
| P1       | 3     | 3     | 0         |
| P2       | 9     | 8     | 1 (accepted risk) |
| P3       | 10    | 9     | 1 (WONTFIX) |
| Info     | 13    | 2     | 11 (closed — notes) |
| **Total**| **36**| **23**| **13 (all dispositioned)** |

## Findings

### P0 — Critical

| ID  | Title | Location | Status |
|-----|-------|----------|--------|
| F01 | Responder parser NTLMv1/v2 misclassification | `src/services/parsers/responder.ts:101-102` | ✅ FIXED |

**F01 Fix (2026-04-14):** Changed both ternary branches to `'ntlmv1_challenge' : 'ntlmv2_challenge'`. Added `case 'ntlmv1_challenge'` to `getCredentialMaterialKind()`. Tests: 3 new assertions in `output-parsers.test.ts` + 1 in `credential-utils.test.ts`.

### P1 — High

| ID  | Title | Location | Status |
|-----|-------|----------|--------|
| F02 | `parse_output` file_path arbitrary file read | `src/tools/parse-output.ts:105` | ✅ FIXED |
| F03 | NXC parser silently drops failed auth results | `src/services/parsers/nxc.ts:156` | ✅ FIXED |
| F04 | Cold store loses finding_id/action_id provenance | `src/services/finding-ingestion.ts:94-109` | ✅ FIXED |

**F02 Fix (2026-04-14):** Created `src/utils/path-validation.ts` with `validateFilePath()`. Wired into `parse-output.ts` before `readFileSync`. Rejects null bytes, empty paths, enforces optional baseDir. Tests: 9 cases in `path-validation.test.ts`.

**F03 Fix (2026-04-14):** Added `[-]` failed auth handling in `nxc.ts` — extracts domain\user, creates user node, adds `TESTED_CRED` edge (confidence 0.0). Added `TESTED_CRED` to `EDGE_TYPES` and `EDGE_CONSTRAINTS`. Tests: 3 new cases in `output-parsers.test.ts`.

**F04 Fix (2026-04-14):** Extended `ColdNodeRecord` with `finding_id?`/`action_id?`. Updated `toColdRecord()` to accept context, wired in `finding-ingestion.ts`. Tests: 2 new cases in `cold-store.test.ts`.

### P2 — Medium

| ID  | Title | Location | Status |
|-----|-------|----------|--------|
| F05 | Hashcat parser accepts whitespace-only passwords | `src/services/parsers/hashcat.ts:89` | ✅ FIXED |
| F06 | Certipy text fallback silently drops ESC edges | `src/services/parsers/certipy.ts:112-126` | ✅ FIXED |
| F07 | State persistence not atomic on Windows | `src/services/state-persistence.ts:29-37` | ✅ FIXED |
| F08 | Socket adapter early buffer race condition | `src/services/session-adapters.ts:291-300` | ✅ FIXED |
| F09 | Kerbrute parser rejects single-char passwords | `src/services/parsers/kerbrute.ts:95-103` | ✅ FIXED |
| F16 | `output_dir` in report/retro tools not validated | `src/tools/reporting.ts`, `src/tools/retrospective.ts` | ✅ FIXED |
| F21 | Dashboard WebSocket has no authentication | `src/services/dashboard-server.ts:60-75` | ✅ FIXED |
| F24 | No concurrency protection on shared GraphEngine | `src/app.ts:241-242` | ⚠️ ACCEPTED |
| F27 | Inference selector fallback creates spurious global edges | `src/services/inference-engine.ts` | ✅ FIXED |

**F05 Fix (2026-04-14):** `plaintext.length === 0` → `plaintext.trim().length === 0`. Test: 1 new case.

**F06 Fix (2026-04-14):** Added post-parse check in `parse-output.ts` — certipy with nodes but zero edges pushes warning about text fallback.

**F07 Fix (2026-04-14):** Added `process.platform === 'win32'` branch with unlink+rename fallback.

**F08 Fix (2026-04-14):** `earlyBuffer.length >= 0` → `earlyBuffer.length > 0` (was always-true).

**F09 Fix (2026-04-14):** `colonIndex === remainder.length - 1` → `colonIndex >= remainder.length - 1`. Test: 1 new case.

**F16 Fix (2026-04-14):** Wired `validateFilePath()` into `reporting.ts` and `retrospective.ts` for `output_dir`.

**F21 Fix (2026-04-14):** Token-based auth on WebSocket upgrade when non-loopback. Requires `OVERWATCH_DASHBOARD_TOKEN` env var. Tests: `isLoopback` + CORS assertions.

**F24 Accepted Risk:** JS single-threaded — no data races. Logical races possible but mitigated by identity resolution dedup. Not a current use case.

**F27 Fix (2026-04-14):** Changed 3 selector fallbacks (`matching_user_domain`, `domain_admins_and_session_holders`, `delegation_targets`) to return `[]`. Tests: 2 updated unit + 3 updated integration tests.

### P3 — Low

| ID  | Title | Location | Status |
|-----|-------|----------|--------|
| F10 | Snapshot files accumulate in working directory | Root directory | ✅ FIXED |
| F11 | `node-pty` native build dependency undocumented | `package.json:31` | ✅ FIXED |
| F12 | No lockfile integrity / `npm audit` in CI | `package.json`, CI | WONTFIX |
| F17 | Credential chain walker produces duplicates | `src/services/retrospective.ts:1313` | ✅ FIXED |
| F18 | RLVR reward skew — enumeration dwarfs objectives | `src/services/retrospective.ts:1035-1040` | ✅ FIXED |
| F22 | CORS regex misses IPv6 loopback `[::1]` | `src/services/dashboard-server.ts:222-226` | ✅ FIXED |
| F23 | Static file traversal checks correct (defensive) | `src/services/dashboard-server.ts:252-270` | ✅ FIXED |
| F25 | Disconnected client tool calls not cancelled | `src/app.ts:288-291` | ✅ FIXED |
| F28 | Custom rule properties spread can override edge fields | `src/services/inference-engine.ts:~164` | ✅ FIXED |
| F29 | Cold store promotion sets confidence to 1.0 | `imperative-inference.ts:~82`, `scope-manager.ts:~105` | ✅ FIXED |
| F33 | Scope manager confirmation gate is soft | `src/tools/scope.ts` confirm param | WONTFIX |

**F12 Excluded:** CI config change, not code fix. Separate effort.

**F22 Fix (2026-04-14):** Updated CORS regex to include `\\[::1\\]`. Tests: 3 CORS assertions in `dashboard-server.test.ts`.

**F33 Excluded:** Acceptable design with audit logging. MCP trust model treats callers as authorized.

**F10 Fix (2026-04-15):** Snapshots now written to `.snapshots/` subdirectory. `listSnapshots()` checks both new and legacy paths for backward compat. `rollbackToSnapshot()` resolves from both. Added `mkdirSync` for subdir creation.

**F11 Fix (2026-04-15):** Moved `node-pty` to `optionalDependencies` in `package.json`. Made import dynamic with graceful fallback. `LocalPtyAdapter.spawn()` and `SshAdapter.spawn()` throw clear error if not installed. Added README note.

**F17 Fix (2026-04-15):** Added `visited.delete(nodeId)` backtracking in `buildCredentialChains()` walk function. Removed `visited.clear()` between starts. Diamond-shaped credential graphs now produce all distinct chains.

**F18 Fix (2026-04-15):** Capped discovery reward: `Math.min(newNodes * 0.5 + newEdges * 0.3, 5.0)` at both structured and heuristic trace paths. Large enumeration findings no longer dominate objective bonuses.

**F23 Fix (2026-04-15):** Added `decodeURIComponent()` defense-in-depth — rejects `%2e%2e`-encoded traversal attempts before the existing `..` check. Secondary defense behind the `relative()` containment check.

**F25 Fix (2026-04-15):** Added per-transport `AbortController` in `sessionAbortControllers` map. Signaled on `transport.onclose`. Exposed on `OverwatchApp` type. Cleaned up in `shutdownOverwatchApp()`.

**F28 Fix (2026-04-15):** Moved `...production.properties` spread BEFORE fixed fields in `applyRuleProductions()`. Fields `type`, `confidence`, `tested`, `discovered_by`, `inferred_by_rule`, `inferred_at` now always take declared values. Test: custom rule with override attempt verifies fixed fields are protected.

**F29 Fix (2026-04-15):** Added `confidence` field to `ColdNodeRecord` interface. Preserved in `toColdRecord()`. Both promotion paths (`imperative-inference.ts`, `scope-manager.ts`) now use `coldRecord.confidence ?? 1.0`.

### Info — Informational

| ID  | Title | Location | Status |
|-----|-------|----------|--------|
| F13 | Parser registry key inconsistency (`linpeas.sh`) | `src/services/parsers/index.ts` | CLOSED — intentional aliases |
| F14 | BloodHound ingest handles both classic+CE formats | `src/services/bloodhound-ingest.ts` | CLOSED — positive finding |
| F15 | Graph edge constraint validation comprehensive | `src/services/graph-schema.ts` | CLOSED — positive finding |
| F19 | Two parallel markdown report generators | `report-generator.ts` vs `retrospective.ts` | CLOSED — serve different purposes |
| F20 | HTML report trace_quality stubbed with zeros | `src/tools/reporting.ts:164-165` | ✅ FIXED |
| F26 | HTTP and dashboard bind to separate ports | `src/app.ts`, `dashboard-server.ts` | CLOSED — architectural choice |
| F30 | Expired credential edges never fully degrade | `imperative-inference.ts` | CLOSED — intentional design |
| F31 | Identity resolution — verified sound | `src/services/identity-resolution.ts` | CLOSED — positive finding |
| F32 | Evidence store path traversal mitigated by manifest | `src/services/evidence-store.ts` | ✅ HARDENED |
| F34 | Skill index — clean local TF-IDF | `src/services/skill-index.ts` | CLOSED — positive finding |
| F35 | System prompt embeds config/state verbatim | `src/services/prompt-generator.ts` | CLOSED — architectural tradeoff |

**F13 Closed:** Both `linpeas` and `linpeas.sh` are registered as aliases — lookup is case-insensitive. No change needed.

**F14 Closed:** Positive audit finding. BloodHound ingest correctly handles both SharpHound v4 and AzureHound/CE formats.

**F15 Closed:** Positive audit finding. Edge constraints enforce source/target type validity for all edge types.

**F19 Closed:** `generateFullReport()` (client deliverable) and `generateReport()` (internal retrospective summary) serve distinct purposes. Maintenance cost is acceptable.

**F20 Fix (2026-04-14):** Extended `TraceQualityReport` with `total_actions`, `structured_count`, `mixed_count`, `heuristic_count`. Populated in `exportTrainingTraces()`. HTML report now maps actual values instead of hardcoded zeros.

**F26 Closed:** Intentional architectural separation. MCP transport (port 3000) and dashboard (port 8384) run independently for isolation.

**F30 Closed:** Confidence floor of 0.1 for expired credentials is intentional — allows re-testing stale credentials. Frontier clutter is acceptable tradeoff.

**F31 Closed:** Positive audit finding. Identity resolution is deterministic, handles FQDN/short hostname matching, and correctly creates opaque nodes for unresolved identities.

**F32 Hardened (2026-04-14):** Added `sanitizeEvidenceId()` defense-in-depth to `getContent()` and `getRawOutput()`. Rejects IDs containing path separators, `..`, or null bytes. Existing manifest-based lookup already prevented exploitation.

**F34 Closed:** Positive audit finding. TF-IDF skill index is clean — local filesystem only, no network calls.

**F35 Closed:** Architectural tradeoff inherent to LLM+state systems. Engagement context must be in the system prompt. Mitigated by Zod validation at ingestion boundary.
