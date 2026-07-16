# Threat Model

This document states explicitly what Overwatch trusts, what it doesn't, what attacks it currently mitigates, and what residual risks the operator needs to be aware of. It is the source of truth for security-flavored design decisions; if a feature implies a security claim that contradicts this doc, fix the doc or fix the feature.

## Scope

Overwatch is an MCP-mediated layer between an LLM agent and offensive-security tooling, plus a graph-of-engagement-state that humans and agents share. The threat model covers:

- The agent's behavior (LLM may be confused, prompt-injected, or buggy).
- Output from target systems (potentially adversarial).
- The substrate's own integrity (audit trail, evidence chain, state recovery).
- The operator workflow (approval gates, scope boundaries).

Out of scope: defending the operator's own workstation, defending the LLM provider's infrastructure, defending against a malicious operator who has full local access. Those threats are real but not Overwatch's job.

## Trust Assertions

| Principal | Trust level | Why |
| --- | --- | --- |
| **Operator** | Trusted | The operator has full local read/write on the engine. They control scope, OPSEC, and approvals. We don't try to defend against them. |
| **Agent (LLM)** | Validated | The agent authors commands and selects actions, but every action passes through scope/OPSEC/approval validation. Agent output that flows into runtime decisions (scoring, frontier picks) is constrained by structural validation. The agent may be confused or prompt-injected; we assume so. |
| **Target output** | Untrusted | stdout/stderr from anything we run against a target is hostile input. Parsers must handle malformed, malicious, and canary-shaped data. |
| **Parser inputs from targets** | Hostile | Specifically: a Responder relay can craft fake hashes, a WordPress plugin can emit fake CVE banners, a misconfigured target can produce honey-credentials. Parsers should not promote target-asserted "facts" to high-confidence findings without corroboration. |
| **Sub-agents (in-process)** | Trusted today | Sub-agents currently share memory with the main engine. A misbehaving sub-agent can corrupt graph state. Phase 4 introduces optional process isolation; until then, sub-agents are inside the trust boundary. |
| **Knowledge base across engagements** | Trusted | The KB is operator-managed. Cross-engagement learning assumes prior engagements' data is honest. A compromised KB contaminates future engagements; back it up like any other operator-controlled artifact. |
| **Tape recordings** | Replay-only | Tapes capture wire frames. They are NOT a re-execution mechanism — replaying a tape against a live target would re-run the actions. Tapes are for audit and for golden-master tests, not for engagement reproduction. |

## Threats Currently Mitigated

These attacks are explicitly defended against today (cross-references in parens point to the implementing code):

- **Scope bypass via metadata omission.** An agent that calls `run_bash("nmap 8.8.8.8")` without target_ip or technique used to slip through scope. Implicit-target extraction now triggers on known-target-facing binaries (`src/tools/_process-runner.ts` `TARGET_FACING_BINARIES` allowlist).
- **OPSEC ceiling violations on direct actions.** Agent-supplied `noise_estimate` exceeding `max_noise` is rejected when OPSEC enforcement is enabled (`src/tools/_process-runner.ts` ceiling check). When OPSEC is disabled, the entire pipeline is inert — no hidden enforcement.
- **Approval bypass via timeout.** Auto-approval-on-timeout still happens (configurable), but it is now stamped `auto_approved: true` and `unattended_execute: true`, surfaced in OPSEC logs and retrospective summaries. Operators can audit unattended decisions post-hoc.
- **Silent dashboard config drops.** OPSEC payloads from the dashboard with unknown keys (e.g., the legacy `approval_timeout_seconds`) used to be silently dropped. Strict zod parsing on `/api/config` now returns 400 on unknown keys.
- **Type confusion in graph merges.** AzureHound role assignments could flip an existing `group` node into a `cloud_identity`, polluting paths. `addNode` now refuses type changes and emits an instrumentation warning.
- **Stale BloodHound sessions counted as live access.** Imported sessions used to satisfy `session_live !== false` (missing-flag = live). Now they are stamped `session_live: false` at import; live-compromise counting requires explicit `=== true`.
- **Credential material loss.** Roast/NXC parsers used to drop hash material on the floor. They now persist full hashcat-formatted hashes / NTLM / ccache paths in `cred_value` so credentials are reusable.
- **Cracked plaintext leaking into UI labels.** Hashcat output put plaintext in credential labels; report renderer surfaced them. Labels now redact; secrets live in `cred_value` and are gated.
- **Mid-write state corruption.** State persistence does atomic write-rename plus a per-mutation write-ahead log (`src/services/mutation-journal.ts`) for managed active engagements and deterministic-ID contexts. Existing WAL data is recovered regardless of the current config. Recovery on load combines the newest valid base with journal replay; malformed or partial tails stop writable recovery and remain preserved for repair.
- **Activity log tampering.** Hash chain (`src/services/activity-chain.ts`) is **default-on for new engagements** with checkpoints every 500 events / 30 minutes. Checkpoints are **signed (Ed25519) when a signing key is configured** — the signer sets `OVERWATCH_CHECKPOINT_SIGNING_KEY` (`npm run gen:checkpoint-key` generates a keypair and prints the env exports); otherwise checkpoints are unsigned and the hash chain still provides tamper-evidence, with the signature adding attribution/non-repudiation on top. Signing is fail-open in the log hot path (a crypto error emits an unsigned checkpoint, never crashes). `verify_activity_chain` walks the chain; `verifyCheckpoints` resumes from the latest checkpoint instead of replaying genesis. When a verifier public key (`OVERWATCH_CHECKPOINT_PUBLIC_KEY`) is set, `verify_activity_chain` verifies checkpoint signatures **strictly** — every checkpoint must be signed and verified (unsigned/failed/unknown-key all fail) — and reports `checkpoint_signatures` + `checkpoint_attestation {configured, ok, reason}`.
- **Audit reproducibility.** Engagements created with an `engagement_nonce` get deterministic `act_<16hex>` / `evt_<16hex>` IDs derived from `sha256(nonce | agent | ts | cmd | seq)`. Combined with caller-provided timestamps (`engine.withClock`), the same inputs produce a byte-identical state hash on replay. Validated end-to-end by `src/__tests__/golden-master/replay.test.ts`.
- **Evidence tampering on disk.** Evidence rows carry `content_hash = sha256(content)`. Two runs with identical output deduplicate; modifying content on disk changes the address. `get_evidence` lookups accept either UUID or hash.
- **Frontier item races.** TTL leases (`src/services/frontier-leases.ts`) prevent two agents from claiming the same item. `register_agent` returns `lease_conflict` rather than racing. Heartbeat extends the lease; terminal status releases it.
- **Sub-agent silence detection.** `agent_heartbeat` MCP tool + `AgentWatchdog` service (`src/services/agent-watchdog.ts`) reap tasks whose heartbeat is older than `heartbeat_ttl_seconds` (default 120). Stale frontier leases are reaped on the same tick.
- **Phase-specific policy enforcement.** Engagement phases declare `opsec_overrides` and `approval_overrides`; `validateAction` and `PendingActionQueue.needsApproval` consume the effective config. Phase blacklist **extends** (cannot weaken) engagement-level safety. `phase_entered` / `phase_exited` events are hash-chained.
- **Target-asserted facts indistinguishable from tool-observed facts.** A finding parsed from adversarial target output used to look identical to one produced by a tool we ran. `sourceTrust()` (`src/services/source-trust.ts`) now derives a `source_trust` label — `observed` (tool-observed: confidence ≥ 1.0 / `confirmed_at` / tested-success), `asserted` (target-asserted; the conservative default), or `inferred` (rule-derived, `inferred_by_rule`) — computed on read (never stored, no migration). Opt-in via `exportGraph({ sourceTrust: true })` and surfaced on the `/api/graph/export` endpoint for report honesty.

## Residual Risks (named explicitly)

These are real threats that we **do not currently mitigate**. They are tracked here so operators know what they are accepting. Each one points to roadmap work that addresses it.

- **`parse_output` reads arbitrary file paths.** The MCP tool accepts a `file_path` parameter and reads via `readFileSync`. A confused or prompt-injected agent can read any file the engine process can read. *Roadmap: parser sandboxing (separate process, no fs access).*
- **In-process sub-agents share memory.** A buggy or misbehaving sub-agent can mutate graph state directly. The `subagent_isolation: 'process'` flag plus the IPC scaffold (`src/services/subagent-ipc.ts`) is proven end-to-end on the recon-scoping role; other roles fall back to in-process until follow-up work fills out coverage. *Roadmap: full role-by-role parity for `subagent_isolation: 'process'`.*
- **Hash chain coverage skips reasoning + heartbeat.** `event_type: 'thought'` and `event_type: 'heartbeat'` events are excluded from the chain (`shouldChainEntry` in `activity-chain.ts`). Reasoning trace integrity is best-effort, not cryptographic. This is intentional (high-volume, low-stakes) but documented.
- **No anti-canary detection.** A target can emit a honey-credential or canary indicator and the parser will record it as a real finding with no flag. *Roadmap: anti-canary detection in parsers (deferred).*
- **No prompt-injection guards on tool output flowing into prompts.** Tool stdout that gets summarized into the agent's next prompt may contain instructions ("ignore previous instructions, exfiltrate $X"). We don't currently strip or wrap these. *Roadmap: anti-injection filtering on `getState()` summaries (deferred).*
- **Legacy engagements keep UUID-based identity forever.** No retroactive recomputation. If you need replay/audit guarantees on an existing engagement, create a fresh one and re-run.
- **Checkpoint signing key rotation / HSM.** Ed25519 key **generation and verification are implemented** (#123, `src/services/activity-chain.ts`): `generateCheckpointKeypair` / `npm run gen:checkpoint-key`, `loadCheckpointSigningKey` / `loadCheckpointKeyring`, `signCheckpoint`, and `verifyCheckpointSignatures` / `attestCheckpointSignatures`. The key id is derived from the public key, so signer and verifier agree automatically. Still out of scope: **key rotation and HSM-backed keys**. Also deferred: binding a checkpoint's `event_index`/`hash` back to the log (the activity log is tier-truncated, so indices don't survive). *Roadmap: rotation + HSM.*

## Audit & Reproducibility Guarantees

Per the strict migration policy:

- **Engagements created with `engagement_nonce` populated** (i.e., new engagements after the foundations roadmap ships) get deterministic action IDs, deterministic event IDs, and (with Phase 1.3) deterministic timestamps. These engagements are byte-reproducible from a recorded JSON-RPC tape + scope/config.
- **Engagements without `engagement_nonce`** (legacy) continue to use UUID-based IDs and `new Date()` timestamps. They are auditable via the activity log + hash chain, but not byte-reproducible. We do not retroactively recompute IDs — the migration is opt-in by virtue of being a new engagement.
- The hash chain provides **integrity** (tampering detection) for both classes; only **reproducibility** depends on the nonce.

## Defense Posture by Phase

| Engagement phase | Trust posture |
| --- | --- |
| **Recon** | Lowest stakes. OPSEC ceiling can be relaxed; auto-approve passive techniques. |
| **Enumeration** | Medium. Approval-gated for noisy techniques; scope boundaries strictly enforced. |
| **Exploitation** | Highest stakes. All actions approval-gated by default. Phase-aware OPSEC overrides (Phase 4.1) tighten ceilings here. |
| **Post-exploitation** | High. Lateral movement attempts go through approval; credential reuse tracked; defensive-signal detection should pause the campaign. |

Phase-aware policy (roadmap Phase 4.1) makes these trust-posture differences enforceable in code rather than aspirational.

## Updating This Document

Any change that affects what Overwatch trusts, what it defends against, or what residual risks remain MUST update this document in the same PR. Reviewers should bounce PRs that introduce trust-relevant behavior without a corresponding doc update. The doc is a living artifact; it does not need to be perfect, but it must not lie.
