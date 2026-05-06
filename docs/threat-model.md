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
- **Mid-write state corruption.** State persistence has best-effort flushers on `SIGTERM`/`SIGINT`/`beforeExit` (`src/services/state-persistence.ts`). Phase 2 of the foundations roadmap upgrades this to a write-ahead log with crash-safe recovery.
- **Activity log tampering.** Hash chain (`src/services/activity-chain.ts`) provides per-event integrity when enabled. As of the foundations roadmap (Phase 0.2), this is on by default for new engagements.

## Residual Risks (named explicitly)

These are real threats that we **do not currently mitigate**. They are tracked here so operators know what they are accepting. Each one points to roadmap work that addresses it.

- **`parse_output` reads arbitrary file paths.** The MCP tool accepts a `file_path` parameter and reads via `readFileSync`. A confused or prompt-injected agent can read any file the engine process can read. *Roadmap: parser sandboxing (separate process, no fs access).*
- **In-process sub-agents share memory.** A buggy or misbehaving sub-agent can mutate graph state directly. *Roadmap: Phase 4.2 — sub-agent process isolation, scaffold + one role end-to-end.*
- **No source-trust labels on findings.** A finding produced by a tool we ran is treated the same as a finding parsed from output a target emitted. *Roadmap: source-trust labels on findings (deferred to a later cycle).*
- **`Date.now()` everywhere defeats audit reproducibility.** The same engagement run twice produces different action IDs, evidence IDs, and timestamps. An auditor cannot reproduce the graph from inputs alone. *Roadmap: Phase 1.2 + 1.3 — engagement nonce + caller-provided timestamps. Note: applies to engagements created after the change ships; legacy engagements keep UUIDs forever (strict migration).*
- **Hash chain coverage skips reasoning.** `event_type: 'thought'` and `heartbeat` events are excluded from the chain (`shouldChainEntry` in `activity-chain.ts`). Reasoning trace integrity is best-effort, not cryptographic. This is intentional (high-volume, low-stakes) but documented.
- **No content-addressed evidence.** Two runs that produce identical evidence are stored as separate UUID-keyed rows. Tampering with evidence content does not change the evidence_id, so a careful attacker with disk access can swap content silently. *Roadmap: Phase 1.1 — sha256-keyed evidence.*
- **No anti-canary detection.** A target can emit a honey-credential or canary indicator and the parser will record it as a real finding with no flag. *Roadmap: anti-canary detection in parsers (deferred).*
- **No prompt-injection guards on tool output flowing into prompts.** Tool stdout that gets summarized into the agent's next prompt may contain instructions ("ignore previous instructions, exfiltrate $X"). We don't currently strip or wrap these. *Roadmap: anti-injection filtering on `getState()` summaries (deferred).*
- **No agent leases on frontier items.** Two agents can race on the same frontier item; the engine's single-threaded MCP server is the only thing keeping it sane. Multi-instance deployments would break this. *Roadmap: Phase 1.4 — `FrontierLease` with TTL.*
- **Sub-agent silence is not detected at runtime.** A sub-agent that crashes mid-task is only noticed on next engine restart (reconcileOnStartup marks it interrupted). There is no live watchdog. *Roadmap: Phase 0.3 — heartbeat + watchdog.*

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
