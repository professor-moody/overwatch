# verify_activity_chain

Verify the tamper-evident activity log hash chain.

**Read-only:** Yes

## Description

Walks the live activity log and verifies the hash chain for events that participate in tamper-evidence. Ingested, inferred, and reasoning-only entries are counted as excluded entries and do not break the chain.

When `hash_chain_enabled` is false in the engagement config, the tool returns `valid: true` with `chain_disabled: true` so callers can distinguish "chain disabled" from "chain verified".

The tool also **binds** each checkpoint back to the live log (`checkpoint_binding`), resolving by `event_id` (indices don't survive log truncation). This catches a *tampered-then-rehashed* log: `verifyChain` passes on an internally-consistent forgery, but its checkpoints no longer match the recomputed chain tail. Binding is checked regardless of whether a signing key is configured.

When a verifier public key is configured (`OVERWATCH_CHECKPOINT_PUBLIC_KEY`), the tool additionally verifies Ed25519 checkpoint signatures and returns `checkpoint_signatures` and `checkpoint_attestation`. Without a verifier key, behavior is hash-chain + binding only.

## Checkpoint signature verification

Checkpoint signing is opt-in: the signer sets `OVERWATCH_CHECKPOINT_SIGNING_KEY`; verifiers set `OVERWATCH_CHECKPOINT_PUBLIC_KEY`. With no key configured, checkpoints are unsigned and the hash chain + binding provide tamper-evidence.

With a verifier key configured, attestation is **strict** — `checkpoint_attestation.ok` is `true` only when **all** of:

- Every checkpoint is signed *and* verifies against a known key (an unsigned run, a bad signature, or an unknown/forged key all fail).
- **Checkpoints exist.** A configured verifier key with **zero** checkpoints is a hard failure — stripping every checkpoint from a signed run must not attest.
- Every checkpoint **binds to this engagement**: its `engagement_nonce` matches the anchor and its `schema_version` equals the current checkpoint schema.
- The checkpoint↔log binding is valid.

The signed canonical form is domain-separated (`overwatch-checkpoint-v1`) and carries a `schema_version`. Bumping the schema is a **hard break** — pre-nonce signatures are not accepted (no dual-path).

### Anti-splice: anchor the nonce out-of-band

The engagement nonce lives in the *same* persisted state an attacker with write access controls. Comparing checkpoints to `config.engagement_nonce` alone is therefore only a **self-consistency** check — it detects a naive splice that forgot to rewrite the config nonce, but **not** a full-state-write transplant that copies engagement A's signed log *and* rewrites the config nonce to A's.

For real anti-splice, the verifier supplies the expected nonce **out-of-band** via `OVERWATCH_CHECKPOINT_ENGAGEMENT_NONCE` (recorded at engagement creation, kept outside the state file). When set it is authoritative: the config nonce **and** every checkpoint must match it, so a transplant is rejected because the attacker cannot change the env-supplied value.

### Rolling window

The activity log is a bounded rolling window (`tieredTruncate`). When it exceeds the cap, the **oldest** chained-entry prefix ages out (never a mid-chain drop), and checkpoints for aged-out events are pruned. Verification seeds from the window's first `prev_hash`, so the surviving contiguous sub-chain still verifies; attestation covers the retained window, not events that have aged out.

## Parameters

None.

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | Whether the enabled chain verifies. |
| `chain_disabled` | boolean | Whether verification was skipped because the config disables the chain. |
| `chained_count` | number | Number of participating events. |
| `excluded_count` | number | Number of excluded events. |
| `breaks` | array | Chain break details, if any. |
| `checkpoint_signatures` | object \| null | Signature report when a verifier key is configured and checkpoints exist, else `null`. |
| `checkpoint_binding` | object | `{ valid, latest_valid_index, mismatch_count }` — whether the checkpoints bind to the live log (by `event_id`). |
| `checkpoint_attestation` | object | Strict attestation outcome (see below). |

`isError` is `true` when the chain is invalid, the checkpoint↔log binding fails, or (with a verifier key) attestation fails.

When a verifier key is configured, `checkpoint_signatures` reports:

| Field | Type | Description |
|-------|------|-------------|
| `total` | number | Number of checkpoints. |
| `signed` | number | Checkpoints carrying a signature. |
| `verified` | number | Signatures that verified against a known key. |
| `failed` | array | `event_index` of checkpoints whose signature failed verification. |
| `unverifiable` | array | `event_index` of signed checkpoints signed by an unknown/forged key. |

`checkpoint_attestation` is `{ configured: false }` when no verifier key is set. When a verifier key is configured it is `{ configured: true, ok, reason }`, where `ok` is `false` (with a human-readable `reason`) unless every checkpoint is signed and verified.
