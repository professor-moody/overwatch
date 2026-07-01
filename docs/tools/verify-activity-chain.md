# verify_activity_chain

Verify the tamper-evident activity log hash chain.

**Read-only:** Yes

## Description

Walks the live activity log and verifies the hash chain for events that participate in tamper-evidence. Ingested, inferred, and reasoning-only entries are counted as excluded entries and do not break the chain.

When `hash_chain_enabled` is false in the engagement config, the tool returns `valid: true` with `chain_disabled: true` so callers can distinguish "chain disabled" from "chain verified".

When a verifier public key is configured (`OVERWATCH_CHECKPOINT_PUBLIC_KEY`), the tool also verifies Ed25519 checkpoint signatures on top of the hash-chain check, and returns `checkpoint_signatures` and `checkpoint_attestation`. Without a verifier key, behavior is unchanged (hash-only chain verification).

## Checkpoint signature verification

Checkpoint signing is opt-in: the signer sets `OVERWATCH_CHECKPOINT_SIGNING_KEY`; verifiers set `OVERWATCH_CHECKPOINT_PUBLIC_KEY`. With no key configured, checkpoints are unsigned and the hash chain alone provides tamper-evidence.

With a verifier key configured, signature attestation is **strict**: every checkpoint must be signed *and* verified. An unsigned run, a bad signature, or a checkpoint signed by an unknown/forged key all fail — `checkpoint_attestation.ok` becomes `false` and the tool errors. This prevents an unverified run from passing silently and giving false assurance.

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
| `checkpoint_attestation` | object | Strict attestation outcome (see below). |

When a verifier key is configured, `checkpoint_signatures` reports:

| Field | Type | Description |
|-------|------|-------------|
| `total` | number | Number of checkpoints. |
| `signed` | number | Checkpoints carrying a signature. |
| `verified` | number | Signatures that verified against a known key. |
| `failed` | array | `event_index` of checkpoints whose signature failed verification. |
| `unverifiable` | array | `event_index` of signed checkpoints signed by an unknown/forged key. |

`checkpoint_attestation` is `{ configured: false }` when no verifier key is set. When a verifier key is configured it is `{ configured: true, ok, reason }`, where `ok` is `false` (with a human-readable `reason`) unless every checkpoint is signed and verified.
