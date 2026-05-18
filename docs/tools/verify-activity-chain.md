# verify_activity_chain

Verify the tamper-evident activity log hash chain.

**Read-only:** Yes

## Description

Walks the live activity log and verifies the hash chain for events that participate in tamper-evidence. Ingested, inferred, and reasoning-only entries are counted as excluded entries and do not break the chain.

When `hash_chain_enabled` is false in the engagement config, the tool returns `valid: true` with `chain_disabled: true` so callers can distinguish "chain disabled" from "chain verified".

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
