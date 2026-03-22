# run_lab_preflight

Aggregate lab-readiness checks for GOAD or single-host testing.

**Read-only:** Yes

## Description

Runs a comprehensive read-only lab-readiness check for the current engagement. Aggregates:

- Engagement config validity and scope shape
- Offensive tool availability for the selected profile
- Graph health summary
- Persistence and restart-safety checks
- Dashboard readiness
- Current graph stage (empty, seeded, or mid-run)

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile` | `"goad_ad"` \| `"single_host"` | `"goad_ad"` | Lab profile to validate against |

### Profiles

- **`goad_ad`** — GOAD-style multi-host AD lab validation. Checks for AD-specific tools (BloodHound, NXC, Impacket, etc.).
- **`single_host`** — HTB-style standalone host validation. Checks for basic reconnaissance tools.

## Returns

A `LabPreflightReport` object:

| Field | Type | Description |
|-------|------|-------------|
| `profile` | `string` | Profile used |
| `status` | `"ready"` \| `"warning"` \| `"blocked"` | Overall readiness |
| `graph_stage` | `string` | `empty`, `seeded`, or `mid_run` |
| `checks` | `LabReadinessCheck[]` | Individual check results |
| `missing_required_tools` | `string[]` | Tools needed but not found |
| `warnings` | `string[]` | Non-blocking issues |
| `recommended_next_steps` | `string[]` | What to do next |
| `dashboard` | `object` | Dashboard enabled/running/address |

## Usage Notes

- Run before your first lab session to validate the environment
- Run after major ingestion to confirm the graph is healthy
- Run after restart to verify state persistence
