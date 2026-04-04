# run_lab_preflight

Aggregate lab-readiness checks for any engagement profile.

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
| `profile` | `"goad_ad"` \| `"single_host"` \| `"network"` \| `"web_app"` \| `"cloud"` \| `"hybrid"` | inferred | Lab profile to validate against. If omitted, inferred from engagement config. |

### Profiles

- **`goad_ad`** — GOAD-style multi-host AD lab validation. Checks for AD-specific tools (BloodHound, NXC, Impacket, etc.).
- **`single_host`** — HTB-style standalone host validation. Checks for basic reconnaissance tools.
- **`network`** — Multi-host CIDR-scoped lab (HTB ProLabs, etc.). Domains discovered organically rather than pre-configured.
- **`web_app`** — Web application assessment. URL-scoped, checks for web-specific tooling (gobuster, feroxbuster, nuclei, etc.).
- **`cloud`** — Cloud environment assessment (AWS/Azure/GCP). Validates cloud resource scope and cloud-specific tooling.
- **`hybrid`** — Combined network + cloud + web assessment. Validates tooling and scope across all surface types.

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
