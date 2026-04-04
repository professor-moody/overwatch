# get_evidence

Retrieve full-fidelity evidence by ID or list stored evidence records.

**Read-only:** Yes

## Description

When evidence or `raw_output` is submitted via [`report_finding`](report-finding.md), the full payload is stored durably on disk (not truncated). Use this tool to retrieve the complete content by `evidence_id`, or list all stored evidence records.

The `evidence_id` is returned in `report_finding` responses and stored in activity log `details.evidence_id` fields.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `evidence_id` | `string` | No | Specific evidence ID to retrieve full content |
| `action_id` | `string` | No | List evidence for a specific action |
| `finding_id` | `string` | No | List evidence for a specific finding |
| `list_only` | `boolean` | No | If true, return manifest records without content (default: `false`) |

## Returns

### Single Evidence Retrieval (with `evidence_id`)

| Field | Type | Description |
|-------|------|-------------|
| `evidence_id` | `string` | Evidence identifier |
| `action_id` | `string` | Associated action ID |
| `finding_id` | `string` | Associated finding ID |
| `evidence_type` | `string` | `screenshot`, `log`, `file`, or `command_output` |
| `filename` | `string` | Associated filename (if any) |
| `content` | `string` | Full evidence content (omitted when `list_only: true`) |
| `raw_output` | `string` | Full raw output (omitted when `list_only: true`) |

### Evidence Listing (without `evidence_id`)

| Field | Type | Description |
|-------|------|-------------|
| `total` | `number` | Total number of matching records |
| `records` | `array` | Array of evidence manifest records |

## Usage Notes

- Use `evidence_id` to retrieve a specific evidence record with full content
- Use `action_id` or `finding_id` to filter the evidence list
- Set `list_only: true` to get metadata without fetching potentially large content payloads
- Evidence is stored durably and survives server restarts (unlike sessions)
- The `evidence_id` is included in `report_finding` responses — capture it for later retrieval
