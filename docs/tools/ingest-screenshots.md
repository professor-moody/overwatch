# ingest_screenshots

Read a visual-recon report's PNG files off disk and ingest them as **viewable** screenshot evidence.

## Description

`parse_output(gowitness)` records the graph nodes plus a `screenshot_path` string on each webapp — but the PNG bytes never enter Overwatch, so nothing can display them. `ingest_screenshots` closes that gap: it reads each PNG, stores it in the evidence store as a binary `screenshot` blob, and stamps the resulting `screenshot_evidence_id` onto the webapp node. The dashboard then renders it via [`/api/evidence/{evidence_id}/image`](#serving).

The image bytes are read straight from disk and **never pass through the model context**. File resolution is path-traversal guarded to stay inside `report_dir`.

## Usage

Run gowitness first, then ingest:

```bash
gowitness scan single -u https://target --write-jsonl   # writes ./gowitness.jsonl + screenshot PNGs
```

Then call `ingest_screenshots` with `report_dir` pointing at that directory.

## Parameters

| Param | Required | Description |
|-------|----------|-------------|
| `report_dir` | yes | Absolute directory holding the screenshot PNGs (and, by default, `gowitness.jsonl`). |
| `jsonl_path` | no | Path to the gowitness JSON-lines report. Defaults to `<report_dir>/gowitness.jsonl`. |
| `agent_id` | no | Attribution: agent that ran the capture. |
| `action_id` | no | Attribution: action id to tie the evidence to. |

## Behavior

- Parses the report with the same logic as `parse_output(gowitness)` (so webapp nodes converge by origin with any existing httpx/nuclei/gowitness webapp).
- For each webapp with a screenshot: resolves `<report_dir>/<file>` (rejecting anything that escapes `report_dir`), reads the PNG, stores it as `screenshot` evidence, and sets `screenshot_evidence_id` on the node.
- A missing PNG, an oversized file (> 25 MB), or a path-traversal attempt is **skipped**, not fatal — the summary reports counts. (When served, only raster images are returned — SVG is deliberately excluded to avoid script-in-image risks.)

Returns `{ screenshots_stored, skipped, skipped_detail, webapps, new_nodes, updated_nodes }`.

## Serving

Stored screenshots are served as raw image bytes at `GET /api/evidence/{evidence_id}/image` (raster types only — PNG/JPEG/GIF/WebP; SVG is deliberately excluded). The dashboard renders the image in the webapp node's detail drawer.

## Example

> **"I ran gowitness into `/tmp/gw` — ingest the screenshots so I can see them."**

```json
{
  "report_dir": "/tmp/gw"
}
```
