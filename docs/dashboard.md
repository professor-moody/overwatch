# Live Dashboard

Overwatch includes a real-time operator dashboard built with [sigma.js](https://www.sigmajs.org/) (WebGL), [graphology](https://graphology.github.io/), and React. It is not merely a read-only graph viewer: operators can inspect the engagement, dispatch and steer agents, approve actions, manage campaigns and playbooks, edit active settings/scope, reconcile recovery, and generate reports. Every durable action goes through the same validated application-command and persistence boundary used by MCP and the CLI.

## Access

The dashboard starts on port **8384** (configurable via
`OVERWATCH_DASHBOARD_PORT`) in the same process as the MCP server. The
recommended startup is one shared daemon:

```bash
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
npm run build
npm run doctor
npm run start:daemon
```

Leave that command running. Do not start a second Overwatch process for the
browser; terminal Claude, the dashboard, the CLI, and managed agents all attach
to this owner. Re-running setup refreshes client wiring but never replaces an
existing engagement. If its config is missing beside retained state or other
engagement artifacts, setup preserves them and enters or requests explicit
recovery instead of creating a competing empty engagement.

```
http://localhost:8384
```

To disable the dashboard, set the port to `0`:

```bash
OVERWATCH_DASHBOARD_PORT=0
```

### Remote token mode

Loopback access needs no dashboard token. When binding the dashboard to a
non-loopback host, set `OVERWATCH_DASHBOARD_TOKEN` and enter through a URL such
as `https://ops.example.test/?token=<token>`.

The browser captures the landing token in `sessionStorage` under
`overwatch.dashboard.token`, removes every `token` query parameter from the
visible URL with `history.replaceState`, and preserves the route, other query
parameters, and hash. The shared transport then sends `Authorization: Bearer
<token>` on JSON/API, evidence-image, report, bundle, smoke, and download
requests. Protected media and downloads are loaded through authenticated blob
URLs. The main-state, session-terminal, and action-output WebSockets receive an
encoded `token` query parameter because browser WebSocket handshakes cannot set
an Authorization header.

If browser storage is unavailable, the captured credential remains in memory
for that page lifetime. Reloading then requires a fresh token-bearing landing
URL. Use TLS (normally a reverse proxy) whenever the dashboard is reachable
beyond the local machine.

Browser HTTP and WebSocket requests must also be same-origin with the served
dashboard host. Different ports are accepted only when both authorities are
loopback; foreign origins are rejected.

## Graph Interactions

### Node Dragging

Click and drag any node to reposition it. Dragged nodes become **fixed** — they stay in place while the layout algorithm continues to arrange the rest of the graph. This lets you pin important nodes (like domain controllers or compromised hosts) where you want them.

### Animated ForceAtlas2 Layout

The graph uses an animated ForceAtlas2 layout that runs continuously in the background:

- Nodes repel each other and cluster by connectivity
- `linLogMode` and `adjustSizes` produce better separation between clusters
- New nodes are initially grouped by type before the layout takes over
- The layout auto-stops after ~10 seconds of stability
- Toggle on/off with the **Layout** button or press **Space**

### Hover Highlighting

Hovering over a node dims all unrelated nodes and edges to 12% opacity, making the neighborhood structure immediately visible. A **tooltip** appears showing:

- Node type (color-coded badge)
- Label and key properties (IP, hostname)
- Connection count

### Edge Coloring

Edges are color-coded by category for quick visual identification:

| Category | Color | Edge Types |
|----------|-------|------------|
| Network | Blue | `REACHABLE`, `RUNS`, `SAME_DOMAIN` |
| Access | Green | `ADMIN_TO`, `HAS_SESSION`, `CAN_RDPINTO`, `CAN_PSREMOTE` |
| Credential | Amber | `VALID_ON`, `OWNS_CRED`, `TESTED_CRED` |
| Derivation | Orange | `DERIVED_FROM`, `DUMPED_FROM` |
| Attack | Red | `CAN_DCSYNC`, `DELEGATES_TO`, `WRITEABLE_BY`, `GENERIC_ALL`, `CAN_READ_LAPS`, `CAN_READ_GMSA`, `RBCD_TARGET`, etc. |
| Roasting | Red | `AS_REP_ROASTABLE`, `KERBEROASTABLE` |
| ADCS | Purple | `CAN_ENROLL`, `ESC1`–`ESC13`, `ESC15` |
| Lateral | Pink | `RELAY_TARGET`, `NULL_SESSION` |

### Path Highlighting

**Shift+click** two nodes to highlight the shortest path between them. The path is drawn in amber with a thicker line weight. An info bar shows the path length and node sequence. Press **Esc** or click the close button to clear.

### Neighborhood Focus

**Double-click** a node to isolate its 2-hop neighborhood. All other nodes are hidden. A "Show All" banner appears at the top — click it or press **Esc** to exit focus mode.

### Node Sizing

Nodes are sized dynamically by degree (connection count): `base + log2(degree + 1) * 1.5`. Highly connected nodes like domain controllers and relay targets appear larger.

### New Node Pulse

When new nodes arrive via WebSocket (from `report_finding` or `parse_output`), they briefly glow with a pulse animation for 2 seconds. This makes it easy to spot new discoveries in real time.

### Search

The search box in the graph overlay matches against node labels, IPs, hostnames, and IDs. Choosing a result opens the inspector and fits the node into the visible workspace.

### Node Detail Panel

Click any node to open the right-side inspector. It shows:

- Node type badge with color
- All properties as key-value pairs
- Connection count
- Clickable neighbor list (click a neighbor to navigate to it)
- Clickable service summary items (navigate to service/edge nodes)
- **Derivation chain** (for credential nodes) — walks `DERIVED_FROM` edges bidirectionally to show the full credential chain with derivation methods
- **Screenshot** (for webapp nodes with a `screenshot_evidence_id`) — the ingested capture is rendered inline (from `/api/evidence/<id>/image`); click to open full-size

### Frontier Item Navigation

Click a graph action from Frontier, Credentials, Sessions, Activity, or an inspector relationship to open `/graph?node=...&hops=...`. The graph enters neighborhood focus, opens the inspector, and fits the visible neighborhood while reserving space for graph chrome and the right drawer.

### Trust Signals

Activity and Findings surface compact trust signals for correctness-sensitive states:

- parser output that extracted no graph data;
- ingest summaries with dropped records;
- path analysis failures or missing endpoints;
- IAM simulator `indeterminate` decisions and assume-depth caps;
- estimated CVSS scores.

These signals are operator-facing diagnostics. They do not mean the target is vulnerable by themselves; they tell you when absence of evidence, path output, or severity scoring needs verification before reporting.

The dashboard derives the summary from `/api/trust-signals`. Activity and Findings show row-level context, Overview shows the newest verification queue, Graph inspectors show signals tied to the selected node, and Smoke checks the endpoint shape.

## Sidebar Panels

The sidebar contains six collapsible panels:

| Panel | Content |
|-------|---------|
| **Lab Readiness** | Current readiness status and top issues |
| **Graph Summary** | Node counts by type, confirmed vs inferred edges |
| **Objectives** | Engagement objectives with achievement status |
| **Frontier** | Top 15 frontier items (click to zoom to node) |
| **Agents** | Active sub-agents with status |
| **Recent Activity** | Last 20 activity entries with timestamps |

Click any panel header to collapse/expand it. Panel state is persisted in `localStorage`.

## Controls

### Recovery status

Every main dashboard view shows a global recovery banner when persistence is not
fully writable or detached runtime ownership needs review. The banner
distinguishes active-config divergence, underlying WAL/state failure, and
unresolved process identity, so selecting file/state authority never appears
to repair an unrelated journal or runtime problem.

Open **Settings → Recovery** for the full outcome, contiguous/on-disk
checkpoints, observed/supported state and journal format versions, migration
backup path/checksum, file/runtime/state revisions and hashes, write-intent
state, and operator-facing reason. For a config-only divergence, **Use file**
and **Use state** submit the exact current hashes behind the abbreviated values
(hover a value to inspect its full digest). The controls require
confirmation and refresh status after success, conflict, or failure. They are
not offered for an incomplete known write or a simultaneous persistence
failure.

Runtime ownership warnings list the run ID, PID, and reason. Verified managed
orphan process trees are reclaimed during startup only after the process start
identity and per-run ownership token match. Reused, unverifiable, legacy, and
externally adopted PIDs are never signaled; they remain visible as `unknown`
for operator review.

While recovery is read-only, inspection routes remain available but durable
dashboard mutations return HTTP 503 with code `PERSISTENCE_READ_ONLY` and the
combined recovery object.

### Tape Toggle (Toolbar)

The top toolbar shows a **Tape** pill that mirrors the in-process JSON-RPC recorder:

- **Grey** — recorder off (default).
- **Red, pulsing** — recorder on; the label includes the start source (`env`, `config`, or `dashboard`) and live frame count when available.
- **Hover** — shows the active tape file path and start source.

Click to flip state. The toggle calls `POST /api/tape/toggle`; mutation auth applies on non-loopback dashboards. The pill hides itself if the build was started without a tape controller attached.

See [Tape Recording](tape-recording.md) for env vars, config, and the standalone proxy.

### Buttons

| Button | Action |
|--------|--------|
| **+** / **−** | Zoom in / out |
| **Fit icon** | Reset camera to fit all nodes |
| **Layout** | Toggle ForceAtlas2 layout on/off |
| **Reset** | Clear all filters, restore all node types |
| **View** | Dropdown for graph mode, label density, and focus presets |
| **Export** | Dropdown: **PNG** screenshot or **SVG** export of the current view |
| **Layers** | Dropdown for attack-path, credential-flow, community, and decluttering overlays |
| **More** | Reset saved node positions or open keyboard shortcuts |

### Layers

The **Layers** dropdown provides three mutually exclusive visualization overlays:

| Layer | Description |
|-------|-------------|
| **Attack Path** | Shows the actual attack path taken during the engagement (gold). Reconstructed from the activity history. |
| **Compare Shortest** | Overlays the theoretical shortest path (cyan) alongside the actual attack path for comparison. |
| **Credential Flow** | Highlights credential relationships: `DERIVED_FROM`, `OWNS_CRED`, `VALID_ON`, `POTENTIAL_AUTH`, `DUMPED_FROM`. Credential nodes show status badges (active=green, stale=amber, expired=red, rotated=purple). |
| **Community Hulls** | Color-coded convex hull overlays grouping nodes by Louvain community. On by default. Communities are detected automatically from graph topology. |

Activating Attack Path, Compare Shortest, or Credential Flow clears the others. Community Hulls is independent and can be toggled separately.

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F` | Fit to screen |
| `Space` | Toggle layout |
| `Esc` | Clear selection / exit focus / close detail |
| `R` | Reset filters |
| `+` / `-` | Zoom in / out |
| `?` | Toggle shortcuts help |

### Mouse Interactions

| Action | Effect |
|--------|--------|
| **Click node** | Open detail panel |
| **Drag node** | Reposition (becomes fixed) |
| **Hover node** | Highlight neighborhood + show tooltip |
| **Shift+Click** | Path highlight (click two nodes) |
| **Double-click** | Neighborhood focus (2-hop isolation) |
| **Click stage** | Close detail panel |

## Minimap

A compact minimap in the bottom-right overlay shows the full graph at a glance with a viewport rectangle indicating the current camera position.

## Architecture

![Dashboard Pipeline](assets/dashboard-pipeline-light.svg#only-light)
![Dashboard Pipeline](assets/dashboard-pipeline-dark.svg#only-dark)

- **HTTP** serves the Vite-built React dashboard from `dist/dashboard-next/` and the authenticated operator API.
- **Main WebSocket** connects immediately and is not considered synchronized until it receives a fresh `full_state` within five seconds.
- **Reconnect ownership** permits at most one physical main socket and one retry timer, with one-shot backoff at 1, 2, 4, 8, 16, then 30 seconds. Generation tags discard callbacks from replaced sockets.
- **HTTP fallback** polls every five seconds only while the main socket is unsynchronized. A newer socket generation aborts a stale poll so it cannot overwrite fresh state.
- **Session and action-output WebSockets** are component-owned and do not reconnect themselves; all three channels use the shared authenticated socket factory.
- **Dashboard mutations** are explicit operator commands routed through the same validation, idempotency, and durable transaction services used by MCP and the CLI.

### File Structure

| Area | Purpose |
|------|---------|
| `src/dashboard-next/src/components/layout/` | Operator shell, top toolbar, sidebar, tape toggle |
| `src/dashboard-next/src/components/panels/` | Console (Agents), Approvals (Actions), Add Targets, Frontier, Sessions, Activity, Evidence, Findings, Overview, Smoke, Settings |
| `src/dashboard-next/src/components/graph/` | Sigma graph workspace, overlays, inspector, export controls |
| `src/dashboard-next/src/hooks/` | Navigation, graph data, layout, Sigma lifecycle, keyboard shortcuts |
| `src/dashboard-next/src/lib/` | API client, graph utilities, camera fitting, route smoke helpers |

## Operator Console (cockpit)

The dashboard uses a **console-first IA**: the **Console** is the landing page and the operator's home, and the left nav is grouped **Console** (Console · Frontier · Approvals · Campaigns) · **Investigate** (Graph · Findings · Attack Paths · Evidence · Identity · Credentials · Activity · Overview) · **Manage** (Sessions · Engagements · Settings · Smoke). The operator works in the Console and steps out only to investigate, with one click back (press `c`).

The Console is a focused **master-detail** workspace:

- a pinned **command bar** (natural-language commands; see the grammar reference below);
- a **"Needs you" strip** — inline **Approve / Deny** for pending actions, an **Answer** box for agent questions, and **Confirm & run / Dismiss** for planner-proposed plans; it hides when nothing is waiting;
- a **Fleet** roster on the left — select an agent to focus its detail, per-agent steering (Pause/Resume/Stop/Tell), and its own activity stream; with nothing selected, a fleet overview sits over the full primary/sub-agent stream. Terminal (completed/failed/interrupted) agents can be **dismissed** from the roster individually or via **Clear finished** in the fleet header;
- a **Deploy** launcher and an **Add Targets** launcher in the header. See [Deploy](#deploy) and [Add Targets](#add-targets) below.

Approve/deny here routes through the same canonical path as the terminal; resolved rows clear off the live `action_resolved` push. The standalone **Approvals** view (Console group) is the deep triage queue with the same controls **plus batch triage** for a busy queue — every path still an explicit operator decision (no auto-approval):

- **Multi-select** (the *Select* toggle) → **Approve/Deny selected**; **per-technique "Approve all (N)"** in each group header; denials always take one shared reason.
- **Keyboard triage:** `a` approve the focused action · `j`/`k` move · `x` toggle its selection. (Deny stays click-driven — a reason is required.)
- A **subtle recommended cue** (a left-edge tint / soft ring on the suggested button) from the engine's risk / defensive-signals / noise-budget — a *visual hint only*, never a pre-selection.

See **[Operator Cockpit](operator-cockpit.md)** for the full model (NL command two-phase, the planner role, the directive substrate, escalation, and the safety invariant).

Free-form commands that need a planner are represented as durable application
commands. The UI follows that server-owned command rather than imposing a
browser-side planning timeout, so a page reload does not manufacture a failed
plan while its worker is still thinking. A planner that really exits without a
proposal reports that terminal outcome explicitly.

Dashboard-managed planners and agents run as isolated headless Claude workers.
Each worker receives a temporary task-specific MCP configuration, a bounded
tool surface, `--strict-mcp-config`, user-only setting sources, and no Claude
session persistence. It therefore shares Overwatch's engine, task leases, and
findings, but not the human terminal Claude session's project MCP servers,
project hooks/settings, or resume history. Keep using terminal Claude normally;
the shared daemon coordinates ownership between both surfaces.

### Deploy

The **Deploy** button opens a one-step deploy: type a target, pick (or accept the recommended) agent type, Deploy.

- A raw **IP / CIDR / domain** is an **ad-hoc real-time** target — `POST /api/agents/quick-deploy` adds it to scope (canonical `updateScope`) and dispatches the recommended agent at it, no engagement-setup ritual.
- Existing **graph node IDs** dispatch against those nodes (`POST /api/agents/dispatch`).
- The modal pre-selects the **recommended agent type** for the target and offers a **manual override** from the catalog (recon_scanner, web_tester, credential_operator, post_exploit, cve_researcher, osint_recon, pathfinder, report_scribe, default). See [Agent types & deploy](operator-cockpit.md#agent-types) for what each type does and its tool surface.
- A **Model** dropdown lets you pick which Claude model the headless agent runs on (passed as `claude -p --model <id>`). The choices come from `available_models` in `engagement.json` (or a default set); "Default" leaves it to `default_agent_model` / the CLI default. See [Agent Models](configuration.md#agent-models).

### Add Targets

The **Add Targets** modal adds scope mid-engagement without leaving the Console:

1. **Paste** IPs, CIDRs, or domains (whitespace/comma separated). Parsing matches the `scan` command exactly — a bare IP becomes `/32`, domains are lowercased, IPv6 and other junk are flagged and ignored.
2. **Preview impact** — `POST /api/config/scope/preview` (read-only) reports how many graph nodes would enter/leave scope and which pending scope suggestions resolve.
3. **Confirm** — `PATCH /api/config/scope` applies it through `engine.updateScope` (the canonical write path: CIDR validation, cold→hot promotion, inference re-run, `scope_updated` audit event).
4. **Enumerate** — new CIDRs surface `network_discovery` items on the Frontier (lazy; no host seeding), which you dispatch from there. The modal links straight to the Frontier.

The MCP-tool equivalent is [`update_scope`](tools/update-scope.md).

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard SPA (index.html) |
| `/assets/...` | GET | Vite-built dashboard JavaScript and CSS assets |
| `/api/state` | GET | Current engagement state (JSON), includes `history_count` |
| `/api/recovery` | GET | Combined WAL/state and active-config recovery status; available in degraded read-only mode |
| `/api/recovery/config/resolve` | POST | Reconcile config with `{ resolution, expected_file_hash, expected_state_hash }`; stale observations return 409 |
| `/api/graph` | GET | Full graph export (JSON) |
| `/api/history` | GET | Paginated activity log. Query params: `limit`, `after` (ISO), `before` (ISO) |
| `/api/evidence-chains/:nodeId` | GET | Evidence chain for a node — walks provenance edges (`DERIVED_FROM`, `DUMPED_FROM`, `OWNS_CRED`) to build the full derivation tree |
| `/api/paths/:objectiveId` | GET | Shortest paths from compromised nodes to an objective — returns path arrays with node/edge details |
| `/api/agents/dispatch` | POST | Dispatch a sub-agent (`{ target_node_ids, archetype?, skill?, campaign_id?, frontier_item_id? }`) |
| `/api/agents/quick-deploy` | POST | Ad-hoc deploy — scope a raw IP/CIDR/domain + dispatch the recommended/chosen agent type |
| `/api/agent-archetypes` | GET | Agent-type catalog for the Deploy picker |
| `/api/agents/:id/directive` | POST | Steer one running agent — one validated directive op via `executeOps` |
| `/api/agents/:id/dismiss` | POST | Remove a terminal agent from the roster (409 if it's still running/pending — cancel first) |
| `/api/fleet/directive` | POST | Fleet-wide pause/resume/stop (optionally one campaign) |
| `/api/fleet/dismiss` | POST | Bulk "Clear finished" — dismiss every terminal agent (optionally one campaign) |
| `/api/commands` | POST | NL command — preview / confirm / deny (operator cockpit) |
| `/api/config/scope/preview` | POST | Read-only dry-run of a scope change — nodes entering/leaving scope, resolved suggestions (Add Targets) |
| `/api/config/scope` | PATCH | Apply a scope change (full-replacement body, diffed server-side → `updateScope`) |
| `/api/actions/:id/approve` · `/api/actions/:id/deny` | POST | Resolve a pending action (inline approve/deny; canonical `resolveApprovalRequest` path) |
| `/api/actions/approve-batch` · `/api/actions/deny-batch` | POST | Bulk resolve `{ action_ids[] }` (deny takes one shared `reason`) — each id routes through the same canonical path |
| `/api/plans` | GET | Open planner-proposed plans awaiting confirmation |
| `/api/agent-queries` · `/api/agent-queries/:id/answer` | GET · POST | Agent→operator question inbox + answer |
| `/api/actions/:id/output` | GET | Raw stdout/stderr (head-by-default) + run metadata (Analysis workspace) |
| `/api/evidence/:id/raw` | GET | Bounded, paged (`offset`/`max_bytes`) raw-evidence read |
| `/api/evidence/:id/image` | GET | Serve a `screenshot` evidence blob as raw image bytes — raster only (PNG/JPEG/GIF/WebP; SVG excluded), 25 MB cap, `nosniff` + inline disposition. 404 if absent, 415 if not a viewable image |
| `/api/actions/:id/reparse` | POST | Re-parse a run's output — preview (`ingest:false`) or promote (`ingest:true`) to the graph |
| `/api/parsers` | GET | Supported parser names for the re-parse picker |
| `ws://…/ws` | WebSocket | Live graph delta + `agent_console_update` / `agent_query` push stream |
| `ws://…/ws/session/:id` | WebSocket | Component-owned interactive-session terminal channel |
| `ws://…/ws/actions/:id/output` | WebSocket | Live stdout/stderr stream of a running action (Analysis) |

## Verifying Dashboard Status

Run `npm run doctor` before startup to verify the local build, configuration,
Claude CLI compatibility, and port ownership. Run it again with the daemon
active to compare the running PID/build identity with the checkout. Use
[`run_lab_preflight`](tools/run-lab-preflight.md) to check engagement-level
dashboard readiness:

```json
{
  "dashboard": {
    "enabled": true,
    "running": true,
    "address": "http://localhost:8384"
  }
}
```

Note: [`get_state`](tools/get-state.md) is an operational engagement briefing;
it neither reports dashboard readiness nor replaces full history/evidence
retrieval. Use `run_lab_preflight` for dashboard readiness, `get_history` and
`get_evidence` for detail, and `bundle_engagement` for a portable archive.
