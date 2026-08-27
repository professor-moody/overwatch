# Frontend Redesign Assessment and Plan

## Executive recommendation

Overwatch does not need another round of panel polish. It needs a smaller product model.

The current dashboard exposes implementation domains as peer destinations: agents, frontier items, approvals, campaigns, graph nodes, findings, paths, evidence, runs, identities, credentials, recon, activity, overview, sessions, engagements, settings, and diagnostics. Most of these screens are individually useful, but the operator must reconstruct the relationship between them.

The redesign should organize the interface around four operator jobs:

1. **Operate** — decide what needs attention, start work, and steer live work.
2. **Investigate** — understand an asset, identity, relationship, path, or piece of evidence.
3. **Review** — validate findings, close evidence gaps, and produce reports.
4. **Manage** — configure the engagement and inspect system health.

This reduces the primary navigation from 18 destinations to four workspaces while preserving the existing domain depth through contextual lenses, inspector tabs, and backward-compatible deep links.

## What was assessed

The assessment covered:

- the React shell, route model, sidebar, toolbar, shared primitives, stores, and navigation helpers;
- the Console, Frontier, Approvals, Campaigns, Graph, Findings, Attack Paths, Evidence, Analysis, and Overview screens;
- the deterministic demo engagement at the default desktop viewport and at 900 px and 640 px widths;
- existing dashboard documentation, operator-cockpit guidance, route smoke tests, and navigation compatibility tests.

The existing UI has a strong functional foundation. The graph canvas, evidence semantics, trust signals, deep links, deterministic demo, and operator-safety controls should be retained.

## Current-state findings

### 1. Navigation reflects the data model, not the operator's work

There are 18 sidebar destinations in three groups. Several are different projections of the same underlying objects:

- Console, Frontier, Approvals, Campaigns, and Overview all describe work state.
- Console, Activity, Analysis, and Sessions all describe execution state.
- Graph, Recon, Identity, Credentials, Attack Paths, and Evidence all describe the engagement graph.
- Findings, Evidence Debt, Evidence, and Reports all describe report readiness.

The group labels help, but do not remove the need to remember which projection contains which action.

### 2. The Console is a dashboard inside the dashboard

The Console first viewport contains fleet controls, target and deploy actions, a command composer, the attention queue, evidence debt, a fleet roster, fleet metrics, and a full activity stream. Each area is legitimate, but together they compete for priority.

The result is an operator home with several simultaneous starting points instead of one obvious decision loop.

### 3. Context is repeatedly lost and reconstructed

An operator can move from a frontier item to Graph, then Evidence, then Analysis, then Findings, with each destination reloading the same identifiers into a different screen. The Evidence screen even presents relationship cards that send the operator back to Sessions, Approvals, Frontier, or Findings.

Those relationships should be tabs in one persistent inspector, not navigation chores.

### 4. Visual hierarchy is flattened by containers

The dashboard uses cards for sections, metrics, rows, empty states, attention items, and nested details. The panel layer currently contains 58 shared `PanelSection` uses and many additional one-off bordered surfaces. Cards often contain more cards.

This makes routine data look as important as urgent decisions. Borders and backgrounds are doing work that spacing, typography, alignment, and selection state should do.

### 5. The interaction system is visually inconsistent

The shared primitive layer is useful, but it is not the only system in use:

- panel code contains 103 shared `ActionButton` uses and 153 direct `<button>` implementations;
- components contain 424 explicit 8–11 px text declarations;
- status, risk, trust, source type, technique, and selection all compete through pills and colored labels;
- labels vary between code, route, navigation, and page title (`actions`/Approvals, `smoke`/Diagnostics, `agents`/Console/Operator Console/Fleet overview).

The interface feels assembled from many locally correct decisions rather than one visual grammar.

### 6. The Graph is a separate product shell

Most routes use the global toolbar, sidebar, breadcrumb, and “Back to Console” control. Graph replaces that shell with a full-canvas toolbar and its own Console link. The canvas benefits from the space, but the abrupt shell change breaks location and workflow continuity.

The graph should remain full-canvas inside the same application frame, with the primary rail collapsed and the shared inspector retained.

### 7. Compact widths technically fit but lose hierarchy

At 640 px, the UI avoids page-level horizontal overflow, but the toolbar truncates, the navigation becomes an unlabeled icon strip, actions wrap into multiple lines, and dense Console regions stack into a long page. The layout is surviving, not adapting.

Overwatch should explicitly target desktop operations. A supported minimum width should be defined, with a deliberate compact-desktop shell below it instead of implicit wrapping.

### 8. Documentation has drifted with the interface

The dashboard guide still describes older sidebar and panel structures in places, while the source and live product expose newer destinations such as Recon, Analysis, Engagements, and the current console-first organization. This is another symptom of an interface model that is difficult to hold in one place.

## Target product model

### Visual thesis

A calm, dark operational canvas: sparse chrome, strong type hierarchy, clear state color, and one selected object anchoring the workspace.

### Content plan

- **Global status:** engagement, connection, OPSEC posture, recovery state, active sessions.
- **Primary workspace:** the current operator job and its dominant list, canvas, or review surface.
- **Context inspector:** the selected work item, asset, finding, run, or session, with related information in tabs.
- **Transient detail:** activity, terminal output, and raw evidence in a resizable bottom drawer.

### Interaction thesis

- Selection should move fluidly between list, canvas, and inspector without route changes.
- The inspector should use a shared layout transition when the selected object changes, preserving tab and scroll context where possible.
- Activity and terminal surfaces should slide into a bottom drawer, with restrained live-update pulses only for new or changed state.

## Proposed information architecture

### Global shell

The top utility bar contains:

- engagement selector and phase/objective context;
- connection, recovery, OPSEC, and live-session status;
- global search/command entry;
- account/system utilities.

The left navigation contains only:

- **Operate**
- **Investigate**
- **Review**
- **Manage**

The right side is a consistent context inspector. The bottom edge hosts a collapsible activity/session drawer. The primary navigation may collapse on narrower desktop widths, but the current destination remains labeled.

### Operate workspace

This workspace replaces Console, Frontier, Approvals, and most of Campaigns and Overview.

Structure:

- a compact mission strip: objectives, phase, OPSEC posture, and the one most important warning;
- an attention inbox for approvals, questions, stuck work, and plans;
- a unified work list with saved views: Active, Ready, Waiting, Campaigns, and Completed;
- one primary “Start work” action that opens target, frontier, and agent-type options in context;
- a persistent inspector for the selected agent, task, approval, plan, or campaign;
- activity and live output in the bottom drawer.

Frontier ranking remains canonical, but becomes the Ready view rather than a separate destination. Campaigns become grouping, batch dispatch, and saved-work views rather than a separate product area. Deep approval triage becomes an Attention view rather than a permanent navigation item.

### Investigate workspace

This workspace replaces Graph, Recon, Identity, Credentials, Attack Paths, and the standalone Evidence route.

Structure:

- a full-canvas graph or dense entity list;
- a lens switcher: Topology, Assets, Identity, Credentials, Paths;
- one global entity search;
- a shared inspector with tabs: Summary, Relationships, Evidence, Activity, Findings, Actions;
- contextual follow-up actions in the inspector, including deploy, validate, open session, and add to campaign.

The graph remains the strongest visual mode, but list lenses handle tasks where labels, sorting, expiry, or bulk selection matter more than topology.

### Review workspace

This workspace replaces Findings plus the report-readiness portions of Overview and Evidence Debt.

Structure:

- prioritized findings list;
- review states: Needs proof, Needs verification, Ready, Included;
- selected-finding inspector with affected assets, evidence narrative, attack path, remediation, and report inclusion;
- report builder and archive as a secondary view.

Evidence should be reachable from any selected object, but proof readiness belongs here because it is a reporting decision.

### Manage workspace

This workspace contains Engagements, Settings, and Diagnostics. It should use a conventional settings hierarchy and keep routine administration out of the live operator loop.

Tape control, recovery, tool inventory, bundle/export, and diagnostics belong here unless their state is urgent; urgent system state remains visible globally.

### Retired top-level destinations

- **Overview:** its useful mission, status, and quality summaries move into Operate and Review.
- **Activity:** becomes the global bottom drawer with an optional expanded route for compatibility.
- **Analysis:** becomes the selected run's Output/Analysis inspector tab and bottom drawer.
- **Sessions:** active sessions become a global dock; session management opens in the inspector/drawer.
- **Evidence:** becomes an inspector tab everywhere; the old route deep-links into Investigate with the Evidence tab selected.

## Key workflows in the new model

### Decide and dispatch

`Operate → Attention/Ready → select item → inspect context → Start work → watch agent/output`

The operator does not leave the workspace. The work item changes state in place and the related agent becomes the selected object.

### Investigate an asset or path

`Investigate → search or select → inspect relationships/evidence/findings → switch lens if needed → launch follow-up`

Graph, list, path, and evidence are views of one selected object, not separate trips.

### Validate and report

`Review → Needs proof → select finding → inspect evidence/path → launch validation or mark ready → add to report`

Evidence debt becomes a workflow state attached to a finding, not a separate dashboard card.

### Work in a live session

`Any workspace → active-session status → open bottom drawer → interact → inspect related asset or agent in the right inspector`

Sessions stay available without displacing the current investigation.

## Delivery plan

### Phase 0 — Baseline and workflow contract

Estimated effort: 2–3 days.

- Define the supported operator workflows and the minimum supported desktop width.
- Capture current screenshots and journey timings for the core demo flows.
- Inventory every existing route, deep link, mutation, keyboard shortcut, and browser journey.
- Define the redirect/compatibility map before changing navigation.
- Add visual-regression fixtures for 1440×900, 1280×800, and the selected compact-desktop width.

Exit criteria:

- Every current capability has a named destination in the target model.
- The five highest-value journeys have automated browser coverage.
- Existing deep links have an explicit migration rule.

### Phase 1 — Shell and visual foundation

Estimated effort: 4–6 days.

- Build the four-destination application shell.
- Introduce shared workspace, inspector, drawer, toolbar, table/list-row, field, and status components.
- Consolidate typography, spacing, button, surface, focus, and semantic-color tokens.
- Remove nested card treatment from routine layout.
- Define a minimum readable utility type size; reserve tiny type for secondary IDs only.
- Keep old routes rendering inside the new shell during migration.

Exit criteria:

- Four primary destinations are visible and labeled at every supported width.
- Graph uses the same global shell and inspector model.
- Routine screens have no more than one enclosing surface border per region.
- Keyboard focus, hover, selected, disabled, warning, and destructive states are visually consistent.

### Phase 2 — Operate workspace

Estimated effort: 7–10 days.

- Merge attention, fleet, frontier, and campaign projections into one work model.
- Build saved views for Active, Ready, Waiting, Campaigns, and Completed.
- Move agent, approval, plan, and campaign detail into the shared inspector.
- Move activity and live output into the bottom drawer.
- Replace the competing Deploy, Add Targets, Bulk from Frontier, and command-bar entry points with one clear start-work flow plus global command access.

Exit criteria:

- A pending approval can be understood and resolved without changing workspace.
- A frontier item can be dispatched and followed through output/finding state without changing workspace.
- No fleet, frontier, approval, or campaign count is duplicated in the same viewport.
- The first viewport has one dominant decision area and one primary action.

### Phase 3 — Investigate workspace

Estimated effort: 8–12 days.

- Embed the graph in the new shell.
- Add the entity-list lenses for assets, identity, credentials, and paths.
- Build the shared object inspector tabs and preserve selection between lenses.
- Unify node/entity search and cross-links.
- Move evidence, related findings, related runs, and follow-up actions into the inspector.

Exit criteria:

- An operator can find an entity and reach its relationships, evidence, findings, paths, and next actions within two interactions.
- Switching between graph and list lenses preserves the selected object.
- Old Graph, Recon, Identity, Credentials, Paths, and Evidence URLs resolve to the correct lens and inspector tab.

### Phase 4 — Review and Manage

Estimated effort: 5–8 days.

- Build the finding review-state workflow.
- Integrate proof readiness, trust signals, evidence narrative, and report inclusion.
- Move report generation and archives into Review.
- Consolidate Engagements, Settings, Recovery, Diagnostics, exports, and tool inventory under Manage.
- Retire the standalone Overview route after its useful summaries have moved.

Exit criteria:

- A reviewer sees finding severity, proof readiness, trust caveats, affected assets, and report state together.
- A report can be generated without visiting another workspace.
- Routine configuration and health detail no longer compete with live engagement work.

### Phase 5 — Compatibility, cleanup, and proof

Estimated effort: 4–6 days.

- Convert old routes into redirects or compatibility entry points.
- Remove superseded panel and one-off primitive implementations.
- Update dashboard, cockpit, getting-started, and development documentation.
- Run visual, accessibility, keyboard, route, browser-journey, build, and performance checks.
- Compare task completion time and navigation count with the Phase 0 baseline.

Exit criteria:

- The primary navigation has four destinations.
- All current functional journeys and safety gates still pass.
- Existing bookmarks continue to resolve.
- No core workflow depends on unlabeled icons.
- The redesign improves navigation count and time-to-action in the benchmark journeys.

## Suggested implementation shape

The redesign can remain incremental and use the existing API/store architecture.

Suggested frontend boundaries:

```text
components/
  shell/
    AppShell
    GlobalStatusBar
    PrimaryNav
    ContextInspector
    ActivityDrawer
  workspaces/
    OperateWorkspace
    InvestigateWorkspace
    ReviewWorkspace
    ManageWorkspace
  operate/
    AttentionInbox
    WorkList
    WorkInspector
  investigate/
    InvestigationCanvas
    LensSwitcher
    EntityList
    EntityInspector
  review/
    FindingQueue
    FindingInspector
    ReportWorkspace
```

Existing selectors and API clients should feed new workspace-level view models. Backend mutations and safety boundaries should not change during the first three phases.

## Measures of success

Track outcomes, not only visual completion:

- primary navigation destinations: 18 → 4;
- route changes required for the core dispatch journey: target 0;
- route changes required to inspect entity relationships, evidence, findings, and runs: target 0;
- duplicated top-level counters in one viewport: target 0;
- unlabeled primary controls at the supported minimum width: target 0;
- first meaningful action from Console/Operate: visible without scrolling;
- evidence-readiness decision from finding selection: available in one inspector;
- old deep links and browser journeys: 100% mapped or intentionally deprecated.

## Recommended first slice

Start with the shell and Operate workspace, not a color or component refresh.

The smallest slice that proves the redesign is:

1. Four-item navigation and shared inspector/drawer shell.
2. Operate with Attention, Active, and Ready views.
3. Agent/frontier/approval details in the inspector.
4. Activity and output in the drawer.
5. Existing routes retained as compatibility entries.

That slice addresses the largest comprehension problem, exercises the new layout primitives, and leaves the graph-heavy Investigate migration for a second contained step.
