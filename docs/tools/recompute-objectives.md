# recompute_objectives

Re-evaluate objective status from the graph.

**Read-only:** No

## Description

Recomputes all engagement objectives from the current graph state and engagement config. Use it after graph correction, bulk ingestion, or any case where objective status appears stale.

Objective truth is derived from current nodes, edges, and config. It is not derived from `PATH_TO_OBJECTIVE` edges alone.

## Parameters

None.

## Returns

Returns the before/after objective status summary produced by the graph engine.
