#!/usr/bin/env node
// PreToolUse:Task — during an active engagement, block delegating to a host-runtime
// subagent (the `Task` tool). A host subagent escapes EVERY Overwatch control at once
// (no frontier_item_id, lease, scope, OPSEC, approval, or audit), which is the biggest
// drift surface. Engagement work must go through Overwatch dispatch instead. Silent on
// a dev checkout (isEngagementActive gate) so building Overwatch itself isn't blocked.
import {
  denyPreToolUse,
  isEngagementActive,
  readHookInput,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

await readHookInput();

if (isEngagementActive()) {
  writeHookOutput(denyPreToolUse([
    'Delegating to a host-runtime subagent (Task) bypasses every Overwatch control at once —',
    'no frontier_item_id, lease, scope validation, OPSEC, approval gate, or audit trail.',
    'Dispatch the work through Overwatch instead: dispatch_agents (or register_agent for a',
    'one-off). Overwatch sub-agents run as MCP clients of the same engine with a bounded',
    'archetype tool-surface, so every action stays scoped, gated, and provable.',
  ].join(' ')));
}
