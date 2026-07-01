#!/usr/bin/env node
// SessionStart / PreCompact — during an active engagement, inject a reminder to (re)load
// the dynamic engagement instructions. CLAUDE.md mandates calling get_system_prompt at
// session start and after compaction, but nothing enforced it — after a compaction the
// model loses the generated prompt and drifts to the static CLAUDE.md. The hook can't call
// MCP itself, so it injects the reminder as context. Silent on a dev checkout.
//
// NB PreCompact's event/output shape is version-dependent; returning additionalContext is
// best-effort (ignored if the installed Claude Code doesn't consume it — never harmful).
import {
  contextOutput,
  isEngagementActive,
  readHookInput,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

const input = await readHookInput();

if (isEngagementActive()) {
  const event = input?.hook_event_name === 'PreCompact' ? 'PreCompact' : 'SessionStart';
  writeHookOutput(contextOutput(event, [
    'Overwatch bootstrap: call get_system_prompt(role="primary") now to load the current',
    'engagement instructions (the dynamic prompt is the source of truth, not memory or the',
    'static CLAUDE.md), then get_state() before reasoning or acting.',
  ].join(' ')));
}
