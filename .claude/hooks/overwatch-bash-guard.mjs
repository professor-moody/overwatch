#!/usr/bin/env node

import {
  denyPreToolUse,
  getBashCommand,
  isLikelyTargetFacingCommand,
  readHookInput,
  suggestedOverwatchRoute,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

const input = await readHookInput();
const command = getBashCommand(input);

if (isLikelyTargetFacingCommand(command)) {
  writeHookOutput(denyPreToolUse([
    'Target-facing raw Bash is blocked for Overwatch engagements.',
    'Route this through Overwatch run_tool/run_bash or open_session/send_to_session so scope validation, action logging, evidence capture, and parse/report follow-up are preserved.',
    suggestedOverwatchRoute(command),
  ].join(' ')));
}
