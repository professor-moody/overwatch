#!/usr/bin/env node

import {
  getRecentUserPrompt,
  isEngagementActive,
  isLikelyEngagementPrompt,
  readHookInput,
  readRecentTranscript,
  transcriptHasOverwatchToolThisTurn,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

const input = await readHookInput();

if (input?.stop_hook_active === true) {
  process.exit(0);
}

// Engagement control only — don't block turn completion while developing Overwatch
// itself (the text heuristics below match this codebase's own vocabulary).
if (!isEngagementActive()) {
  process.exit(0);
}

const transcriptLines = readRecentTranscript(input);
const recentPrompt = getRecentUserPrompt(transcriptLines);
const lastAssistant = String(input?.last_assistant_message || '');
const looksEngagementRelated = isLikelyEngagementPrompt(recentPrompt) || (
  isLikelyEngagementPrompt(lastAssistant) && /\b(frontier|graph|target|credential|finding|objective)\b/i.test(lastAssistant)
);

if (looksEngagementRelated && !transcriptHasOverwatchToolThisTurn(transcriptLines)) {
  writeHookOutput({
    decision: 'block',
    reason: [
      'Overwatch drift check: this looks like engagement work, but this turn did not appear to use an Overwatch MCP tool.',
      'Continue by calling get_state() before answering from memory, then use next_task/validate_action or parse_output/report_finding as appropriate.',
      'If Overwatch is unavailable or this is actually repo maintenance, say that explicitly and finish.',
    ].join(' '),
  });
}
