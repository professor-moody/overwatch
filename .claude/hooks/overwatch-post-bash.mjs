#!/usr/bin/env node

import {
  contextOutput,
  getBashCommand,
  isEngagementActive,
  isLikelyTargetFacingCommand,
  outputLooksLikeDiscovery,
  readHookInput,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

const input = await readHookInput();
const command = getBashCommand(input);

// Engagement control only — no record-discovery nudges while developing Overwatch.
if (isEngagementActive() && (isLikelyTargetFacingCommand(command) || outputLooksLikeDiscovery(input))) {
  writeHookOutput(contextOutput('PostToolUse', [
    'Overwatch follow-up: if this Bash output contains discovery, credentials, services, vulnerabilities, or access changes, record it now with parse_output(), report_finding(), or ingest_json().',
    'Do not leave recon results only in prose.',
  ].join(' ')));
}
