#!/usr/bin/env node
// PostToolUse:Write|WebFetch — during an active engagement, nudge the model to land
// anything it wrote to disk or fetched from the web into the Overwatch graph, so recon
// doesn't stay off-graph (a finding only in a file or a fetch buffer is invisible to the
// rest of the engagement). A soft reminder, not a block. Silent on a dev checkout.
import {
  contextOutput,
  isEngagementActive,
  readHookInput,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

const input = await readHookInput();

if (isEngagementActive()) {
  const verb = input?.tool_name === 'WebFetch' ? 'fetched' : 'wrote';
  writeHookOutput(contextOutput('PostToolUse', [
    `Overwatch follow-up: if this ${verb} engagement discovery (recon, credentials, services,`,
    'vulnerabilities, access), record it in the graph with parse_output(), report_finding(),',
    'or ingest_json(). Do not leave it only in a file or a fetch buffer.',
  ].join(' ')));
}
