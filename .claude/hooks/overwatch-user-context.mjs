#!/usr/bin/env node

import {
  OVERWATCH_REMINDER,
  contextOutput,
  readHookInput,
  shouldInjectUserContext,
  writeHookOutput,
} from './overwatch-hook-lib.mjs';

const input = await readHookInput();

if (shouldInjectUserContext(input)) {
  writeHookOutput(contextOutput('UserPromptSubmit', OVERWATCH_REMINDER));
}
