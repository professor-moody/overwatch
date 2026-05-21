#!/usr/bin/env node

import { OVERWATCH_REMINDER, contextOutput, readHookInput, writeHookOutput } from './overwatch-hook-lib.mjs';

await readHookInput();
writeHookOutput(contextOutput('UserPromptSubmit', OVERWATCH_REMINDER));
