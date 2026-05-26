#!/usr/bin/env node

import { spawnSync } from 'child_process';
import { join, resolve } from 'path';

const hookDir = resolve('.claude/hooks');

function runHook(script, input) {
  const result = spawnSync(process.execPath, [join(hookDir, script)], {
    input: JSON.stringify(input),
    encoding: 'utf8',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${script} exited ${result.status}: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function parseOutput(text) {
  return text ? JSON.parse(text) : undefined;
}

const denied = parseOutput(runHook('overwatch-bash-guard.mjs', {
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'nmap -sV 10.0.0.5' },
}));

if (denied?.hookSpecificOutput?.permissionDecision !== 'deny') {
  throw new Error('expected target-facing Bash to be denied');
}

const allowed = runHook('overwatch-bash-guard.mjs', {
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'git status --short' },
});

if (allowed !== '') {
  throw new Error('expected repo-maintenance Bash to be allowed without output');
}

const context = parseOutput(runHook('overwatch-user-context.mjs', {
  hook_event_name: 'UserPromptSubmit',
  prompt: 'what should we scan next on the target?',
}));

if (!context?.hookSpecificOutput?.additionalContext?.includes('Overwatch grounding')) {
  throw new Error('expected engagement prompt to receive Overwatch grounding context');
}

console.log('Claude hook smoke passed');
