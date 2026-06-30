import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { spawnSync } from 'child_process';
import { describe, expect, it, afterEach } from 'vitest';

const HOOK_DIR = resolve('.claude/hooks');
const tmpPaths: string[] = [];

// The hooks are engagement controls gated on isEngagementActive(). Tests simulate an
// active engagement by default (OVERWATCH_ENGAGEMENT_ACTIVE=1); pass { active: false } to
// assert the dev-checkout behavior where every hook stays silent.
function runHook(script: string, input: unknown, { active = true }: { active?: boolean } = {}) {
  const env = { ...process.env };
  if (active) {
    env.OVERWATCH_ENGAGEMENT_ACTIVE = '1';
  } else {
    env.OVERWATCH_ENGAGEMENT_ACTIVE = '';
    delete env.OVERWATCH_CONFIG;
  }
  const result = spawnSync(process.execPath, [join(HOOK_DIR, script)], {
    input: JSON.stringify(input),
    encoding: 'utf8',
    env,
  });
  if (result.error) throw result.error;
  return result;
}

function parseStdout(result: ReturnType<typeof runHook>) {
  const text = result.stdout.trim();
  return text ? JSON.parse(text) : undefined;
}

function writeTranscript(lines: unknown[]) {
  const dir = mkdtempSync(join(tmpdir(), 'overwatch-hook-test-'));
  tmpPaths.push(dir);
  const path = join(dir, 'transcript.jsonl');
  writeFileSync(path, lines.map(line => JSON.stringify(line)).join('\n'));
  return path;
}

afterEach(() => {
  for (const path of tmpPaths.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

describe('Claude Code Overwatch hooks', () => {
  it('injects grounding context on user prompt submit', () => {
    const result = runHook('overwatch-user-context.mjs', {
      hook_event_name: 'UserPromptSubmit',
      prompt: 'what should we scan next on the target?',
    });

    expect(result.status).toBe(0);
    const output = parseStdout(result);
    expect(output.hookSpecificOutput.hookEventName).toBe('UserPromptSubmit');
    expect(output.hookSpecificOutput.additionalContext).toContain('Overwatch grounding');
    expect(output.hookSpecificOutput.additionalContext).toContain('get_state()');
  });

  it('skips grounding context for obvious repo maintenance prompts', () => {
    const result = runHook('overwatch-user-context.mjs', {
      hook_event_name: 'UserPromptSubmit',
      prompt: 'commit and push the docs changes',
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('blocks target-facing raw Bash and redirects to Overwatch tools', () => {
    const result = runHook('overwatch-bash-guard.mjs', {
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'nmap -sV 10.0.0.5' },
    });

    expect(result.status).toBe(0);
    const output = parseStdout(result);
    expect(output.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(output.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(output.hookSpecificOutput.permissionDecisionReason).toContain('run_tool/run_bash');
    expect(output.hookSpecificOutput.permissionDecisionReason).toContain("run_bash(command='nmap -sV 10.0.0.5')");
  });

  it('allows normal repo-maintenance Bash', () => {
    const result = runHook('overwatch-bash-guard.mjs', {
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rg "Drift prevention" src docs' },
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('nudges graph ingestion after discovery-looking Bash output', () => {
    const result = runHook('overwatch-post-bash.mjs', {
      hook_event_name: 'PostToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'cat nmap.txt' },
      tool_response: { stdout: 'Nmap scan report for 10.0.0.5\nPORT STATE SERVICE\n22/tcp open ssh' },
    });

    expect(result.status).toBe(0);
    const output = parseStdout(result);
    expect(output.hookSpecificOutput.hookEventName).toBe('PostToolUse');
    expect(output.hookSpecificOutput.additionalContext).toContain('parse_output()');
    expect(output.hookSpecificOutput.additionalContext).toContain('Do not leave recon results only in prose');
  });

  it('blocks likely engagement drift at stop when no Overwatch tool was used', () => {
    const transcript = writeTranscript([
      { role: 'user', content: 'What should we scan next on the target?' },
      { role: 'assistant', content: 'We should probably scan the host from memory.' },
    ]);
    const result = runHook('overwatch-stop-check.mjs', {
      hook_event_name: 'Stop',
      transcript_path: transcript,
      stop_hook_active: false,
      last_assistant_message: 'We should probably scan the target next.',
    });

    expect(result.status).toBe(0);
    const output = parseStdout(result);
    expect(output.decision).toBe('block');
    expect(output.reason).toContain('get_state()');
  });

  it('does not block stop when the CURRENT turn used an Overwatch tool', () => {
    const filler = Array.from({ length: 300 }, (_, i) => ({ role: 'tool_result', content: `line ${i}` }));
    const transcript = writeTranscript([
      { role: 'user', content: 'What should we scan next on the target?' },
      { role: 'assistant', name: 'parse_output', content: 'parsed nmap output' },
      ...filler,
      { role: 'assistant', content: 'The graph now has the scan result.' },
    ]);
    const result = runHook('overwatch-stop-check.mjs', {
      hook_event_name: 'Stop',
      transcript_path: transcript,
      stop_hook_active: false,
      last_assistant_message: 'The target scan result is in the graph.',
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  // Turn-scoping regression: a tool call from a PRIOR turn must not suppress the block on a
  // later "answered from memory" turn (the old whole-transcript scan's hole).
  it('blocks when the only Overwatch tool call was in a prior turn', () => {
    const transcript = writeTranscript([
      { role: 'user', content: 'Scan the target for services.' },
      { role: 'assistant', name: 'get_state', content: 'oriented' },   // prior turn used a tool
      { role: 'assistant', content: 'Found ssh on the host.' },
      { role: 'user', content: 'What should we scan next on the target?' },  // CURRENT turn
      { role: 'assistant', content: 'We should probably scan the host from memory.' }, // no tool this turn
    ]);
    const result = runHook('overwatch-stop-check.mjs', {
      hook_event_name: 'Stop',
      transcript_path: transcript,
      stop_hook_active: false,
      last_assistant_message: 'We should probably scan the target next.',
    });

    expect(result.status).toBe(0);
    const output = parseStdout(result);
    expect(output.decision).toBe('block');
    expect(output.reason).toContain('get_state()');
  });

  it('does not block when the current turn used a tool, even after a prior tool-less turn', () => {
    const transcript = writeTranscript([
      { role: 'user', content: 'What should we do about the target?' },
      { role: 'assistant', content: 'Let me think about the target.' },  // prior turn: no tool
      { role: 'user', content: 'Go ahead and check the frontier.' },     // current turn
      { role: 'assistant', name: 'next_task', content: 'pulled the frontier' }, // current turn: tool
    ]);
    const result = runHook('overwatch-stop-check.mjs', {
      hook_event_name: 'Stop',
      transcript_path: transcript,
      stop_hook_active: false,
      last_assistant_message: 'The frontier has three credential tests queued.',
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('does not loop when stop hook is already active', () => {
    const result = runHook('overwatch-stop-check.mjs', {
      hook_event_name: 'Stop',
      stop_hook_active: true,
      last_assistant_message: 'Scan the target.',
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  // The active-engagement gate: on a dev checkout (no OVERWATCH_ENGAGEMENT_ACTIVE /
  // OVERWATCH_CONFIG) every hook stays silent, so developing Overwatch itself doesn't
  // trip the engagement controls (kills the alarm-fatigue false positives).
  describe('engagement-active gate (dev checkout → all hooks silent)', () => {
    it('does not inject grounding when no engagement is active', () => {
      const result = runHook('overwatch-user-context.mjs', {
        hook_event_name: 'UserPromptSubmit',
        prompt: 'what should we scan next on the target?',
      }, { active: false });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe('');
    });

    it('does not block target-facing Bash when no engagement is active', () => {
      const result = runHook('overwatch-bash-guard.mjs', {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'nmap -sV 10.0.0.5' },
      }, { active: false });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe('');
    });

    it('does not nudge after discovery output when no engagement is active', () => {
      const result = runHook('overwatch-post-bash.mjs', {
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'cat nmap.txt' },
        tool_response: { stdout: 'Nmap scan report for 10.0.0.5\nPORT STATE SERVICE\n22/tcp open ssh' },
      }, { active: false });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe('');
    });

    it('does not block stop on engagement-looking drift when no engagement is active', () => {
      const transcript = writeTranscript([
        { role: 'user', content: 'What should we scan next on the target?' },
        { role: 'assistant', content: 'We should probably scan the host from memory.' },
      ]);
      const result = runHook('overwatch-stop-check.mjs', {
        hook_event_name: 'Stop',
        transcript_path: transcript,
        stop_hook_active: false,
        last_assistant_message: 'We should probably scan the target next.',
      }, { active: false });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe('');
    });

    it('OVERWATCH_CONFIG pointing at an existing file also arms the hooks', () => {
      const result = runHook('overwatch-bash-guard.mjs', {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'nmap -sV 10.0.0.5' },
      }, { active: false });
      expect(result.stdout.trim()).toBe(''); // baseline: silent on dev
      const armed = spawnSync(process.execPath, [join(HOOK_DIR, 'overwatch-bash-guard.mjs')], {
        input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'nmap -sV 10.0.0.5' } }),
        encoding: 'utf8',
        env: { ...process.env, OVERWATCH_ENGAGEMENT_ACTIVE: '', OVERWATCH_CONFIG: resolve('engagement.example.json') },
      });
      expect(JSON.parse(armed.stdout.trim()).hookSpecificOutput.permissionDecision).toBe('deny');
    });
  });
});
