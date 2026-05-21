#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';

export const OVERWATCH_REMINDER = [
  'Overwatch grounding:',
  '- For engagement work, refresh with get_system_prompt(role="primary") when needed, then get_state() before reasoning from memory.',
  '- Use next_task()/validate_action() for target-facing work and route execution through Overwatch run_tool/run_bash or session tools.',
  '- Every useful discovery must enter the graph via parse_output(), report_finding(), or ingest_json(); do not leave recon only in prose.',
].join('\n');

const TARGET_TOOLS = [
  'nmap', 'masscan', 'naabu', 'ffuf', 'gobuster', 'feroxbuster', 'dirsearch',
  'nuclei', 'nikto', 'sqlmap', 'curl', 'wget', 'ssh', 'scp', 'sftp',
  'nc', 'ncat', 'netcat', 'socat', 'openssl', 'ldapsearch', 'smbclient',
  'nxc', 'netexec', 'crackmapexec', 'cme', 'kerbrute', 'certipy',
  'impacket-getnpusers', 'impacket-getuserspns', 'impacket-secretsdump',
  'impacket-smbclient', 'impacket-wmiexec', 'impacket-psexec',
  'secretsdump.py', 'GetNPUsers.py', 'GetUserSPNs.py', 'wmiexec.py', 'psexec.py',
];

const TARGET_TOOL_RE = new RegExp(`(?:^|[\\s;&|()])(?:sudo\\s+)?(?:${TARGET_TOOLS.map(escapeRe).join('|')})(?:\\s|$)`, 'i');
const TARGET_TOKEN_RE = new RegExp([
  String.raw`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`,
  String.raw`\bhttps?://[^\s'"<>]+`,
  String.raw`\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+(?::\d{1,5})?\b`,
  String.raw`\b[a-z0-9_-]+@(?:[a-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})\b`,
].join('|'), 'i');

const ENGAGEMENT_TERMS_RE = /\b(frontier|objective|target|recon|scan|exploit|credential|hash|session|shell|finding|parse_output|report_finding|get_state|next_task|validate_action|nmap|bloodhound|kerberoast|adcs|entra|aws|github token|mcp)\b/i;
const DEV_TERMS_RE = /\b(commit|push|git|docs?|markdown|typescript|codebase|refactor|test|build|tsc|mkdocs|package\.json|settings\.json|claude\.md|agents\.md|hook|file|repo|diff|branch)\b/i;

export async function readHookInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

export function writeHookOutput(output) {
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

export function contextOutput(hookEventName, additionalContext) {
  return {
    hookSpecificOutput: {
      hookEventName,
      additionalContext,
    },
  };
}

export function denyPreToolUse(permissionDecisionReason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason,
    },
  };
}

export function getBashCommand(input) {
  return String(input?.tool_input?.command || '');
}

export function isLikelyTargetFacingCommand(command) {
  const normalized = stripComments(command);
  if (!TARGET_TOOL_RE.test(normalized)) return false;
  if (!TARGET_TOKEN_RE.test(normalized)) return false;
  return true;
}

export function outputLooksLikeDiscovery(input) {
  const response = JSON.stringify(input?.tool_response ?? '').slice(0, 12000);
  return /\b(open port|host is up|discovered|credential|password|hash|vulnerab|shell|token|domain|service|PORT\s+STATE|Starting Nmap|Nmap scan report)\b/i.test(response);
}

export function isLikelyEngagementPrompt(prompt) {
  if (!prompt || DEV_TERMS_RE.test(prompt)) return false;
  return ENGAGEMENT_TERMS_RE.test(prompt);
}

export function transcriptHasRecentOverwatchTool(input) {
  const path = input?.transcript_path;
  if (!path || !existsSync(path)) return false;
  try {
    const lines = readFileSync(path, 'utf8').trim().split('\n').slice(-250);
    const recent = lines.join('\n');
    return /mcp__overwatch__|"(?:tool_name|name)"\s*:\s*"(?:get_state|next_task|validate_action|run_tool|run_bash|parse_output|report_finding|query_graph|send_to_session)"/i.test(recent);
  } catch {
    return false;
  }
}

export function getRecentUserPrompt(input) {
  const path = input?.transcript_path;
  if (!path || !existsSync(path)) return '';
  try {
    const lines = readFileSync(path, 'utf8').trim().split('\n').slice(-250).reverse();
    for (const line of lines) {
      if (!line.includes('"user"') && !line.includes('"human"')) continue;
      const parsed = safeJson(line);
      const text = extractText(parsed);
      if (text) return text;
    }
  } catch {
    return '';
  }
  return '';
}

export function extractText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(extractText).filter(Boolean).join('\n');
  if (typeof value === 'object') {
    if (typeof value.text === 'string') return value.text;
    if (typeof value.content === 'string') return value.content;
    if (Array.isArray(value.content)) return extractText(value.content);
    if (value.message) return extractText(value.message);
  }
  return '';
}

function stripComments(command) {
  return command
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');
}

function escapeRe(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function safeJson(line) {
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}
