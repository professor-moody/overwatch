#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';

const root = resolve(dirname(new URL(import.meta.url).pathname), '..');
const checks = [];

function add(status, label, detail, fix) {
  checks.push({ status, label, detail, fix });
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function statusRank(status) {
  return status === 'fail' ? 2 : status === 'warn' ? 1 : 0;
}

async function isPortFree(port) {
  return new Promise((resolveFree) => {
    const server = createServer();
    server.once('error', () => resolveFree(false));
    server.once('listening', () => {
      server.close(() => resolveFree(true));
    });
    server.listen(port, '127.0.0.1');
  });
}

function which(cmd) {
  try {
    return execFileSync('sh', ['-lc', `command -v ${cmd}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

const major = Number(process.versions.node.split('.')[0]);
if (major >= 20) add('pass', 'Node version', process.version);
else add('fail', 'Node version', `${process.version} is unsupported`, 'Install Node 20 or newer.');

const distIndex = join(root, 'dist', 'index.js');
if (existsSync(distIndex)) add('pass', 'Runtime build', distIndex);
else add('fail', 'Runtime build', 'dist/index.js is missing', 'Run: npm run build');

const dashboardBuild = join(root, 'dist', 'dashboard-next', 'index.html');
if (existsSync(dashboardBuild)) add('pass', 'Dashboard build', dashboardBuild);
else add('fail', 'Dashboard build', 'dist/dashboard-next/index.html is missing', 'Run: npm run build');

const mcpPath = join(root, '.mcp.json');
const claudeSettingsPath = join(root, '.claude', 'settings.json');
if (existsSync(mcpPath)) add('pass', 'MCP config', mcpPath);
else add('fail', 'MCP config', '.mcp.json is missing', 'Run: npm run setup');

if (existsSync(claudeSettingsPath)) add('pass', 'Claude hooks config', claudeSettingsPath);
else add('warn', 'Claude hooks config', '.claude/settings.json is missing', 'Run: npm run setup');

for (const hook of [
  '.claude/hooks/overwatch-user-context.mjs',
  '.claude/hooks/overwatch-bash-guard.mjs',
  '.claude/hooks/overwatch-post-bash.mjs',
  '.claude/hooks/overwatch-stop-check.mjs',
]) {
  const path = join(root, hook);
  if (existsSync(path)) add('pass', `Hook ${hook.split('/').pop()}`, path);
  else add('warn', `Hook ${hook.split('/').pop()}`, `${hook} is missing`, 'Restore hooks from the repository or reinstall.');
}

let configPath = process.env.OVERWATCH_CONFIG || join(root, 'engagement.json');
let config = null;
try {
  if (!process.env.OVERWATCH_CONFIG && existsSync(mcpPath)) {
    const mcp = readJson(mcpPath);
    const configured = mcp?.mcpServers?.overwatch?.env?.OVERWATCH_CONFIG;
    if (configured) configPath = configured;
  }
  if (!existsSync(configPath)) throw new Error('missing');
  config = readJson(configPath);
  add('pass', 'Engagement config', configPath);
} catch (err) {
  add('fail', 'Engagement config', `${configPath} could not be read`, 'Run: npm run setup');
}

if (config) {
  if (config.engagement_nonce) add('pass', 'Engagement nonce', 'present');
  else add('warn', 'Engagement nonce', 'missing', 'Run: npm run setup -- --force or add engagement_nonce to the config.');
  const statePath = process.env.OVERWATCH_STATE_FILE || join(dirname(resolve(configPath)), `state-${config.id}.json`);
  add('pass', 'Resolved state path', statePath);
}

const dashboardPort = Number(process.env.OVERWATCH_DASHBOARD_PORT || '8384');
if (Number.isFinite(dashboardPort)) {
  if (await isPortFree(dashboardPort)) add('pass', 'Dashboard port', `127.0.0.1:${dashboardPort} is free`);
  else add('warn', 'Dashboard port', `127.0.0.1:${dashboardPort} is already in use`, 'Use OVERWATCH_DASHBOARD_PORT=<free-port>.');
}

for (const cmd of ['nmap', 'curl', 'python3', 'socat', 'fuser']) {
  const found = which(cmd);
  if (found) add('pass', `Tool ${cmd}`, found);
  else add('warn', `Tool ${cmd}`, 'not found on PATH', `Install ${cmd} if your engagement workflow needs it.`);
}

const width = Math.max(...checks.map(c => c.label.length), 8);
for (const c of checks) {
  const marker = c.status === 'pass' ? 'PASS' : c.status === 'warn' ? 'WARN' : 'FAIL';
  console.log(`${marker} ${c.label.padEnd(width)}  ${c.detail}`);
  if (c.fix) console.log(`${' '.repeat(width + 6)}fix: ${c.fix}`);
}

const worst = checks.reduce((max, c) => Math.max(max, statusRank(c.status)), 0);
process.exit(worst === 2 ? 1 : 0);
