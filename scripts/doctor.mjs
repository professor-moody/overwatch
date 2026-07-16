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

async function probeDashboard(port) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/health`, {
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const body = await response.json();
    return Boolean(
      body
      && typeof body === 'object'
      && (
        'health_checks' in body
        || 'status' in body
        || 'issues' in body
      )
    );
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function probeMcp(config) {
  if (!config || typeof config.url !== 'string') {
    return { status: 'invalid', detail: 'HTTP MCP config has no URL' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  try {
    const response = await fetch(config.url, {
      method: 'GET',
      headers: config.headers || {},
      signal: controller.signal,
    });
    if (response.status === 401 || response.status === 403) {
      return {
        status: 'unauthorized',
        detail: `${config.url} rejected the configured bearer token (${response.status})`,
      };
    }
    return {
      status: 'reachable',
      detail: `${config.url} responded (${response.status})`,
    };
  } catch (error) {
    return {
      status: 'unreachable',
      detail: `${config.url} is not reachable`,
      error,
    };
  } finally {
    clearTimeout(timer);
  }
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
let mcpMode = 'missing';
let overwatchMcpConfig = null;
if (existsSync(mcpPath)) add('pass', 'MCP config', mcpPath);
else add('fail', 'MCP config', '.mcp.json is missing', 'Run: npm run setup');
if (existsSync(mcpPath)) {
  try {
    const mcp = readJson(mcpPath)?.mcpServers?.overwatch;
    overwatchMcpConfig = mcp;
    mcpMode = mcp?.type === 'http' || typeof mcp?.url === 'string'
      ? 'http'
      : typeof mcp?.command === 'string'
        ? 'stdio'
        : 'unknown';
    if (mcpMode === 'http') {
      add('pass', 'MCP operating mode', 'shared HTTP daemon');
    } else if (mcpMode === 'stdio') {
      add('pass', 'MCP operating mode', 'private stdio process');
    } else {
      add('warn', 'MCP operating mode', 'unrecognized .mcp.json shape');
    }
  } catch {
    add('fail', 'MCP operating mode', '.mcp.json could not be parsed');
  }
}

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
  const free = await isPortFree(dashboardPort);
  const runningDashboard = !free && await probeDashboard(dashboardPort);
  const mcpProbe = mcpMode === 'http'
    ? await probeMcp(overwatchMcpConfig)
    : undefined;
  if (mcpProbe?.status === 'reachable') {
    add('pass', 'MCP daemon endpoint', mcpProbe.detail);
  } else if (mcpProbe?.status === 'unauthorized') {
    add(
      'fail',
      'MCP daemon endpoint',
      mcpProbe.detail,
      'Run: npm run setup -- --daemon  (refreshes only the Overwatch MCP entry and token).',
    );
  } else if (mcpProbe && mcpProbe.status !== 'invalid') {
    add(
      'warn',
      'MCP daemon endpoint',
      mcpProbe.detail,
      'Run: npm run start:daemon',
    );
  } else if (mcpProbe?.status === 'invalid') {
    add('fail', 'MCP daemon endpoint', mcpProbe.detail, 'Run: npm run setup -- --daemon');
  }
  if (runningDashboard && mcpProbe?.status === 'reachable') {
    add('pass', 'Shared daemon', `dashboard and MCP are both reachable`);
  } else if (runningDashboard) {
    if (mcpMode === 'stdio') {
      add(
        'fail',
        'Process ownership',
        `An Overwatch instance is already running at http://127.0.0.1:${dashboardPort}, but Claude is configured to launch another stdio writer.`,
        'Run: npm run setup -- --daemon  (keeps engagement.json and points Claude at the existing daemon).',
      );
    } else {
      add(
        'fail',
        'Shared daemon',
        'dashboard is reachable but the configured MCP endpoint is not usable',
        'Confirm OVERWATCH_HTTP_PORT and rerun: npm run setup -- --daemon',
      );
    }
  } else if (free && mcpMode === 'http') {
    add(
      'warn',
      'Shared daemon',
      `not running on 127.0.0.1:${dashboardPort}`,
      'Run: npm run start:daemon',
    );
  } else if (free) {
    add('pass', 'Dashboard port', `127.0.0.1:${dashboardPort} is free`);
  } else {
    add(
      'warn',
      'Dashboard port',
      `127.0.0.1:${dashboardPort} is occupied by another service`,
      'Stop that service or set OVERWATCH_DASHBOARD_PORT=<free-port>.',
    );
  }
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
