#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { createServer } from 'node:net';
import { basename, dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectBuildFreshness } from './build-fingerprint.mjs';
import {
  inventoryEngagementArtifacts,
  selectRecoveryState,
  summarizeArtifacts,
  validateEngagementConfigShape,
} from './engagement-artifacts.mjs';
import { runtimeEnvironment, runtimeProfilePath } from './runtime-profile.mjs';
import {
  processIsAlive,
  processStartIdentityMatches,
} from './process-identity.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(process.env.OVERWATCH_DOCTOR_ROOT || sourceRoot);
const checks = [];
let runtimeEnv = { ...process.env };
let runtimeProfile = null;
let runtimeProfileError;
try {
  ({ environment: runtimeEnv, profile: runtimeProfile } = runtimeEnvironment(root));
} catch (error) {
  runtimeProfileError = error instanceof Error ? error.message : String(error);
}

function add(status, label, detail, fix) {
  checks.push({ status, label, detail, fix });
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function statusRank(status) {
  return status === 'fail' ? 2 : status === 'warn' ? 1 : 0;
}

if (runtimeProfileError) {
  add(
    'fail',
    'Runtime profile',
    runtimeProfileError,
    'Stop the verified owner if one is live, remove conflicting transient OVERWATCH_* overrides, then run npm run setup. Engagement artifacts are preserved.',
  );
}

function pathIdentity(path) {
  let candidate = resolve(path);
  const suffix = [];
  while (!existsSync(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate || candidate === parse(candidate).root) break;
    suffix.unshift(basename(candidate));
    candidate = parent;
  }
  const canonical = suffix.length > 0
    ? join(existsSync(candidate) ? realpathSync.native(candidate) : candidate, ...suffix)
    : existsSync(candidate) ? realpathSync.native(candidate) : candidate;
  return createHash('sha256').update(canonical).digest('hex');
}

async function isPortFree(port, host) {
  return new Promise((resolveFree) => {
    const server = createServer();
    server.once('error', () => resolveFree(false));
    server.once('listening', () => {
      server.close(() => resolveFree(true));
    });
    server.listen(port, host);
  });
}

function dashboardProbeHost(host) {
  const normalized = host.trim().toLowerCase();
  if (normalized === '0.0.0.0') return '127.0.0.1';
  if (normalized === '::' || normalized === '[::]') return '[::1]';
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

async function probeDashboard(port, authorization, host) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  try {
    const response = await fetch(`http://${dashboardProbeHost(host)}:${port}/api/runtime`, {
      ...(authorization ? { headers: { Authorization: authorization } } : {}),
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const body = await response.json();
    return Boolean(
      body
      && typeof body === 'object'
      && 'runtime_build' in body
    ) ? body : null;
  } catch {
    return null;
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

async function probeMcpRuntime(config) {
  if (!config || typeof config.url !== 'string') return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  try {
    const base = new URL(config.url);
    base.pathname = '/api/runtime';
    base.search = '';
    const response = await fetch(base, {
      headers: config.headers || {},
      signal: controller.signal,
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
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

const claudePath = which('claude');
if (!claudePath) {
  add(
    'fail',
    'Claude Code CLI',
    'claude is not available on PATH',
    'Install or repair Claude Code before deploying planner or reasoning agents.',
  );
} else {
  try {
    const version = execFileSync(claudePath, ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5_000,
    }).trim();
    const help = execFileSync(claudePath, ['--help'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5_000,
    });
    const requiredFlags = [
      '--strict-mcp-config',
      '--setting-sources',
      '--no-session-persistence',
    ];
    const missingFlags = requiredFlags.filter(flag => !help.includes(flag));
    if (missingFlags.length > 0) {
      add(
        'fail',
        'Claude Code CLI',
        `${version || claudePath} lacks ${missingFlags.join(', ')}`,
        'Update Claude Code before deploying planner or reasoning agents.',
      );
    } else {
      add('pass', 'Claude Code CLI', `${version || 'installed'} (${claudePath})`);
    }
  } catch (error) {
    add(
      'fail',
      'Claude Code CLI',
      `claude could not be inspected: ${error instanceof Error ? error.message : String(error)}`,
      'Run claude --version and claude --help, then update or repair Claude Code.',
    );
  }
}

const distIndex = join(root, 'dist', 'index.js');
const dashboardBuild = join(root, 'dist', 'dashboard-next', 'index.html');
const buildFreshness = inspectBuildFreshness(root);
if (buildFreshness.fresh) {
  add(
    'pass',
    'Runtime build',
    buildFreshness.info?.git_sha
      ? `${distIndex} (${String(buildFreshness.info.git_sha).slice(0, 8)})`
      : distIndex,
  );
  add('pass', 'Dashboard build', dashboardBuild);
} else {
  add('fail', 'Runtime build', buildFreshness.reason, 'Run: npm run build');
  if (!existsSync(dashboardBuild)) {
    add('fail', 'Dashboard build', 'dist/dashboard-next/index.html is missing', 'Run: npm run build');
  } else {
    add('warn', 'Dashboard build', 'present, but freshness is not proven', 'Run: npm run build');
  }
}

const mcpPath = runtimeProfile?.mcp_config_path || join(root, '.mcp.json');
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

const managedHookPaths = [
  '.claude/hooks/overwatch-user-context.mjs',
  '.claude/hooks/overwatch-bash-guard.mjs',
  '.claude/hooks/overwatch-task-guard.mjs',
  '.claude/hooks/overwatch-post-bash.mjs',
  '.claude/hooks/overwatch-write-fetch-nudge.mjs',
  '.claude/hooks/overwatch-session-bootstrap.mjs',
  '.claude/hooks/overwatch-stop-check.mjs',
  '.claude/hooks/overwatch-hook-lib.mjs',
];
for (const hook of managedHookPaths) {
  const path = join(root, hook);
  if (existsSync(path)) add('pass', `Hook ${hook.split('/').pop()}`, path);
  else add('warn', `Hook ${hook.split('/').pop()}`, `${hook} is missing`, 'Restore hooks from the repository or reinstall.');
}
if (existsSync(claudeSettingsPath)) {
  try {
    const settingsText = JSON.stringify(readJson(claudeSettingsPath));
    const requiredCommands = managedHookPaths
      .filter(path => !path.endsWith('overwatch-hook-lib.mjs'))
      .map(path => path.split('/').pop());
    const missing = requiredCommands.filter(name => !settingsText.includes(name));
    if (missing.length === 0) {
      add('pass', 'Claude hook wiring', 'all managed hook commands are configured');
    } else {
      add(
        'fail',
        'Claude hook wiring',
        `settings are missing ${missing.join(', ')}`,
        'Run: npm run setup  (merges managed hooks and preserves unrelated settings).',
      );
    }
  } catch {
    add('fail', 'Claude hook wiring', '.claude/settings.json is not valid JSON', 'Repair it, then run: npm run setup');
  }
}

if (runtimeProfile) {
  add(
    'pass',
    'Runtime profile',
    `${runtimeProfilePath(root)} → ${runtimeProfile.config_path}${
      runtimeProfile.state_file_path ? ` / ${runtimeProfile.state_file_path}` : ''
    }`,
  );
  const expectedMcpMode = runtimeProfile.mode === 'daemon' ? 'http' : 'stdio';
  let convergenceProblem;
  if (mcpMode !== expectedMcpMode) {
    convergenceProblem = `${runtimeProfile.mode} profile conflicts with ${mcpMode} .mcp.json wiring`;
  } else if (runtimeProfile.mode === 'daemon') {
    const expectedHost = dashboardProbeHost(runtimeProfile.http_host);
    const expectedUrl = `http://${expectedHost}:${runtimeProfile.http_port}/mcp`;
    let token;
    try { token = readFileSync(runtimeProfile.mcp_token_file, 'utf8').trim(); } catch { token = ''; }
    let configuredUrl;
    try { configuredUrl = new URL(overwatchMcpConfig?.url).toString(); } catch { configuredUrl = ''; }
    if (!token) convergenceProblem = `MCP token file ${runtimeProfile.mcp_token_file} is missing or empty`;
    else if (configuredUrl !== new URL(expectedUrl).toString()) {
      convergenceProblem = `MCP URL ${overwatchMcpConfig?.url || 'missing'} differs from profile endpoint ${expectedUrl}`;
    } else if (overwatchMcpConfig?.headers?.Authorization !== `Bearer ${token}`) {
      convergenceProblem = 'MCP Bearer authority differs from the runtime profile token file';
    }
  } else {
    const args = overwatchMcpConfig?.args;
    if (
      overwatchMcpConfig?.command !== 'node'
      || !Array.isArray(args)
      || args.at(-1) !== 'run-stdio'
      || overwatchMcpConfig?.env?.OVERWATCH_RUNTIME_PROFILE !== runtimeProfilePath(root)
    ) {
      convergenceProblem = 'stdio MCP wiring bypasses the lifecycle runner or selects another runtime profile';
    }
  }
  if (!convergenceProblem) {
    add('pass', 'Runtime/MCP convergence', `${runtimeProfile.mode} profile, endpoint, and credentials match .mcp.json`);
  } else {
    add(
      'fail',
      'Runtime/MCP convergence',
      convergenceProblem,
      'Run: npm run setup  (publishes one matching profile and MCP entry).',
    );
  }
} else {
  add('warn', 'Runtime profile', 'not configured', 'Run: npm run setup');
}

let configPath = runtimeEnv.OVERWATCH_CONFIG || join(root, 'engagement.json');
let config = null;
let artifactInventory;
let configProblem;
try {
  if (!runtimeEnv.OVERWATCH_CONFIG && existsSync(mcpPath)) {
    const mcp = readJson(mcpPath);
    const configured = mcp?.mcpServers?.overwatch?.env?.OVERWATCH_CONFIG;
    if (configured) configPath = configured;
  }
} catch (err) {
  configProblem = `.mcp.json could not be read: ${err instanceof Error ? err.message : String(err)}`;
}
configPath = resolve(root, configPath);
if (!configProblem) {
  if (!existsSync(configPath)) {
    configProblem = 'file is missing';
  } else {
    try {
      const parsed = readJson(configPath);
      const validation = validateEngagementConfigShape(parsed);
      if (validation.valid) config = validation.config;
      else configProblem = `schema validation failed: ${validation.reason}`;
    } catch (error) {
      configProblem = error instanceof Error ? error.message : String(error);
    }
  }
}

try {
  artifactInventory = inventoryEngagementArtifacts(root, {
    configPath,
    explicitStateFile: runtimeEnv.OVERWATCH_STATE_FILE,
  });
} catch (inventoryError) {
  add(
    'fail',
    'Durable artifact inventory',
    inventoryError instanceof Error ? inventoryError.message : String(inventoryError),
    'Repair directory access and rerun doctor. Do not create or replace engagement configuration while inventory is incomplete.',
  );
}

if (!config) {
  const selection = artifactInventory ? selectRecoveryState(artifactInventory) : undefined;
  if (!artifactInventory) {
    add('fail', 'Engagement config', `${configPath} could not be validated: ${configProblem}`);
  } else if (artifactInventory.artifacts.length === 0) {
    const fix = configProblem === 'file is missing'
      ? 'Run: npm run setup'
      : 'Restore or repair the existing config; setup will not replace it.';
    add('fail', 'Engagement config', `${configPath} could not be validated: ${configProblem}`, fix);
  } else if (selection.status === 'selected') {
    add(
      'fail',
      'Engagement config',
      `${configPath} could not be validated (${configProblem}); preserved recovery state selected at ${selection.family.state_path}`,
      `Start read-only with OVERWATCH_STATE_FILE=${JSON.stringify(selection.family.state_path)}, inspect Recovery, then reconcile with durable state. Do not create or force-replace engagement.json.`,
    );
    add('pass', 'Recovery state selection', `${selection.family.state_path} (${selection.via})`);
  } else {
    const reason = selection.status === 'ambiguous'
      ? 'multiple recoverable state families exist'
      : selection.status === 'missing_explicit'
        ? `the explicit state path is missing: ${selection.state_path}`
        : selection.status === 'no_base'
          ? 'state/WAL artifacts have no base containing a readable engagement config'
          : selection.status === 'unmatched_config'
            ? 'the active config does not match any preserved state family'
            : 'only non-state durable artifacts were found';
    add(
      'fail',
      'Engagement config',
      `${configPath} could not be validated (${configProblem}) and ${reason}`,
      'Restore the matching config or a complete verified backup. Set OVERWATCH_STATE_FILE only when it identifies the intended state; never run setup --force over these artifacts.',
    );
  }
} else {
  add('pass', 'Engagement config', configPath);
  if (config.engagement_nonce) add('pass', 'Engagement nonce', 'present');
  else add('warn', 'Engagement nonce', 'missing; WAL durability remains enabled, but deterministic IDs use legacy behavior');

  const selection = artifactInventory
    ? selectRecoveryState(artifactInventory, { activeConfig: config })
    : undefined;
  if (selection?.status === 'selected') {
    add('pass', 'Resolved state path', `${selection.family.state_path} (${selection.via})`);
    if (selection.semantic_match !== true) {
      const convergenceDetail = selection.semantic_match === 'unknown'
        ? `retained recovery bases do not establish one configuration authority (${selection.base_config_status})`
        : 'the active config file and selected durable state contain different configuration semantics';
      add(
        'fail',
        'Config convergence',
        convergenceDetail,
        'Start the daemon read-only, inspect overwatch recovery, and reconcile with the exact file/state hashes.',
      );
    }
  } else if (
    selection
    && (artifactInventory.state_families.length > 0 || artifactInventory.explicit_state_file)
  ) {
    const reason = selection.status === 'unmatched_config'
      ? 'the active config does not match any preserved state family'
      : selection.status === 'ambiguous'
        ? 'more than one preserved state family matches the active config'
        : selection.status === 'missing_explicit'
          ? `the explicit state path is missing: ${selection.state_path}`
          : 'preserved state artifacts do not contain a readable embedded engagement config';
    add(
      'fail',
      'Resolved state path',
      reason,
      'Restore the matching config or set OVERWATCH_STATE_FILE explicitly before starting the daemon.',
    );
  } else {
    add('pass', 'Resolved state path', join(dirname(configPath), `state-${config.id}.json`));
  }
}

if (artifactInventory?.artifacts.length > 0) {
  add(
    config ? 'pass' : 'warn',
    'Durable artifact inventory',
    `${artifactInventory.artifacts.length} preserved artifact entries: ${summarizeArtifacts(artifactInventory)}`,
  );
}

const dashboardPort = Number(runtimeEnv.OVERWATCH_DASHBOARD_PORT || '8384');
const dashboardHost = runtimeEnv.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
let liveStateOwner;
if (runtimeProfile?.state_file_path) {
  const ownerPath = `${resolve(runtimeProfile.state_file_path)}.runtime-owner.json`;
  if (existsSync(ownerPath)) {
    try {
      const owner = readJson(ownerPath);
      if (processIsAlive(owner.pid)) {
        const matches = typeof owner.process_start_identity === 'string'
          ? processStartIdentityMatches(owner.pid, owner.process_start_identity)
          : undefined;
        if (matches === undefined || typeof owner.process_start_identity !== 'string') {
          add(
            'fail',
            'Runtime state owner',
            `live PID ${owner.pid} has an unverifiable owner record at ${ownerPath}`,
            'Do not start or signal another runtime; inspect the owner process and record manually.',
          );
        } else if (matches) {
          liveStateOwner = owner;
        } else {
          add('warn', 'Runtime state owner', `${ownerPath} refers to a reused/dead process identity`);
        }
      }
    } catch (error) {
      add(
        'fail',
        'Runtime state owner',
        `${ownerPath} is unreadable: ${error instanceof Error ? error.message : String(error)}`,
        'Do not start another writer until the owner record is understood.',
      );
    }
  }
}
if (Number.isFinite(dashboardPort)) {
  const dashboardDisabled = dashboardPort === 0;
  const free = dashboardDisabled ? true : await isPortFree(dashboardPort, dashboardHost);
  const dashboardToken = runtimeEnv.OVERWATCH_DASHBOARD_TOKEN;
  const authorization = dashboardToken ? `Bearer ${dashboardToken}` : undefined;
  const runningDashboard = dashboardDisabled
    ? await probeMcpRuntime(overwatchMcpConfig)
    : !free ? await probeDashboard(dashboardPort, authorization, dashboardHost) : null;
  const mcpProbe = mcpMode === 'http'
    ? await probeMcp(overwatchMcpConfig)
    : undefined;
  if (runningDashboard) {
    const daemonBuild = runningDashboard.runtime_build;
    const localHash = buildFreshness.info?.input_sha256;
    const daemonHash = daemonBuild?.input_sha256;
    if (typeof localHash === 'string' && typeof daemonHash === 'string') {
      if (localHash === daemonHash) {
        add(
          'pass',
          'Running daemon build',
          `${String(daemonBuild.git_sha || daemonHash).slice(0, 12)} (PID ${daemonBuild.runtime_pid || 'unknown'}) matches this checkout`,
        );
      } else {
        add(
          'fail',
          'Running daemon build',
          `${String(daemonBuild.git_sha || daemonHash).slice(0, 12)} (PID ${daemonBuild.runtime_pid || 'unknown'}) does not match local ${String(buildFreshness.info?.git_sha || localHash).slice(0, 12)}`,
          'Run npm run upgrade (or npm run daemon:restart after an intentional local rebuild), then reload the dashboard tab.',
        );
      }
    } else if (!daemonBuild) {
      add(
        'fail',
        'Running daemon build',
        'the running dashboard does not expose build identity and is older than this checkout',
        'Stop the old owner from its original checkout, then run npm run daemon:start and reload the dashboard tab.',
      );
    } else {
      add(
        'warn',
        'Running daemon build',
        'the running daemon is identifiable, but the local build is not current enough to compare',
        'Run npm run build, then rerun npm run doctor.',
      );
    }
    const runtimeStatus = runningDashboard.runtime_status;
    if (liveStateOwner) {
      if (runningDashboard.runtime_build?.runtime_pid === liveStateOwner.pid) {
        add(
          'pass',
          'Runtime state owner',
          `PID ${liveStateOwner.pid} owns the selected state and matches the runtime API`,
        );
      } else {
        add(
          'fail',
          'Runtime state owner',
          `PID ${liveStateOwner.pid} owns the selected state but the runtime API reports PID ${runningDashboard.runtime_build?.runtime_pid || 'unknown'}`,
          'Do not start or stop another runtime until the ownership conflict is resolved.',
        );
      }
    }
    if (runtimeProfile?.state_file_path && runtimeStatus) {
      const configMatches = runtimeStatus.config_identity_sha256 === pathIdentity(runtimeProfile.config_path);
      const stateMatches = runtimeStatus.state_identity_sha256 === pathIdentity(runtimeProfile.state_file_path);
      if (configMatches && stateMatches) {
        add(
          'pass',
          'Running daemon engagement',
          `${runtimeStatus.engagement_id || 'unknown'} owns the configured config/state family (${runtimeStatus.phase || 'unknown phase'})`,
        );
      } else {
        add(
          'fail',
          'Running daemon engagement',
          'the listening daemon build is identifiable but it owns a different config or durable state family',
          'Use the owning checkout/profile to stop it; do not start another writer against this state.',
        );
      }
    } else if (runtimeProfile?.state_file_path) {
      add(
        'fail',
        'Running daemon engagement',
        'the daemon does not expose state-family lifecycle identity and is older than this checkout',
        'Stop it from its original terminal before starting the current build.',
      );
    }
  }
  if (liveStateOwner && !runningDashboard) {
    add(
      'fail',
      'Runtime state owner',
      `Overwatch PID ${liveStateOwner.pid} owns the selected state (${liveStateOwner.transport || 'unknown transport'}, ${liveStateOwner.phase || 'unknown phase'}) but no matching runtime API is reachable`,
      'The runtime is not stopped. Inspect its terminal/log and stop that exact owner before starting another writer.',
    );
  }
  if (!dashboardDisabled && !free && !runningDashboard) {
    add(
      'fail',
      'Dashboard port ownership',
      `port ${dashboardPort} is occupied, but its runtime identity could not be read`,
      'Stop the process using the dashboard port before starting Overwatch, or refresh the daemon token with npm run setup.',
    );
  }
  if (mcpProbe?.status === 'reachable') {
    add('pass', 'MCP daemon endpoint', mcpProbe.detail);
  } else if (mcpProbe?.status === 'unauthorized') {
    add(
      'fail',
      'MCP daemon endpoint',
      mcpProbe.detail,
      'Run: npm run setup  (refreshes only the Overwatch MCP entry and token).',
    );
  } else if (mcpProbe && mcpProbe.status !== 'invalid') {
    add(
      'warn',
      'MCP daemon endpoint',
      mcpProbe.detail,
      'Run: npm run daemon:start',
    );
  } else if (mcpProbe?.status === 'invalid') {
    add('fail', 'MCP daemon endpoint', mcpProbe.detail, 'Run: npm run setup');
  }
  if (runningDashboard && mcpProbe?.status === 'reachable') {
    add('pass', 'Shared daemon', `dashboard and MCP are both reachable`);
  } else if (runningDashboard) {
    if (mcpMode === 'stdio') {
      add(
        'fail',
        'Process ownership',
        `An Overwatch instance is already running at http://127.0.0.1:${dashboardPort}, but Claude is configured to launch another stdio writer.`,
        'Run: npm run setup  (keeps engagement.json and points Claude at the existing daemon).',
      );
    } else {
      add(
        'fail',
        'Shared daemon',
        'dashboard is reachable but the configured MCP endpoint is not usable',
        'Confirm OVERWATCH_HTTP_PORT and rerun: npm run setup',
      );
    }
  } else if (free && mcpMode === 'http') {
    add(
      'warn',
      'Shared daemon',
      dashboardDisabled
        ? 'not running at the configured MCP runtime endpoint (dashboard disabled)'
        : `not running on ${dashboardHost}:${dashboardPort}`,
      'Run: npm run daemon:start',
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
