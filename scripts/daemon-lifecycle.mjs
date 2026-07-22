#!/usr/bin/env node

import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  realpathSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import { basename, dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectBuildFreshness, readBuildInfo } from './build-fingerprint.mjs';
import {
  assertRuntimePathSeparation,
  managedDaemonLogPath,
  managedDaemonPath,
  readRuntimeProfile,
  runtimeEnvironment,
  runtimeProfilePath,
} from './runtime-profile.mjs';
import {
  processIsAlive,
  processStartIdentity,
  processStartIdentityMatches,
} from './process-identity.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const command = process.argv[2] || 'status';
const READY_PHASES = new Set(['ready', 'ready_read_only']);
const START_TIMEOUT_MS = Number(process.env.OVERWATCH_DAEMON_START_TIMEOUT_MS || '30000');
const STOP_TIMEOUT_MS = Number(process.env.OVERWATCH_DAEMON_STOP_TIMEOUT_MS || '25000');
const LIFECYCLE_LOCK_FILE = 'lifecycle.lock.json';

function usage(exitCode = 0) {
  console.log(`Usage: npm run daemon -- <command>

Commands:
  start       Start one detached shared daemon; an exact running daemon is a no-op.
  run         Run the shared daemon in the foreground (npm run start:daemon).
  status      Show lifecycle, build, engagement, endpoints, and recovery state.
  stop        Gracefully stop only an identity-verified managed daemon.
  restart     Stop the verified daemon, rebuild if needed, and start it detached.
  logs        Print the managed log path and its latest lines.
  upgrade     Stop, run npm ci + build, then start without changing engagement data.
  run-stdio   Explicit solo compatibility mode (npm run start:stdio).
`);
  process.exit(exitCode);
}

function sha256(value) {
  return createHash('sha256').update(canonicalPath(value)).digest('hex');
}

function canonicalPath(value) {
  let candidate = resolve(value);
  const suffix = [];
  while (!existsSync(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate || candidate === parse(candidate).root) break;
    suffix.unshift(basename(candidate));
    candidate = parent;
  }
  const base = existsSync(candidate) ? realpathSync.native(candidate) : candidate;
  return suffix.length > 0 ? join(base, ...suffix) : base;
}

function fsyncDirectory(path) {
  if (process.platform === 'win32') return;
  const fd = openSync(path, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function readLifecycleBuildInfo() {
  const override = process.env.OVERWATCH_LIFECYCLE_BUILD_INFO_PATH;
  if (override) {
    try { return JSON.parse(readFileSync(resolve(override), 'utf8')); } catch { return null; }
  }
  return readBuildInfo(root);
}

function probeHost(host) {
  const normalized = host.trim().toLowerCase();
  if (normalized === '0.0.0.0') return '127.0.0.1';
  if (normalized === '::' || normalized === '[::]') return '[::1]';
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function expectedRuntime(environment, profile) {
  const configPath = canonicalPath(environment.OVERWATCH_CONFIG || profile?.config_path || join(root, 'engagement.json'));
  let statePath = environment.OVERWATCH_STATE_FILE || profile?.state_file_path;
  if (!statePath) {
    try {
      const config = JSON.parse(readFileSync(configPath, 'utf8'));
      if (typeof config.id === 'string' && config.id.length > 0) {
        statePath = join(dirname(configPath), `state-${config.id}.json`);
      }
    } catch { /* startup will provide the authoritative recovery diagnostic */ }
  }
  const dashboardHost = environment.OVERWATCH_DASHBOARD_HOST || profile?.dashboard_host || '127.0.0.1';
  const dashboardPort = Number(environment.OVERWATCH_DASHBOARD_PORT || profile?.dashboard_port || 8384);
  const httpHost = environment.OVERWATCH_HTTP_HOST || profile?.http_host || '127.0.0.1';
  const httpPort = Number(environment.OVERWATCH_HTTP_PORT || profile?.http_port || 3000);
  const dashboardUrl = dashboardPort > 0
    ? `http://${probeHost(dashboardHost)}:${dashboardPort}`
    : undefined;
  const dashboardIdentityUrl = dashboardPort > 0
    ? `http://${dashboardHost.includes(':') && !dashboardHost.startsWith('[') ? `[${dashboardHost}]` : dashboardHost}:${dashboardPort}`
    : undefined;
  const mcpBaseUrl = `http://${probeHost(httpHost)}:${httpPort}`;
  return {
    configPath,
    statePath: statePath ? canonicalPath(statePath) : undefined,
    dashboardHost,
    dashboardPort,
    dashboardUrl,
    dashboardIdentityUrl,
    runtimeUrl: dashboardUrl || mcpBaseUrl,
    runtimeHost: dashboardUrl ? dashboardHost : httpHost,
    runtimePort: dashboardUrl ? dashboardPort : httpPort,
    probeAuth: dashboardUrl ? 'dashboard' : 'mcp',
    httpHost,
    httpPort,
    mcpUrl: `${mcpBaseUrl}/mcp`,
    transport: 'http',
  };
}

function assertDaemonMcpConvergence(environment, profile, expected) {
  if (!profile || profile.mode !== 'daemon') return;
  let token;
  try { token = readFileSync(profile.mcp_token_file, 'utf8').trim(); } catch { /* diagnostic below */ }
  if (!token || environment.OVERWATCH_MCP_TOKEN?.trim() !== token) {
    throw new Error(
      `The daemon MCP token file ${profile.mcp_token_file} is missing, empty, or differs from the runtime profile. `
      + 'Run `npm run setup` before starting; no build or process change was attempted.',
    );
  }
  if (profile.dashboard_token_file) {
    let dashboardToken;
    try { dashboardToken = readFileSync(profile.dashboard_token_file, 'utf8').trim(); } catch { /* diagnostic below */ }
    if (!dashboardToken || environment.OVERWATCH_DASHBOARD_TOKEN?.trim() !== dashboardToken) {
      throw new Error(
        `The dashboard token file ${profile.dashboard_token_file} is missing, empty, or differs from the runtime profile. `
        + 'Run `npm run setup` before starting; no build or process change was attempted.',
      );
    }
  }
  const path = profile.mcp_config_path || join(root, '.mcp.json');
  let mcp;
  try {
    mcp = JSON.parse(readFileSync(path, 'utf8'))?.mcpServers?.overwatch;
  } catch (error) {
    throw new Error(
      `MCP config ${path} cannot be read: ${error instanceof Error ? error.message : String(error)}. `
      + 'Run `npm run setup` before starting; no build or process change was attempted.',
    );
  }
  let configuredUrl;
  let expectedUrl;
  try {
    configuredUrl = new URL(mcp?.url).toString();
    expectedUrl = new URL(expected.mcpUrl).toString();
  } catch {
    throw new Error(`MCP config ${path} does not contain a valid Overwatch HTTP URL. Run \`npm run setup\`.`);
  }
  if (
    mcp?.type !== 'http'
    || configuredUrl !== expectedUrl
    || mcp?.headers?.Authorization !== `Bearer ${token}`
  ) {
    throw new Error(
      `Runtime profile, MCP token, and ${path} do not describe the same daemon endpoint. `
      + 'Run `npm run setup` to reconcile them before starting; no build or process change was attempted.',
    );
  }
}

async function portOccupied(port, host) {
  if (!Number.isSafeInteger(port) || port <= 0 || port > 65_535) return false;
  const bindHost = host.startsWith('[') && host.endsWith(']')
    ? host.slice(1, -1)
    : host;
  return new Promise(resolveOccupied => {
    const server = createServer();
    server.once('error', () => resolveOccupied(true));
    server.once('listening', () => server.close(() => resolveOccupied(false)));
    server.listen(port, bindHost);
  });
}

async function probeRuntime(expected, environment, override = {}) {
  const runtimeUrl = override.url || expected.runtimeUrl;
  const runtimePort = override.port ?? expected.runtimePort;
  const runtimeHost = override.host ?? expected.runtimeHost;
  if (!runtimeUrl) return { running: false, disabled: true };
  // A managed record gives us an exact endpoint to probe. Binding a second
  // socket is not a portable occupancy test for wildcard listeners (notably on
  // macOS), so only use the bind probe during endpoint discovery.
  if (!override.url && !(await portOccupied(runtimePort, runtimeHost))) return { running: false };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_500);
  try {
    let token = override.token;
    const auth = override.auth || expected.probeAuth;
    if (!token && auth === 'dashboard') token = environment.OVERWATCH_DASHBOARD_TOKEN;
    if (!token && auth === 'mcp') {
      token = environment.OVERWATCH_MCP_TOKEN;
      if (!token && environment.OVERWATCH_MCP_TOKEN_FILE) {
        try { token = readFileSync(environment.OVERWATCH_MCP_TOKEN_FILE, 'utf8').trim(); } catch { /* response will fail closed */ }
      }
    }
    const response = await fetch(`${runtimeUrl}/api/runtime`, {
      ...(token ? { headers: { Authorization: `Bearer ${token}` } } : {}),
      signal: controller.signal,
    });
    if (!response.ok) return { running: true, identifiable: false, status: response.status };
    const body = await response.json();
    if (!body?.runtime_build || typeof body.runtime_build.input_sha256 !== 'string') {
      return { running: true, identifiable: false };
    }
    return { running: true, identifiable: true, body };
  } catch (error) {
    return { running: true, identifiable: false, error };
  } finally {
    clearTimeout(timer);
  }
}

function runtimeMatchesExpected(probe, expected) {
  if (!probe.identifiable || !expected.statePath) return false;
  const status = probe.body.runtime_status;
  return Boolean(
    status
    && status.transport === expected.transport
    && status.config_identity_sha256 === sha256(expected.configPath)
    && status.state_identity_sha256 === sha256(expected.statePath)
    && (expected.dashboardIdentityUrl
      ? endpointIdentityMatches(status.dashboard_url, expected.dashboardIdentityUrl)
      : status.dashboard_url === undefined)
    && endpointIdentityMatches(status.mcp_url, expected.mcpUrl),
  );
}

function endpointIdentityMatches(actual, expected) {
  if (!actual || !expected) return false;
  try {
    const left = new URL(actual);
    const right = new URL(expected);
    return left.protocol === right.protocol
      && left.hostname === right.hostname
      && Number(left.port || (left.protocol === 'https:' ? 443 : 80))
        === Number(right.port || (right.protocol === 'https:' ? 443 : 80));
  } catch {
    return false;
  }
}

function runtimeDescription(probe) {
  const build = probe.body?.runtime_build;
  const status = probe.body?.runtime_status;
  if (!build) return 'an unidentifiable service';
  return `Overwatch PID ${build.runtime_pid} (${status?.engagement_id || 'unknown engagement'}, ${status?.phase || 'legacy lifecycle'})`;
}

function readManagedRecord() {
  const path = managedDaemonPath(root);
  if (!existsSync(path)) return null;
  try {
    const record = JSON.parse(readFileSync(path, 'utf8'));
    if (
      record.version !== 1
      || !Number.isSafeInteger(record.pid)
      || record.pid <= 0
      || typeof record.process_start_identity !== 'string'
      || typeof record.management_nonce !== 'string'
      || typeof record.daemon_instance_id !== 'string'
      || typeof record.runtime_instance_id !== 'string'
      || typeof record.state_identity_sha256 !== 'string'
      || typeof record.config_identity_sha256 !== 'string'
      || (record.transport !== undefined && record.transport !== 'http')
    ) throw new Error('unsupported shape');
    return record;
  } catch (error) {
    throw new Error(`Managed daemon record ${path} is invalid; refusing to signal any PID.`, { cause: error });
  }
}

function removeManagedRecord(expectedInstanceId) {
  const path = managedDaemonPath(root);
  if (!existsSync(path)) return;
  if (expectedInstanceId) {
    const current = readManagedRecord();
    if (current?.daemon_instance_id !== expectedInstanceId) return;
  }
  unlinkSync(path);
  fsyncDirectory(dirname(path));
}

function archiveManagedRecord(record, reason) {
  const path = managedDaemonPath(root);
  if (!existsSync(path)) return undefined;
  const safeReason = String(reason).replace(/[^a-z0-9-]+/gi, '-').toLowerCase();
  const archive = `${path}.${safeReason}-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  renameSync(path, archive);
  fsyncDirectory(dirname(path));
  return archive;
}

function processAlive(pid) {
  return processIsAlive(pid);
}

function processMatchesRecord(record) {
  if (!processAlive(record.pid)) return false;
  const matches = processStartIdentityMatches(record.pid, record.process_start_identity);
  if (matches === undefined) {
    throw new Error(`PID ${record.pid} is alive but its start identity cannot be verified; refusing lifecycle changes.`);
  }
  return matches;
}

function endpointProbeTarget(urlString, auth = 'dashboard') {
  if (!urlString) return null;
  const url = new URL(urlString);
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
  return {
    url: `${url.protocol}//${probeHost(url.hostname)}:${port}`,
    host: url.hostname,
    port,
    auth,
  };
}

async function probeManagedRecord(record, environment, expected) {
  let dashboardProbe;
  if (record.dashboard_url) {
    const target = endpointProbeTarget(record.dashboard_url, 'dashboard');
    dashboardProbe = await probeRuntime(expected, environment, target);
    if (managedProbeMatchesRecord(record, dashboardProbe)) return dashboardProbe;
  }
  if (record.mcp_url) {
    const target = endpointProbeTarget(record.mcp_url.replace(/\/mcp\/?$/, ''), 'mcp');
    const mcpProbe = await probeRuntime(expected, environment, target);
    if (managedProbeMatchesRecord(record, mcpProbe)) return mcpProbe;
    return mcpProbe;
  }
  return dashboardProbe || { running: true, identifiable: false };
}

function managedProbeMatchesRecord(record, probe) {
  const build = probe.body?.runtime_build;
  const status = probe.body?.runtime_status;
  return Boolean(
    probe.identifiable
    && build?.runtime_pid === record.pid
    && build.runtime_instance_id === record.runtime_instance_id
    && build.runtime_started_at === record.runtime_started_at
    && status?.daemon_instance_id === record.daemon_instance_id
    && status.transport === 'http'
    && status.state_identity_sha256 === record.state_identity_sha256
    && status.config_identity_sha256 === record.config_identity_sha256,
  );
}

function readStateOwner(expected) {
  if (!expected.statePath) return null;
  const ownerPath = `${canonicalPath(expected.statePath)}.runtime-owner.json`;
  if (!existsSync(ownerPath)) return null;
  try {
    return JSON.parse(readFileSync(ownerPath, 'utf8'));
  } catch (error) {
    throw new Error(`Runtime owner ${ownerPath} is unreadable; refusing a build or second writer.`, { cause: error });
  }
}

function runChecked(
  executable,
  args,
  label,
  environment = process.env,
  stdio = 'inherit',
) {
  const result = spawnSync(executable, args, {
    cwd: root,
    env: environment,
    stdio,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${label} failed with exit code ${result.status ?? 'unknown'}`);
}

function assertLifecyclePathSelection(selection) {
  if (!selection.profile) {
    throw new Error(
      'No persisted runtime profile exists. Run `npm run setup` first; lifecycle commands do not infer writable engagement authority.',
    );
  }
  const expected = expectedRuntime(selection.environment, selection.profile);
  const recordPath = managedDaemonPath(root);
  const lockPath = join(dirname(recordPath), LIFECYCLE_LOCK_FILE);
  assertRuntimePathSeparation({
    configPath: expected.configPath,
    statePath: expected.statePath,
    operationalPaths: [
      { label: 'runtime profile', path: runtimeProfilePath(root) },
      { label: 'managed daemon record', path: recordPath },
      { label: 'managed daemon log', path: managedDaemonLogPath(root) },
      { label: 'lifecycle lock', path: lockPath },
      { label: 'MCP token', path: selection.profile.mcp_token_file },
      ...(selection.profile.dashboard_token_file
        ? [{ label: 'dashboard token', path: selection.profile.dashboard_token_file }]
        : []),
      ...(selection.profile.mcp_config_path
        ? [{ label: 'MCP client config', path: selection.profile.mcp_config_path }]
        : []),
    ],
  });
  return { expected, recordPath, lockPath };
}

async function withLifecycleLock(operation) {
  const selection = runtimeEnvironment(root);
  const { lockPath: path } = assertLifecyclePathSelection(selection);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const nonce = randomBytes(32).toString('hex');
  const owner = {
    version: 1,
    pid: process.pid,
    process_start_identity: processStartIdentity(process.pid),
    nonce,
    command,
    acquired_at: new Date().toISOString(),
  };
  if (!owner.process_start_identity) {
    throw new Error(`Lifecycle PID ${process.pid} start identity cannot be verified.`);
  }
  let acquired = false;
  let released = false;
  const release = () => {
    if (released || !acquired) return;
    const current = JSON.parse(readFileSync(path, 'utf8'));
    if (current.nonce !== nonce) {
      throw new Error('Lifecycle lock identity changed while this command was running.');
    }
    unlinkSync(path);
    fsyncDirectory(dirname(path));
    released = true;
  };
  for (let attempt = 0; attempt < 3 && !acquired; attempt += 1) {
    try {
      const fd = openSync(path, 'wx', 0o600);
      try {
        writeFileSync(fd, `${JSON.stringify(owner, null, 2)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      fsyncDirectory(dirname(path));
      acquired = true;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let current;
      let readFailure;
      // open(..., "wx") publishes the directory entry before the owner bytes
      // are written and fsynced. A simultaneous starter may therefore observe
      // an empty/partial lock for a few milliseconds. Retry only that narrow
      // publication window; a persistently malformed lock still fails closed.
      for (let readAttempt = 0; readAttempt < 5 && !current; readAttempt += 1) {
        try {
          current = JSON.parse(readFileSync(path, 'utf8'));
        } catch (lockReadError) {
          readFailure = lockReadError;
          if (readAttempt < 4) await new Promise(resolveWait => setTimeout(resolveWait, 10));
        }
      }
      if (!current) {
        throw new Error(`Lifecycle lock ${path} is unreadable; refusing concurrent changes.`, { cause: readFailure });
      }
      if (processAlive(current.pid)) {
        const matches = typeof current.process_start_identity === 'string'
          ? processStartIdentityMatches(current.pid, current.process_start_identity)
          : undefined;
        if (
          typeof current.process_start_identity !== 'string'
          || matches !== false
        ) {
          throw new Error(
            `Lifecycle command ${current.command || 'unknown'} is active as PID ${current.pid}.`,
          );
        }
      }
      // Reclaim the stale lock. Two concurrent commands can both observe the same
      // dead owner and race to unlink it; the loser sees ENOENT, which is success
      // (the lock is gone), so the next loop iteration re-attempts openSync(wx).
      try {
        unlinkSync(path);
        fsyncDirectory(dirname(path));
      } catch (unlinkError) {
        if (unlinkError?.code !== 'ENOENT') throw unlinkError;
      }
    }
  }
  if (!acquired) throw new Error(`Could not acquire lifecycle lock ${path}.`);
  try {
    return await operation(release);
  } finally {
    if (!released) release();
  }
}

function preflightSourceUpgrade() {
  const required = [
    join(root, 'package-lock.json'),
    join(root, 'src', 'index.ts'),
    join(root, 'package.json'),
  ];
  const missing = required.filter(path => !existsSync(path));
  if (missing.length > 0) {
    throw new Error(
      'This installation is not an upgradeable source checkout. Update it with the package/source manager that installed it; '
      + `the running daemon was not stopped. Missing: ${missing.join(', ')}`,
    );
  }
  const npm = process.env.OVERWATCH_LIFECYCLE_NPM
    || (process.platform === 'win32' ? 'npm.cmd' : 'npm');
  const probe = spawnSync(npm, ['--version'], { cwd: root, stdio: 'ignore' });
  if (probe.status !== 0) {
    throw new Error('npm is unavailable; the running daemon was not stopped.');
  }
  const dependencyProbe = spawnSync(npm, ['ci', '--dry-run', '--ignore-scripts'], {
    cwd: root,
    env: process.env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (dependencyProbe.status !== 0) {
    const detail = String(dependencyProbe.stderr || dependencyProbe.stdout || '').trim();
    throw new Error(
      `npm dependency preflight failed; the running daemon was not stopped.${detail ? ` ${detail}` : ''}`,
    );
  }
}

function preflightStateUpgrade(selection, { frozen = false } = {}) {
  const stateDescription = frozen
    ? 'after the verified daemon stopped'
    : 'while the running daemon remains active';
  if (!selection.profile) {
    throw new Error(
      `No persisted runtime profile exists. Run \`npm run setup\` before upgrading; checked ${stateDescription}.`,
    );
  }
  const expected = expectedRuntime(selection.environment, selection.profile);
  if (!expected.statePath) {
    throw new Error(
      `The runtime profile does not identify an engagement state file. Run \`npm run setup\` before upgrading; checked ${stateDescription}.`,
    );
  }
  const tsx = process.env.OVERWATCH_LIFECYCLE_STATE_PREFLIGHT
    || join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs');
  if (!existsSync(tsx)) {
    throw new Error(
      `The offline migration preflight runner is unavailable at ${tsx}; checked ${stateDescription}. Run \`npm ci\` without changing engagement artifacts, then retry the upgrade.`,
    );
  }
  runChecked(
    process.execPath,
    [
      tsx,
      join(root, 'src', 'cli', 'operator-cli.ts'),
      'state',
      'migrate',
      '--check',
      '--state-file',
      expected.statePath,
      '--config-file',
      expected.configPath,
      '--no-color',
    ],
    `offline state/WAL migration preflight ${stateDescription}`,
    selection.environment,
  );
}

async function acquireUpgradeStateLease(selection) {
  const expected = expectedRuntime(selection.environment, selection.profile);
  if (!expected.statePath) throw new Error('Cannot reserve an upgrade without a selected state file.');
  const helper = spawn(
    process.execPath,
    [join(root, 'scripts', 'upgrade-state-lease.mjs'), expected.statePath],
    {
      cwd: root,
      env: selection.environment,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  helper.stdout.setEncoding('utf8');
  helper.stderr.setEncoding('utf8');
  let stdout = '';
  let stderr = '';
  helper.stdout.on('data', chunk => { stdout += chunk; });
  helper.stderr.on('data', chunk => { stderr += chunk; });
  const exit = new Promise(resolveExit => {
    helper.once('error', error => resolveExit({ code: 1, signal: null, error }));
    helper.once('exit', (code, signal) => resolveExit({ code, signal }));
  });
  let token;
  const deadline = Date.now() + START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const line = stdout.split('\n').find(candidate => candidate.trim().startsWith('{'));
    if (line) {
      try {
        const ready = JSON.parse(line);
        if (ready.ready === true && typeof ready.token === 'string' && ready.token.length > 0) {
          token = ready.token;
          break;
        }
      } catch { /* wait for a complete line */ }
    }
    if (!processAlive(helper.pid)) {
      const result = await exit;
      throw result.error || new Error(
        `Upgrade state lease exited before acquisition (${result.code ?? result.signal ?? 'unknown'}).${stderr.trim() ? ` ${stderr.trim()}` : ''}`,
      );
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  if (!token) {
    try { helper.kill('SIGTERM'); } catch { /* helper already exited */ }
    await exit;
    throw new Error(`Upgrade state lease did not become ready within ${START_TIMEOUT_MS}ms.${stderr.trim() ? ` ${stderr.trim()}` : ''}`);
  }

  let released = false;
  return {
    token,
    get released() { return released; },
    async release() {
      if (released) return;
      if (!processAlive(helper.pid)) {
        const result = await exit;
        throw result.error || new Error(
          `Upgrade state lease exited before release (${result.code ?? result.signal ?? 'unknown'}).${stderr.trim() ? ` ${stderr.trim()}` : ''}`,
        );
      }
      helper.stdin.end('release\n');
      const result = await exit;
      if (result.error || result.code !== 0) {
        throw result.error || new Error(
          `Upgrade state lease release failed (${result.code ?? result.signal ?? 'unknown'}).${stderr.trim() ? ` ${stderr.trim()}` : ''}`,
        );
      }
      released = true;
    },
  };
}

async function holdUpgradeLeaseForTest(environment) {
  const marker = environment.OVERWATCH_LIFECYCLE_UPGRADE_HOLD_FILE;
  if (!marker) return;
  writeFileSync(marker, `${process.pid}\n`, { flag: 'wx', mode: 0o600 });
  const deadline = Date.now() + START_TIMEOUT_MS;
  while (existsSync(marker) && Date.now() < deadline) {
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  if (existsSync(marker)) {
    throw new Error(`Timed out waiting for the upgrade hold marker to be removed: ${marker}`);
  }
}

function ensureFreshBuild(environment, stdio = 'inherit') {
  const freshness = inspectBuildFreshness(root);
  if (freshness.fresh) return;
  if (!freshness.rebuildable) throw new Error(`Runtime build is not usable: ${freshness.reason}`);
  runChecked(
    process.execPath,
    [join(root, 'scripts', 'ensure-fresh-build.mjs')],
    'build',
    environment,
    stdio,
  );
}

async function inspectBeforeStart(environment, profile) {
  if (!profile) {
    throw new Error('No persisted runtime profile exists. Run `npm run setup` before starting Overwatch.');
  }
  const expected = expectedRuntime(environment, profile);
  if (profile?.mode === 'stdio') {
    throw new Error('The runtime profile is configured for stdio. Run `npm run setup -- --daemon` before starting the shared daemon.');
  }
  assertDaemonMcpConvergence(environment, profile, expected);
  const record = readManagedRecord();
  if (record) {
    const recordPidAlive = processAlive(record.pid);
    if (recordPidAlive && processMatchesRecord(record)) {
      const managedProbe = await probeManagedRecord(record, environment, expected);
      if (!managedProbeMatchesRecord(record, managedProbe)) {
        throw new Error(
          `Managed Overwatch PID ${record.pid} is alive but its API identity cannot be verified. `
          + 'No build, spawn, overwrite, or signal was attempted.',
        );
      }
      if (!runtimeMatchesExpected(managedProbe, expected)) {
        throw new Error(
          `${runtimeDescription(managedProbe)} is already managed by this checkout with a different profile/state. `
          + 'Stop it before changing runtime selection.',
        );
      }
      const freshness = inspectBuildFreshness(root);
      const localBuild = readLifecycleBuildInfo();
      if (!freshness.fresh || localBuild?.input_sha256 !== managedProbe.body.runtime_build.input_sha256) {
        throw new Error(
          `${runtimeDescription(managedProbe)} owns the intended state but does not match current source/build. `
          + 'No rebuild was performed while it is live. Run `npm run daemon:restart`.',
        );
      }
      if (!READY_PHASES.has(managedProbe.body.runtime_status?.phase)) {
        throw new Error(`${runtimeDescription(managedProbe)} is ${managedProbe.body.runtime_status?.phase || 'not ready'}; inspect npm run daemon:status.`);
      }
      return { expected, probe: managedProbe, reuse: true };
    }
    if (!recordPidAlive && record.shutdown_succeeded !== true) {
      const archive = archiveManagedRecord(record, 'crash');
      console.error(
        `RECOVERY — prior managed PID ${record.pid} exited without a clean acknowledgement. `
        + `Preserved its operational record at ${archive}; authoritative state/WAL recovery will run before READY.`,
      );
    } else {
      // A PID-reused or cleanly stopped record is stale. It carries no
      // authority once its exact process start identity differs.
      removeManagedRecord(record.daemon_instance_id);
    }
  }

  // The state-family owner is the final authority and must be checked before a
  // freshness rebuild. A directly launched or otherwise unmanaged daemon may
  // use different ports while still executing the current dist tree.
  const stateOwner = readStateOwner(expected);
  if (stateOwner && processAlive(stateOwner.pid)) {
    const matches = processStartIdentityMatches(stateOwner.pid, stateOwner.process_start_identity);
    if (matches !== false) {
      throw new Error(
        `Engagement ${stateOwner.engagement_id || 'state'} is already owned by Overwatch PID ${stateOwner.pid} `
        + `(${stateOwner.transport || 'unknown transport'}, ${stateOwner.phase || 'unknown phase'}). `
        + 'No rebuild was performed; reuse or stop that runtime first.',
      );
    }
  }
  const probe = await probeRuntime(expected, environment);
  if (!probe.running) return { expected, probe, reuse: false };
  if (!probe.identifiable) {
    throw new Error(
      `Runtime endpoint ${expected.runtimeUrl} is occupied but its identity could not be verified. `
      + 'Provide OVERWATCH_DASHBOARD_TOKEN if configured, or stop the owning process manually.',
    );
  }
  if (!runtimeMatchesExpected(probe, expected)) {
    throw new Error(
      `${runtimeDescription(probe)} is already using ${expected.runtimeUrl}, but it does not own the configured engagement/state. `
      + 'Use its checkout/profile to stop it; this command will not reuse or signal it.',
    );
  }
  const freshness = inspectBuildFreshness(root);
  const localBuild = readLifecycleBuildInfo();
  const sameBuild = freshness.fresh
    && localBuild?.input_sha256 === probe.body.runtime_build.input_sha256;
  if (!sameBuild) {
    throw new Error(
      `${runtimeDescription(probe)} owns the intended state but does not match the current source/build. `
      + 'No rebuild was performed while it is live. Run `npm run daemon:restart`.',
    );
  }
  if (!READY_PHASES.has(probe.body.runtime_status?.phase)) {
    throw new Error(`${runtimeDescription(probe)} is ${probe.body.runtime_status?.phase || 'not ready'}; inspect npm run daemon:status.`);
  }
  return { expected, probe, reuse: true };
}

async function waitForReady(child, expected, environment) {
  const deadline = Date.now() + START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!processAlive(child.pid)) throw new Error(`Daemon process ${child.pid} exited before becoming ready.`);
    const probe = await probeRuntime(expected, environment);
    if (
      probe.identifiable
      && probe.body.runtime_build.runtime_pid === child.pid
      && runtimeMatchesExpected(probe, expected)
      && READY_PHASES.has(probe.body.runtime_status?.phase)
    ) {
      const record = readManagedRecord();
      if (record && managedProbeMatchesRecord(record, probe)) return probe;
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  throw new Error(`Daemon PID ${child.pid} did not become ready within ${START_TIMEOUT_MS}ms.`);
}

async function waitForStateOwnership(child, expected) {
  const deadline = Date.now() + START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!processAlive(child.pid)) {
      throw new Error(`Stdio process ${child.pid} exited before acquiring durable state ownership.`);
    }
    const owner = readStateOwner(expected);
    if (owner?.pid === child.pid) {
      const matches = processStartIdentityMatches(child.pid, owner.process_start_identity);
      if (matches !== true) {
        throw new Error(`Stdio process ${child.pid} published an unverifiable state-owner identity.`);
      }
      return;
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  throw new Error(`Stdio process ${child.pid} did not acquire durable state ownership within ${START_TIMEOUT_MS}ms.`);
}

async function startDaemon({
  detached,
  onReady,
  allowStaleBuild = false,
  upgradeStateLease,
}) {
  const { environment, profile } = runtimeEnvironment(root);
  const inspected = await inspectBeforeStart(environment, profile);
  if (inspected.reuse) {
    console.log(`READY — ${runtimeDescription(inspected.probe)} is already serving ${inspected.expected.runtimeUrl}.`);
    return { reused: true, probe: inspected.probe };
  }
  if (allowStaleBuild) {
    if (!existsSync(join(root, 'dist', 'index.js'))) {
      throw new Error('The previous compiled runtime is unavailable; refusing to synthesize a replacement during recovery.');
    }
  } else {
    ensureFreshBuild(environment);
  }
  const logPath = managedDaemonLogPath(root);
  let out = 'inherit';
  let err = 'inherit';
  let logFd;
  if (detached) {
    mkdirSync(dirname(logPath), { recursive: true, mode: 0o700 });
    logFd = openSync(logPath, 'a', 0o600);
    out = logFd;
    err = logFd;
  }
  const managementNonce = randomBytes(32).toString('hex');
  const child = spawn(process.execPath, [join(root, 'dist', 'index.js'), '--http'], {
    cwd: root,
    env: {
      ...environment,
      OVERWATCH_DAEMON_MANAGED: '1',
      OVERWATCH_DAEMON_RECORD: managedDaemonPath(root),
      OVERWATCH_DAEMON_LOG: logPath,
      OVERWATCH_DAEMON_MANAGEMENT_NONCE: managementNonce,
      ...(upgradeStateLease
        ? { OVERWATCH_UPGRADE_MIGRATION_TOKEN: upgradeStateLease.token }
        : {}),
    },
    detached,
    stdio: ['ignore', out, err],
  });
  if (logFd !== undefined) closeSync(logFd);
  const childExit = new Promise(resolveExit => {
    child.once('error', error => resolveExit({ code: 1, signal: null, error }));
    child.once('exit', (code, signal) => resolveExit({ code, signal }));
  });
  if (!child.pid) {
    const result = await childExit;
    throw result.error || new Error('Daemon process did not return a PID.');
  }
  const forwardSignal = signal => {
    if (processAlive(child.pid)) {
      try { process.kill(child.pid, signal); } catch { /* child already exited */ }
    }
  };
  const forwardInterrupt = () => forwardSignal('SIGINT');
  const forwardTerminate = () => forwardSignal('SIGTERM');
  if (!detached) {
    process.on('SIGINT', forwardInterrupt);
    process.on('SIGTERM', forwardTerminate);
  }
  let probe;
  try {
    if (upgradeStateLease) {
      await waitForStateOwnership(child, inspected.expected);
      await upgradeStateLease.release();
    }
    probe = await waitForReady(child, inspected.expected, environment);
    const mode = probe.body.runtime_status.phase === 'ready_read_only'
      ? `RECOVERY READ-ONLY — ${probe.body.runtime_status.recovery_reason || 'explicit recovery is required'}`
      : 'READY';
    console.log(`${mode}\nPID ${child.pid}\nDashboard ${inspected.expected.dashboardUrl || 'disabled'}\nMCP ${probe.body.runtime_status.mcp_url}\nLog ${logPath}`);
    onReady?.();
    // Keep the child referenced until readiness succeeds. Otherwise a failed
    // detached start can let this wrapper exit 0 while it is still awaiting the
    // child's shutdown, releasing the lifecycle lock too early.
    if (detached) child.unref();
  } catch (error) {
    if (processAlive(child.pid)) {
      try {
        await requestShutdownEndpoint(
          inspected.expected.mcpUrl,
          environment.OVERWATCH_MCP_TOKEN,
          managementNonce,
        );
      } catch {
        if (process.platform !== 'win32') {
          try { child.kill('SIGTERM'); } catch { /* child exited between checks */ }
        }
      }
    }
    // Never release the lifecycle lock while a failed child might still own
    // durable state. On Windows an unavailable control endpoint is not replaced
    // with a forceful pseudo-SIGTERM; the wrapper remains attached until exit.
    await childExit;
    process.removeListener('SIGINT', forwardInterrupt);
    process.removeListener('SIGTERM', forwardTerminate);
    if (detached && existsSync(logPath)) {
      const tail = readFileSync(logPath, 'utf8').split('\n').slice(-25).join('\n');
      if (tail.trim()) console.error(`\nLatest daemon log:\n${tail}`);
    }
    throw error;
  }
  if (!detached) {
    const result = await childExit;
    process.removeListener('SIGINT', forwardInterrupt);
    process.removeListener('SIGTERM', forwardTerminate);
    // The child publishes its shutdown outcome. Leave that acknowledgement for
    // a concurrent `daemon:stop` (or the next status/start) to verify and reap;
    // removing it here would create a race that turns a clean stop into an
    // unacknowledged one.
    if (result.code !== 0) process.exitCode = result.code ?? 1;
  }
  return { reused: false, probe };
}

async function statusDaemon({ quiet = false } = {}) {
  const selection = runtimeEnvironment(root);
  assertLifecyclePathSelection(selection);
  const { environment, profile } = selection;
  const expected = expectedRuntime(environment, profile);
  let record = readManagedRecord();
  let managed = false;
  let probe;
  const recordPidAlive = record ? processAlive(record.pid) : false;
  if (record && recordPidAlive && processMatchesRecord(record)) {
    managed = true;
    probe = await probeManagedRecord(record, environment, expected);
    if (!managedProbeMatchesRecord(record, probe)) {
      const detail = probe.identifiable
        ? `API reported PID ${probe.body?.runtime_build?.runtime_pid || 'unknown'}, runtime ${probe.body?.runtime_build?.runtime_instance_id || 'unknown'}, daemon ${probe.body?.runtime_status?.daemon_instance_id || 'unknown'}, state ${String(probe.body?.runtime_status?.state_identity_sha256 || 'unknown').slice(0, 12)}.`
        : `API probe was ${probe.running ? 'occupied but unidentifiable' : 'not listening'}${probe.status ? ` (HTTP ${probe.status})` : ''}.`;
      throw new Error(
        `LIVE UNVERIFIED — managed PID ${record.pid} is alive but its runtime API identity is unavailable or differs. `
        + `${detail} No dependency, build, record, or process change was attempted.`,
      );
    }
  } else {
    if (record) {
      if (!recordPidAlive && record.shutdown_succeeded !== true) {
        throw new Error(
          `FAILED — prior managed PID ${record.pid} exited without a successful shutdown acknowledgement. `
          + `${record.shutdown_error || 'Inspect the managed log and recovery status before restarting or upgrading.'}`,
        );
      }
      removeManagedRecord(record.daemon_instance_id);
      record = null;
    }
    probe = await probeRuntime(expected, environment);
  }
  if (!probe.running) {
    const owner = readStateOwner(expected);
    if (owner && processAlive(owner.pid)) {
      const matches = typeof owner.process_start_identity === 'string'
        ? processStartIdentityMatches(owner.pid, owner.process_start_identity)
        : undefined;
      if (matches === undefined || typeof owner.process_start_identity !== 'string') {
        throw new Error(
          `LIVE OWNER — PID ${owner.pid} owns ${expected.statePath || 'the configured state'}, `
          + 'but its process identity or API endpoint cannot be verified. No process was signaled.',
        );
      }
      if (matches) {
        throw new Error(
          `LIVE OWNER — Overwatch PID ${owner.pid} owns ${expected.statePath || 'the configured state'} `
          + `(${owner.transport || 'unknown transport'}, ${owner.phase || 'unknown phase'}), `
          + 'but its API endpoint is unavailable. It is not stopped.',
        );
      }
    }
    if (!quiet) console.log(`STOPPED — no daemon is listening at ${expected.runtimeUrl}.`);
    return { running: false, expected, probe, healthy: true };
  }
  if (!probe.identifiable) {
    throw new Error(`OCCUPIED — ${expected.runtimeUrl} did not provide a verifiable Overwatch runtime identity.`);
  }
  const exact = runtimeMatchesExpected(probe, expected);
  const build = probe.body.runtime_build;
  const runtime = probe.body.runtime_status;
  const local = readLifecycleBuildInfo();
  const buildMatch = local?.input_sha256 === build.input_sha256 && inspectBuildFreshness(root).fresh;
  if (!quiet) {
    console.log(`${String(runtime.phase).toUpperCase()} — Overwatch PID ${build.runtime_pid}
Engagement ${runtime.engagement_id}
State ${exact ? expected.statePath : `MISMATCH (${runtime.state_identity_sha256?.slice(0, 12) || 'unknown'})`}
Dashboard ${record?.dashboard_url || expected.dashboardUrl || 'disabled'}
MCP ${runtime.mcp_url || 'not published'}
Build ${build.git_sha || build.input_sha256.slice(0, 12)} (${buildMatch ? 'matches checkout' : 'DIFFERS from checkout'})
Writable ${runtime.persistence_writable ? 'yes' : 'no'}${runtime.recovery_reason ? `\nRecovery ${runtime.recovery_reason}` : ''}`);
  }
  return {
    running: true,
    managed,
    record,
    exact,
    expected,
    probe,
    buildMatch,
    healthy: exact && buildMatch && READY_PHASES.has(runtime.phase),
  };
}

async function requestManagedShutdown(record, environment) {
  if (!record.mcp_url) throw new Error('managed record does not publish an MCP control endpoint');
  const token = environment.OVERWATCH_MCP_TOKEN?.trim();
  if (!token) throw new Error('the persisted MCP authority is unavailable');
  return requestShutdownEndpoint(record.mcp_url, token, record.management_nonce);
}

async function requestShutdownEndpoint(mcpUrl, tokenValue, managementNonce) {
  const token = tokenValue?.trim();
  if (!token) throw new Error('the persisted MCP authority is unavailable');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3_000);
  try {
    const endpoint = new URL('/api/runtime/shutdown', mcpUrl);
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'x-overwatch-management-nonce': managementNonce,
      },
      signal: controller.signal,
    });
    if (response.status !== 202) {
      throw new Error(`managed shutdown endpoint returned HTTP ${response.status}`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

async function waitForManagedEndpointsReleased(record) {
  const targets = [
    endpointProbeTarget(record.dashboard_url, 'dashboard'),
    endpointProbeTarget(record.mcp_url?.replace(/\/mcp\/?$/, ''), 'mcp'),
  ].filter(Boolean);
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const occupied = await Promise.all(targets.map(target => portOccupied(target.port, target.host)));
    if (occupied.every(value => !value)) return;
    await new Promise(resolveWait => setTimeout(resolveWait, 50));
  }
  throw new Error(
    `Verified daemon PID ${record.pid} stopped, but a configured endpoint remained occupied for 5000ms. `
    + 'The managed record was retained; inspect the ports before restarting.',
  );
}

async function stopDaemon() {
  const { environment } = runtimeEnvironment(root);
  const status = await statusDaemon({ quiet: true });
  const record = status.record ?? readManagedRecord();
  if (!status.running) {
    if (record && !processAlive(record.pid)) removeManagedRecord(record.daemon_instance_id);
    console.log('STOPPED — no managed daemon is running.');
    return;
  }
  if (!status.managed || !record) {
    throw new Error(
      `${runtimeDescription(status.probe)} is not recorded as a managed daemon. `
      + 'Stop its foreground terminal with Ctrl-C; no PID was signaled.',
    );
  }
  if (!status.exact) {
    throw new Error('The managed daemon does not match the selected profile/state; refusing to signal any PID.');
  }
  const build = status.probe.body.runtime_build;
  const runtime = status.probe.body.runtime_status;
  if (
    record.pid !== build.runtime_pid
    || record.runtime_instance_id !== build.runtime_instance_id
    || record.runtime_started_at !== build.runtime_started_at
    || record.daemon_instance_id !== runtime.daemon_instance_id
    || record.state_identity_sha256 !== runtime.state_identity_sha256
    || record.config_identity_sha256 !== runtime.config_identity_sha256
  ) throw new Error('Managed record and live runtime identity differ; refusing to signal any PID.');
  const startMatches = processStartIdentityMatches(record.pid, record.process_start_identity);
  if (startMatches !== true) {
    throw new Error(`PID ${record.pid} start identity cannot be verified; refusing to signal it.`);
  }
  try {
    await requestManagedShutdown(record, environment);
  } catch (error) {
    if (process.platform === 'win32') {
      throw new Error(
        `Verified daemon PID ${record.pid} could not accept a graceful managed shutdown: ${
          error instanceof Error ? error.message : String(error)
        }. It was not force-terminated.`,
      );
    }
    console.error(
      `Managed shutdown endpoint unavailable (${error instanceof Error ? error.message : String(error)}); `
      + `falling back to SIGTERM for verified PID ${record.pid}.`,
    );
    // The authenticated request can consume its full timeout. Re-prove the
    // physical process immediately before the compatibility signal so a daemon
    // exit plus PID reuse cannot redirect SIGTERM to an unrelated process.
    if (processStartIdentityMatches(record.pid, record.process_start_identity) !== true) {
      throw new Error(
        `Verified daemon PID ${record.pid} changed or became unverifiable before SIGTERM; no signal was sent.`,
      );
    }
    process.kill(record.pid, 'SIGTERM');
  }
  const deadline = Date.now() + STOP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!processAlive(record.pid)) {
      const outcome = readManagedRecord();
      if (
        outcome?.daemon_instance_id === record.daemon_instance_id
        && outcome.shutdown_succeeded === true
        && outcome.phase === 'stopped'
      ) {
        await waitForManagedEndpointsReleased(record);
        removeManagedRecord(record.daemon_instance_id);
        console.log(`STOPPED — verified daemon PID ${record.pid} completed graceful shutdown.`);
        return;
      }
      throw new Error(
        `Daemon PID ${record.pid} exited without a successful durable shutdown acknowledgement. `
        + `${outcome?.shutdown_error || 'Inspect the managed log and recovery status before restarting or upgrading.'}`,
      );
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  throw new Error(
    `Daemon PID ${record.pid} did not finish within ${STOP_TIMEOUT_MS}ms. `
    + 'It was not force-killed; inspect the log and preserve the runtime owner record for recovery.',
  );
}

function showLogs() {
  const path = managedDaemonLogPath(root);
  console.log(path);
  if (!existsSync(path)) return;
  const tail = readFileSync(path, 'utf8').split('\n').slice(-80).join('\n');
  if (tail.trim()) console.log(tail);
}

async function runStdio({ onSpawn } = {}) {
  const { environment, profile } = runtimeEnvironment(root);
  if (!profile) {
    throw new Error(
      'No runtime profile is configured. Run `npm run setup:stdio` before starting a private stdio writer.',
    );
  }
  if (profile.mode === 'daemon') {
    throw new Error('The runtime profile is configured for the shared daemon. Run `npm run setup -- --stdio` before starting a private stdio writer.');
  }
  const expected = expectedRuntime(environment, profile);
  const managed = readManagedRecord();
  if (managed && processMatchesRecord(managed)) {
    throw new Error(`Managed Overwatch PID ${managed.pid} is already running; reuse it instead of starting a stdio writer.`);
  }
  const stateOwner = readStateOwner(expected);
  if (stateOwner && processAlive(stateOwner.pid)) {
    const matches = processStartIdentityMatches(stateOwner.pid, stateOwner.process_start_identity);
    if (matches !== false) {
      throw new Error(`Overwatch PID ${stateOwner.pid} already owns the selected state; no build was performed.`);
    }
  }
  const probe = await probeRuntime(expected, environment);
  if (probe.running) {
    throw new Error('A shared daemon is already running. Reuse it through `.mcp.json`; do not start a second stdio writer.');
  }
  // stdout is the MCP JSON-RPC transport in this mode. A freshness rebuild may
  // be noisy, so route every build diagnostic to stderr instead of corrupting
  // the protocol stream.
  ensureFreshBuild(environment, ['ignore', 2, 2]);
  const child = spawn(process.execPath, [join(root, 'dist', 'index.js')], {
    cwd: root,
    env: { ...environment, OVERWATCH_TRANSPORT: 'stdio' },
    stdio: 'inherit',
  });
  let childSettled = false;
  const childExit = new Promise(resolveExit => {
    child.once('error', error => {
      childSettled = true;
      resolveExit({ code: 1, signal: null, error });
    });
    child.once('exit', (code, signal) => {
      childSettled = true;
      resolveExit({ code, signal });
    });
  });
  if (!child.pid) {
    const result = await childExit;
    throw result.error || new Error('Stdio process did not return a PID.');
  }
  let forwardedSignal;
  const forwardSignal = signal => {
    forwardedSignal = signal;
    if (childSettled) return;
    try { child.kill(signal); } catch { /* child exited between the check and signal */ }
  };
  const forwardInterrupt = () => forwardSignal('SIGINT');
  const forwardTerminate = () => forwardSignal('SIGTERM');
  process.on('SIGINT', forwardInterrupt);
  process.on('SIGTERM', forwardTerminate);

  const terminateAndWait = async () => {
    if (!childSettled) {
      try { child.kill('SIGTERM'); } catch { /* child already exited */ }
    }
    // Do not let the wrapper exit while its child might still own the durable
    // state. A stuck shutdown remains attached and visible instead of becoming
    // an orphan writer.
    return childExit;
  };
  try {
    await waitForStateOwnership(child, expected);
    onSpawn?.();
    const result = await childExit;
    if (result.error) throw result.error;
    if (forwardedSignal) {
      process.exitCode = forwardedSignal === 'SIGINT' ? 130 : 143;
    } else if (result.code !== 0) {
      process.exitCode = result.code ?? 1;
    }
  } catch (error) {
    await terminateAndWait();
    throw error;
  } finally {
    process.removeListener('SIGINT', forwardInterrupt);
    process.removeListener('SIGTERM', forwardTerminate);
  }
}

async function main() {
  switch (command) {
    case 'start':
      await withLifecycleLock(() => startDaemon({ detached: true }));
      break;
    case 'run':
      await withLifecycleLock(release => startDaemon({ detached: false, onReady: release }));
      break;
    case 'status':
      if (!(await statusDaemon()).healthy) process.exitCode = 1;
      break;
    case 'stop':
      await withLifecycleLock(() => stopDaemon());
      break;
    case 'restart':
      await withLifecycleLock(async () => {
        await stopDaemon();
        await startDaemon({ detached: true });
      });
      break;
    case 'logs':
      showLogs();
      break;
    case 'upgrade': {
      await withLifecycleLock(async () => {
        preflightSourceUpgrade();
        const beforeStop = runtimeEnvironment(root);
        if (beforeStop.profile?.mode === 'stdio') {
          throw new Error(
            'The runtime profile is configured for stdio; upgrade did not stop or change it. '
            + 'Run `npm run setup -- --daemon` before using the managed daemon upgrade command.',
          );
        }
        preflightStateUpgrade(beforeStop);
        await stopDaemon();
        const frozenSelection = runtimeEnvironment(root);
        const upgradeStateLease = await acquireUpgradeStateLease(frozenSelection);
        try {
          const unexpectedOwner = readStateOwner(expectedRuntime(
            frozenSelection.environment,
            frozenSelection.profile,
          ));
          if (unexpectedOwner) {
            throw new Error(
              `State ownership changed during upgrade reservation (PID ${unexpectedOwner.pid ?? 'unknown'}); no install or build was attempted.`,
            );
          }
          await holdUpgradeLeaseForTest(frozenSelection.environment);
          try {
            preflightStateUpgrade(frozenSelection, { frozen: true });
          } catch (preflightError) {
            try {
              await upgradeStateLease.release();
              await startDaemon({ detached: true, allowStaleBuild: true });
            } catch (restartError) {
              throw new Error(
                'The authoritative frozen state/WAL preflight failed after shutdown, and the previous compiled runtime could not be restarted. '
                + 'No dependency install or build was attempted; the daemon remains stopped. '
                + `Preflight: ${preflightError instanceof Error ? preflightError.message : String(preflightError)}. `
                + `Restart: ${restartError instanceof Error ? restartError.message : String(restartError)}.`,
              );
            }
            throw new Error(
              'The authoritative frozen state/WAL preflight failed after shutdown; no dependency install or build was attempted, '
              + 'and the previous compiled runtime was restarted unchanged. '
              + `${preflightError instanceof Error ? preflightError.message : String(preflightError)}`,
            );
          }
          const { environment } = frozenSelection;
          const npm = process.env.OVERWATCH_LIFECYCLE_NPM
            || (process.platform === 'win32' ? 'npm.cmd' : 'npm');
          runChecked(npm, ['ci'], 'npm ci', environment);
          runChecked(npm, ['run', 'build'], 'build', environment);
          await startDaemon({ detached: true, upgradeStateLease });
        } finally {
          if (!upgradeStateLease.released) await upgradeStateLease.release();
        }
      });
      break;
    }
    case 'run-stdio':
      await withLifecycleLock(release => runStdio({ onSpawn: release }));
      break;
    case '--help':
    case '-h':
    case 'help':
      usage(0);
      break;
    default:
      usage(1);
  }
}

main().catch(error => {
  console.error(`STARTUP BLOCKED — ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
