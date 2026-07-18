#!/usr/bin/env node

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { processIsAlive } from './process-identity.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = mkdtempSync(join(tmpdir(), 'overwatch-lifecycle-smoke-'));
const lifecycleScript = join(root, 'scripts', 'daemon-lifecycle.mjs');
const setupScript = join(root, 'scripts', 'setup.mjs');
const sanitizedProcessEnvironment = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith('OVERWATCH_')),
);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('could not reserve a test port');
  const port = address.port;
  await new Promise(resolveClose => server.close(resolveClose));
  return port;
}

function runNode(script, args, environment, expectSuccess = true, timeoutMs = 60_000) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: root,
    env: environment,
    encoding: 'utf8',
    timeout: timeoutMs,
  });
  if (expectSuccess && result.status !== 0) {
    throw new Error(`${script} ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`);
  }
  if (!expectSuccess && result.status === 0) {
    throw new Error(`${script} ${args.join(' ')} unexpectedly succeeded:\n${result.stdout}`);
  }
  return result;
}

function runNodeAsync(script, args, environment, onSpawn) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: root,
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('spawn', () => onSpawn?.(child));
    const timeout = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* already exited */ }
      rejectRun(new Error(`${script} ${args.join(' ')} timed out`));
    }, 60_000);
    child.once('error', error => {
      clearTimeout(timeout);
      rejectRun(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      resolveRun({ status: code, signal, stdout, stderr, pid: child.pid });
    });
  });
}

async function fetchChecked(label, input, init) {
  try {
    return await fetch(input, init);
  } catch (error) {
    throw new Error(`${label} request failed`, { cause: error });
  }
}

async function waitForProcessExit(pid) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (!processIsAlive(pid)) return;
    await new Promise(resolveWait => setTimeout(resolveWait, 50));
  }
  throw new Error(`PID ${pid} did not exit after SIGKILL`);
}

async function waitFor(label, predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

let environment;
let activeEnvironment;
let activeStdioWrapper;
let activeStdioOwnerPid;
let lifecycleError;
try {
  const dashboardPort = await freePort();
  const mcpPort = await freePort();
  const conflictingDashboardPort = await freePort();
  const conflictingMcpPort = await freePort();
  environment = {
    ...sanitizedProcessEnvironment,
    OVERWATCH_SETUP_ROOT: fixture,
    OVERWATCH_RUNTIME_PROFILE: join(fixture, '.overwatch-runtime', 'profile.json'),
    OVERWATCH_DAEMON_RECORD: join(fixture, 'daemon.json'),
    OVERWATCH_DAEMON_LOG: join(fixture, 'daemon.log'),
    OVERWATCH_HTTP_HOST: '0.0.0.0',
    OVERWATCH_HTTP_PORT: String(mcpPort),
    OVERWATCH_DASHBOARD_HOST: '0.0.0.0',
    OVERWATCH_DASHBOARD_PORT: String(dashboardPort),
    OVERWATCH_DASHBOARD_TOKEN: 'lifecycle-dashboard-token',
  };
  runNode(setupScript, [
    '--template', join(root, 'engagement-templates', 'ctf.json'),
    '--name', 'Lifecycle smoke',
    '--id', 'lifecycle-smoke',
    '--cidr', '10.255.255.0/30',
  ], environment);
  delete environment.OVERWATCH_DASHBOARD_TOKEN;
  const configPath = join(fixture, 'engagement.json');
  const statePath = join(fixture, 'state-lifecycle-smoke.json');
  const setupConfig = JSON.parse(readFileSync(configPath, 'utf8'));
  const dashboardAuthorization = `Bearer ${readFileSync(join(fixture, '.overwatch-dashboard-token'), 'utf8').trim()}`;
  const tokenPath = join(fixture, '.overwatch-mcp-token');
  const mcpConfigPath = join(fixture, '.mcp.json');
  const originalToken = readFileSync(tokenPath);
  const originalMcpConfig = readFileSync(mcpConfigPath);
  writeFileSync(tokenPath, 'changed-without-setup');
  const changedToken = runNode(lifecycleScript, ['start'], environment, false);
  assert(
    `${changedToken.stdout}\n${changedToken.stderr}`.includes('do not describe the same daemon endpoint'),
    'changed token file did not block before daemon startup',
  );
  assert(!existsSync(environment.OVERWATCH_DAEMON_RECORD), 'changed token published a daemon record');
  writeFileSync(tokenPath, originalToken);
  const changedMcp = JSON.parse(originalMcpConfig.toString('utf8'));
  changedMcp.mcpServers.overwatch.headers.Authorization = 'Bearer changed-without-setup';
  writeFileSync(mcpConfigPath, `${JSON.stringify(changedMcp, null, 2)}\n`);
  const changedMcpStart = runNode(lifecycleScript, ['start'], environment, false);
  assert(
    `${changedMcpStart.stdout}\n${changedMcpStart.stderr}`.includes('do not describe the same daemon endpoint'),
    'changed MCP config did not block before daemon startup',
  );
  assert(!existsSync(environment.OVERWATCH_DAEMON_RECORD), 'changed MCP config published a daemon record');
  writeFileSync(mcpConfigPath, originalMcpConfig);

  const occupiedMcp = createServer();
  await new Promise((resolveListen, rejectListen) => {
    occupiedMcp.once('error', rejectListen);
    occupiedMcp.listen(mcpPort, '0.0.0.0', resolveListen);
  });
  const failedBind = runNode(lifecycleScript, ['start'], environment, false);
  assert(
    `${failedBind.stdout}\n${failedBind.stderr}`.includes('exited before becoming ready'),
    'occupied MCP startup did not fail before READY',
  );
  assert(!existsSync(environment.OVERWATCH_DAEMON_RECORD), 'failed startup published a managed record');
  let dashboardExposed = false;
  try {
    await fetch(`http://127.0.0.1:${dashboardPort}/api/runtime`);
    dashboardExposed = true;
  } catch { /* expected: dashboard never bound */ }
  assert(!dashboardExposed, 'failed MCP bind exposed the dashboard');
  await new Promise(resolveClose => occupiedMcp.close(resolveClose));

  const timedOutStart = runNode(lifecycleScript, ['start'], {
    ...environment,
    OVERWATCH_DAEMON_START_TIMEOUT_MS: '0',
  }, false);
  assert(
    `${timedOutStart.stdout}\n${timedOutStart.stderr}`.includes('did not become ready'),
    'zero-deadline startup did not exercise failed-child cleanup',
  );
  const timedOutOwnerPath = `${statePath}.runtime-owner.json`;
  assert(!existsSync(timedOutOwnerPath), 'failed startup returned while its child still owned durable state');
  if (existsSync(environment.OVERWATCH_DAEMON_RECORD)) {
    const timedOutRecord = JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD, 'utf8'));
    assert(!processIsAlive(timedOutRecord.pid), 'failed startup returned while its recorded child was alive');
  }

  const concurrentStarts = await Promise.all([
    runNodeAsync(lifecycleScript, ['start'], environment),
    runNodeAsync(lifecycleScript, ['start'], environment),
  ]);
  const successfulStarts = concurrentStarts.filter(result => result.status === 0);
  const blockedStarts = concurrentStarts.filter(result => result.status !== 0);
  assert(successfulStarts.length >= 1, 'concurrent daemon starts produced no READY owner');
  assert(
    blockedStarts.every(result => `${result.stdout}\n${result.stderr}`.includes('Lifecycle command start is active')),
    `a concurrent start failed for a reason other than lifecycle serialization: ${JSON.stringify(concurrentStarts)}`,
  );
  const firstStart = successfulStarts[0];
  activeEnvironment = environment;
  assert(
    concurrentStarts.some(result => result.stdout.includes('READY')),
    'serialized detached start did not report READY',
  );
  const firstRecord = JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD, 'utf8'));
  assert(typeof firstRecord.management_nonce === 'string' && firstRecord.management_nonce.length === 64,
    'ready daemon did not publish its own management handshake');
  const firstRuntime = await fetchChecked('first dashboard runtime', `http://127.0.0.1:${dashboardPort}/api/runtime`, {
    headers: { Authorization: dashboardAuthorization },
  }).then(response => response.json());
  assert(firstRuntime.runtime_status?.engagement_id === 'lifecycle-smoke', 'runtime loaded the wrong engagement');
  assert(firstRuntime.runtime_status?.phase === 'ready', 'runtime did not reach writable READY');
  assert(firstRuntime.runtime_status?.persistence_writable === true, 'runtime is unexpectedly read-only');
  assert(firstRuntime.runtime_build?.runtime_pid === firstRecord.pid, 'managed PID does not match runtime PID');
  const token = readFileSync(tokenPath, 'utf8').trim();
  const authenticatedMcp = await fetchChecked('authenticated MCP', `http://127.0.0.1:${mcpPort}/mcp`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert(authenticatedMcp.status === 400, 'persisted external-config token did not authenticate to MCP');
  const rejectedMcp = await fetchChecked('rejected MCP', `http://127.0.0.1:${mcpPort}/mcp`, {
    headers: { Authorization: 'Bearer incorrect-lifecycle-token' },
  });
  assert(rejectedMcp.status === 401, 'MCP accepted the wrong lifecycle token');
  const configAfterInitialRecovery = readFileSync(configPath);
  const recoveredConfig = JSON.parse(configAfterInitialRecovery.toString('utf8'));
  assert(recoveredConfig.id === setupConfig.id, 'startup changed engagement identity');
  assert(
    JSON.stringify(recoveredConfig.scope) === JSON.stringify(setupConfig.scope),
    'startup changed engagement scope',
  );

  const repeated = runNode(lifecycleScript, ['start'], environment);
  assert(repeated.stdout.includes('already serving'), 'exact repeated start was not an idempotent no-op');
  const buildInfoPath = join(root, 'dist', 'build-info.json');
  const buildInfoBefore = readFileSync(buildInfoPath);
  const staleBuildInfo = {
    ...JSON.parse(buildInfoBefore.toString('utf8')),
    input_sha256: '0'.repeat(64),
  };
  const staleBuildInfoPath = join(fixture, 'stale-build-info.json');
  writeFileSync(staleBuildInfoPath, `${JSON.stringify(staleBuildInfo, null, 2)}\n`);
  const staleStart = runNode(lifecycleScript, ['start'], {
    ...environment,
    OVERWATCH_LIFECYCLE_BUILD_INFO_PATH: staleBuildInfoPath,
  }, false);
  assert(
    `${staleStart.stdout}\n${staleStart.stderr}`.includes('No rebuild was performed while it is live'),
    'stale start did not refuse before rebuilding a live daemon',
  );
  assert(
    readFileSync(buildInfoPath).equals(buildInfoBefore),
    'stale start rebuilt or replaced shared dist while the daemon was live',
  );
  const changedProfile = runNode(lifecycleScript, ['start'], {
    ...environment,
    OVERWATCH_HTTP_PORT: String(conflictingMcpPort),
    OVERWATCH_DASHBOARD_PORT: String(conflictingDashboardPort),
  }, false);
  assert(
    `${changedProfile.stdout}\n${changedProfile.stderr}`.includes('conflicts with the persisted runtime profile'),
    'a live managed record did not block a changed endpoint/profile before spawn',
  );
  assert(
    JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD, 'utf8')).daemon_instance_id
      === firstRecord.daemon_instance_id,
    'changed-profile start overwrote the live managed record',
  );
  const journalBefore = readFileSync(`${statePath.replace(/\.json$/, '')}.journal.jsonl`);
  const conflictingProfilePath = join(fixture, '.overwatch-runtime', 'conflicting-profile.json');
  const conflictingMcpConfigPath = join(fixture, '.mcp-conflict.json');
  const conflictingProfile = {
    ...JSON.parse(readFileSync(environment.OVERWATCH_RUNTIME_PROFILE, 'utf8')),
    http_port: conflictingMcpPort,
    dashboard_port: conflictingDashboardPort,
    mcp_config_path: conflictingMcpConfigPath,
    updated_at: new Date().toISOString(),
  };
  writeFileSync(conflictingProfilePath, `${JSON.stringify(conflictingProfile, null, 2)}\n`);
  writeFileSync(conflictingMcpConfigPath, `${JSON.stringify({
    mcpServers: {
      overwatch: {
        type: 'http',
        url: `http://127.0.0.1:${conflictingMcpPort}/mcp`,
        headers: { Authorization: `Bearer ${token}` },
      },
    },
  }, null, 2)}\n`);
  const conflict = runNode(lifecycleScript, ['start'], {
    ...environment,
    OVERWATCH_RUNTIME_PROFILE: conflictingProfilePath,
    OVERWATCH_DAEMON_RECORD: join(fixture, 'daemon-conflict.json'),
    OVERWATCH_DAEMON_LOG: join(fixture, 'daemon-conflict.log'),
    OVERWATCH_HTTP_PORT: String(conflictingMcpPort),
    OVERWATCH_DASHBOARD_PORT: String(conflictingDashboardPort),
  }, false);
  assert(
    `${conflict.stdout}\n${conflict.stderr}`.includes('already owned by Overwatch PID'),
    'same-state/different-port collision did not identify the lifetime owner',
  );
  assert(
    readFileSync(`${statePath.replace(/\.json$/, '')}.journal.jsonl`).equals(journalBefore),
    'losing startup changed the durable journal',
  );
  assert(
    readFileSync(buildInfoPath).equals(buildInfoBefore),
    'same-state/different-port collision rebuilt dist before lifetime ownership rejection',
  );

  const recordBeforeFailedPreflight = readFileSync(environment.OVERWATCH_DAEMON_RECORD);
  const failedUpgradePreflight = runNode(lifecycleScript, ['upgrade'], {
    ...environment,
    OVERWATCH_LIFECYCLE_NPM: join(fixture, 'missing-npm'),
  }, false);
  assert(
    `${failedUpgradePreflight.stdout}\n${failedUpgradePreflight.stderr}`.includes('npm is unavailable; the running daemon was not stopped'),
    'upgrade dependency preflight did not fail before downtime',
  );
  assert(
    readFileSync(environment.OVERWATCH_DAEMON_RECORD).equals(recordBeforeFailedPreflight),
    'failed upgrade preflight changed the live managed record',
  );
  assert(processIsAlive(firstRecord.pid), 'failed upgrade preflight stopped the live daemon');

  const failingNpm = join(fixture, 'failing-npm');
  writeFileSync(failingNpm, `#!/bin/sh
if [ "$1" = "--version" ]; then echo 10.0.0; exit 0; fi
if [ "$1" = "ci" ] && [ "$2" = "--dry-run" ]; then exit 0; fi
exit 42
`);
  chmodSync(failingNpm, 0o755);
  const failedUpgradeInstall = runNode(lifecycleScript, ['upgrade'], {
    ...environment,
    OVERWATCH_LIFECYCLE_NPM: failingNpm,
  }, false);
  activeEnvironment = undefined;
  assert(
    `${failedUpgradeInstall.stdout}\n${failedUpgradeInstall.stderr}`.includes('npm ci failed with exit code 42'),
    'post-stop upgrade install failure was not surfaced',
  );
  const stoppedAfterUpgradeFailure = runNode(lifecycleScript, ['status'], environment);
  assert(stoppedAfterUpgradeFailure.stdout.includes('STOPPED'), 'failed upgrade install left false live status');
  assert(readFileSync(configPath).equals(configAfterInitialRecovery), 'failed upgrade install changed engagement config');
  const restartAfterUpgradeFailure = runNode(lifecycleScript, ['start'], environment);
  activeEnvironment = environment;
  assert(restartAfterUpgradeFailure.stdout.includes('READY'), 'daemon could not restart after an install failure');

  const upgrade = runNode(lifecycleScript, ['upgrade'], environment, true, 180_000);
  assert(
    upgrade.stdout.includes('STOPPED') && upgrade.stdout.includes('READY'),
    'state-preserving post-pull upgrade did not stop, build, and return to READY',
  );
  const secondRecord = JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD, 'utf8'));
  assert(secondRecord.pid !== firstRecord.pid, 'upgrade did not replace the runtime process');
  assert(readFileSync(configPath).equals(configAfterInitialRecovery), 'upgrade changed converged engagement.json bytes');
  const afterRestart = await fetchChecked('post-restart dashboard runtime', `http://127.0.0.1:${dashboardPort}/api/runtime`, {
    headers: { Authorization: dashboardAuthorization },
  }).then(response => response.json());
  assert(afterRestart.runtime_status?.engagement_id === 'lifecycle-smoke', 'upgrade selected another engagement');
  assert(afterRestart.runtime_status?.phase === 'ready', 'upgrade did not return to READY');

  const killedRecordBytes = readFileSync(environment.OVERWATCH_DAEMON_RECORD);
  process.kill(secondRecord.pid, 'SIGKILL');
  await waitForProcessExit(secondRecord.pid);
  activeEnvironment = undefined;
  const crashedStatus = runNode(lifecycleScript, ['status'], environment, false);
  assert(
    `${crashedStatus.stdout}\n${crashedStatus.stderr}`.includes('without a successful shutdown acknowledgement'),
    'status hid an unacknowledged daemon crash',
  );
  assert(
    readFileSync(environment.OVERWATCH_DAEMON_RECORD).equals(killedRecordBytes),
    'status changed or discarded the unacknowledged managed record',
  );
  const recoveredStart = runNode(lifecycleScript, ['start'], environment);
  activeEnvironment = environment;
  assert(
    `${recoveredStart.stdout}\n${recoveredStart.stderr}`.includes('RECOVERY')
      && recoveredStart.stdout.includes('READY'),
    'direct start did not archive the crash and recover to READY',
  );
  const crashArchiveName = readdirSync(dirname(environment.OVERWATCH_DAEMON_RECORD)).find(name =>
    name.startsWith(`${basename(environment.OVERWATCH_DAEMON_RECORD)}.crash-`));
  assert(Boolean(crashArchiveName), 'crash recovery did not preserve the prior managed record');
  assert(
    readFileSync(join(dirname(environment.OVERWATCH_DAEMON_RECORD), crashArchiveName)).equals(killedRecordBytes),
    'crash archive did not preserve the prior managed record byte-for-byte',
  );
  const recoveredRecord = JSON.parse(readFileSync(environment.OVERWATCH_DAEMON_RECORD, 'utf8'));
  assert(recoveredRecord.pid !== secondRecord.pid, 'crash recovery reused the dead PID');
  assert(
    recoveredRecord.daemon_instance_id !== secondRecord.daemon_instance_id,
    'crash recovery reused the dead daemon instance identity',
  );
  const afterCrashRecovery = await fetchChecked('post-crash dashboard runtime', `http://127.0.0.1:${dashboardPort}/api/runtime`, {
    headers: { Authorization: dashboardAuthorization },
  }).then(response => response.json());
  assert(afterCrashRecovery.runtime_status?.phase === 'ready', 'crash recovery did not return to writable READY');
  assert(
    afterCrashRecovery.runtime_status?.state_identity_sha256 === afterRestart.runtime_status?.state_identity_sha256,
    'crash recovery selected a different durable state family',
  );
  assert(readFileSync(configPath).equals(configAfterInitialRecovery), 'crash recovery changed engagement config bytes');

  // Losing local secret files must not strand a verified live owner: the
  // setup-generated MCP client retains equivalent authority for status/stop.
  rmSync(tokenPath);
  rmSync(join(fixture, '.overwatch-dashboard-token'));
  const missingTokenStatus = runNode(lifecycleScript, ['status'], environment);
  assert(missingTokenStatus.stdout.includes('READY'), 'MCP fallback could not identify the token-file-loss runtime');
  runNode(lifecycleScript, ['stop'], environment);
  activeEnvironment = undefined;
  assert(!existsSync(environment.OVERWATCH_DAEMON_RECORD), 'stop retained the managed daemon record');
  const stopped = runNode(lifecycleScript, ['status'], environment);
  assert(stopped.stdout.includes('STOPPED'), 'status did not report STOPPED after shutdown');
  assert(readFileSync(configPath).equals(configAfterInitialRecovery), 'lifecycle changed converged engagement.json bytes');

  const dashboardlessEnvironment = {
    ...environment,
    OVERWATCH_DASHBOARD_PORT: '0',
  };
  runNode(setupScript, ['--template', join(root, 'engagement-templates', 'ctf.json')], dashboardlessEnvironment);
  const dashboardlessStart = runNode(lifecycleScript, ['start'], dashboardlessEnvironment);
  activeEnvironment = dashboardlessEnvironment;
  assert(dashboardlessStart.stdout.includes('Dashboard disabled'), 'dashboard-disabled daemon did not become ready');
  const dashboardlessToken = readFileSync(tokenPath, 'utf8').trim();
  const runtimeWithoutDashboard = await fetchChecked('dashboardless MCP runtime', `http://127.0.0.1:${mcpPort}/api/runtime`, {
    headers: { Authorization: `Bearer ${dashboardlessToken}` },
  }).then(response => response.json());
  assert(runtimeWithoutDashboard.runtime_status?.phase === 'ready', 'MCP runtime identity endpoint did not report ready');
  runNode(lifecycleScript, ['stop'], dashboardlessEnvironment);
  activeEnvironment = undefined;

  runNode(setupScript, ['--stdio', '--template', join(root, 'engagement-templates', 'ctf.json')], dashboardlessEnvironment);
  const stdioResultPromise = runNodeAsync(
    lifecycleScript,
    ['run-stdio'],
    dashboardlessEnvironment,
    child => { activeStdioWrapper = child; },
  );
  await waitFor('stdio durable-state ownership', () => existsSync(`${statePath}.runtime-owner.json`));
  const stdioOwner = JSON.parse(readFileSync(`${statePath}.runtime-owner.json`, 'utf8'));
  activeStdioOwnerPid = stdioOwner.pid;
  assert(stdioOwner.pid !== activeStdioWrapper.pid, 'stdio wrapper incorrectly claimed child state ownership');
  activeStdioWrapper.kill('SIGTERM');
  const stdioResult = await stdioResultPromise;
  activeStdioWrapper = undefined;
  assert(stdioResult.status === 143, `stdio wrapper returned ${stdioResult.status} instead of forwarded SIGTERM status 143`);
  await waitForProcessExit(stdioOwner.pid);
  activeStdioOwnerPid = undefined;
  assert(!existsSync(`${statePath}.runtime-owner.json`), 'stdio signal shutdown left a durable owner record');

  console.log('Lifecycle smoke passed: convergence guards, concurrent start, failed-child cleanup, detached reuse, upgrade, crash recovery, dashboardless control, stdio signal forwarding, and stop.');
} catch (error) {
  lifecycleError = error;
  throw error;
} finally {
  let cleanupError;
  if (activeStdioWrapper) {
    try {
      activeStdioWrapper.kill('SIGTERM');
      await waitForProcessExit(activeStdioWrapper.pid);
      if (activeStdioOwnerPid) await waitForProcessExit(activeStdioOwnerPid);
      activeStdioWrapper = undefined;
      activeStdioOwnerPid = undefined;
    } catch (error) {
      cleanupError = error;
    }
  }
  if (activeEnvironment) {
    try {
      runNode(lifecycleScript, ['stop'], activeEnvironment);
      activeEnvironment = undefined;
    } catch (error) {
      cleanupError = error;
    }
  }
  if (cleanupError) {
    console.error(`Lifecycle smoke cleanup failed; preserved fixture ${fixture} for exact-owner recovery.`);
    if (!lifecycleError) throw cleanupError;
  } else {
    rmSync(fixture, { recursive: true, force: true });
  }
}
