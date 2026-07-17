#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const playwrightCli = resolve(workspaceRoot, 'node_modules', '@playwright', 'test', 'cli.js');
const token = process.env.OVERWATCH_BROWSER_TOKEN ?? `browser-${randomUUID()} / encoded`;
const activeChildren = new Set();
let handlingSignal = false;

function browserEnvironment(overrides = {}) {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('OVERWATCH_')),
  );
  return { ...environment, ...overrides };
}

function childIsRunning(child) {
  return child.exitCode === null && child.signalCode === null;
}

function childTreeIsRunning(child) {
  if (!child.pid) return false;
  if (process.platform === 'win32') return childIsRunning(child);
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    if (error?.code === 'EPERM') return true;
    throw error;
  }
}

function signalChildTree(child, signal) {
  if (!child.pid || !childTreeIsRunning(child)) return;
  if (process.platform !== 'win32') {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch (error) {
      if (error?.code === 'ESRCH') return;
      throw error;
    }
  }
  child.kill(signal);
}

function trackChild(child) {
  activeChildren.add(child);
  const remove = () => activeChildren.delete(child);
  child.once('error', remove);
  child.once('exit', remove);
  return child;
}

function waitForChildExit(child, timeoutMs) {
  if (!childTreeIsRunning(child)) return Promise.resolve(true);
  return new Promise((resolveWait) => {
    const deadline = Date.now() + timeoutMs;
    const poll = () => {
      if (!childTreeIsRunning(child)) resolveWait(true);
      else if (Date.now() >= deadline) resolveWait(false);
      else setTimeout(poll, 25);
    };
    poll();
  });
}

async function terminateChild(child, graceMs = 5_000) {
  if (!childTreeIsRunning(child)) return;
  signalChildTree(child, 'SIGTERM');
  if (await waitForChildExit(child, graceMs)) return;
  signalChildTree(child, 'SIGKILL');
  if (!await waitForChildExit(child, graceMs)) {
    throw new Error(`Child process ${child.pid ?? 'unknown'} did not exit after SIGKILL`);
  }
}

async function terminateAllForSignal(signal) {
  await Promise.allSettled([...activeChildren].map(child => terminateChild(child)));
  try {
    process.kill(process.pid, signal);
  } catch {
    process.exit(signal === 'SIGINT' ? 130 : 143);
  }
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    if (handlingSignal) return;
    handlingSignal = true;
    void terminateAllForSignal(signal);
  });
}

function run(command, args, options = {}) {
  return new Promise((resolveRun, reject) => {
    const child = trackChild(spawn(command, args, {
      cwd: workspaceRoot,
      env: browserEnvironment(),
      stdio: 'inherit',
      detached: process.platform !== 'win32',
      ...options,
    }));
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolveRun();
      else reject(new Error(`${command} exited with ${code ?? signal ?? 'unknown status'}`));
    });
  });
}

async function startFixture() {
  const child = trackChild(spawn(
    process.execPath,
    ['--import', 'tsx', 'scripts/browser-journey-server.ts'],
    {
      cwd: workspaceRoot,
      env: browserEnvironment({
        OVERWATCH_BROWSER_PORT: '0',
        OVERWATCH_BROWSER_RECOVERY_PORT: '0',
        OVERWATCH_BROWSER_CONTROL_PORT: '0',
        OVERWATCH_BROWSER_TOKEN: token,
      }),
      stdio: ['ignore', 'pipe', 'inherit'],
      detached: process.platform !== 'win32',
    },
  ));

  let stdout = '';
  const ready = new Promise((resolveReady, reject) => {
    let settled = false;
    const finish = (error, endpoints) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      child.off('error', onError);
      child.off('exit', onExit);
      if (error) reject(error);
      else resolveReady(endpoints);
    };
    const onError = error => finish(error);
    const onExit = (code, signal) => finish(new Error(
      `Browser fixture exited before readiness with ${code ?? signal ?? 'unknown status'}`,
    ));
    const timeout = setTimeout(
      () => finish(new Error('Browser fixture did not become ready within 60 seconds')),
      60_000,
    );
    child.once('error', onError);
    child.once('exit', onExit);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      process.stdout.write(chunk);
      if (settled) return;
      stdout += chunk;
      let newline;
      while ((newline = stdout.indexOf('\n')) >= 0) {
        const line = stdout.slice(0, newline).trim();
        stdout = stdout.slice(newline + 1);
        if (!line.startsWith('{')) continue;
        try {
          const message = JSON.parse(line);
          if (message.ready && message.dashboard && message.recovery && message.control) {
            finish(undefined, message);
            return;
          }
        } catch {
          // Preserve non-protocol fixture output for the operator.
        }
      }
    });
  });

  try {
    return { child, endpoints: await ready };
  } catch (error) {
    try {
      await terminateChild(child);
    } catch (terminationError) {
      throw new AggregateError([error, terminationError], 'Browser fixture startup and cleanup failed');
    }
    throw error;
  }
}

function portOf(url) {
  const port = Number.parseInt(new URL(url).port, 10);
  if (!Number.isInteger(port) || port < 1) throw new Error(`Fixture returned an invalid URL: ${url}`);
  return String(port);
}

await run('npm', ['run', 'build']);
const artifactHygiene = await import(pathToFileURL(
  resolve(workspaceRoot, 'dist', 'test-support', 'artifact-hygiene.js'),
).href);
const artifactsBefore = artifactHygiene.snapshotSensitiveArtifacts(workspaceRoot);

let fixture;
let testError;
let teardownError;
try {
  fixture = await startFixture();
  await run(process.execPath, [playwrightCli, 'test', ...process.argv.slice(2)], {
    env: browserEnvironment({
      OVERWATCH_BROWSER_EXTERNAL_SERVER: '1',
      OVERWATCH_BROWSER_PORT: portOf(fixture.endpoints.dashboard),
      OVERWATCH_BROWSER_RECOVERY_PORT: portOf(fixture.endpoints.recovery),
      OVERWATCH_BROWSER_CONTROL_PORT: portOf(fixture.endpoints.control),
      OVERWATCH_BROWSER_TOKEN: token,
    }),
  });
} catch (error) {
  testError = error;
} finally {
  if (fixture) {
    try {
      await terminateChild(fixture.child);
    } catch (error) {
      teardownError = error;
    }
  }
}

let hygieneError;
try {
  artifactHygiene.assertArtifactSnapshotUnchanged(
    artifactsBefore,
    artifactHygiene.snapshotSensitiveArtifacts(workspaceRoot),
  );
} catch (error) {
  hygieneError = error;
}

const errors = [testError, teardownError, hygieneError].filter(Boolean);
if (errors.length > 1) throw new AggregateError(errors, 'Browser tests or cleanup failed');
if (errors.length === 1) throw errors[0];
