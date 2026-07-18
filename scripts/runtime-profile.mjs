import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

export const RUNTIME_DIRECTORY = '.overwatch-runtime';
export const RUNTIME_PROFILE_FILE = 'profile.json';
export const MANAGED_DAEMON_FILE = 'daemon.json';
export const MANAGED_DAEMON_LOG = 'daemon.log';
export const DASHBOARD_TOKEN_FILE = 'dashboard-token';
const CASE_FOLDED_PATHS = process.platform === 'win32' || process.platform === 'darwin';

function comparablePath(value) {
  return CASE_FOLDED_PATHS ? value.toLowerCase() : value;
}

export function runtimeProfilePath(root) {
  return resolve(
    process.env.OVERWATCH_RUNTIME_PROFILE
      || join(root, RUNTIME_DIRECTORY, RUNTIME_PROFILE_FILE),
  );
}

export function managedDaemonPath(root) {
  return resolve(
    process.env.OVERWATCH_DAEMON_RECORD
      || join(root, RUNTIME_DIRECTORY, MANAGED_DAEMON_FILE),
  );
}

export function managedDaemonLogPath(root) {
  return resolve(
    process.env.OVERWATCH_DAEMON_LOG
      || join(root, RUNTIME_DIRECTORY, MANAGED_DAEMON_LOG),
  );
}

/** Resolve symlinks through the deepest existing ancestor without creating it. */
export function canonicalRuntimePath(value) {
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

function pathIsWithin(path, directory) {
  const child = relative(comparablePath(directory), comparablePath(path));
  return child === '' || (!child.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
    && child !== '..'
    && !isAbsolute(child));
}

/**
 * Runtime-control files must never alias durable engagement authority. A typo
 * in an environment override must fail before setup opens a token, record, log,
 * or lifecycle lock for writing.
 */
export function assertRuntimePathSeparation({ configPath, statePath, operationalPaths }) {
  const config = canonicalRuntimePath(configPath);
  const state = statePath ? canonicalRuntimePath(statePath) : undefined;
  const durable = [
    { label: 'engagement config', path: config },
    { label: 'config write intent', path: canonicalRuntimePath(`${config}.write-intent.json`) },
  ];
  const reservedFamilyPrefixes = [
    { label: 'config temporary file', prefix: `${config}.overwatch-` },
    { label: 'config temporary file', prefix: `${config}.tmp-` },
    { label: 'config intent conflict', prefix: `${config}.write-intent.json.conflict-` },
    { label: 'config intent temporary file', prefix: `${config}.write-intent.json.overwatch-` },
    { label: 'config intent temporary file', prefix: `${config}.write-intent.json.tmp-` },
  ];
  const protectedDirectories = new Map();
  for (const base of new Set([dirname(config), ...(state ? [dirname(state)] : [])])) {
    for (const name of ['.snapshots', '.migration-backups', 'engagements', 'evidence', 'reports', 'tapes', 'session-jars']) {
      const path = canonicalRuntimePath(join(base, name));
      protectedDirectories.set(path, name);
    }
  }
  if (state) {
    const stateBase = basename(state, '.json');
    const journalPath = canonicalRuntimePath(join(dirname(state), `${stateBase}.journal.jsonl`));
    durable.push(
      { label: 'durable state', path: state },
      { label: 'mutation journal', path: journalPath },
      { label: 'runtime owner', path: canonicalRuntimePath(`${state}.runtime-owner.json`) },
      { label: 'writer lock', path: canonicalRuntimePath(`${state}.writer-lock`) },
      { label: 'migration lock', path: canonicalRuntimePath(`${state}.migration-lock`) },
      { label: 'rollback intent', path: canonicalRuntimePath(`${state}.rollback-intent.json`) },
      { label: 'migration intent', path: canonicalRuntimePath(`${state}.migration-intent.json`) },
    );
    reservedFamilyPrefixes.push(
      { label: 'journal recovery artifact', prefix: `${journalPath}.` },
      { label: 'legacy root snapshot', prefix: `${state.replace(/\.json$/i, '')}.snap-` },
      { label: 'state temporary file', prefix: `${state}.tmp` },
    );
    protectedDirectories.set(canonicalRuntimePath(`${state}.writer-lock`), 'state writer-lock');
    protectedDirectories.set(canonicalRuntimePath(`${state}.migration-lock`), 'state migration-lock');
  }

  const operational = operationalPaths
    .filter(entry => entry?.path)
    .map(entry => ({ label: entry.label, path: canonicalRuntimePath(entry.path) }));
  const all = [...durable, ...operational];
  const seen = new Map();
  for (const entry of all) {
    const key = comparablePath(entry.path);
    const prior = seen.get(key);
    if (prior) {
      throw new Error(
        `Runtime path collision: ${entry.label} and ${prior} both resolve to ${entry.path}. `
        + 'No runtime-control file was changed.',
      );
    }
    seen.set(key, entry.label);
  }
  for (const entry of operational) {
    const comparable = comparablePath(entry.path);
    for (const family of reservedFamilyPrefixes) {
      const prefix = comparablePath(family.prefix);
      if (comparable.startsWith(prefix)) {
        throw new Error(
          `Runtime path collision: ${entry.label} aliases the protected ${family.label} family ${family.prefix}. `
          + 'No runtime-control file was changed.',
        );
      }
    }
    for (const [directory, label] of protectedDirectories) {
      if (pathIsWithin(entry.path, directory)) {
        throw new Error(
          `Runtime path collision: ${entry.label} resolves inside the protected ${label} artifact directory ${directory}. `
          + 'No runtime-control file was changed.',
        );
      }
    }
  }
}

function validPort(value, allowDisabled = false) {
  return Number.isSafeInteger(value)
    && (allowDisabled ? value >= 0 : value >= 1)
    && value <= 65_535;
}

export function validateRuntimeProfile(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('runtime profile must be a JSON object');
  }
  if (
    value.schema_version !== 1
    || (value.mode !== 'daemon' && value.mode !== 'stdio')
    || typeof value.config_path !== 'string'
    || value.config_path.length === 0
    || (value.state_file_path !== undefined
      && (typeof value.state_file_path !== 'string' || value.state_file_path.length === 0))
    || typeof value.skills_path !== 'string'
    || value.skills_path.length === 0
    || typeof value.mcp_token_file !== 'string'
    || value.mcp_token_file.length === 0
    || (value.mcp_config_path !== undefined
      && (typeof value.mcp_config_path !== 'string' || value.mcp_config_path.length === 0))
    || (value.dashboard_token_file !== undefined
      && (typeof value.dashboard_token_file !== 'string' || value.dashboard_token_file.length === 0))
    || typeof value.http_host !== 'string'
    || value.http_host.length === 0
    || !validPort(value.http_port)
    || typeof value.dashboard_host !== 'string'
    || value.dashboard_host.length === 0
    || !validPort(value.dashboard_port, true)
    || typeof value.updated_at !== 'string'
  ) {
    throw new Error('runtime profile has an unsupported or invalid shape');
  }
  return {
    schema_version: 1,
    mode: value.mode,
    config_path: resolve(value.config_path),
    ...(value.state_file_path ? { state_file_path: resolve(value.state_file_path) } : {}),
    skills_path: resolve(value.skills_path),
    mcp_token_file: resolve(value.mcp_token_file),
    ...(value.mcp_config_path ? { mcp_config_path: resolve(value.mcp_config_path) } : {}),
    ...(value.dashboard_token_file
      ? { dashboard_token_file: resolve(value.dashboard_token_file) }
      : {}),
    http_host: value.http_host,
    http_port: value.http_port,
    dashboard_host: value.dashboard_host,
    dashboard_port: value.dashboard_port,
    updated_at: value.updated_at,
  };
}

export function readRuntimeProfile(root) {
  const path = runtimeProfilePath(root);
  if (!existsSync(path)) return null;
  try {
    return validateRuntimeProfile(JSON.parse(readFileSync(path, 'utf8')));
  } catch (error) {
    throw new Error(
      `Runtime profile ${path} is invalid: ${error instanceof Error ? error.message : String(error)}. `
      + 'Run `npm run setup` to repair local wiring; engagement artifacts will not be replaced.',
    );
  }
}

function configuredMcpToken(profile) {
  try {
    const value = JSON.parse(readFileSync(
      profile.mcp_config_path,
      'utf8',
    ))?.mcpServers?.overwatch?.headers?.Authorization;
    return typeof value === 'string' && value.startsWith('Bearer ')
      ? value.slice('Bearer '.length).trim() || undefined
      : undefined;
  } catch {
    return undefined;
  }
}

function rejectConflictingOverride(name, actual, expected, normalize = String) {
  if (actual === undefined) return;
  if (expected !== undefined && normalize(actual) === normalize(expected)) return;
  throw new Error(
    `${name} conflicts with the persisted runtime profile. `
    + 'Stop the verified owner and rerun `npm run setup` with the intended value; transient lifecycle overrides are not accepted.',
  );
}

export function runtimeEnvironment(root, baseEnvironment = process.env) {
  const profile = readRuntimeProfile(root);
  if (!profile) return { environment: { ...baseEnvironment }, profile: null };
  let mcpToken;
  if (profile.mode === 'daemon') {
    try { mcpToken = readFileSync(profile.mcp_token_file, 'utf8').trim() || undefined; } catch {}
    // Status/stop must remain usable if the token file is lost. The setup-
    // generated client entry retains the same authority and start separately
    // requires the private token file to be restored.
    mcpToken ??= configuredMcpToken(profile);
  }
  let dashboardToken;
  if (profile.dashboard_token_file) {
    try { dashboardToken = readFileSync(profile.dashboard_token_file, 'utf8').trim() || undefined; } catch {}
  }
  const pathValue = value => resolve(String(value));
  const portValue = value => String(Number(value));
  const hostValue = value => String(value).trim().toLowerCase();
  rejectConflictingOverride('OVERWATCH_CONFIG', baseEnvironment.OVERWATCH_CONFIG, profile.config_path, pathValue);
  rejectConflictingOverride('OVERWATCH_STATE_FILE', baseEnvironment.OVERWATCH_STATE_FILE, profile.state_file_path, pathValue);
  rejectConflictingOverride('OVERWATCH_SKILLS', baseEnvironment.OVERWATCH_SKILLS, profile.skills_path, pathValue);
  if (profile.mode === 'daemon') {
    rejectConflictingOverride('OVERWATCH_MCP_TOKEN_FILE', baseEnvironment.OVERWATCH_MCP_TOKEN_FILE, profile.mcp_token_file, pathValue);
    rejectConflictingOverride('OVERWATCH_MCP_TOKEN', baseEnvironment.OVERWATCH_MCP_TOKEN, mcpToken);
  }
  rejectConflictingOverride('OVERWATCH_HTTP_HOST', baseEnvironment.OVERWATCH_HTTP_HOST, profile.http_host, hostValue);
  rejectConflictingOverride('OVERWATCH_HTTP_PORT', baseEnvironment.OVERWATCH_HTTP_PORT, profile.http_port, portValue);
  rejectConflictingOverride('OVERWATCH_DASHBOARD_HOST', baseEnvironment.OVERWATCH_DASHBOARD_HOST, profile.dashboard_host, hostValue);
  rejectConflictingOverride('OVERWATCH_DASHBOARD_PORT', baseEnvironment.OVERWATCH_DASHBOARD_PORT, profile.dashboard_port, portValue);
  rejectConflictingOverride('OVERWATCH_DASHBOARD_TOKEN', baseEnvironment.OVERWATCH_DASHBOARD_TOKEN, dashboardToken);
  const environment = {
    ...baseEnvironment,
    OVERWATCH_CONFIG: profile.config_path,
    OVERWATCH_SKILLS: profile.skills_path,
    OVERWATCH_MCP_TOKEN_FILE: profile.mcp_token_file,
    ...(profile.state_file_path ? { OVERWATCH_STATE_FILE: profile.state_file_path } : {}),
    ...(mcpToken ? { OVERWATCH_MCP_TOKEN: mcpToken } : {}),
    ...(dashboardToken ? { OVERWATCH_DASHBOARD_TOKEN: dashboardToken } : {}),
    OVERWATCH_HTTP_HOST: profile.http_host,
    OVERWATCH_HTTP_PORT: String(profile.http_port),
    OVERWATCH_DASHBOARD_HOST: profile.dashboard_host,
    OVERWATCH_DASHBOARD_PORT: String(profile.dashboard_port),
  };
  if (!profile.state_file_path) delete environment.OVERWATCH_STATE_FILE;
  if (!mcpToken) delete environment.OVERWATCH_MCP_TOKEN;
  if (!dashboardToken) delete environment.OVERWATCH_DASHBOARD_TOKEN;
  return {
    profile,
    environment,
  };
}

export function writeRuntimeProfile(root, value, { dryRun = false } = {}) {
  const path = runtimeProfilePath(root);
  const profile = validateRuntimeProfile(value);
  if (dryRun) return { path, profile };
  const directory = dirname(path);
  const directoryExisted = existsSync(directory);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (!directoryExisted && process.platform !== 'win32') {
    const parentFd = openSync(dirname(directory), 'r');
    try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
  }
  const temp = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  let fd;
  try {
    fd = openSync(temp, 'wx', 0o600);
    writeFileSync(fd, `${JSON.stringify(profile, null, 2)}\n`);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    if (process.platform !== 'win32') {
      const directoryFd = openSync(directory, 'r');
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temp); } catch { /* renamed or already cleaned */ }
  }
  return { path, profile };
}
