#!/usr/bin/env node
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
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
import { basename, dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  inventoryEngagementArtifacts,
  selectRecoveryState,
  summarizeArtifacts,
  validateEngagementConfigShape,
} from './engagement-artifacts.mjs';
import {
  assertRuntimePathSeparation,
  managedDaemonLogPath,
  managedDaemonPath,
  readRuntimeProfile,
  runtimeProfilePath,
  writeRuntimeProfile,
} from './runtime-profile.mjs';
import {
  processIsAlive,
  processStartIdentity,
  processStartIdentityMatches,
} from './process-identity.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(process.env.OVERWATCH_SETUP_ROOT || sourceRoot);

function fsyncDirectory(path) {
  if (process.platform === 'win32') return;
  const fd = openSync(path, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function canonicalPath(path) {
  let candidate = resolve(path);
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

function recordProcessMayBeAlive(record) {
  if (!record || !Number.isSafeInteger(record.pid) || record.pid <= 0) return false;
  if (!processIsAlive(record.pid)) return false;
  if (typeof record.process_start_identity !== 'string') return true;
  const matches = processStartIdentityMatches(record.pid, record.process_start_identity);
  return matches === undefined || matches;
}

function acquireSetupLifecycleLock() {
  const path = join(dirname(managedDaemonPath(root)), 'lifecycle.lock.json');
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const nonce = randomBytes(32).toString('hex');
  const startIdentity = processStartIdentity(process.pid);
  if (!startIdentity) {
    throw new Error(`Setup PID ${process.pid} start identity cannot be verified; setup changed nothing.`);
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const fd = openSync(path, 'wx', 0o600);
      try {
        writeFileSync(fd, `${JSON.stringify({
          version: 1,
          pid: process.pid,
          process_start_identity: startIdentity,
          nonce,
          command: 'setup',
          acquired_at: new Date().toISOString(),
        }, null, 2)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      fsyncDirectory(dirname(path));
      const release = () => {
        if (!existsSync(path)) return;
        try {
          const current = JSON.parse(readFileSync(path, 'utf8'));
          if (current.nonce !== nonce) return;
          unlinkSync(path);
          fsyncDirectory(dirname(path));
        } catch { /* a changed or unreadable lock remains authoritative */ }
      };
      process.once('exit', release);
      return;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let current;
      try { current = JSON.parse(readFileSync(path, 'utf8')); } catch {
        throw new Error(`Lifecycle lock ${path} is unreadable; setup changed nothing.`);
      }
      const alive = processIsAlive(current.pid);
      const matches = alive && typeof current.process_start_identity === 'string'
        ? processStartIdentityMatches(current.pid, current.process_start_identity)
        : undefined;
      if (
        alive
        && (typeof current.process_start_identity !== 'string'
          || matches !== false)
      ) {
        throw new Error(
          `Lifecycle command ${current.command || 'unknown'} is active as PID ${current.pid}; setup changed nothing.`,
        );
      }
      unlinkSync(path);
      fsyncDirectory(dirname(path));
    }
  }
  throw new Error(`Could not acquire lifecycle lock ${path}; setup changed nothing.`);
}

function usage(exitCode = 0) {
  console.log(`Usage: npm run setup -- [options]

Options:
  --template <name>   Engagement template name or path (default: ctf)
  --name <name>       Engagement display name
  --id <id>           Engagement id (default: slug from name/template)
  --cidr <cidr>       Scope CIDR. Can be repeated.
  --domain <domain>   Scope domain. Can be repeated.
  --host <host>       Scope host. Can be repeated.
  --exclude <value>   Scope exclusion. Can be repeated.
  --daemon            Use the recommended shared HTTP daemon (default).
  --stdio             Configure a private Claude-only stdio process instead.
  --force             Compatibility alias; never replaces engagement or existing settings
  --dry-run           Print generated files without writing
`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const out = {
    template: 'ctf',
    cidrs: [],
    domains: [],
    hosts: [],
    exclusions: [],
    daemon: true,
    explicitMode: null,
    force: false,
    dryRun: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[++i];
      if (!value || value.startsWith('--')) {
        console.error(`Missing value for ${arg}`);
        usage(1);
      }
      return value;
    };
    switch (arg) {
      case '--help':
      case '-h':
        usage(0);
        break;
      case '--template':
        out.template = next();
        break;
      case '--name':
        out.name = next();
        break;
      case '--id':
        out.id = next();
        break;
      case '--cidr':
        out.cidrs.push(next());
        break;
      case '--domain':
        out.domains.push(next());
        break;
      case '--host':
        out.hosts.push(next());
        break;
      case '--exclude':
        out.exclusions.push(next());
        break;
      case '--daemon':
        if (out.explicitMode === 'stdio') {
          console.error('--daemon and --stdio cannot be used together');
          usage(1);
        }
        out.daemon = true;
        out.explicitMode = 'daemon';
        break;
      case '--stdio':
        if (out.explicitMode === 'daemon') {
          console.error('--daemon and --stdio cannot be used together');
          usage(1);
        }
        out.daemon = false;
        out.explicitMode = 'stdio';
        break;
      case '--force':
        out.force = true;
        break;
      case '--dry-run':
        out.dryRun = true;
        break;
      default:
        console.error(`Unknown option: ${arg}`);
        usage(1);
    }
  }
  return out;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeAtomic(path, contents, mode) {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  const temp = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  let fd;
  try {
    fd = openSync(temp, 'wx', mode || 0o600);
    writeFileSync(fd, contents);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    if (mode) chmodSync(path, mode);
    if (process.platform !== 'win32') {
      const directoryFd = openSync(directory, 'r');
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temp); } catch { /* renamed or already cleaned */ }
  }
}

function writeJson(path, value, opts) {
  const rel = path.replace(root + '/', '');
  if (existsSync(path) && !opts.force && !opts.dryRun) {
    throw new Error(`${rel} already exists. Re-run with --force to overwrite.`);
  }
  const printable = opts.dryRun && rel === '.mcp.json'
    ? JSON.parse(JSON.stringify(value, (_key, candidate) =>
        typeof candidate === 'string' && candidate.startsWith('Bearer ')
          ? 'Bearer <redacted>'
          : candidate))
    : value;
  const text = JSON.stringify(printable, null, 2) + '\n';
  if (opts.dryRun) {
    console.log(`\n--- ${rel} ---\n${text}`);
    return;
  }
  writeAtomic(path, JSON.stringify(value, null, 2) + '\n', opts.mode);
  console.log(`wrote ${rel}`);
}

function writeSecret(path, value, opts) {
  const rel = path.replace(root + '/', '');
  if (opts.dryRun) {
    console.log(`would write ${rel} (0600 secret; value hidden)`);
    return;
  }
  writeAtomic(path, value, 0o600);
  console.log(`wrote ${rel} (0600)`);
}

function mergeClaudeSettings(existing, managed) {
  const merged = { ...(existing || {}) };
  const existingHooks = existing?.hooks && typeof existing.hooks === 'object'
    ? existing.hooks
    : {};
  const managedHooks = managed?.hooks && typeof managed.hooks === 'object'
    ? managed.hooks
    : {};
  merged.hooks = { ...existingHooks };
  for (const [event, entries] of Object.entries(managedHooks)) {
    const prior = Array.isArray(existingHooks[event]) ? existingHooks[event] : [];
    const managedEntries = Array.isArray(entries) ? entries : [];
    const managedScripts = new Set(managedEntries.flatMap(entry =>
      Array.isArray(entry?.hooks)
        ? entry.hooks.map(hook => {
            const haystack = [hook?.command, ...(Array.isArray(hook?.args) ? hook.args : [])]
              .filter(value => typeof value === 'string')
              .join(' ');
            return haystack.match(/overwatch-[a-z0-9-]+\.mjs/i)?.[0];
          }).filter(Boolean)
        : []));
    const retained = [];
    for (const entry of prior) {
      if (!Array.isArray(entry?.hooks)) {
        retained.push(entry);
        continue;
      }
      const hooks = entry.hooks.filter(hook => {
        const haystack = [hook?.command, ...(Array.isArray(hook?.args) ? hook.args : [])]
          .filter(value => typeof value === 'string')
          .join(' ');
        const script = haystack.match(/overwatch-[a-z0-9-]+\.mjs/i)?.[0];
        return !script || !managedScripts.has(script);
      });
      if (hooks.length > 0) retained.push({ ...entry, hooks });
    }
    merged.hooks[event] = [...retained, ...managedEntries];
  }
  return merged;
}

function slugify(input) {
  return String(input || 'engagement')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'engagement';
}

function resolveTemplate(template) {
  const direct = resolve(process.cwd(), template);
  if (existsSync(direct)) return direct;
  const named = join(sourceRoot, 'engagement-templates', template.endsWith('.json') ? template : `${template}.json`);
  if (existsSync(named)) return named;
  throw new Error(`Template not found: ${template}`);
}

const opts = parseArgs(process.argv.slice(2));
const existingProfile = readRuntimeProfile(root);
const templatePath = resolveTemplate(opts.template);
const template = readJson(templatePath);
const name = opts.name || template.name || 'Overwatch Engagement';
const id = opts.id || slugify(name || opts.template);

const generatedEngagement = {
  ...template,
  id,
  name,
  created_at: new Date().toISOString(),
  engagement_nonce: randomBytes(32).toString('hex'),
  hash_chain_enabled: template.hash_chain_enabled ?? true,
  scope: {
    ...(template.scope || {}),
    cidrs: opts.cidrs.length > 0 ? opts.cidrs : (template.scope?.cidrs || []),
    domains: opts.domains.length > 0 ? opts.domains : (template.scope?.domains || []),
    hosts: opts.hosts.length > 0 ? opts.hosts : (template.scope?.hosts || []),
    exclusions: opts.exclusions.length > 0 ? opts.exclusions : (template.scope?.exclusions || []),
  },
};

const engagementPath = resolve(
  root,
  process.env.OVERWATCH_CONFIG || existingProfile?.config_path || 'engagement.json',
);
const explicitStatePath = process.env.OVERWATCH_STATE_FILE || existingProfile?.state_file_path;
const mcpPath = join(root, '.mcp.json');
const claudeSettingsPath = join(root, '.claude', 'settings.json');
let existingEngagement;
let existingConfigError;
if (existsSync(engagementPath)) {
  try {
    const parsed = readJson(engagementPath);
    const validation = validateEngagementConfigShape(parsed);
    if (validation.valid) existingEngagement = validation.config;
    else existingConfigError = `schema validation failed: ${validation.reason}`;
  } catch (error) {
    existingConfigError = error instanceof Error ? error.message : String(error);
  }
}
let artifactInventory;
try {
  artifactInventory = inventoryEngagementArtifacts(root, {
    configPath: engagementPath,
    explicitStateFile: explicitStatePath,
  });
} catch (error) {
  console.error(
    `Refusing setup because durable artifacts could not be inventoried: ${error instanceof Error ? error.message : String(error)}\n`
    + 'Repair directory access and retry. No setup file was changed.',
  );
  process.exit(1);
}
let setupMode = existingEngagement ? 'existing' : 'fresh';
let recoveryStatePath;
const selection = selectRecoveryState(artifactInventory, {
  activeConfig: existingEngagement,
});
if (
  existingEngagement
  && (artifactInventory.state_families.length > 0 || artifactInventory.explicit_state_file)
) {
  if (selection.status === 'selected') {
    recoveryStatePath = selection.family.state_path;
    if (selection.semantic_match !== true) setupMode = 'diverged';
  } else if (
    selection.status === 'missing_explicit'
    && existingProfile?.state_file_path === explicitStatePath
    && artifactInventory.state_families.length === 0
    && artifactInventory.artifacts.length === 0
  ) {
    // A first setup may intentionally select a not-yet-created state path.
    // Re-running setup before the first daemon write must retain that authority,
    // not reinterpret it as lost engagement data.
    recoveryStatePath = explicitStatePath;
  } else {
    const reason = selection.status === 'unmatched_config'
      ? `the active config does not match any of ${selection.families.length} preserved state families`
      : selection.status === 'ambiguous'
        ? 'more than one preserved state family matches the active config'
        : selection.status === 'missing_explicit'
          ? `OVERWATCH_STATE_FILE does not identify an existing state family: ${selection.state_path}`
          : 'preserved state artifacts do not contain a readable embedded engagement config';
    console.error(
      `Refusing setup because ${reason}.\n`
      + `Preserved artifacts: ${summarizeArtifacts(artifactInventory)}\n`
      + 'Restore the matching config or set OVERWATCH_STATE_FILE to the intended state. No files were changed.',
    );
    process.exit(1);
  }
} else if (!existingEngagement && artifactInventory.artifacts.length > 0) {
  if (selection.status === 'selected') {
    setupMode = 'recovery';
    recoveryStatePath = selection.family.state_path;
  } else {
    const reason = selection.status === 'ambiguous'
      ? 'multiple recoverable state families exist'
      : selection.status === 'missing_explicit'
        ? `OVERWATCH_STATE_FILE does not identify an existing state family: ${selection.state_path}`
        : selection.status === 'unmatched_config'
          ? 'the active config does not match any preserved state family'
        : selection.status === 'no_base'
          ? 'durable state/WAL artifacts exist without a base containing a readable engagement config'
          : 'durable engagement artifacts exist without a selectable state base';
    console.error(
      `Refusing to create engagement.json because ${reason}.\n`
      + `Preserved artifacts: ${summarizeArtifacts(artifactInventory)}\n`
      + 'Restore the matching engagement.json or set OVERWATCH_STATE_FILE to one intended state file. '
      + 'For backup-only or WAL-only recovery, restore a complete verified backup first. No files were changed.',
    );
    process.exit(1);
  }
} else if (existingConfigError) {
  console.error(
    `Refusing to replace unreadable or invalid engagement.json: ${existingConfigError}\n`
    + 'Restore or reconcile the active config; setup never overwrites operator engagement data. No files were changed.',
  );
  process.exit(1);
}
const engagement = existingEngagement ?? (setupMode === 'fresh' ? generatedEngagement : undefined);
const tokenPath = resolve(existingProfile?.mcp_token_file || join(root, '.overwatch-mcp-token'));
let daemonToken;
if (opts.daemon) {
  const environmentToken = process.env.OVERWATCH_MCP_TOKEN?.trim();
  daemonToken = environmentToken || (existsSync(tokenPath)
    ? readFileSync(tokenPath, 'utf8').trim()
    : randomBytes(32).toString('hex'));
  if (!daemonToken) daemonToken = randomBytes(32).toString('hex');
}
const existingMcp = existsSync(mcpPath)
  ? readJson(mcpPath)
  : {};
const httpPort = Number(process.env.OVERWATCH_HTTP_PORT ?? existingProfile?.http_port ?? 3000);
const httpHost = process.env.OVERWATCH_HTTP_HOST || existingProfile?.http_host || '127.0.0.1';
if (!Number.isSafeInteger(httpPort) || httpPort < 1 || httpPort > 65535) {
  throw new Error('OVERWATCH_HTTP_PORT must be an integer from 1 through 65535');
}
const dashboardPort = Number(
  process.env.OVERWATCH_DASHBOARD_PORT ?? existingProfile?.dashboard_port ?? 8384,
);
const dashboardHost = process.env.OVERWATCH_DASHBOARD_HOST
  || existingProfile?.dashboard_host
  || '127.0.0.1';
if (!Number.isSafeInteger(dashboardPort) || dashboardPort < 0 || dashboardPort > 65535) {
  throw new Error('OVERWATCH_DASHBOARD_PORT must be an integer from 0 through 65535');
}
const connectHost = host => {
  const normalized = host.trim().toLowerCase();
  if (normalized === '0.0.0.0') return '127.0.0.1';
  if (normalized === '::' || normalized === '[::]') return '[::1]';
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
};
const loopbackHost = host => ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(host.trim().toLowerCase());
const dashboardTokenPath = resolve(
  existingProfile?.dashboard_token_file || join(root, '.overwatch-dashboard-token'),
);
let dashboardToken = process.env.OVERWATCH_DASHBOARD_TOKEN?.trim();
if (!dashboardToken && existsSync(dashboardTokenPath)) {
  dashboardToken = readFileSync(dashboardTokenPath, 'utf8').trim() || undefined;
}
if (opts.daemon && dashboardPort > 0 && !loopbackHost(dashboardHost) && !dashboardToken) {
  dashboardToken = randomBytes(32).toString('hex');
}
const overwatchMcp = opts.daemon ? {
      type: 'http',
      url: `http://${connectHost(httpHost)}:${httpPort}/mcp`,
      headers: {
        Authorization: `Bearer ${daemonToken}`,
      },
    } : {
      command: 'node',
      args: [join(sourceRoot, 'scripts', 'daemon-lifecycle.mjs'), 'run-stdio'],
      env: {
        OVERWATCH_RUNTIME_PROFILE: runtimeProfilePath(root),
      },
    };
const mcp = {
  ...existingMcp,
  mcpServers: {
    ...(existingMcp.mcpServers || {}),
    overwatch: overwatchMcp,
  },
};
const claudeSettings = readJson(join(sourceRoot, '.claude', 'settings.example.json'));
let mergedClaudeSettings = claudeSettings;
if (existsSync(claudeSettingsPath)) {
  try {
    mergedClaudeSettings = mergeClaudeSettings(readJson(claudeSettingsPath), claudeSettings);
  } catch (error) {
    throw new Error(
      `Refusing partial setup because ${claudeSettingsPath} is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
const runtimeCommand = (command, selectedState) => {
  const assignments = [];
  if (engagementPath !== join(root, 'engagement.json')) {
    assignments.push(`OVERWATCH_CONFIG=${JSON.stringify(engagementPath)}`);
  }
  if (selectedState) assignments.push(`OVERWATCH_STATE_FILE=${JSON.stringify(selectedState)}`);
  return `${assignments.length > 0 ? `${assignments.join(' ')} ` : ''}${command}`;
};
const dashboardNextStep = dashboardPort > 0
  ? `# Open http://${connectHost(dashboardHost)}:${dashboardPort}`
  : '# Dashboard disabled by the persisted runtime profile; use the terminal CLI/MCP surface.';

const selectedStatePath = explicitStatePath
  || recoveryStatePath
  || (engagement ? join(dirname(engagementPath), `state-${engagement.id}.json`) : undefined);
const proposedProfile = {
  schema_version: 1,
  mode: opts.daemon ? 'daemon' : 'stdio',
  config_path: engagementPath,
  ...(selectedStatePath ? { state_file_path: selectedStatePath } : {}),
  skills_path: existingProfile?.skills_path || join(sourceRoot, 'skills'),
  mcp_token_file: tokenPath,
  mcp_config_path: mcpPath,
  ...(dashboardToken ? { dashboard_token_file: dashboardTokenPath } : {}),
  http_host: httpHost,
  http_port: httpPort,
  dashboard_host: dashboardHost,
  dashboard_port: dashboardPort,
  updated_at: new Date().toISOString(),
};

const daemonRecordPath = managedDaemonPath(root);
assertRuntimePathSeparation({
  configPath: engagementPath,
  statePath: selectedStatePath,
  operationalPaths: [
    { label: 'runtime profile', path: runtimeProfilePath(root) },
    { label: 'managed daemon record', path: daemonRecordPath },
    { label: 'managed daemon log', path: managedDaemonLogPath(root) },
    { label: 'lifecycle lock', path: join(dirname(daemonRecordPath), 'lifecycle.lock.json') },
    { label: 'MCP token', path: tokenPath },
    ...(dashboardToken ? [{ label: 'dashboard token', path: dashboardTokenPath }] : []),
    { label: 'MCP client config', path: mcpPath },
    { label: 'Claude settings', path: claudeSettingsPath },
  ],
});

if (!opts.dryRun) acquireSetupLifecycleLock();

const liveOwners = [];
for (const ownerPath of [
  managedDaemonPath(root),
  ...(selectedStatePath ? [`${canonicalPath(selectedStatePath)}.runtime-owner.json`] : []),
]) {
  if (!existsSync(ownerPath)) continue;
  let owner;
  try { owner = readJson(ownerPath); } catch {
    throw new Error(`Refusing setup because runtime owner ${ownerPath} is unreadable.`);
  }
  if (recordProcessMayBeAlive(owner)) liveOwners.push({ path: ownerPath, owner });
}

if (existingProfile) {
  const semanticProfile = profile => JSON.stringify({
    ...profile,
    updated_at: undefined,
  });
  const profileChanges = semanticProfile(existingProfile) !== semanticProfile(proposedProfile);
  const liveManagedOwner = liveOwners.find(entry => entry.path === daemonRecordPath)?.owner;
  const sha256 = value => value
    ? createHash('sha256').update(value).digest('hex')
    : undefined;
  const mcpTokenChanges = opts.daemon && liveManagedOwner
    ? typeof liveManagedOwner.mcp_token_sha256 !== 'string'
      || sha256(daemonToken) !== liveManagedOwner.mcp_token_sha256
    : opts.daemon && (!existsSync(tokenPath)
      || readFileSync(tokenPath, 'utf8').trim() !== daemonToken);
  const dashboardTokenChanges = opts.daemon && liveManagedOwner
    ? sha256(dashboardToken) !== liveManagedOwner.dashboard_token_sha256
    : opts.daemon && Boolean(dashboardToken)
      && (!existsSync(dashboardTokenPath)
        || readFileSync(dashboardTokenPath, 'utf8').trim() !== dashboardToken);
  if (liveOwners.length > 0 && (profileChanges || mcpTokenChanges || dashboardTokenChanges)) {
    throw new Error(
      `Refusing to change runtime profile or credentials while Overwatch PID ${liveOwners[0].owner.pid} is alive. `
      + 'Run `npm run daemon:stop` (or close the stdio owner), then rerun setup.',
    );
  }
} else if (liveOwners.length > 0) {
  throw new Error(
    `Refusing first-time runtime wiring while Overwatch PID ${liveOwners[0].owner.pid} already owns the selected state.`,
  );
}

try {
  if (existingEngagement) {
    console.log('kept existing engagement.json (mode switching never replaces engagement state)');
  } else if (setupMode === 'fresh') {
    writeJson(engagementPath, engagement, opts);
  } else if (existsSync(engagementPath)) {
    console.log('kept unreadable or invalid engagement.json unchanged (durable recovery state selected)');
  } else {
    console.log('kept engagement.json absent (durable recovery state detected; setup will not create a competing config)');
  }
  if (opts.daemon && daemonToken) writeSecret(tokenPath, daemonToken, opts);
  if (opts.daemon && dashboardToken) writeSecret(dashboardTokenPath, dashboardToken, opts);
  const profileResult = writeRuntimeProfile(root, proposedProfile, { dryRun: opts.dryRun });
  console.log(opts.dryRun
    ? `would write ${profileResult.path.replace(root + '/', '')} (state-preserving runtime selection)`
    : `wrote ${profileResult.path.replace(root + '/', '')}`);
  // Publish the MCP client entry only after the token and runtime selection it
  // references are durable. A setup interruption therefore never advertises
  // wiring that a later plain daemon start cannot reproduce.
  writeJson(
    mcpPath,
    mcp,
    { ...opts, force: true, mode: 0o600 },
  );
  const settingsUnchanged = existsSync(claudeSettingsPath)
    && JSON.stringify(readJson(claudeSettingsPath)) === JSON.stringify(mergedClaudeSettings);
  if (settingsUnchanged && !opts.dryRun) console.log('kept existing .claude/settings.json');
  else writeJson(claudeSettingsPath, mergedClaudeSettings, { ...opts, force: true });
  if (setupMode === 'recovery' || setupMode === 'diverged') {
    const selected = explicitStatePath || recoveryStatePath;
    const authorityWarning = selection.base_config_status !== 'consistent'
      ? `
⚠ retained bases do not establish one configuration authority (${selection.base_config_status})
  startup will remain recovery/read-only until the daemon validates the base and configuration is reconciled`
      : '';
    const configStatus = setupMode === 'diverged'
      ? selection.semantic_match === 'unknown'
        ? 'the active config and every retained recovery base were preserved without assuming which base is authoritative'
        : 'the active config and durable state have different semantics and were both preserved'
      : existsSync(engagementPath)
        ? 'the unreadable or invalid engagement.json was preserved byte-for-byte'
        : 'engagement.json remains absent';
    console.log(`
✓ recovery wiring configured for preserved state ${selected}${authorityWarning}
  ${configStatus}; the daemon will start read-only until you inspect and reconcile configuration.

Next steps:
  ${runtimeCommand('npm run daemon:start', selected)}
  ${runtimeCommand('npm run doctor', selected)}
  ${dashboardNextStep}${dashboardPort > 0 ? ', inspect Recovery, then choose the durable-state reconciliation path.' : ''}

No state, WAL, snapshot, backup, evidence, report, or tape artifact was modified.`);
  } else {
    const statePath = recoveryStatePath
      || join(dirname(engagementPath), `state-${engagement.id}.json`);
    const s = engagement.scope || {};
    const scopeItems = [...(s.cidrs || []), ...(s.domains || []), ...(s.hosts || [])];
    console.log(`\n✓ engagement "${engagement.name}" (template: ${opts.template}, id: ${engagement.id})`);
    if (scopeItems.length === 0) {
      // The most common first-run confusion: setup succeeds but scope is empty, so
      // the agent/tools can't touch anything. Say so loudly + how to fix it.
      console.log(`
⚠  SCOPE IS EMPTY — this engagement can't touch anything until you add targets.
   Preserve engagement.json and durable state. Add scope through a live surface:
   • Conversationally — tell terminal Claude:
       "scope this engagement to 10.10.10.0/24, objective domain-admin, quiet OPSEC"
   • In the dashboard: use "Add Targets" or "Deploy <ip/cidr>"
   Setup does not rewrite active engagement scope; the live update is journaled.`);
    } else {
      console.log(`   scope: ${scopeItems.join(', ')}`);
    }
    console.log(`
Next steps:
  ${opts.daemon ? `${runtimeCommand('npm run daemon:start', explicitStatePath || recoveryStatePath)}
  ${runtimeCommand('npm run doctor', explicitStatePath || recoveryStatePath)}${scopeItems.length === 0 ? '        # safe to start; add scope after launch' : ''}
  ${dashboardNextStep} and run claude in this or another terminal.` : `
  claude`}

State persists to ${statePath} unless OVERWATCH_STATE_FILE is set.`);
  }
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
