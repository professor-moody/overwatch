#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  inventoryEngagementArtifacts,
  selectRecoveryState,
  summarizeArtifacts,
  validateEngagementConfigShape,
} from './engagement-artifacts.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(process.env.OVERWATCH_SETUP_ROOT || sourceRoot);

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
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {
    ...(opts.mode ? { mode: opts.mode } : {}),
  });
  if (opts.mode) chmodSync(path, opts.mode);
  console.log(`wrote ${rel}`);
}

function writeSecret(path, value, opts) {
  const rel = path.replace(root + '/', '');
  if (opts.dryRun) {
    console.log(`would write ${rel} (0600 secret; value hidden)`);
    return;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, value, { mode: 0o600 });
  chmodSync(path, 0o600);
  console.log(`wrote ${rel} (0600)`);
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

const engagementPath = resolve(root, process.env.OVERWATCH_CONFIG || 'engagement.json');
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
    explicitStateFile: process.env.OVERWATCH_STATE_FILE,
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
const tokenPath = join(root, '.overwatch-mcp-token');
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
const httpPort = Number(process.env.OVERWATCH_HTTP_PORT || '3000');
if (!Number.isSafeInteger(httpPort) || httpPort < 1 || httpPort > 65535) {
  throw new Error('OVERWATCH_HTTP_PORT must be an integer from 1 through 65535');
}
const overwatchMcp = opts.daemon ? {
      type: 'http',
      url: `http://127.0.0.1:${httpPort}/mcp`,
      headers: {
        Authorization: `Bearer ${daemonToken}`,
      },
    } : {
      command: 'node',
      args: [join(root, 'dist', 'index.js')],
      env: {
        OVERWATCH_CONFIG: engagementPath,
        OVERWATCH_SKILLS: join(root, 'skills'),
        ...((process.env.OVERWATCH_STATE_FILE || recoveryStatePath)
          ? { OVERWATCH_STATE_FILE: process.env.OVERWATCH_STATE_FILE || recoveryStatePath }
          : {}),
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
const runtimeCommand = (command, selectedState) => {
  const assignments = [];
  if (engagementPath !== join(root, 'engagement.json')) {
    assignments.push(`OVERWATCH_CONFIG=${JSON.stringify(engagementPath)}`);
  }
  if (selectedState) assignments.push(`OVERWATCH_STATE_FILE=${JSON.stringify(selectedState)}`);
  return `${assignments.length > 0 ? `${assignments.join(' ')} ` : ''}${command}`;
};

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
  writeJson(
    mcpPath,
    mcp,
    { ...opts, force: true, mode: 0o600 },
  );
  if (existsSync(claudeSettingsPath) && !opts.dryRun) {
    console.log('kept existing .claude/settings.json');
  } else {
    writeJson(claudeSettingsPath, claudeSettings, opts);
  }
  if (opts.daemon && daemonToken) writeSecret(tokenPath, daemonToken, opts);
  if (setupMode === 'recovery' || setupMode === 'diverged') {
    const selected = process.env.OVERWATCH_STATE_FILE || recoveryStatePath;
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
  npm install
  npm run build
  ${runtimeCommand('npm run doctor', selected)}
  ${runtimeCommand('npm run start:daemon', selected)}
  # Open http://127.0.0.1:8384, inspect Recovery, then choose the durable-state reconciliation path.

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
  npm install
  npm run build
  ${runtimeCommand('npm run doctor', process.env.OVERWATCH_STATE_FILE || recoveryStatePath)}${scopeItems.length === 0 ? '        # safe to start; add scope after launch' : ''}${opts.daemon ? `
  ${runtimeCommand('npm run start:daemon', process.env.OVERWATCH_STATE_FILE || recoveryStatePath)}
  # Leave that running, then open http://127.0.0.1:8384 and run claude in another terminal.` : `
  claude`}

State persists to ${statePath} unless OVERWATCH_STATE_FILE is set.`);
  }
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
