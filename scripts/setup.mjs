#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const sourceRoot = resolve(dirname(new URL(import.meta.url).pathname), '..');
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
  --daemon            Configure Claude, dashboard, CLI, and agents to share one HTTP daemon.
  --force             Overwrite existing .mcp.json/.claude/settings.json/engagement.json
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
    daemon: false,
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
        out.daemon = true;
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

const engagementPath = join(root, 'engagement.json');
const mcpPath = join(root, '.mcp.json');
const claudeSettingsPath = join(root, '.claude', 'settings.json');
const existingEngagement = opts.daemon
  && !opts.force
  && existsSync(engagementPath)
  ? readJson(engagementPath)
  : undefined;
const engagement = existingEngagement ?? generatedEngagement;
const tokenPath = join(root, '.overwatch-mcp-token');
let daemonToken;
if (opts.daemon) {
  daemonToken = existsSync(tokenPath)
    ? readFileSync(tokenPath, 'utf8').trim()
    : randomBytes(32).toString('hex');
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

try {
  if (existingEngagement) {
    console.log('kept existing engagement.json (daemon setup never replaces engagement state)');
  } else {
    writeJson(engagementPath, engagement, opts);
  }
  writeJson(
    mcpPath,
    mcp,
    opts.daemon ? { ...opts, force: true, mode: 0o600 } : opts,
  );
  if (existsSync(claudeSettingsPath) && opts.daemon && !opts.force && !opts.dryRun) {
    console.log('kept existing .claude/settings.json');
  } else {
    writeJson(claudeSettingsPath, claudeSettings, opts);
  }
  if (opts.daemon && daemonToken) writeSecret(tokenPath, daemonToken, opts);
  const statePath = join(root, `state-${engagement.id}.json`);
  const s = engagement.scope || {};
  const scopeItems = [...(s.cidrs || []), ...(s.domains || []), ...(s.hosts || [])];
  console.log(`\n✓ engagement "${engagement.name}" (template: ${opts.template}, id: ${engagement.id})`);
  if (scopeItems.length === 0) {
    // The most common first-run confusion: setup succeeds but scope is empty, so
    // the agent/tools can't touch anything. Say so loudly + how to fix it.
    console.log(`
⚠  SCOPE IS EMPTY — this engagement can't touch anything until you add targets.
   Add scope any of these ways:
   • Re-run with flags:  npm run setup -- --template ${opts.template} --cidr 10.10.10.0/24 --domain lab.local --force
   • Edit engagement.json → "scope": { "cidrs": ["10.10.10.0/24"] }
   • Conversationally (once the session is running) — tell the model:
       "scope this engagement to 10.10.10.0/24, objective domain-admin, quiet OPSEC"
   • In the dashboard (daemon mode): the "Add Targets" or "Deploy <ip/cidr>" button`);
  } else {
    console.log(`   scope: ${scopeItems.join(', ')}`);
  }
  console.log(`
Next steps:
  npm install
  npm run build
  npm run doctor${scopeItems.length === 0 ? '        # add scope first — see above' : ''}${opts.daemon ? `
  npm run start:daemon
  # Leave that running, then open http://127.0.0.1:8384 and run claude in another terminal.` : `
  claude`}

State persists to ${statePath} unless OVERWATCH_STATE_FILE is set.`);
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
