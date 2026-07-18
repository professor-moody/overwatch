import { readFileSync, readdirSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

async function loadEngagementConfigSchema() {
  let sourceError;
  const previousNoDeprecation = process.noDeprecation;
  try {
    process.noDeprecation = true;
    const { tsImport } = await import('tsx/esm/api');
    const sourceTypes = await tsImport('../src/types.ts', import.meta.url);
    if (sourceTypes.engagementConfigSchema) return sourceTypes.engagementConfigSchema;
  } catch (error) {
    sourceError = error;
  } finally {
    process.noDeprecation = previousNoDeprecation;
  }
  try {
    const compiledTypes = await import('../dist/types.js');
    if (compiledTypes.engagementConfigSchema) return compiledTypes.engagementConfigSchema;
  } catch (compiledError) {
    throw new Error(
      'The authoritative engagement validator could not be loaded. Run npm install (source checkout) or npm run build.',
      { cause: new AggregateError([sourceError, compiledError].filter(Boolean)) },
    );
  }
  throw new Error('The authoritative engagement validator is unavailable.');
}

const engagementConfigSchema = await loadEngagementConfigSchema();

async function loadPersistedStateBaseInspector() {
  let sourceError;
  const previousNoDeprecation = process.noDeprecation;
  try {
    process.noDeprecation = true;
    const { tsImport } = await import('tsx/esm/api');
    const sourceModule = await tsImport('../src/services/state-migration.ts', import.meta.url);
    if (sourceModule.inspectPersistedStateRecoveryBase) {
      return sourceModule.inspectPersistedStateRecoveryBase;
    }
  } catch (error) {
    sourceError = error;
  } finally {
    process.noDeprecation = previousNoDeprecation;
  }
  try {
    const compiledModule = await import('../dist/services/state-migration.js');
    if (compiledModule.inspectPersistedStateRecoveryBase) {
      return compiledModule.inspectPersistedStateRecoveryBase;
    }
  } catch (compiledError) {
    throw new Error(
      'The authoritative persisted-state validator could not be loaded. Run npm install (source checkout) or npm run build.',
      { cause: new AggregateError([sourceError, compiledError].filter(Boolean)) },
    );
  }
  throw new Error('The authoritative persisted-state validator is unavailable.');
}

const inspectPersistedStateRecoveryBase = await loadPersistedStateBaseInspector();

const DURABLE_DIRECTORIES = [
  '.migration-backups',
  'engagements',
  'evidence',
  'reports',
  'tapes',
];

function entries(path) {
  try {
    return readdirSync(path, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

function stateFamilyFromName(name) {
  // Process-lifetime ownership is operational metadata, not a recoverable
  // state base. Its filename deliberately follows the selected state path but
  // must never create a phantom state family during setup/doctor inventory.
  if (/\.runtime-owner\.json$/.test(name)) return undefined;
  const patterns = [
    /^(state-.+)\.snap-.+\.json$/,
    /^(state-.+)\.journal\.jsonl(?:\..+)?$/,
    /^(state-.+)\.json\.(?:rollback-intent|migration-intent)\.json$/,
    /^(state-.+)\.json\.(?:writer-lock|migration-lock)$/,
    /^(state-.+)\.json\.tmp(?:-.+)?$/,
    /^(state-.+)\.json$/,
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(name);
    if (match) return match[1];
  }
  return undefined;
}

function stateArtifactKind(name, nestedSnapshot = false) {
  if (nestedSnapshot || /\.snap-.+\.json$/.test(name)) return 'snapshot';
  if (/\.journal\.jsonl\.quarantine-/.test(name)) return 'wal_quarantine';
  if (/\.journal\.jsonl(?:\..+)?$/.test(name)) return 'wal';
  if (/\.rollback-intent\.json$/.test(name)) return 'rollback_intent';
  if (/\.migration-intent\.json$/.test(name)) return 'migration_intent';
  if (/\.writer-lock$/.test(name)) return 'writer_lock';
  if (/\.migration-lock$/.test(name)) return 'migration_lock';
  if (/\.json\.tmp(?:-.+)?$/.test(name)) return 'state_temp';
  return 'state';
}

function configRecoveryKind(name, configName) {
  const intent = `${configName}.write-intent.json`;
  if (name === intent) return 'config_write_intent';
  if (name.startsWith(`${intent}.conflict-`)) return 'config_intent_conflict';
  if (name.startsWith(`${intent}.overwatch-`)) return 'config_intent_temp';
  if (name.startsWith(`${intent}.tmp-`)) return 'config_intent_temp';
  if (name.startsWith(`${configName}.overwatch-`)) return 'config_temp';
  if (name.startsWith(`${configName}.tmp-`)) return 'config_temp';
  return undefined;
}

export function validateEngagementConfigShape(config) {
  const result = engagementConfigSchema.safeParse(config);
  if (result.success) return { valid: true, config: result.data };
  const reason = result.error.issues
    .map(issue => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
    .join('; ');
  return { valid: false, reason };
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function semanticConfig(config) {
  const parsed = engagementConfigSchema.safeParse(config);
  const normalized = parsed.success ? parsed.data : config;
  const { config_revision: _revision, config_hash: _hash, ...semantic } = normalized;
  return semantic;
}

export function configurationSemanticsEqual(left, right) {
  return canonical(semanticConfig(left)) === canonical(semanticConfig(right));
}

function readBaseInspection(path) {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8'));
    const rollback_marker = Boolean(
      value
      && typeof value === 'object'
      && !Array.isArray(value)
      && Object.prototype.hasOwnProperty.call(value, 'rollbackIntent'),
    );
    try {
      const validated = inspectPersistedStateRecoveryBase(path, 'state', 0);
      return {
        config: validated.config,
        state_version: validated.stateVersion,
        rollback_marker,
      };
    } catch {
      return { rollback_marker };
    }
  } catch {
    return { rollback_marker: false };
  }
}

function pushStateArtifact(
  artifacts,
  families,
  directory,
  entry,
  nestedSnapshot = false,
  forcedFamily,
  stateDirectory = directory,
) {
  const family = forcedFamily ?? stateFamilyFromName(entry.name);
  if (!family) return;
  const path = resolve(directory, entry.name);
  const statePath = resolve(stateDirectory, `${family}.json`);
  const kind = stateArtifactKind(entry.name, nestedSnapshot);
  artifacts.push({ kind, path, state_path: statePath });
  const current = families.get(statePath) ?? {
    state_path: statePath,
    artifacts: [],
    base_paths: [],
    has_primary: false,
    has_snapshot: false,
    has_wal: false,
    has_rollback_intent: false,
    has_embedded_config: false,
    embedded_configs: [],
  };
  current.artifacts.push(path);
  if (kind === 'state') current.has_primary = true;
  if (kind === 'snapshot') current.has_snapshot = true;
  if ((kind === 'state' || kind === 'snapshot') && !current.base_paths.includes(path)) {
    current.base_paths.push(path);
  }
  if (kind === 'rollback_intent') current.has_rollback_intent = true;
  if (kind === 'state' || kind === 'snapshot') {
    const inspection = readBaseInspection(path);
    if (inspection.rollback_marker) current.has_rollback_intent = true;
    const config = inspection.config;
    if (config) {
      current.has_embedded_config = true;
      if (!current.embedded_configs.some(candidate => candidate.path === path)) {
        current.embedded_configs.push({
          path,
          kind,
          config,
          state_version: inspection.state_version,
        });
      }
    }
  }
  if (kind === 'wal' || kind === 'wal_quarantine') current.has_wal = true;
  families.set(statePath, current);
}

function scanExplicitStateFile(stateFilePath, artifacts, families) {
  const absoluteStatePath = resolve(stateFilePath);
  const directory = dirname(absoluteStatePath);
  const fileName = basename(absoluteStatePath);
  const family = fileName.endsWith('.json') ? fileName.slice(0, -'.json'.length) : fileName;
  const matches = name => (
    name === fileName
    || name.startsWith(`${family}.snap-`)
    || name.startsWith(`${family}.journal.jsonl`)
    || name.startsWith(`${fileName}.rollback-intent.json`)
    || name.startsWith(`${fileName}.migration-intent.json`)
    || name.startsWith(`${fileName}.writer-lock`)
    || name.startsWith(`${fileName}.migration-lock`)
    || name.startsWith(`${fileName}.tmp`)
  );
  for (const entry of entries(directory)) {
    if (matches(entry.name)) {
      pushStateArtifact(artifacts, families, directory, entry, false, family);
    }
  }
  const snapshotDirectory = join(directory, '.snapshots');
  for (const entry of entries(snapshotDirectory)) {
    if (entry.name.startsWith(`${family}.snap-`)) {
      pushStateArtifact(artifacts, families, snapshotDirectory, entry, true, family, directory);
    }
  }
}

function scanStateDirectory(directory, configName, artifacts, families) {
  for (const entry of entries(directory)) {
    const recoveryKind = configRecoveryKind(entry.name, configName);
    if (recoveryKind) {
      artifacts.push({ kind: recoveryKind, path: resolve(directory, entry.name) });
      continue;
    }
    pushStateArtifact(artifacts, families, directory, entry);
  }
  const snapshotDirectory = join(directory, '.snapshots');
  for (const entry of entries(snapshotDirectory)) {
    pushStateArtifact(artifacts, families, snapshotDirectory, entry, true, undefined, directory);
  }
}

/** Conservative, read-only inventory used before setup or doctor may suggest
 * creating configuration. Any unreadable directory throws so callers fail
 * closed instead of treating an incomplete inventory as a fresh workspace. */
export function inventoryEngagementArtifacts(root, options = {}) {
  const absoluteRoot = resolve(root);
  const configPath = options.configPath
    ? resolve(absoluteRoot, options.configPath)
    : join(absoluteRoot, 'engagement.json');
  const engagementDirectory = dirname(configPath);
  const artifacts = [];
  const families = new Map();
  scanStateDirectory(engagementDirectory, basename(configPath), artifacts, families);

  const explicitState = options.explicitStateFile
    ? resolve(absoluteRoot, options.explicitStateFile)
    : undefined;
  if (explicitState) scanExplicitStateFile(explicitState, artifacts, families);

  for (const name of DURABLE_DIRECTORIES) {
    const path = join(engagementDirectory, name);
    if (entries(path).length > 0) artifacts.push({ kind: 'durable_directory', path: resolve(path) });
  }

  const uniqueArtifacts = [...new Map(
    artifacts.map(artifact => [`${artifact.kind}:${artifact.path}`, artifact]),
  ).values()].sort((left, right) => left.path.localeCompare(right.path));
  const stateFamilies = [...families.values()]
    .map(family => ({
      ...family,
      artifacts: [...new Set(family.artifacts)].sort(),
      base_paths: [...new Set(family.base_paths)].sort(),
      embedded_configs: [...family.embedded_configs].sort((left, right) => {
        const leftPrimary = left.path === family.state_path;
        const rightPrimary = right.path === family.state_path;
        if (leftPrimary !== rightPrimary) return leftPrimary ? -1 : 1;
        const leftNested = basename(dirname(left.path)) === '.snapshots';
        const rightNested = basename(dirname(right.path)) === '.snapshots';
        if (leftNested !== rightNested) return leftNested ? -1 : 1;
        return right.path.localeCompare(left.path);
      }),
    }))
    .map(family => {
      const allBasesExposeConfig = family.base_paths.length === family.embedded_configs.length;
      const semanticsAgree = family.embedded_configs.length > 0
        && family.embedded_configs.every(candidate =>
          configurationSemanticsEqual(candidate.config, family.embedded_configs[0].config));
      const legacyBasePresent = family.embedded_configs.some(candidate =>
        candidate.state_version === 0);
      const base_config_status = family.has_rollback_intent
        ? 'rollback_pending'
        : !allBasesExposeConfig
          ? 'incomplete'
          : legacyBasePresent
            ? 'legacy_unverified'
            : semanticsAgree
              ? 'consistent'
              : 'conflicting';
      return {
        ...family,
        base_config_status,
        ...(base_config_status === 'consistent'
          ? { effective_config: family.embedded_configs[0] }
          : {}),
      };
    })
    .sort((left, right) => left.state_path.localeCompare(right.state_path));
  return {
    root: absoluteRoot,
    config_path: configPath,
    explicit_state_file: explicitState,
    artifacts: uniqueArtifacts,
    state_families: stateFamilies,
  };
}

export function selectRecoveryState(inventory, options = {}) {
  const selectionFor = (family, via) => ({
    status: 'selected',
    family,
    via,
    base_config_status: family.base_config_status,
    ...(options.activeConfig
      ? (() => {
          const unanimousConfig = family.embedded_configs.length > 0
            && family.embedded_configs.every(candidate =>
              configurationSemanticsEqual(candidate.config, family.embedded_configs[0].config));
          const matchesUnanimous = unanimousConfig
            ? configurationSemanticsEqual(options.activeConfig, family.embedded_configs[0].config)
            : undefined;
          return {
            semantic_match: family.base_config_status === 'consistent'
              ? matchesUnanimous
              : matchesUnanimous === false
                ? false
                : 'unknown',
          };
        })()
      : {}),
  });
  const familiesWithConfig = inventory.state_families.filter(family =>
    family.has_embedded_config);
  if (inventory.explicit_state_file) {
    const selected = inventory.state_families.find(family =>
      family.state_path === inventory.explicit_state_file);
    return selected
      ? selected.has_embedded_config
        ? selectionFor(selected, 'environment')
        : { status: 'no_base', family: selected, via: 'environment' }
      : { status: 'missing_explicit', state_path: inventory.explicit_state_file, via: 'environment' };
  }
  if (options.activeConfig) {
    // Match a family against every readable retained base. StatePersistence
    // chooses the authoritative base only after full validation, checkpoint
    // ranking, and pending-rollback recovery; setup/doctor must not pretend the
    // primary file is authoritative merely because it is present.
    const idMatches = familiesWithConfig.filter(family =>
      family.embedded_configs.some(candidate => candidate.config.id === options.activeConfig.id));
    if (idMatches.length === 1) return selectionFor(idMatches[0], 'config_id');
    if (idMatches.length > 1) return { status: 'ambiguous', families: idMatches, reason: 'config_id' };
    const identityMatches = familiesWithConfig.filter(family =>
      family.embedded_configs.some(candidate =>
        candidate.config.created_at === options.activeConfig.created_at
        && candidate.config.engagement_nonce === options.activeConfig.engagement_nonce));
    if (identityMatches.length === 1) return selectionFor(identityMatches[0], 'config_identity');
    if (identityMatches.length > 1) return { status: 'ambiguous', families: identityMatches, reason: 'config_identity' };
    if (familiesWithConfig.length > 0) return { status: 'unmatched_config', families: familiesWithConfig };
  }
  if (familiesWithConfig.length === 1) return selectionFor(familiesWithConfig[0], 'unique_family');
  if (familiesWithConfig.length > 1) return { status: 'ambiguous', families: familiesWithConfig };
  if (inventory.state_families.length > 0) {
    return { status: 'no_base', families: inventory.state_families };
  }
  return { status: 'none' };
}

export function summarizeArtifacts(inventory, limit = 8) {
  const paths = inventory.artifacts.map(artifact => artifact.path);
  const shown = paths.slice(0, limit);
  return `${shown.join(', ')}${paths.length > shown.length ? ` (+${paths.length - shown.length} more)` : ''}`;
}
