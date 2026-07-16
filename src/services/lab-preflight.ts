import { accessSync, constants, existsSync, readFileSync } from 'fs';
import { dirname } from 'path';
import { engagementConfigSchema, inferProfile } from '../types.js';
import type {
  ConfigRecoveryStatus,
  ExportedGraph,
  HealthReport,
  LabPreflightReport,
  LabProfile,
  LabReadinessCheck,
  LabReadinessStatus,
  LabReadinessSummary,
  PersistenceRecoveryStatus,
} from '../types.js';
import type { GraphEngine } from './graph-engine.js';
import { contextualFilterHealthReport } from './graph-health.js';
import type { ToolStatus } from './tool-check.js';

type DashboardStatus = {
  enabled: boolean;
  running: boolean;
  address?: string;
};

type LabPreflightOptions = {
  profile?: LabProfile;
  dashboard?: DashboardStatus;
  toolStatuses?: ToolStatus[];
};

type SyncReadinessInputs = {
  config: ReturnType<GraphEngine['getConfig']>;
  graph: ExportedGraph;
  health: HealthReport;
};

const DEFAULT_DASHBOARD_STATUS: DashboardStatus = {
  enabled: false,
  running: false,
};

const SEED_NODE_TYPES = new Set(['host', 'domain', 'objective', 'subnet']);

export function summarizeInlineLabReadiness(engine: GraphEngine): LabReadinessSummary {
  const inputs = getSyncReadinessInputs(engine);
  const profile = inferProfile(inputs.config);
  const adContext = engine.checkADContext();
  const filteredHealth = contextualFilterHealthReport(inputs.health, profile, adContext);
  const recovery = engine.getPersistenceRecoveryStatus();
  const issues = buildInlineIssues({ ...inputs, health: filteredHealth }, profile, recovery);
  return {
    status: deriveStatusFromIssues(issues),
    top_issues: issues.slice(0, 3),
  };
}

export function runLabPreflight(engine: GraphEngine, options: LabPreflightOptions = {}): LabPreflightReport {
  const config = engine.getConfig();
  const profile = options.profile || inferProfile(config);
  const dashboard = options.dashboard || DEFAULT_DASHBOARD_STATUS;
  const graph = engine.exportGraph();
  const rawHealth = engine.getHealthReport();
  const adContext = engine.checkADContext();
  const health = contextualFilterHealthReport(rawHealth, profile, adContext);
  const graphStage = determineGraphStage(graph);

  const checks: LabReadinessCheck[] = [];
  const missingRequiredTools: string[] = [];
  const warnings: string[] = [];
  const recommendedNextSteps: string[] = [];
  const toolStatuses = options.toolStatuses || [];

  const configParse = engagementConfigSchema.safeParse(config);
  checks.push(configParse.success
    ? { name: 'config_validation', status: 'pass', message: 'Engagement config is valid.' }
    : { name: 'config_validation', status: 'fail', message: 'Engagement config failed schema validation.' });

  if (profile === 'goad_ad') {
    const hasDomainScope = config.scope.domains.length > 0;
    checks.push(hasDomainScope
      ? { name: 'domain_scope', status: 'pass', message: 'Domain-aware scope is configured.', details: { domains: config.scope.domains } }
      : { name: 'domain_scope', status: 'fail', message: 'GOAD profile requires at least one scoped domain.' });
  } else if (profile === 'network') {
    const hasCidrScope = config.scope.cidrs.length > 0;
    checks.push(hasCidrScope
      ? { name: 'scope_shape', status: 'pass', message: 'Network CIDR scope is configured.', details: { cidrs: config.scope.cidrs } }
      : { name: 'scope_shape', status: 'warning', message: 'Network profile has no CIDR scope yet.' });
  } else if (profile === 'web_app') {
    const hasUrlScope = (config.scope.url_patterns?.length || 0) > 0;
    checks.push(hasUrlScope
      ? { name: 'scope_shape', status: 'pass', message: 'URL scope patterns are configured.', details: { url_patterns: config.scope.url_patterns } }
      : { name: 'scope_shape', status: 'warning', message: 'Web app profile has no url_patterns in scope yet.' });
  } else if (profile === 'cloud') {
    const hasCloudScope = (config.scope.aws_accounts?.length || 0) > 0
      || (config.scope.azure_subscriptions?.length || 0) > 0
      || (config.scope.gcp_projects?.length || 0) > 0;
    checks.push(hasCloudScope
      ? { name: 'scope_shape', status: 'pass', message: 'Cloud account scope is configured.' }
      : { name: 'scope_shape', status: 'warning', message: 'Cloud profile has no cloud accounts/subscriptions/projects in scope yet.' });
  } else if (profile === 'hybrid') {
    const hasDomainScope = config.scope.domains.length > 0;
    const hasCloudScope = (config.scope.aws_accounts?.length || 0) > 0
      || (config.scope.azure_subscriptions?.length || 0) > 0
      || (config.scope.gcp_projects?.length || 0) > 0;
    checks.push(hasDomainScope && hasCloudScope
      ? { name: 'scope_shape', status: 'pass', message: 'Hybrid scope covers both AD domains and cloud accounts.' }
      : { name: 'scope_shape', status: 'warning', message: `Hybrid profile is missing ${!hasDomainScope ? 'domain' : ''}${!hasDomainScope && !hasCloudScope ? ' and ' : ''}${!hasCloudScope ? 'cloud account' : ''} scope.` });
  } else {
    checks.push({
      name: 'scope_shape',
      status: config.scope.cidrs.length > 0 || (config.scope.hosts?.length || 0) > 0
        ? 'pass'
        : 'warning',
      message: config.scope.cidrs.length > 0 || (config.scope.hosts?.length || 0) > 0
        ? 'Single-host scope is configured.'
        : 'Single-host profile has no explicit host or CIDR scope yet.',
    });
  }

  const toolCheck = evaluateToolReadiness(profile, toolStatuses);
  checks.push(...toolCheck.checks);
  missingRequiredTools.push(...toolCheck.missingRequiredTools);
  warnings.push(...toolCheck.warnings);
  recommendedNextSteps.push(...toolCheck.recommendedNextSteps);

  checks.push({
    name: 'graph_health',
    status: health.counts_by_severity.critical > 0 ? 'fail' : health.counts_by_severity.warning > 0 ? 'warning' : 'pass',
    message: health.counts_by_severity.critical > 0
      ? `${health.counts_by_severity.critical} critical graph health issue(s) detected.`
      : health.counts_by_severity.warning > 0
        ? `${health.counts_by_severity.warning} graph health warning(s) detected.`
        : 'Graph health checks are clean.',
    details: {
      counts_by_severity: health.counts_by_severity,
      top_issues: health.issues.slice(0, 5),
    },
  });

  const persistenceCheck = evaluatePersistence(engine);
  checks.push(persistenceCheck);
  checks.push(evaluateConfigConsistency(engine));

  const processCheck = evaluateProcessTracker(engine);
  checks.push(processCheck);

  checks.push(evaluateDashboard(dashboard));

  checks.push({
    name: 'graph_stage',
    status: 'pass',
    message: graphStage === 'empty'
      ? 'Graph is empty but valid for a first run.'
      : graphStage === 'seeded'
        ? 'Graph is seeded from config and ready for first ingest.'
        : 'Graph already contains operational findings.',
    details: {
      stage: graphStage,
      nodes: graph.nodes.length,
      edges: graph.edges.length,
    },
  });

  warnings.push(...health.issues
    .filter(issue => issue.severity === 'warning')
    .slice(0, 5)
    .map(issue => issue.message));

  if (health.counts_by_severity.critical > 0) {
    recommendedNextSteps.push('Resolve critical graph health issues before starting the lab workflow.');
  }

  if (graphStage === 'empty' || graphStage === 'seeded') {
    if (profile === 'goad_ad') {
      recommendedNextSteps.push('Seed the graph with BloodHound, then parse Nmap and NXC output for the same hosts.');
    } else if (profile === 'network') {
      recommendedNextSteps.push('Start with an Nmap sweep of the CIDR scope, then parse results. AD domains will be detected automatically if present.');
    } else {
      recommendedNextSteps.push('Parse an Nmap scan and report at least one manual or parsed finding before relying on frontier output.');
    }
  }

  if (profile === 'goad_ad' && !toolCheck.hasRecommendedCredentialWorkflow) {
    recommendedNextSteps.push('Install at least one credential workflow tool such as impacket, hashcat, or john for richer GOAD testing.');
  }

  const status = deriveStatusFromChecks(checks, missingRequiredTools.length > 0);

  return {
    profile,
    status,
    graph_stage: graphStage,
    checks,
    missing_required_tools: [...new Set(missingRequiredTools)],
    warnings: [...new Set(warnings)].slice(0, 10),
    recommended_next_steps: [...new Set(recommendedNextSteps)],
    dashboard,
  };
}

function getSyncReadinessInputs(engine: GraphEngine): SyncReadinessInputs {
  return {
    config: engine.getConfig(),
    graph: engine.exportGraph(),
    health: engine.getHealthReport(),
  };
}

function buildInlineIssues(
  inputs: SyncReadinessInputs,
  profile: LabProfile,
  recovery: PersistenceRecoveryStatus | undefined,
): string[] {
  const issues: string[] = [];
  const graphStage = determineGraphStage(inputs.graph);
  const recoveryAssessment = recovery ? assessPersistenceRecovery(recovery) : undefined;
  const configAssessment = recovery?.config_recovery
    ? assessConfigRecovery(recovery.config_recovery)
    : undefined;

  if (configAssessment?.status === 'fail') {
    issues.push(`[CRITICAL] ${configAssessment.message}`);
  } else if (configAssessment?.status === 'warning') {
    issues.push(configAssessment.message);
  }

  // A config-only gate is already reported above with the actionable reason.
  // Avoid replacing it with the combined status' less-specific persistence
  // message in the compact get_state briefing.
  if (recoveryAssessment?.status === 'fail' && configAssessment?.status !== 'fail') {
    issues.push(`[CRITICAL] ${recoveryAssessment.message}`);
  } else if (recoveryAssessment?.status === 'fail' && recovery?.persistence_reason) {
    issues.push(`[CRITICAL] Persistence recovery is incomplete: ${recovery.persistence_reason}`);
  } else if (recoveryAssessment?.status === 'warning' && configAssessment?.status !== 'warning') {
    issues.push(recoveryAssessment.message);
  }

  if (inputs.health.counts_by_severity.critical > 0) {
    issues.push(`[CRITICAL] ${inputs.health.counts_by_severity.critical} graph health issue(s) need attention.`);
  } else if (inputs.health.counts_by_severity.warning > 0) {
    issues.push(`${inputs.health.counts_by_severity.warning} graph health warning(s) are present.`);
  }

  if (profile === 'goad_ad' && inputs.config.scope.domains.length === 0) {
    issues.push('No scoped domains are configured, so GOAD-style AD workflows will be limited.');
  }

  if (graphStage === 'empty') {
    issues.push('Graph is empty; start with BloodHound, Nmap, or a first reported finding.');
  } else if (graphStage === 'seeded') {
    issues.push('Graph is seeded from config only; ingest real lab data before relying on frontier depth.');
  }

  return issues;
}

function deriveStatusFromIssues(issues: string[]): LabReadinessStatus {
  if (issues.some(issue => issue.startsWith('[CRITICAL]'))) return 'blocked';
  return issues.length > 0 ? 'warning' : 'ready';
}

function deriveStatusFromChecks(checks: LabReadinessCheck[], hasMissingRequiredTools: boolean): LabReadinessStatus {
  if (hasMissingRequiredTools || checks.some(check => check.status === 'fail')) return 'blocked';
  return checks.some(check => check.status === 'warning') ? 'warning' : 'ready';
}

function determineGraphStage(graph: ExportedGraph): 'empty' | 'seeded' | 'mid_run' {
  if (graph.nodes.length === 0) return 'empty';

  const hasOnlySeedNodes = graph.nodes.every(node => SEED_NODE_TYPES.has(node.properties.type));
  if (hasOnlySeedNodes && graph.edges.length === 0) return 'seeded';

  return 'mid_run';
}

function evaluateToolReadiness(profile: LabProfile, toolStatuses: ToolStatus[]): {
  checks: LabReadinessCheck[];
  missingRequiredTools: string[];
  warnings: string[];
  recommendedNextSteps: string[];
  hasRecommendedCredentialWorkflow: boolean;
} {
  const checks: LabReadinessCheck[] = [];
  const missingRequiredTools: string[] = [];
  const warnings: string[] = [];
  const recommendedNextSteps: string[] = [];

  const installed = new Set(toolStatuses.filter(tool => tool.installed).map(tool => tool.name));

  const requireOne = (names: string[], label: string, message: string): void => {
    if (!names.some(name => installed.has(name))) {
      missingRequiredTools.push(label);
      checks.push({ name: `tool_${label}`, status: 'fail', message });
    } else {
      checks.push({ name: `tool_${label}`, status: 'pass', message: `${label} tooling is available.` });
    }
  };

  const requireSingle = (name: string, label: string = name): void => {
    if (!installed.has(name)) {
      missingRequiredTools.push(label);
      checks.push({ name: `tool_${label}`, status: 'fail', message: `${label} is required for the ${profile} profile.` });
    } else {
      checks.push({ name: `tool_${label}`, status: 'pass', message: `${label} is available.` });
    }
  };

  if (profile === 'goad_ad') {
    requireSingle('nmap');
    requireOne(['netexec'], 'netexec_or_nxc', 'NetExec/NXC is required for GOAD-first SMB validation.');
    requireSingle('bloodhound-python');
  } else if (profile === 'web_app') {
    requireOne(['nuclei', 'nikto'], 'web_scanner', 'A web vulnerability scanner (nuclei or nikto) is recommended for web_app profile.');
    requireOne(['gobuster', 'feroxbuster', 'ffuf'], 'dir_enum', 'A directory enumeration tool (gobuster, feroxbuster, or ffuf) is recommended for web_app profile.');
  } else if (profile === 'cloud') {
    requireOne(['pacu', 'prowler'], 'cloud_audit', 'A cloud audit/exploitation tool (pacu or prowler) is recommended for cloud profile.');
  } else if (profile === 'hybrid') {
    requireSingle('nmap');
    requireOne(['netexec'], 'netexec_or_nxc', 'NetExec/NXC is required for AD validation in hybrid environments.');
    requireOne(['pacu', 'prowler'], 'cloud_audit', 'A cloud audit tool is recommended for the cloud component of hybrid profile.');
  } else {
    requireSingle('nmap');
  }

  const hasCredentialWorkflow = [...installed].some(name =>
    name.startsWith('impacket-') || name === 'hashcat' || name === 'john',
  );

  if (hasCredentialWorkflow) {
    checks.push({
      name: 'tool_credential_workflow',
      status: 'pass',
      message: 'At least one credential workflow tool is available.',
    });
  } else {
    checks.push({
      name: 'tool_credential_workflow',
      status: 'warning',
      message: 'No credential workflow tool was detected. GOAD testing can start, but credential follow-on paths will be limited.',
    });
    warnings.push('Credential workflow tooling is missing or not on PATH.');
    recommendedNextSteps.push('Install or expose impacket, hashcat, or john before deeper AD credential testing.');
  }

  return {
    checks,
    missingRequiredTools,
    warnings,
    recommendedNextSteps,
    hasRecommendedCredentialWorkflow: hasCredentialWorkflow,
  };
}

function evaluatePersistence(engine: GraphEngine): LabReadinessCheck {
  const stateFilePath = engine.getStateFilePath();

  try {
    const recovery = engine.getStatePersistenceRecoveryStatus();

    accessSync(dirname(stateFilePath), constants.R_OK | constants.W_OK);

    if (existsSync(stateFilePath)) {
      const persisted = JSON.parse(readFileSync(stateFilePath, 'utf-8'));
      const validShape = persisted && typeof persisted === 'object' && persisted.config && persisted.graph;
      if (!validShape) {
        return applyPersistenceRecovery({
          name: 'persistence',
          status: 'fail',
          message: 'Persisted state file exists but is missing required top-level fields.',
          details: { state_file: stateFilePath },
        }, recovery);
      }
      return applyPersistenceRecovery({
        name: 'persistence',
        status: 'pass',
        message: 'Persisted state file is readable and restart-safe.',
        details: { state_file: stateFilePath, snapshots: engine.listSnapshots().length },
      }, recovery);
    }

    JSON.stringify({
      config: engine.getConfig(),
      graph: engine.exportGraph(),
      activityLog: engine.getFullHistory(),
      agents: engine.getAllAgents(),
      trackedProcesses: engine.getTrackedProcesses(),
    });

    return applyPersistenceRecovery({
      name: 'persistence',
      status: 'pass',
      message: 'State file path is writable and current state shape is serializable.',
      details: { state_file: stateFilePath },
    }, recovery);
  } catch (error) {
    return {
      name: 'persistence',
      status: 'fail',
      message: `Persistence path is not ready: ${error instanceof Error ? error.message : String(error)}`,
      details: { state_file: stateFilePath },
    };
  }
}

function evaluateConfigConsistency(engine: GraphEngine): LabReadinessCheck {
  const recovery = engine.getConfigRecoveryStatus();
  const assessment = assessConfigRecovery(recovery);
  return {
    name: 'config_consistency',
    status: assessment.status,
    message: assessment.message,
    details: {
      status: recovery.status,
      resolution_required: recovery.resolution_required,
      intent_present: recovery.intent_present,
      file_valid: recovery.file_valid,
      file_revision: recovery.file_revision,
      state_revision: recovery.state_revision,
      runtime_revision: recovery.runtime_revision,
      file_hash: recovery.file_hash,
      state_hash: recovery.state_hash,
      runtime_hash: recovery.runtime_hash,
      last_resolution: recovery.last_resolution,
      allowed_resolutions: recovery.allowed_resolutions,
      reason: recovery.reason,
    },
  };
}

export function assessConfigRecovery(recovery: ConfigRecoveryStatus): {
  status: 'pass' | 'warning' | 'fail';
  message: string;
} {
  if (recovery.status === 'write_incomplete') {
    return {
      status: 'fail',
      message: `A known configuration write is incomplete and must be resumed by restarting${recovery.reason ? `: ${recovery.reason}` : '.'}`,
    };
  }
  if (recovery.resolution_required || recovery.status === 'diverged') {
    return {
      status: 'fail',
      message: `Configuration consistency requires explicit reconciliation${recovery.reason ? `: ${recovery.reason}` : '.'}`,
    };
  }
  if (recovery.status === 'recovered') {
    return {
      status: 'warning',
      message: 'Configuration consistency was recovered during this startup; review the recovery status before target execution.',
    };
  }
  if (recovery.status === 'unmanaged') {
    return {
      status: 'pass',
      message: 'Configuration is running in fileless managed-test mode.',
    };
  }
  return { status: 'pass', message: 'File, runtime, and durable configuration are consistent.' };
}

function applyPersistenceRecovery(
  check: LabReadinessCheck,
  recovery: PersistenceRecoveryStatus | undefined,
): LabReadinessCheck {
  if (!recovery) return check;

  const assessment = assessPersistenceRecovery(recovery);
  const appliedLogical = recovery.highest_contiguous_applied_logical_seq
    ?? recovery.highest_contiguous_applied_seq;
  const recoveryMessage = assessment.status === 'pass'
    ? recovery.outcome === 'recovered'
      ? `Recovery completed through sequence ${appliedLogical}.`
      : undefined
    : assessment.message;
  const status = check.status === 'fail' || assessment.status === 'fail'
    ? 'fail'
    : assessment.status;

  return {
    ...check,
    status,
    message: recoveryMessage
      ? check.status === 'fail' || assessment.status === 'pass'
        ? `${check.message} ${recoveryMessage}`
        : recoveryMessage
      : check.message,
    details: { ...(check.details || {}), recovery },
  };
}

export function assessPersistenceRecovery(recovery: PersistenceRecoveryStatus): {
  status: 'pass' | 'warning' | 'fail';
  message: string;
} {
  const reason = recovery.reason || recovery.last_persistence_error;
  const reasonSuffix = reason ? `: ${reason}` : '';
  const appliedLogical = recovery.highest_contiguous_applied_logical_seq
    ?? recovery.highest_contiguous_applied_seq;
  const sequenceIncomplete = appliedLogical < recovery.highest_on_disk_seq;
  const recoveryBlocked = recovery.outcome === 'incomplete'
    || recovery.outcome === 'reinitialized'
    || !recovery.complete
    || !recovery.writable
    || recovery.journal.malformed
    || recovery.journal.skipped > 0
    || recovery.journal.failed > 0
    || sequenceIncomplete;

  if (recoveryBlocked) {
    const message = recovery.outcome === 'reinitialized'
      ? `Persistence state was reinitialized from ${recovery.source}${reasonSuffix}.`
      : `Persistence recovery is incomplete or not writable${reasonSuffix}.`;
    return {
      status: 'fail',
      message,
    };
  }

  const recoveryWarning = (recovery.outcome === 'recovered' && recovery.source === 'snapshot')
    || recovery.consecutive_persistence_failures > 0
    || recovery.journal.preserved
    || (recovery.coordination_warnings?.length ?? 0) > 0;
  if (recoveryWarning) {
    const message = (recovery.coordination_warnings?.length ?? 0) > 0
      ? `${recovery.coordination_warnings!.length} legacy coordination relationship(s) could not be linked without guessing.`
      : recovery.consecutive_persistence_failures > 0
      ? `Persistence has ${recovery.consecutive_persistence_failures} consecutive write failure(s)${reasonSuffix}.`
      : recovery.journal.preserved
        ? 'The mutation journal remains preserved for inspection after persistence recovery.'
        : 'Persistence recovered from a snapshot; review the recovery details before continuing.';
    return {
      status: 'warning',
      message,
    };
  }

  return { status: 'pass', message: 'Persistence recovery is healthy.' };
}

function evaluateProcessTracker(engine: GraphEngine): LabReadinessCheck {
  try {
    const trackedProcesses = engine.getTrackedProcesses();
    JSON.stringify(trackedProcesses);
    return {
      name: 'process_tracker',
      status: 'pass',
      message: 'Tracked process state is serializable for restart persistence.',
      details: { tracked_processes: trackedProcesses.length },
    };
  } catch (error) {
    return {
      name: 'process_tracker',
      status: 'fail',
      message: `Tracked process state is not restart-safe: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

function evaluateDashboard(dashboard: DashboardStatus): LabReadinessCheck {
  if (!dashboard.enabled) {
    return {
      name: 'dashboard',
      status: 'warning',
      message: 'Dashboard is disabled. MCP testing can proceed, but operator visibility will be reduced.',
    };
  }

  if (!dashboard.running) {
    return {
      name: 'dashboard',
      status: 'warning',
      message: 'Dashboard is configured but not currently running.',
      details: { address: dashboard.address },
    };
  }

  return {
    name: 'dashboard',
    status: 'pass',
    message: 'Dashboard is running and ready for live inspection.',
    details: { address: dashboard.address },
  };
}
