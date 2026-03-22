import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { basename, join, resolve } from 'path';
import type { ExportedGraph, EngagementConfig, ExportedGraphNode } from '../types.js';
import { callJsonTool, startMcpStdioSession, stopMcpStdioSession } from '../test-support/mcp-stdio.js';
import type { McpStdioSession } from '../test-support/mcp-stdio.js';

export type LabSmokeOptions = {
  keepState?: boolean;
  verbose?: boolean;
};

export type ProvenanceCheckResult = {
  host_id: string;
  host_label: string;
  first_seen_at?: string;
  last_seen_at?: string;
  confirmed_at?: string;
  sources: string[];
  expected_sources: string[];
  checks: {
    first_seen_present: boolean;
    last_seen_present: boolean;
    last_seen_not_before_first_seen: boolean;
    sources_complete: boolean;
    confirmed_at_valid: boolean;
    preserved_after_restart: boolean;
  };
  passed: boolean;
};

export type LabSmokeReport = {
  build: {
    dist_present: boolean;
    server_entry: string;
  };
  server: {
    started: boolean;
    tools_present: string[];
  };
  preflight: {
    status: string;
    warnings: string[];
    missing_required_tools: string[];
  };
  graph_stage: {
    before_ingest: string;
    after_ingest: string;
    after_restart: string;
  };
  graph_summary: {
    before_ingest: Record<string, unknown>;
    after_ingest: Record<string, unknown>;
    after_restart: Record<string, unknown>;
  };
  ingest_steps: Array<{
    step: string;
    summary: Record<string, unknown>;
  }>;
  graph_health: {
    after_ingest: {
      status: string;
      counts_by_severity: Record<string, number>;
      top_issues: string[];
    };
    after_restart: {
      status: string;
      counts_by_severity: Record<string, number>;
      top_issues: string[];
    };
  };
  restart_check: {
    passed: boolean;
    graph_summary_preserved: boolean;
    health_preserved: boolean;
  };
  provenance: ProvenanceCheckResult;
  retrospective: {
    summary: string;
    logging_quality_status: string;
    trace_quality_status: string;
  };
  output_dir: string;
  report_file: string;
  state_file: string;
};

type SmokeWorkspace = {
  rootDir: string;
  configPath: string;
  stateFile: string;
  fakeToolBin: string;
  fixtureDir: string;
  reportFile: string;
};

const FIXTURE_CONFIG_ID = 'eng-lab-smoke';
const FIXTURE_NAME = 'goad-synth';
const FAKE_TOOL_COMMANDS = ['nmap', 'nxc', 'bloodhound-python', 'impacket-secretsdump'];
const REQUIRED_MCP_TOOLS = [
  'get_state',
  'run_lab_preflight',
  'ingest_bloodhound',
  'parse_output',
  'run_graph_health',
  'run_retrospective',
  'export_graph',
];
const PROVENANCE_HOST_ID = 'host-10-10-10-20';
const EXPECTED_PROVENANCE_SOURCES = ['bloodhound-ingest', 'nmap-parser', 'nxc-parser'];

export function parseLabSmokeArgs(args: string[]): LabSmokeOptions {
  return {
    keepState: args.includes('--keep-state'),
    verbose: args.includes('--verbose'),
  };
}

export function validateProvenanceForHost(
  graphAfterIngest: ExportedGraph,
  graphAfterRestart: ExportedGraph,
  hostId: string = PROVENANCE_HOST_ID,
): ProvenanceCheckResult {
  const afterIngest = getExportedNode(graphAfterIngest, hostId);
  const afterRestart = getExportedNode(graphAfterRestart, hostId);
  if (!afterIngest || !afterRestart) {
    return {
      host_id: hostId,
      host_label: hostId,
      sources: [],
      expected_sources: EXPECTED_PROVENANCE_SOURCES,
      checks: {
        first_seen_present: false,
        last_seen_present: false,
        last_seen_not_before_first_seen: false,
        sources_complete: false,
        confirmed_at_valid: false,
        preserved_after_restart: false,
      },
      passed: false,
    };
  }

  const props = afterIngest.properties;
  const restartProps = afterRestart.properties;
  const sources = Array.isArray(props.sources) ? props.sources.map(value => String(value)) : [];
  const firstSeen = typeof props.first_seen_at === 'string' ? props.first_seen_at : undefined;
  const lastSeen = typeof props.last_seen_at === 'string' ? props.last_seen_at : undefined;
  const confirmedAt = typeof props.confirmed_at === 'string' ? props.confirmed_at : undefined;

  const checks = {
    first_seen_present: Boolean(firstSeen),
    last_seen_present: Boolean(lastSeen),
    last_seen_not_before_first_seen: Boolean(firstSeen && lastSeen && lastSeen >= firstSeen),
    sources_complete: EXPECTED_PROVENANCE_SOURCES.every(source => sources.includes(source)),
    confirmed_at_valid: Boolean(confirmedAt && firstSeen && confirmedAt >= firstSeen && (!lastSeen || confirmedAt <= lastSeen)),
    preserved_after_restart: jsonEqual(props, restartProps),
  };

  return {
    host_id: hostId,
    host_label: String(props.label || hostId),
    first_seen_at: firstSeen,
    last_seen_at: lastSeen,
    confirmed_at: confirmedAt,
    sources,
    expected_sources: EXPECTED_PROVENANCE_SOURCES,
    checks,
    passed: Object.values(checks).every(Boolean),
  };
}

export async function runLabSmoke(options: LabSmokeOptions = {}): Promise<LabSmokeReport> {
  const workspace = createWorkspace();
  const serverEntry = resolve(process.cwd(), 'dist/index.js');
  if (!existsSync(serverEntry)) {
    throw new Error(`Built server entrypoint not found: ${serverEntry}. Run npm run build first.`);
  }

  let session: McpStdioSession | null = await startSession(serverEntry, workspace, 'lab-smoke');
  let restartedSession: McpStdioSession | null = null;

  try {
    const toolNames = await listAndValidateTools(session.client);
    const initialState = await callJsonTool<Record<string, any>>(session.client, 'get_state', {});
    const preflight = await callJsonTool<Record<string, any>>(session.client, 'run_lab_preflight', {
      profile: 'goad_ad',
    });
    if (preflight.status === 'blocked') {
      throw new Error(`Lab preflight blocked smoke run: ${String((preflight.missing_required_tools || []).join(', '))}`);
    }

    const ingestSteps: LabSmokeReport['ingest_steps'] = [];

    const bloodhoundResult = await callJsonTool<Record<string, unknown>>(session.client, 'ingest_bloodhound', {
      path: join(workspace.fixtureDir, 'bloodhound'),
      max_files: 10,
    });
    ingestSteps.push({ step: 'ingest_bloodhound', summary: bloodhoundResult });

    const nmapResult = await callJsonTool<Record<string, unknown>>(session.client, 'parse_output', {
      tool_name: 'nmap',
      output: readFileSync(join(workspace.fixtureDir, 'nmap-scan.xml'), 'utf-8'),
      ingest: true,
    });
    ingestSteps.push({ step: 'parse_nmap', summary: nmapResult });

    const nxcResult = await callJsonTool<Record<string, unknown>>(session.client, 'parse_output', {
      tool_name: 'nxc',
      output: readFileSync(join(workspace.fixtureDir, 'nxc-smb.txt'), 'utf-8'),
      ingest: true,
    });
    ingestSteps.push({ step: 'parse_nxc', summary: nxcResult });

    const secretsdumpResult = await callJsonTool<Record<string, unknown>>(session.client, 'parse_output', {
      tool_name: 'secretsdump',
      output: readFileSync(join(workspace.fixtureDir, 'secretsdump.txt'), 'utf-8'),
      ingest: true,
    });
    ingestSteps.push({ step: 'parse_secretsdump', summary: secretsdumpResult });

    const healthAfterIngest = await callJsonTool<Record<string, any>>(session.client, 'run_graph_health', {});
    assertHealthyGraph(healthAfterIngest, 'after ingest');
    const stateAfterIngest = await callJsonTool<Record<string, any>>(session.client, 'get_state', {});
    const graphAfterIngest = await callJsonTool<ExportedGraph>(session.client, 'export_graph', {});

    await stopMcpStdioSession(session);
    session = null;

    restartedSession = await restartSession(serverEntry, workspace);
    await listAndValidateTools(restartedSession.client);

    const stateAfterRestart = await callJsonTool<Record<string, any>>(restartedSession.client, 'get_state', {});
    const healthAfterRestart = await callJsonTool<Record<string, any>>(restartedSession.client, 'run_graph_health', {});
    assertHealthyGraph(healthAfterRestart, 'after restart');
    const graphAfterRestart = await callJsonTool<ExportedGraph>(restartedSession.client, 'export_graph', {});
    const retrospective = await callJsonTool<Record<string, any>>(restartedSession.client, 'run_retrospective', {});

    const graphSummaryPreserved = jsonEqual(stateAfterIngest.graph_summary, stateAfterRestart.graph_summary);
    const healthPreserved = jsonEqual(
      {
        status: healthAfterIngest.status,
        counts_by_severity: healthAfterIngest.counts_by_severity,
      },
      {
        status: healthAfterRestart.status,
        counts_by_severity: healthAfterRestart.counts_by_severity,
      },
    );
    if (!graphSummaryPreserved || !healthPreserved) {
      throw new Error('Restart/load materially changed graph summary or graph health.');
    }

    const provenance = validateProvenanceForHost(graphAfterIngest, graphAfterRestart);
    if (!provenance.passed) {
      throw new Error(`Provenance assertions failed for ${provenance.host_id}`);
    }

    const report: LabSmokeReport = {
      build: {
        dist_present: true,
        server_entry: serverEntry,
      },
      server: {
        started: true,
        tools_present: toolNames,
      },
      preflight: {
        status: String(preflight.status || 'unknown'),
        warnings: toStringArray(preflight.warnings),
        missing_required_tools: toStringArray(preflight.missing_required_tools),
      },
      graph_stage: {
        before_ingest: String(preflight.graph_stage || inferGraphStage(initialState)),
        after_ingest: inferGraphStage(stateAfterIngest),
        after_restart: inferGraphStage(stateAfterRestart),
      },
      graph_summary: {
        before_ingest: asObject(initialState.graph_summary),
        after_ingest: asObject(stateAfterIngest.graph_summary),
        after_restart: asObject(stateAfterRestart.graph_summary),
      },
      ingest_steps: ingestSteps,
      graph_health: {
        after_ingest: summarizeHealth(healthAfterIngest),
        after_restart: summarizeHealth(healthAfterRestart),
      },
      restart_check: {
        passed: true,
        graph_summary_preserved: graphSummaryPreserved,
        health_preserved: healthPreserved,
      },
      provenance,
      retrospective: {
        summary: String(retrospective.summary || ''),
        logging_quality_status: String(retrospective.context_improvements?.logging_quality?.status || 'unknown'),
        trace_quality_status: String(retrospective.trace_quality?.status || 'unknown'),
      },
      output_dir: workspace.rootDir,
      report_file: workspace.reportFile,
      state_file: workspace.stateFile,
    };

    writeFileSync(workspace.reportFile, JSON.stringify(report, null, 2));

    if (!options.keepState) {
      removeStateArtifacts(workspace.rootDir, workspace.stateFile);
    }

    return report;
  } finally {
    await stopMcpStdioSession(session);
    await stopMcpStdioSession(restartedSession);
  }
}

async function startSession(
  serverEntry: string,
  workspace: SmokeWorkspace,
  clientName: string,
): Promise<McpStdioSession> {
  return startMcpStdioSession({
    command: 'node',
    args: [serverEntry],
    cwd: workspace.rootDir,
    env: {
      ...(process.env as Record<string, string>),
      OVERWATCH_CONFIG: workspace.configPath,
      OVERWATCH_SKILLS: resolve(process.cwd(), 'skills'),
      OVERWATCH_DASHBOARD_PORT: '0',
      PATH: `${workspace.fakeToolBin}:${process.env.PATH || ''}`,
    },
    clientName,
  });
}

async function restartSession(serverEntry: string, workspace: SmokeWorkspace): Promise<McpStdioSession> {
  return startSession(serverEntry, workspace, 'lab-smoke-restart');
}

async function listAndValidateTools(sessionClient: McpStdioSession['client']): Promise<string[]> {
  const listedTools = await sessionClient.listTools();
  const toolNames = listedTools.tools.map(tool => tool.name).sort();
  for (const requiredTool of REQUIRED_MCP_TOOLS) {
    if (!toolNames.includes(requiredTool)) {
      throw new Error(`Required MCP tool missing from server: ${requiredTool}`);
    }
  }
  return toolNames;
}

function createWorkspace(): SmokeWorkspace {
  const rootDir = mkdtempSync(join(tmpdir(), 'overwatch-lab-smoke-'));
  mkdirSync(rootDir, { recursive: true });

  const fixtureDir = resolve(process.cwd(), 'fixtures', 'lab-smoke', FIXTURE_NAME);
  if (!existsSync(fixtureDir)) {
    throw new Error(`Fixture not found: ${fixtureDir}`);
  }

  const configPath = join(rootDir, 'engagement.smoke.json');
  const stateFile = join(rootDir, `state-${FIXTURE_CONFIG_ID}.json`);
  const fakeToolBin = join(rootDir, 'fake-bin');
  const reportFile = join(rootDir, 'lab-smoke-report.json');

  mkdirSync(fakeToolBin, { recursive: true });
  writeFixtureConfig(configPath);
  installFakeTools(fakeToolBin, FAKE_TOOL_COMMANDS);

  return { rootDir, configPath, stateFile, fakeToolBin, fixtureDir, reportFile };
}

function writeFixtureConfig(configPath: string): void {
  const config: EngagementConfig = {
    id: FIXTURE_CONFIG_ID,
    name: 'Lab Smoke Harness',
    created_at: '2026-03-22T00:00:00Z',
    scope: {
      cidrs: [],
      domains: ['acme.local'],
      exclusions: [],
    },
    objectives: [
      {
        id: 'obj-da-credential',
        description: 'Obtain a privileged credential in acme.local',
        target_node_type: 'credential',
        target_criteria: {
          privileged: true,
          cred_domain: 'ACME.LOCAL',
        },
        achieved: false,
      },
    ],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
    },
  };

  writeFileSync(configPath, JSON.stringify(config, null, 2));
}

function installFakeTools(binDir: string, commands: string[]): void {
  for (const command of commands) {
    const toolPath = join(binDir, command);
    writeFileSync(toolPath, `#!/bin/sh\necho "${command} smoke stub"\n`);
    chmodSync(toolPath, 0o755);
  }
}

function assertHealthyGraph(report: Record<string, any>, phase: string): void {
  if (Number(report.counts_by_severity?.critical || 0) <= 0) return;
  const messages = Array.isArray(report.issues)
    ? report.issues.slice(0, 3).map((issue: { message?: string }) => issue.message || 'unknown issue')
    : [];
  throw new Error(`Graph health has critical issues ${phase}: ${messages.join('; ')}`);
}

function summarizeHealth(report: Record<string, any>): {
  status: string;
  counts_by_severity: Record<string, number>;
  top_issues: string[];
} {
  return {
    status: String(report.status || 'unknown'),
    counts_by_severity: asObject(report.counts_by_severity) as Record<string, number>,
    top_issues: Array.isArray(report.issues)
      ? report.issues.slice(0, 5).map((issue: { message?: string }) => String(issue.message || 'unknown issue'))
      : [],
  };
}

function inferGraphStage(state: Record<string, any>): string {
  const totalNodes = Number(state.graph_summary?.total_nodes || 0);
  const totalEdges = Number(state.graph_summary?.total_edges || 0);
  if (totalNodes === 0) return 'empty';
  return totalEdges === 0 ? 'seeded' : 'mid_run';
}

function getExportedNode(graph: ExportedGraph, nodeId: string): ExportedGraphNode | undefined {
  return graph.nodes.find(node => node.id === nodeId);
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function jsonEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function removeStateArtifacts(rootDir: string, stateFile: string): void {
  const stateBasename = basename(stateFile);
  const entries = [stateFile, ...listSnapshotFiles(rootDir, stateBasename)];
  for (const entry of entries) {
    try {
      rmSync(entry, { force: true });
    } catch {
      // best effort cleanup only
    }
  }
}

function listSnapshotFiles(rootDir: string, stateBasename: string): string[] {
  const prefix = stateBasename.replace(/\.json$/, '.snap-');
  try {
    return readdirSync(rootDir)
      .filter(name => name.startsWith(prefix) && name.endsWith('.json'))
      .map(name => join(rootDir, name));
  } catch {
    return [];
  }
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(entry => String(entry));
}
