import { describe, it, expect } from 'vitest';
import {
  buildFindings,
  buildEvidenceChainsForNode,
  buildAllEvidenceChains,
  buildAttackNarrative,
  generateFullReport,
} from '../report-generator.js';
import type { ReportInput } from '../report-generator.js';
import { renderReportHtml } from '../report-html.js';
import type { EngagementConfig, NodeProperties, EdgeProperties, ExportedGraph } from '../../types.js';
import type { ActivityLogEntry } from '../engine-context.js';

// ============================================================
// Test Helpers
// ============================================================

function makeConfig(overrides?: Partial<EngagementConfig>): EngagementConfig {
  return {
    id: 'test-report',
    name: 'Report Test Engagement',
    created_at: '2026-01-01T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['corp.local'],
      exclusions: [],
    },
    objectives: [
      {
        id: 'obj-da',
        description: 'Get domain admin',
        target_node_type: 'credential',
        target_criteria: { privileged: true },
        achieved: true,
        achieved_at: '2026-01-01T12:00:00Z',
      },
      {
        id: 'obj-dc',
        description: 'Compromise DC',
        target_node_type: 'host',
        target_criteria: { hostname: 'dc01' },
        achieved: false,
      },
    ],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function makeGraph(overrides?: Partial<ExportedGraph>): ExportedGraph {
  return {
    nodes: [
      { id: 'host-1', properties: { id: 'host-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', os: 'Windows Server 2019', alive: true, domain_joined: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'host-2', properties: { id: 'host-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', os: 'Linux', alive: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'svc-smb-1', properties: { id: 'svc-smb-1', type: 'service', label: 'SMB', port: 445, service_name: 'smb', discovered_at: '2026-01-01T01:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'user-admin', properties: { id: 'user-admin', type: 'user', label: 'admin', username: 'admin', privileged: true, discovered_at: '2026-01-01T02:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'cred-admin', properties: { id: 'cred-admin', type: 'credential', label: 'admin NTLM', cred_type: 'ntlm', cred_user: 'admin', cred_domain: 'corp.local', privileged: true, cred_usable_for_auth: true, discovered_at: '2026-01-01T10:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'cred-jdoe', properties: { id: 'cred-jdoe', type: 'credential', label: 'jdoe password', cred_type: 'plaintext', cred_user: 'jdoe', cred_usable_for_auth: true, discovered_at: '2026-01-01T05:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'vuln-1', properties: { id: 'vuln-1', type: 'vulnerability', label: 'CVE-2024-1234', cve: 'CVE-2024-1234', cvss: 9.8, vuln_type: 'rce', exploitable: true, exploit_available: true, affected_component: 'SMB v1', discovered_at: '2026-01-01T03:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'domain-corp', properties: { id: 'domain-corp', type: 'domain', label: 'corp.local', domain_name: 'corp.local', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'objective-da', properties: { id: 'objective-da', type: 'objective', label: 'Domain Admin', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
    ],
    edges: [
      // Host-1 has admin access
      { source: 'user-admin', target: 'host-1', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      { source: 'user-admin', target: 'host-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      // Service on host-1
      { source: 'host-1', target: 'svc-smb-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T01:00:00Z' } as EdgeProperties },
      // Credential valid on service
      { source: 'cred-admin', target: 'svc-smb-1', properties: { type: 'VALID_ON', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      { source: 'cred-jdoe', target: 'svc-smb-1', properties: { type: 'POTENTIAL_AUTH', confidence: 0.6, discovered_at: '2026-01-01T05:00:00Z', tested: false } as EdgeProperties },
      // Credential ownership
      { source: 'user-admin', target: 'cred-admin', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      // Credential derivation
      { source: 'cred-admin', target: 'cred-jdoe', properties: { type: 'DERIVED_FROM', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z', derivation_method: 'secretsdump' } as EdgeProperties },
      // Vulnerability
      { source: 'svc-smb-1', target: 'vuln-1', properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: '2026-01-01T03:00:00Z' } as EdgeProperties },
      { source: 'vuln-1', target: 'user-admin', properties: { type: 'EXPLOITS', confidence: 0.9, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
    ],
    ...overrides,
  };
}

function makeHistory(entries?: Partial<ActivityLogEntry>[]): ActivityLogEntry[] {
  const defaults: ActivityLogEntry[] = [
    {
      event_id: 'e1', timestamp: '2026-01-01T00:30:00Z',
      description: 'Nmap scan of 10.10.10.0/24 — discovered 2 hosts',
      tool_name: 'nmap', category: 'finding', outcome: 'success',
      target_node_ids: ['host-1', 'host-2'],
    },
    {
      event_id: 'e2', timestamp: '2026-01-01T02:00:00Z',
      description: 'Enumerated SMB services on 10.10.10.1',
      action_id: 'act-smb-enum', event_type: 'action_validated' as any,
      tool_name: 'nxc', technique: 'smb-enumeration',
      target_node_ids: ['svc-smb-1'],
    },
    {
      event_id: 'e3', timestamp: '2026-01-01T02:01:00Z',
      description: 'SMB enumeration completed — found 1 service',
      action_id: 'act-smb-enum', event_type: 'action_completed' as any,
      result_classification: 'success',
      target_node_ids: ['svc-smb-1'],
    },
    {
      event_id: 'e4', timestamp: '2026-01-01T05:00:00Z',
      description: 'Password spray found jdoe credential',
      action_id: 'act-spray', event_type: 'action_completed' as any,
      tool_name: 'nxc', technique: 'password-spray', result_classification: 'success',
      target_node_ids: ['cred-jdoe'],
      linked_finding_ids: ['cred-jdoe'],
    },
    {
      event_id: 'e5', timestamp: '2026-01-01T10:00:00Z',
      description: 'Secretsdump on 10.10.10.1 — obtained admin NTLM hash',
      action_id: 'act-dump', event_type: 'action_completed' as any,
      tool_name: 'secretsdump', technique: 'credential-dumping', result_classification: 'success',
      target_node_ids: ['cred-admin', 'host-1'],
      linked_finding_ids: ['cred-admin'],
    },
    {
      event_id: 'e6', timestamp: '2026-01-01T12:00:00Z',
      description: 'Objective achieved: Get domain admin',
      event_type: 'objective_achieved' as any,
      category: 'objective', outcome: 'success',
    },
  ];

  if (entries) {
    return entries.map((e, i) => ({
      event_id: `e${i}`,
      timestamp: `2026-01-01T0${i}:00:00Z`,
      description: 'test entry',
      ...e,
    })) as ActivityLogEntry[];
  }
  return defaults as ActivityLogEntry[];
}

// ============================================================
// buildFindings
// ============================================================

describe('buildFindings', () => {
  it('generates findings for compromised hosts', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const hostFindings = findings.filter(f => f.category === 'compromised_host');
    expect(hostFindings.length).toBe(1);
    expect(hostFindings[0].title).toContain('10.10.10.1');
    expect(hostFindings[0].severity).toBe('critical'); // has ADMIN_TO
    expect(hostFindings[0].risk_score).toBeGreaterThan(5);
  });

  it('generates findings for credentials', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const credFindings = findings.filter(f => f.category === 'credential');
    expect(credFindings.length).toBe(2);
    const adminCred = credFindings.find(f => f.title.includes('admin'));
    expect(adminCred).toBeDefined();
    expect(adminCred!.severity).toBe('critical'); // privileged
    expect(adminCred!.risk_score).toBe(9.5);
  });

  it('generates findings for vulnerabilities', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const vulnFindings = findings.filter(f => f.category === 'vulnerability');
    expect(vulnFindings.length).toBe(1);
    expect(vulnFindings[0].title).toContain('CVE-2024-1234');
    expect(vulnFindings[0].severity).toBe('critical'); // cvss 9.8
  });

  it('sorts findings by risk score descending', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    for (let i = 1; i < findings.length; i++) {
      expect(findings[i].risk_score).toBeLessThanOrEqual(findings[i - 1].risk_score);
    }
  });

  it('returns empty for graph with no compromised assets', () => {
    const emptyGraph: ExportedGraph = { nodes: [], edges: [] };
    const findings = buildFindings(emptyGraph, [], makeConfig());
    expect(findings).toHaveLength(0);
  });

  it('generates host remediation for Windows hosts', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const hostFinding = findings.find(f => f.category === 'compromised_host');
    expect(hostFinding).toBeDefined();
    expect(hostFinding!.remediation).toContain('Revoke all active sessions');
    expect(hostFinding!.remediation).toContain('scheduled tasks'); // Windows-specific
  });

  it('generates credential remediation for privileged creds', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const credFinding = findings.find(f => f.category === 'credential' && f.title.includes('admin'));
    expect(credFinding).toBeDefined();
    expect(credFinding!.remediation).toContain('Immediately rotate');
    expect(credFinding!.remediation).toContain('privileged');
  });

  it('generates vulnerability remediation with CVE', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const vulnFinding = findings.find(f => f.category === 'vulnerability');
    expect(vulnFinding).toBeDefined();
    expect(vulnFinding!.remediation).toContain('Patch CVE-2024-1234');
    expect(vulnFinding!.remediation).toContain('affected component');
  });
});

// ============================================================
// buildEvidenceChainsForNode
// ============================================================

describe('buildEvidenceChainsForNode', () => {
  it('finds evidence from activity log by action_id grouping', () => {
    const chains = buildEvidenceChainsForNode('cred-admin', makeGraph(), makeHistory());
    const actionChain = chains.find(c => c.action_id === 'act-dump');
    expect(actionChain).toBeDefined();
    expect(actionChain!.tool).toBe('secretsdump');
    expect(actionChain!.technique).toBe('credential-dumping');
  });

  it('includes derivation edge provenance', () => {
    const chains = buildEvidenceChainsForNode('cred-admin', makeGraph(), makeHistory());
    const derivChain = chains.find(c => c.claim.includes('DERIVED_FROM'));
    expect(derivChain).toBeDefined();
    expect(derivChain!.claim).toContain('secretsdump');
  });

  it('returns empty chains for node with no evidence', () => {
    const chains = buildEvidenceChainsForNode('domain-corp', makeGraph(), makeHistory());
    expect(chains).toHaveLength(0);
  });
});

describe('buildAllEvidenceChains', () => {
  it('builds chains for all interesting node types', () => {
    const allChains = buildAllEvidenceChains(makeGraph(), makeHistory());
    // Should have chains for hosts, credentials, and vulnerabilities
    expect(allChains.size).toBeGreaterThan(0);
    // host-1 should have evidence (it's in target_node_ids of act-dump)
    expect(allChains.has('host-1')).toBe(true);
  });
});

// ============================================================
// buildAttackNarrative
// ============================================================

describe('buildAttackNarrative', () => {
  it('produces multiple phases from rich history', () => {
    const narrative = buildAttackNarrative(makeGraph(), makeHistory(), makeConfig());
    expect(narrative.length).toBeGreaterThan(0);
    const phaseNames = narrative.map(p => p.name);
    // Should have at least recon and objective phases
    expect(phaseNames.some(n => n.includes('Reconnaissance'))).toBe(true);
    expect(phaseNames.some(n => n.includes('Objective'))).toBe(true);
  });

  it('includes timestamps on phases', () => {
    const narrative = buildAttackNarrative(makeGraph(), makeHistory(), makeConfig());
    for (const phase of narrative) {
      if (phase.paragraphs.length > 0) {
        expect(phase.start_time).toBeDefined();
      }
    }
  });

  it('handles empty history gracefully', () => {
    const narrative = buildAttackNarrative(makeGraph(), [], makeConfig());
    expect(narrative).toHaveLength(0);
  });

  it('classifies credential activity into access phase', () => {
    const history = makeHistory([
      { description: 'Discovered password for jdoe', tool_name: 'nxc', technique: 'password-spray' },
      { description: 'NTLM hash captured via secretsdump', tool_name: 'secretsdump' },
    ]);
    const narrative = buildAttackNarrative(makeGraph(), history, makeConfig());
    const accessPhase = narrative.find(p => p.name.includes('Access'));
    expect(accessPhase).toBeDefined();
  });

  it('classifies lateral movement entries', () => {
    const history = makeHistory([
      { description: 'New session opened on 10.10.10.2 via SSH', event_type: 'session_opened' as any },
      { description: 'Lateral movement to host-2 via pivot', tool_name: 'ssh' },
    ]);
    const narrative = buildAttackNarrative(makeGraph(), history, makeConfig());
    const lateralPhase = narrative.find(p => p.name.includes('Lateral'));
    expect(lateralPhase).toBeDefined();
  });
});

// ============================================================
// generateFullReport (markdown)
// ============================================================

describe('generateFullReport', () => {
  it('produces a complete markdown report', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input);

    expect(report).toContain('# Penetration Test Report');
    expect(report).toContain('## Executive Summary');
    expect(report).toContain('## Scope');
    expect(report).toContain('## Findings Summary');
    expect(report).toContain('## Detailed Findings');
    expect(report).toContain('## Attack Narrative');
    expect(report).toContain('## Objectives');
    expect(report).toContain('## Recommendations');
    expect(report).toContain('## Activity Timeline');
  });

  it('includes severity distribution in executive summary', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input);
    expect(report).toContain('Critical');
    expect(report).toContain('High');
  });

  it('includes per-finding detail sections', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input);
    expect(report).toContain('#### Description');
    expect(report).toContain('#### Remediation');
    expect(report).toContain('#### Affected Assets');
  });

  it('includes evidence sections when enabled', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input, { include_evidence: true });
    expect(report).toContain('#### Evidence');
  });

  it('omits evidence when disabled', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input, { include_evidence: false });
    expect(report).not.toContain('#### Evidence');
  });

  it('omits narrative when disabled', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input, { include_narrative: false });
    expect(report).not.toContain('## Attack Narrative');
  });

  it('includes credential chains', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input);
    expect(report).toContain('## Credential Chains');
  });

  it('includes objectives table', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
    };
    const report = generateFullReport(input);
    expect(report).toContain('Get domain admin');
    expect(report).toContain('Achieved');
    expect(report).toContain('Pending');
  });

  it('includes cloud scope when present', () => {
    const config = makeConfig({
      scope: {
        cidrs: ['10.0.0.0/8'],
        domains: [],
        exclusions: [],
        aws_accounts: ['123456789012'],
      },
    });
    const input: ReportInput = {
      config,
      graph: { nodes: [], edges: [] },
      history: [],
      agents: [],
    };
    const report = generateFullReport(input);
    expect(report).toContain('AWS Accounts');
    expect(report).toContain('123456789012');
  });

  it('handles empty graph without error', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: { nodes: [], edges: [] },
      history: [],
      agents: [],
    };
    const report = generateFullReport(input);
    expect(report).toContain('# Penetration Test Report');
    expect(report).toContain('No significant findings');
  });

  it('includes agent activity when agents present', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [
        { id: 'a1', agent_id: 'agent-1', assigned_at: '2026-01-01T00:00:00Z', status: 'completed', frontier_item_id: 'f1', subgraph_node_ids: [] },
        { id: 'a2', agent_id: 'agent-2', assigned_at: '2026-01-01T01:00:00Z', status: 'failed', frontier_item_id: 'f2', subgraph_node_ids: [] },
      ],
    };
    const report = generateFullReport(input);
    expect(report).toContain('## Agent Activity');
    expect(report).toContain('Completed:** 1');
    expect(report).toContain('Failed:** 1');
  });

  it('includes retrospective findings when provided', () => {
    const input: ReportInput = {
      config: makeConfig(),
      graph: makeGraph(),
      history: makeHistory(),
      agents: [],
      retrospective: {
        inference_suggestions: [{
          rule: {
            id: 'test-rule', name: 'Test suggested rule',
            description: 'test', trigger: { node_type: 'host' },
            produces: [{ edge_type: 'REACHABLE', source_selector: 'trigger_node', target_selector: 'domain_nodes', confidence: 0.5 }],
          },
          evidence: 'Pattern seen 5 times',
          occurrences: 5,
        }],
        skill_gaps: {
          unused_skills: ['ad-discovery'],
          missing_skills: ['cloud-enum'],
          failed_techniques: ['kerberoast'],
          mentioned_techniques: [],
          skill_usage_counts: {},
        },
      },
    };
    const report = generateFullReport(input, { include_retrospective: true });
    expect(report).toContain('## Retrospective Findings');
    expect(report).toContain('Test suggested rule');
    expect(report).toContain('cloud-enum');
  });
});

// ============================================================
// renderReportHtml
// ============================================================

describe('renderReportHtml', () => {
  it('produces valid HTML document', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const narrative = buildAttackNarrative(makeGraph(), makeHistory(), makeConfig());
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings,
      narrative,
      markdown: '',
    });

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
    expect(html).toContain('<title>Pentest Report:');
  });

  it('includes table of contents', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings,
      narrative: [],
      markdown: '',
    }, { include_toc: true });

    expect(html).toContain('id="toc"');
    expect(html).toContain('Table of Contents');
  });

  it('includes severity cards', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings,
      narrative: [],
      markdown: '',
    });

    expect(html).toContain('severity-critical');
    expect(html).toContain('severity-high');
  });

  it('includes finding details with evidence toggle', () => {
    const findings = buildFindings(makeGraph(), makeHistory(), makeConfig());
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings,
      narrative: [],
      markdown: '',
    });

    expect(html).toContain('evidence-toggle');
    expect(html).toContain('finding-header');
    expect(html).toContain('remediation');
  });

  it('supports dark theme', () => {
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings: [],
      narrative: [],
      markdown: '',
    }, { theme: 'dark' });

    expect(html).toContain('data-theme="dark"');
  });

  it('includes narrative section when phases present', () => {
    const narrative = buildAttackNarrative(makeGraph(), makeHistory(), makeConfig());
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings: [],
      narrative,
      markdown: '',
    });

    expect(html).toContain('id="attack-narrative"');
    expect(html).toContain('narrative-phase');
  });

  it('includes print CSS', () => {
    const html = renderReportHtml({
      config: makeConfig(),
      graph: makeGraph(),
      findings: [],
      narrative: [],
      markdown: '',
    });
    expect(html).toContain('@media print');
  });

  it('escapes HTML in user content', () => {
    const config = makeConfig({ name: 'Test <script>alert(1)</script>' });
    const html = renderReportHtml({
      config,
      graph: makeGraph(),
      findings: [],
      narrative: [],
      markdown: '',
    });

    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});

// ============================================================
// Risk scoring
// ============================================================

describe('risk scoring', () => {
  it('rates ADMIN_TO higher than HAS_SESSION only', () => {
    const graphAdmin = makeGraph();
    const graphSession: ExportedGraph = {
      ...makeGraph(),
      edges: makeGraph().edges.filter(e => e.properties.type !== 'ADMIN_TO'),
    };

    const adminFindings = buildFindings(graphAdmin, makeHistory(), makeConfig());
    const sessionFindings = buildFindings(graphSession, makeHistory(), makeConfig());

    const adminHost = adminFindings.find(f => f.category === 'compromised_host');
    const sessionHost = sessionFindings.find(f => f.category === 'compromised_host');

    if (adminHost && sessionHost) {
      expect(adminHost.risk_score).toBeGreaterThan(sessionHost.risk_score);
    }
  });

  it('maps CVSS to correct severity', () => {
    const vulnFindings = buildFindings(makeGraph(), makeHistory(), makeConfig())
      .filter(f => f.category === 'vulnerability');
    const cve = vulnFindings.find(f => f.title.includes('CVE-2024-1234'));
    expect(cve).toBeDefined();
    expect(cve!.severity).toBe('critical'); // cvss 9.8
  });
});

// ============================================================
// SSRF vulnerability remediation
// ============================================================

describe('vulnerability-specific remediation', () => {
  it('generates SSRF-specific remediation', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'vuln-ssrf', properties: { id: 'vuln-ssrf', type: 'vulnerability', label: 'SSRF', vuln_type: 'ssrf', cvss: 7.5, exploitable: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'webapp-1', properties: { id: 'webapp-1', type: 'webapp', label: 'app.corp.io', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [
        { source: 'webapp-1', target: 'vuln-ssrf', properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } as EdgeProperties },
      ],
    };
    const findings = buildFindings(graph, [], makeConfig());
    const ssrfFinding = findings.find(f => f.title.includes('SSRF'));
    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding!.remediation).toContain('SSRF protections');
    expect(ssrfFinding!.remediation).toContain('IMDSv2');
  });
});

// ============================================================
// Cloud-only engagement report coverage
// ============================================================

describe('buildFindings — cloud engagement', () => {
  it('produces findings for cloud_identity nodes with policies', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'ci-admin', properties: { id: 'ci-admin', type: 'cloud_identity', label: 'arn:aws:iam::123:user/admin', principal_type: 'user', provider: 'aws', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'cp-admin', properties: { id: 'cp-admin', type: 'cloud_policy', label: 'AdministratorAccess', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [
        { source: 'ci-admin', target: 'cp-admin', properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } as EdgeProperties },
      ],
    };
    const findings = buildFindings(graph, [], makeConfig());
    const cloudFindings = findings.filter(f => f.category === 'cloud_exposure');
    expect(cloudFindings.length).toBe(1);
    expect(cloudFindings[0].title).toContain('arn:aws:iam');
    expect(cloudFindings[0].severity).toBe('critical');
    expect(cloudFindings[0].description).toContain('AdministratorAccess');
    expect(cloudFindings[0].remediation).toContain('least-privilege');
  });

  it('produces findings for public cloud_resource nodes', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'cr-bucket', properties: { id: 'cr-bucket', type: 'cloud_resource', label: 's3://public-data', resource_type: 's3_bucket', provider: 'aws', region: 'us-east-1', public: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [],
    };
    const findings = buildFindings(graph, [], makeConfig());
    const cloudFindings = findings.filter(f => f.category === 'cloud_exposure');
    expect(cloudFindings.length).toBe(1);
    expect(cloudFindings[0].title).toContain('s3://public-data');
    expect(cloudFindings[0].severity).toBe('high');
    expect(cloudFindings[0].description).toContain('Publicly accessible');
    expect(cloudFindings[0].remediation).toContain('Block Public Access');
  });

  it('cloud-only engagement does NOT produce zero findings', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'ci-user', properties: { id: 'ci-user', type: 'cloud_identity', label: 'arn:aws:iam::123:user/dev', principal_type: 'user', provider: 'aws', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'cp-s3full', properties: { id: 'cp-s3full', type: 'cloud_policy', label: 'AmazonS3FullAccess', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'cr-bucket', properties: { id: 'cr-bucket', type: 'cloud_resource', label: 's3://sensitive-logs', resource_type: 's3_bucket', provider: 'aws', region: 'us-east-1', public: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [
        { source: 'ci-user', target: 'cp-s3full', properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } as EdgeProperties },
      ],
    };
    const findings = buildFindings(graph, [], makeConfig());
    expect(findings.length).toBeGreaterThan(0);
    const categories = new Set(findings.map(f => f.category));
    expect(categories.has('cloud_exposure')).toBe(true);
  });
});

// ============================================================
// Webapp finding coverage
// ============================================================

describe('buildFindings — webapp engagement', () => {
  it('produces webapp findings with URL/technology context', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'webapp-login', properties: { id: 'webapp-login', type: 'webapp', label: 'https://app.corp.io/login', url: 'https://app.corp.io/login', has_login_form: true, technology: 'Django 4.2', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'vuln-sqli', properties: { id: 'vuln-sqli', type: 'vulnerability', label: 'SQL Injection in /search', vuln_type: 'sqli', cvss: 8.5, exploitable: true, exploit_available: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [
        { source: 'webapp-login', target: 'vuln-sqli', properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } as EdgeProperties },
      ],
    };
    const findings = buildFindings(graph, [], makeConfig());
    const webFindings = findings.filter(f => f.category === 'webapp');
    expect(webFindings.length).toBe(1);
    expect(webFindings[0].title).toContain('https://app.corp.io/login');
    expect(webFindings[0].description).toContain('Django 4.2');
    expect(webFindings[0].description).toContain('has login form');
    expect(webFindings[0].remediation).toContain('Harden authentication');
  });

  it('webapp with auth edges gets its own finding', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'webapp-portal', properties: { id: 'webapp-portal', type: 'webapp', label: 'https://portal.corp.io', url: 'https://portal.corp.io', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'user-attacker', properties: { id: 'user-attacker', type: 'user', label: 'attacker', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [
        { source: 'user-attacker', target: 'webapp-portal', properties: { type: 'AUTHENTICATED_AS', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } as EdgeProperties },
      ],
    };
    const findings = buildFindings(graph, [], makeConfig());
    const webFindings = findings.filter(f => f.category === 'webapp');
    expect(webFindings.length).toBe(1);
    expect(webFindings[0].description).toContain('Authenticated via');
  });
});

// ============================================================
// Evidence chain linkage for nodes created inside findings
// ============================================================

describe('buildEvidenceChainsForNode — finding-created nodes', () => {
  it('finds evidence via ingested_node_ids in details', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'vuln-new', properties: { id: 'vuln-new', type: 'vulnerability', label: 'New RCE', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [],
    };
    const history: ActivityLogEntry[] = [{
      event_id: 'e-finding-1',
      timestamp: '2026-01-01T06:00:00Z',
      description: 'Finding reported: 1 nodes, 0 edges',
      action_id: 'act-scan',
      event_type: 'finding_reported' as any,
      tool_name: 'nuclei',
      target_node_ids: [],
      linked_finding_ids: ['finding-uuid-abc'],
      details: {
        ingested_node_ids: ['vuln-new'],
        evidence_type: 'command_output',
        evidence_content: 'GET /vuln HTTP/1.1\n200 OK',
        raw_output: '[nuclei] vuln-new detected at /vuln',
      },
    }];

    const chains = buildEvidenceChainsForNode('vuln-new', graph, history);
    expect(chains.length).toBeGreaterThanOrEqual(1);
    const chain = chains.find(c => c.action_id === 'act-scan');
    expect(chain).toBeDefined();
    expect(chain!.tool).toBe('nuclei');
    expect(chain!.evidence_content).toContain('GET /vuln');
    expect(chain!.raw_output).toContain('nuclei');
  });

  it('finds evidence via target_node_ids when finding populates them', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'ci-role', properties: { id: 'ci-role', type: 'cloud_identity', label: 'role/S3Admin', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [],
    };
    const history: ActivityLogEntry[] = [{
      event_id: 'e-finding-2',
      timestamp: '2026-01-01T07:00:00Z',
      description: 'Finding reported: 1 nodes, 1 edges',
      action_id: 'act-pacu',
      event_type: 'finding_reported' as any,
      tool_name: 'pacu',
      target_node_ids: ['ci-role'],
      linked_finding_ids: ['finding-uuid-xyz'],
      details: {
        ingested_node_ids: ['ci-role'],
      },
    }];

    const chains = buildEvidenceChainsForNode('ci-role', graph, history);
    expect(chains.length).toBeGreaterThanOrEqual(1);
    expect(chains[0].tool).toBe('pacu');
  });
});

// ============================================================
// Evidence rendering in full report
// ============================================================

describe('generateFullReport — evidence content rendering', () => {
  it('renders evidence_content and raw_output in markdown', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'host-ev', properties: { id: 'host-ev', type: 'host', label: '10.10.10.99', ip: '10.10.10.99', os: 'Linux', alive: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'user-ev', properties: { id: 'user-ev', type: 'user', label: 'root', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [
        { source: 'user-ev', target: 'host-ev', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } as EdgeProperties },
      ],
    };
    const history: ActivityLogEntry[] = [{
      event_id: 'e-ev',
      timestamp: '2026-01-01T05:00:00Z',
      description: 'Root access obtained via SSH',
      action_id: 'act-root',
      event_type: 'action_completed' as any,
      tool_name: 'ssh',
      target_node_ids: ['host-ev'],
      details: {
        evidence_type: 'command_output',
        evidence_content: 'uid=0(root) gid=0(root)',
        evidence_filename: 'id-output.txt',
        raw_output: 'root@target:~# id\nuid=0(root) gid=0(root)',
      },
    }];

    const input: ReportInput = {
      config: makeConfig(),
      graph,
      history: history as ActivityLogEntry[],
      agents: [],
    };
    const report = generateFullReport(input, { include_evidence: true });
    expect(report).toContain('uid=0(root)');
    expect(report).toContain('id-output.txt');
    expect(report).toContain('Raw output (truncated)');
  });
});

// ============================================================
// buildAllEvidenceChains includes cloud/webapp
// ============================================================

describe('buildAllEvidenceChains — expanded coverage', () => {
  it('includes cloud_identity and webapp nodes', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'ci-1', properties: { id: 'ci-1', type: 'cloud_identity', label: 'ci-1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'cr-1', properties: { id: 'cr-1', type: 'cloud_resource', label: 'cr-1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
        { id: 'wa-1', properties: { id: 'wa-1', type: 'webapp', label: 'wa-1', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      ],
      edges: [],
    };
    const history: ActivityLogEntry[] = [
      { event_id: 'e1', timestamp: '2026-01-01T00:00:00Z', description: 'cloud scan', target_node_ids: ['ci-1', 'cr-1', 'wa-1'] },
    ];

    const allChains = buildAllEvidenceChains(graph, history as ActivityLogEntry[]);
    expect(allChains.has('ci-1')).toBe(true);
    expect(allChains.has('cr-1')).toBe(true);
    expect(allChains.has('wa-1')).toBe(true);
  });
});
