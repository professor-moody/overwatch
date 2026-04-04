import { describe, it, expect } from 'vitest';
import { renderReportHtml, inlineMarkdownToHtml, type HtmlReportData, type HtmlRetrospective } from '../report-html.js';
import type { ReportFinding, NarrativePhase, EvidenceChain } from '../report-generator.js';
import type { CredentialChain } from '../retrospective.js';

function makeFinding(overrides: Partial<ReportFinding> = {}): ReportFinding {
  return {
    id: 'f-1',
    title: 'Test Finding',
    severity: 'high',
    category: 'vulnerability',
    description: 'A test finding description',
    affected_assets: ['10.10.10.1'],
    evidence: [],
    remediation: 'Patch the system',
    risk_score: 7.5,
    ...overrides,
  };
}

function makeReportData(overrides: Partial<HtmlReportData> = {}): HtmlReportData {
  return {
    config: {
      id: 'eng-001',
      name: 'Test Engagement',
      created_at: '2026-03-20T00:00:00Z',
      scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
      objectives: [
        { id: 'obj-1', description: 'Obtain domain admin', achieved: true, achieved_at: '2026-03-21T12:00:00Z' },
        { id: 'obj-2', description: 'Exfiltrate data', achieved: false },
      ],
      opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    } as any,
    graph: { nodes: [], edges: [] },
    findings: [],
    narrative: [],
    ...overrides,
  };
}

describe('renderReportHtml', () => {
  it('produces valid HTML structure', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html lang="en"');
    expect(html).toContain('<head>');
    expect(html).toContain('<body>');
    expect(html).toContain('</html>');
  });

  it('includes engagement name and id', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).toContain('Test Engagement');
    expect(html).toContain('eng-001');
  });

  it('renders TOC by default', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).toContain('id="toc"');
    expect(html).toContain('Table of Contents');
  });

  it('omits TOC when include_toc is false', () => {
    const html = renderReportHtml(makeReportData(), { include_toc: false });
    expect(html).not.toContain('id="toc"');
  });

  it('sets data-theme attribute', () => {
    const light = renderReportHtml(makeReportData());
    expect(light).toContain('data-theme="light"');

    const dark = renderReportHtml(makeReportData(), { theme: 'dark' });
    expect(dark).toContain('data-theme="dark"');
  });

  it('renders objectives with achieved/pending badges', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).toContain('Obtain domain admin');
    expect(html).toContain('badge-success');
    expect(html).toContain('Exfiltrate data');
    expect(html).toContain('badge-pending');
  });

  it('shows scope CIDRs and domains', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).toContain('10.10.10.0/24');
    expect(html).toContain('test.local');
  });
});

describe('esc (XSS escaping)', () => {
  it('escapes HTML special characters in engagement name', () => {
    const data = makeReportData();
    (data.config as any).name = '<script>alert("xss")</script>';
    const html = renderReportHtml(data);
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  });

  it('escapes ampersands and angle brackets in finding titles', () => {
    const data = makeReportData({
      findings: [makeFinding({ title: 'SQL Injection via param <id> & "name"' })],
    });
    const html = renderReportHtml(data);
    expect(html).toContain('SQL Injection via param &lt;id&gt; &amp; &quot;name&quot;');
  });
});

describe('severity rendering', () => {
  it('renders severity badge for each finding', () => {
    const findings: ReportFinding[] = [
      makeFinding({ id: 'f-c', title: 'Critical Bug', severity: 'critical', risk_score: 9.5 }),
      makeFinding({ id: 'f-h', title: 'High Bug', severity: 'high', risk_score: 7.0 }),
      makeFinding({ id: 'f-m', title: 'Medium Bug', severity: 'medium', risk_score: 5.0 }),
      makeFinding({ id: 'f-l', title: 'Low Bug', severity: 'low', risk_score: 2.0 }),
      makeFinding({ id: 'f-i', title: 'Info Item', severity: 'info', risk_score: 1.0 }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));

    expect(html).toContain('severity-critical');
    expect(html).toContain('severity-high');
    expect(html).toContain('severity-medium');
    expect(html).toContain('severity-low');
    expect(html).toContain('severity-info');

    expect(html).toContain('CRITICAL');
    expect(html).toContain('HIGH');
    expect(html).toContain('MEDIUM');
    expect(html).toContain('LOW');
    expect(html).toContain('INFO');
  });

  it('renders correct severity counts in executive summary', () => {
    const findings: ReportFinding[] = [
      makeFinding({ id: 'f-1', severity: 'critical', risk_score: 9.0 }),
      makeFinding({ id: 'f-2', severity: 'critical', risk_score: 9.5 }),
      makeFinding({ id: 'f-3', severity: 'high', risk_score: 7.0 }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));

    const criticalMatch = html.match(/severity-card severity-critical.*?<span class="sev-count">(\d+)<\/span>/s);
    expect(criticalMatch?.[1]).toBe('2');

    const highMatch = html.match(/severity-card severity-high.*?<span class="sev-count">(\d+)<\/span>/s);
    expect(highMatch?.[1]).toBe('1');
  });

  it('shows no-findings message when findings are empty', () => {
    const html = renderReportHtml(makeReportData({ findings: [] }));
    expect(html).toContain('No significant findings were identified');
  });
});

describe('evidence toggle', () => {
  it('includes evidence toggle script', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).toContain('evidence-toggle');
    expect(html).toContain('addEventListener');
    expect(html).toContain('Show Evidence');
  });

  it('renders evidence button when finding has evidence', () => {
    const findings = [
      makeFinding({
        evidence: [
          { claim: 'Port 22 open', tool: 'nmap', source_nodes: ['n1'], target_nodes: ['n2'], timestamp: '2026-03-21T10:00:00Z' },
        ],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    expect(html).toContain('<button class="evidence-toggle">Show Evidence</button>');
    expect(html).toContain('Port 22 open');
    expect(html).toContain('(nmap)');
  });

  it('omits evidence section when finding has no evidence', () => {
    const findings = [makeFinding({ evidence: [] })];
    const html = renderReportHtml(makeReportData({ findings }));
    const findingSection = html.split('id="finding-0"')[1]?.split('</div>\n    </div>')[0] ?? '';
    expect(findingSection).not.toContain('<button class="evidence-toggle">');
  });
});

describe('narrative rendering', () => {
  it('renders narrative phases', () => {
    const narrative: NarrativePhase[] = [
      { name: 'Reconnaissance', start_time: '2026-03-20T08:00:00Z', paragraphs: ['Scanned the perimeter.'] },
      { name: 'Exploitation', paragraphs: ['Exploited CVE-2025-1234.'] },
    ];
    const html = renderReportHtml(makeReportData({ narrative }));
    expect(html).toContain('Reconnaissance');
    expect(html).toContain('Scanned the perimeter.');
    expect(html).toContain('Exploitation');
    expect(html).toContain('Exploited CVE-2025-1234.');
  });

  it('omits narrative section when no phases exist', () => {
    const html = renderReportHtml(makeReportData({ narrative: [] }));
    expect(html).not.toContain('id="attack-narrative"');
  });
});

describe('evidence content rendering', () => {
  function makeEvidenceChain(overrides: Partial<EvidenceChain> = {}): EvidenceChain {
    return {
      claim: 'Found open port',
      source_nodes: ['n1'],
      target_nodes: ['n2'],
      ...overrides,
    };
  }

  it('renders evidence_content in a pre block when present', () => {
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({
          evidence_content: 'uid=0(root) gid=0(root)',
          tool: 'ssh',
        })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    expect(html).toContain('<pre class="evidence-content">');
    expect(html).toContain('uid=0(root)');
  });

  it('renders raw_output in a collapsible details block', () => {
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({
          raw_output: 'root@target:~# id\nuid=0(root)',
          tool: 'ssh',
        })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    expect(html).toContain('<details>');
    expect(html).toContain('<summary>Raw Output</summary>');
    expect(html).toContain('root@target:~# id');
  });

  it('renders evidence_filename as a label', () => {
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({
          evidence_filename: 'id-output.txt',
          tool: 'ssh',
        })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    expect(html).toContain('<div class="evidence-file">File: id-output.txt</div>');
  });

  it('truncates evidence_content beyond 2048 chars', () => {
    const longContent = 'A'.repeat(3000);
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({ evidence_content: longContent })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    const preMatch = html.match(/<pre class="evidence-content">([\s\S]*?)<\/pre>/);
    expect(preMatch).toBeDefined();
    expect(preMatch![1].length).toBeLessThanOrEqual(2048 + 50);
  });

  it('truncates evidence_content beyond 30 lines', () => {
    const manyLines = Array.from({ length: 50 }, (_, i) => `line ${i}`).join('\n');
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({ evidence_content: manyLines })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    const preMatch = html.match(/<pre class="evidence-content">([\s\S]*?)<\/pre>/);
    expect(preMatch).toBeDefined();
    const renderedLines = preMatch![1].split('\n');
    expect(renderedLines.length).toBeLessThanOrEqual(30);
  });

  it('escapes HTML in evidence_content', () => {
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({
          evidence_content: '<script>alert("xss")</script>',
        })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('escapes HTML in raw_output', () => {
    const findings = [
      makeFinding({
        evidence: [makeEvidenceChain({
          raw_output: '<img onerror=alert(1) src=x>',
        })],
      }),
    ];
    const html = renderReportHtml(makeReportData({ findings }));
    expect(html).not.toContain('<img onerror');
    expect(html).toContain('&lt;img onerror');
  });
});

describe('inlineMarkdownToHtml', () => {
  it('converts **bold** to <strong>', () => {
    expect(inlineMarkdownToHtml('Use **strong** auth')).toBe('Use <strong>strong</strong> auth');
  });

  it('converts *italic* to <em>', () => {
    expect(inlineMarkdownToHtml('This is *important*')).toBe('This is <em>important</em>');
  });

  it('converts `code` to <code>', () => {
    expect(inlineMarkdownToHtml('Run `whoami` first')).toBe('Run <code>whoami</code> first');
  });

  it('handles mixed bold, italic, and code', () => {
    const result = inlineMarkdownToHtml('**bold** and *italic* and `code`');
    expect(result).toContain('<strong>bold</strong>');
    expect(result).toContain('<em>italic</em>');
    expect(result).toContain('<code>code</code>');
  });

  it('escapes HTML in plain text portions', () => {
    const result = inlineMarkdownToHtml('Use <script> tag');
    expect(result).not.toContain('<script>');
    expect(result).toContain('&lt;script&gt;');
  });

  it('escapes HTML inside bold markers', () => {
    const result = inlineMarkdownToHtml('**<script>alert(1)</script>**');
    expect(result).not.toContain('<script>');
    expect(result).toContain('<strong>&lt;script&gt;');
  });

  it('escapes HTML inside code markers', () => {
    const result = inlineMarkdownToHtml('`<img onerror=alert(1)>`');
    expect(result).not.toContain('<img');
    expect(result).toContain('<code>&lt;img');
  });

  it('returns plain escaped text when no markdown present', () => {
    expect(inlineMarkdownToHtml('no markdown here')).toBe('no markdown here');
  });
});

// ============================================================
// New section tests
// ============================================================

describe('credential chains section', () => {
  it('renders credential chains when present', () => {
    const chains: CredentialChain[] = [
      { chain: ['n1', 'n2', 'n3'], labels: ['admin', 'svc_acct', 'da_user'], methods: ['secretsdump', 'kerberoast'] },
    ];
    const html = renderReportHtml(makeReportData({ credentialChains: chains }));
    expect(html).toContain('id="credential-chains"');
    expect(html).toContain('Credential Chains');
    expect(html).toContain('admin');
    expect(html).toContain('secretsdump');
    expect(html).toContain('da_user');
  });

  it('omits credential chains section when not provided', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).not.toContain('id="credential-chains"');
  });

  it('omits credential chains section when array is empty', () => {
    const html = renderReportHtml(makeReportData({ credentialChains: [] }));
    expect(html).not.toContain('id="credential-chains"');
  });

  it('adds TOC entry for credential chains', () => {
    const chains: CredentialChain[] = [
      { chain: ['n1', 'n2'], labels: ['a', 'b'], methods: ['dump'] },
    ];
    const html = renderReportHtml(makeReportData({ credentialChains: chains }));
    expect(html).toContain('href="#credential-chains"');
  });
});

describe('discovery summary section', () => {
  it('renders node and edge type tables', () => {
    const html = renderReportHtml(makeReportData({
      discoveryStats: {
        nodesByType: { host: 5, credential: 3 },
        edgesByType: { HAS_SESSION: 2, OWNS_CRED: 4 },
        confirmed: 4,
        inferred: 2,
      },
    }));
    expect(html).toContain('id="discovery-summary"');
    expect(html).toContain('Discovery Summary');
    expect(html).toContain('host');
    expect(html).toContain('credential');
    expect(html).toContain('HAS_SESSION');
    expect(html).toContain('4 confirmed');
    expect(html).toContain('2 inferred');
  });

  it('omits discovery summary when not provided', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).not.toContain('id="discovery-summary"');
  });
});

describe('agent activity section', () => {
  it('renders agent stats when total > 0', () => {
    const html = renderReportHtml(makeReportData({
      agents: { total: 10, completed: 8, failed: 2 },
    }));
    expect(html).toContain('id="agent-activity"');
    expect(html).toContain('Agent Activity');
    expect(html).toContain('10');
    expect(html).toContain('8');
    expect(html).toContain('2');
  });

  it('omits agent activity when total is 0', () => {
    const html = renderReportHtml(makeReportData({
      agents: { total: 0, completed: 0, failed: 0 },
    }));
    expect(html).not.toContain('id="agent-activity"');
  });

  it('omits agent activity when not provided', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).not.toContain('id="agent-activity"');
  });
});

describe('retrospective section', () => {
  it('renders context improvements and inference suggestions', () => {
    const retro: HtmlRetrospective = {
      context_improvements: {
        frontier_observations: [{ area: 'network', observation: 'Sparse scanning', confidence: 'high' }],
        context_gaps: [{ area: 'AD', gap: 'No LDAP enum', recommendation: 'Run ldapsearch' }],
      },
      inference_suggestions: [{ rule: { name: 'kerberoast_chain' }, evidence: 'SPN found but not roasted' }],
      skill_gaps: { missing_skills: ['cloud_enum'], failed_techniques: ['zerologon'] },
      trace_quality: { total_actions: 50, with_frontier_id: 45, with_action_id: 48, coverage_pct: 90.0 },
    };
    const html = renderReportHtml(makeReportData({ retrospective: retro }));
    expect(html).toContain('id="retrospective"');
    expect(html).toContain('Retrospective Findings');
    expect(html).toContain('Sparse scanning');
    expect(html).toContain('kerberoast_chain');
    expect(html).toContain('cloud_enum');
    expect(html).toContain('zerologon');
    expect(html).toContain('90.0%');
  });

  it('omits retrospective when not provided', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).not.toContain('id="retrospective"');
  });

  it('renders empty string when retrospective has no content', () => {
    const html = renderReportHtml(makeReportData({ retrospective: {} }));
    expect(html).not.toContain('Retrospective Findings');
  });
});

describe('activity timeline section', () => {
  it('renders timeline table', () => {
    const timeline = [
      { timestamp: '2026-03-20T08:00:00Z', description: 'Started nmap scan', agent_id: 'agent-1' },
      { timestamp: '2026-03-20T09:00:00Z', description: 'Found open port 22' },
    ];
    const html = renderReportHtml(makeReportData({ timeline }));
    expect(html).toContain('id="activity-timeline"');
    expect(html).toContain('Activity Timeline');
    expect(html).toContain('Started nmap scan');
    expect(html).toContain('agent-1');
    expect(html).toContain('Found open port 22');
  });

  it('omits timeline when not provided', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).not.toContain('id="activity-timeline"');
  });

  it('omits timeline when array is empty', () => {
    const html = renderReportHtml(makeReportData({ timeline: [] }));
    expect(html).not.toContain('id="activity-timeline"');
  });
});

describe('recommendations section', () => {
  it('renders ordered list of recommendations', () => {
    const recommendations = [
      '**Patch CVE-2025-1234** on all affected hosts.',
      '**Rotate all compromised credentials** immediately.',
    ];
    const html = renderReportHtml(makeReportData({ recommendations }));
    expect(html).toContain('id="recommendations"');
    expect(html).toContain('Recommendations');
    expect(html).toContain('<ol>');
    expect(html).toContain('Patch CVE-2025-1234');
    expect(html).toContain('Rotate all compromised credentials');
  });

  it('omits recommendations when not provided', () => {
    const html = renderReportHtml(makeReportData());
    expect(html).not.toContain('id="recommendations"');
  });

  it('omits recommendations when array is empty', () => {
    const html = renderReportHtml(makeReportData({ recommendations: [] }));
    expect(html).not.toContain('id="recommendations"');
  });
});
