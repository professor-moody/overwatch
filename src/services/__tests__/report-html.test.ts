import { describe, it, expect } from 'vitest';
import { renderReportHtml, type HtmlReportData } from '../report-html.js';
import type { ReportFinding, NarrativePhase } from '../report-generator.js';

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
    markdown: '',
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
