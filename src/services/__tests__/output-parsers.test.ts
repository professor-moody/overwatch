import { describe, it, expect } from 'vitest';
import { parseNmapXml, parseCme, parseCertipy, parseOutput, getSupportedParsers } from '../output-parsers.js';

describe('Output Parsers', () => {

  describe('parseNmapXml', () => {
    const sampleNmap = `<?xml version="1.0"?>
<nmaprun>
  <host starttime="1234567890" endtime="1234567899">
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.acme.local" type="PTR"/></hostnames>
    <os><osmatch name="Windows Server 2019" accuracy="95"/></os>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Windows Server" version="2019"/>
      </port>
      <port protocol="tcp" portid="88">
        <state state="open"/>
        <service name="kerberos-sec"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="filtered"/>
        <service name="netbios-ssn"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.10.10.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

    it('extracts host nodes from nmap XML', () => {
      const finding = parseNmapXml(sampleNmap);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(2);
      expect(hosts[0].ip).toBe('10.10.10.5');
      expect(hosts[0].hostname).toBe('dc01.acme.local');
      expect(hosts[0].os).toBe('Windows Server 2019');
    });

    it('extracts service nodes for open ports', () => {
      const finding = parseNmapXml(sampleNmap);
      const services = finding.nodes.filter(n => n.type === 'service');
      // 3 open ports on first host + 1 on second = 4 (filtered port excluded)
      expect(services.length).toBe(4);
      expect(services.some(s => s.port === 445)).toBe(true);
      expect(services.some(s => s.port === 139)).toBe(false); // filtered
    });

    it('creates RUNS edges from hosts to services', () => {
      const finding = parseNmapXml(sampleNmap);
      const runsEdges = finding.edges.filter(e => e.properties.type === 'RUNS');
      expect(runsEdges.length).toBe(4);
    });

    it('extracts version and banner info', () => {
      const finding = parseNmapXml(sampleNmap);
      const httpSvc = finding.nodes.find(n => n.type === 'service' && n.port === 80);
      expect(httpSvc).toBeDefined();
      expect(httpSvc!.version).toContain('Apache');
      expect(httpSvc!.banner).toBe('Ubuntu');
    });

    it('normalizes nmap service names to match inference rules', () => {
      const finding = parseNmapXml(sampleNmap);
      const services = finding.nodes.filter(n => n.type === 'service');
      const svcNames = services.map(s => s.service_name);
      // Raw nmap names should be normalized
      expect(svcNames).toContain('smb');         // was microsoft-ds
      expect(svcNames).toContain('kerberos');     // was kerberos-sec
      expect(svcNames).toContain('rdp');          // was ms-wbt-server
      expect(svcNames).not.toContain('microsoft-ds');
      expect(svcNames).not.toContain('kerberos-sec');
      expect(svcNames).not.toContain('ms-wbt-server');
    });

    it('handles empty XML gracefully', () => {
      const finding = parseNmapXml('<nmaprun></nmaprun>');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });
  });

  describe('parseCme', () => {
    it('extracts admin access from Pwn3d! output', () => {
      const output = `SMB  10.10.10.5  445  ACME\\jdoe  [+]  (Pwn3d!)`;
      const finding = parseCme(output);

      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].ip).toBe('10.10.10.5');

      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].username).toBe('jdoe');

      const adminEdges = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1);
    });

    it('extracts valid auth from + status', () => {
      const output = `SMB  10.10.10.5  445  ACME\\scanner  [+]  Windows Server 2019`;
      const finding = parseCme(output);

      const sessionEdges = finding.edges.filter(e => e.properties.type === 'HAS_SESSION');
      expect(sessionEdges.length).toBe(1);
    });

    it('handles multi-line output', () => {
      const output = [
        'SMB  10.10.10.5  445  ACME\\admin  [+]  (Pwn3d!)',
        'SMB  10.10.10.6  445  ACME\\admin  [+]  Windows Server 2016',
        'SMB  10.10.10.7  445  ACME\\admin  [-]  Access denied',
      ].join('\n');

      const finding = parseCme(output);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(3); // All matched hosts are recorded

      // But only successful auth produces edges
      const adminEdges = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1); // Only Pwn3d! line
      const sessionEdges = finding.edges.filter(e => e.properties.type === 'HAS_SESSION');
      expect(sessionEdges.length).toBe(2); // Both [+] lines produce session edges
    });

    it('handles empty output', () => {
      const finding = parseCme('');
      expect(finding.nodes.length).toBe(0);
    });
  });

  describe('parseCertipy', () => {
    it('extracts certificate templates from JSON', () => {
      const data = {
        'Certificate Authorities': {
          'ACME-CA': { 'CA Name': 'ACME-CA' },
        },
        'Certificate Templates': {
          'UserTemplate': {
            'Enrollee Supplies Subject': true,
            'Client Authentication': true,
            'Extended Key Usage': ['Client Authentication'],
            '[!] Vulnerabilities': {
              'ESC1': { 'Description': 'Enrollee supplies subject' },
            },
            'Enrollment Permissions': {
              'Enrollment Rights': ['ACME\\Domain Users'],
            },
          },
        },
      };

      const finding = parseCertipy(JSON.stringify(data));
      const certs = finding.nodes.filter(n => n.type === 'certificate');
      expect(certs.length).toBe(2); // CA + template

      const escEdges = finding.edges.filter(e => e.properties.type === 'ESC1');
      expect(escEdges.length).toBe(1);
    });

    it('handles non-JSON certipy output', () => {
      const output = 'Template Name : VulnTemplate\nSome other data\nTemplate Name : SafeTemplate';
      const finding = parseCertipy(output);
      const certs = finding.nodes.filter(n => n.type === 'certificate');
      expect(certs.length).toBe(2);
    });

    it('handles empty JSON', () => {
      const finding = parseCertipy('{}');
      expect(finding.nodes.length).toBe(0);
    });
  });

  describe('parseOutput', () => {
    it('dispatches to correct parser by name', () => {
      const finding = parseOutput('nmap', '<nmaprun></nmaprun>');
      expect(finding).not.toBeNull();
    });

    it('returns null for unknown tool', () => {
      const finding = parseOutput('unknown-tool', 'some output');
      expect(finding).toBeNull();
    });

    it('supports aliases', () => {
      expect(parseOutput('cme', '')).not.toBeNull();
      expect(parseOutput('nxc', '')).not.toBeNull();
      expect(parseOutput('nmap-xml', '<nmaprun></nmaprun>')).not.toBeNull();
    });
  });

  describe('getSupportedParsers', () => {
    it('returns a list of supported parser names', () => {
      const parsers = getSupportedParsers();
      expect(parsers).toContain('nmap');
      expect(parsers).toContain('cme');
      expect(parsers).toContain('certipy');
      expect(parsers.length).toBeGreaterThan(3);
    });
  });
});
