import { describe, it, expect } from 'vitest';
import { parseNmapXml, parseNxc, parseCertipy, parseSecretsdump, parseKerbrute, parseHashcat, parseResponder, parseLdapsearch, parseEnum4linux, parseRubeus, parseWebDirEnum, parseOutput, getSupportedParsers, parseTestssl, parseNuclei, parseLinpeas, parseNikto, parsePacu, parseProwler, parseBurp, parseZap, parseSqlmap, parseWpscan, parseScoutSuite, parseCloudFox, parseTerraformState, parseEnumerateIam } from '../parsers/index.js';

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

    it('infers OS from service banners when osmatch is absent', () => {
      const noOsNmap = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Microsoft Windows" version="Server 2019"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.10.10.21" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5"/>
      </port>
    </ports>
  </host>
</nmaprun>`;
      const finding = parseNmapXml(noOsNmap);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      const winHost = hosts.find(h => h.ip === '10.10.10.20');
      const linuxHost = hosts.find(h => h.ip === '10.10.10.21');
      expect(winHost?.os).toBe('Windows');
      expect(linuxHost?.os).toBe('Linux/Ubuntu');
    });

    it('does not override osmatch with banner inference', () => {
      // The original sampleNmap has osmatch="Windows Server 2019" — banner inference should not override
      const finding = parseNmapXml(sampleNmap);
      const host = finding.nodes.find(n => n.ip === '10.10.10.5');
      expect(host?.os).toBe('Windows Server 2019');
    });

    it('parses IPv6-only hosts', () => {
      const ipv6Nmap = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="fe80::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
    </ports>
  </host>
</nmaprun>`;
      const finding = parseNmapXml(ipv6Nmap);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].ip).toBe('fe80::1');
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      expect(services[0].port).toBe(22);
    });
  });

  describe('parseNxc', () => {
    it('extracts admin access from Pwn3d! output', () => {
      const output = `SMB  10.10.10.5  445  DC01  [+] ACME\\jdoe (Pwn3d!)`;
      const finding = parseNxc(output);

      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].ip).toBe('10.10.10.5');

      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].username).toBe('jdoe');

      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services).toHaveLength(1);
      expect(services[0].service_name).toBe('smb');
      expect(services[0].port).toBe(445);

      const runsEdges = finding.edges.filter(e => e.properties.type === 'RUNS');
      expect(runsEdges).toHaveLength(1);

      const adminEdges = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1);
    });

    it('extracts valid auth from + status', () => {
      const output = `SMB  10.10.10.5  445  DC01  [+] ACME\\scanner Windows Server 2019`;
      const finding = parseNxc(output);

      const validOnEdges = finding.edges.filter(e => e.properties.type === 'VALID_ON');
      expect(validOnEdges.length).toBe(1);
      expect(finding.nodes.some(n => n.type === 'service' && n.service_name === 'smb')).toBe(true);
    });

    it('handles multi-line output', () => {
      const output = [
        'SMB  10.10.10.5  445  DC01  [+] ACME\\admin (Pwn3d!)',
        'SMB  10.10.10.6  445  SRV01  [+] ACME\\admin Windows Server 2016',
        'SMB  10.10.10.7  445  WEB01  [-] ACME\\admin Access denied',
      ].join('\n');

      const finding = parseNxc(output);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(3); // All matched hosts are recorded

      // Successful auth edges
      const adminEdges = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1); // Only Pwn3d! line
      const validOnEdges = finding.edges.filter(e => e.properties.type === 'VALID_ON');
      expect(validOnEdges.length).toBe(2); // Both [+] lines produce VALID_ON edges

      // F03: Failed auth produces TESTED_CRED edge
      const testedEdges = finding.edges.filter(e => e.properties.type === 'TESTED_CRED');
      expect(testedEdges.length).toBe(1); // The [-] line
      expect(testedEdges[0].properties.confidence).toBe(0.0);
    });

    it('connects enumerated shares back to the host and SMB service', () => {
      const output = `SMB  10.10.10.5  445  DC01  IPC$  READ, WRITE`;
      const finding = parseNxc(output);

      const services = finding.nodes.filter(n => n.type === 'service');
      const shares = finding.nodes.filter(n => n.type === 'share');
      expect(services).toHaveLength(1);
      expect(shares).toHaveLength(1);

      const runsEdges = finding.edges.filter(e => e.properties.type === 'RUNS');
      const relatedEdges = finding.edges.filter(e => e.properties.type === 'RELATED');
      expect(runsEdges).toHaveLength(1);
      expect(relatedEdges).toHaveLength(1);
      expect(relatedEdges[0].target).toBe(shares[0].id);
    });

    it('deduplicates repeated host, service, and share discoveries', () => {
      const output = [
        'SMB  10.10.10.5  445  DC01  [+] ACME\\scanner Windows Server 2019',
        'SMB  10.10.10.5  445  DC01  [+] ACME\\scanner Windows Server 2019',
        'SMB  10.10.10.5  445  DC01  IPC$  READ',
        'SMB  10.10.10.5  445  DC01  IPC$  READ',
      ].join('\n');
      const finding = parseNxc(output);

      expect(finding.nodes.filter(n => n.type === 'host')).toHaveLength(1);
      expect(finding.nodes.filter(n => n.type === 'service')).toHaveLength(1);
      expect(finding.nodes.filter(n => n.type === 'share')).toHaveLength(1);
      expect(finding.edges.filter(e => e.properties.type === 'RUNS')).toHaveLength(1);
      expect(finding.edges.filter(e => e.properties.type === 'VALID_ON')).toHaveLength(1);
      expect(finding.edges.filter(e => e.properties.type === 'RELATED')).toHaveLength(1);
    });

    it('handles empty output', () => {
      const finding = parseNxc('');
      expect(finding.nodes.length).toBe(0);
    });

    it('parses IPv6 SMB output', () => {
      const output = `SMB  fe80::1  445  DC01  [+] ACME\\admin (Pwn3d!)`;
      const finding = parseNxc(output);

      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].id).toContain('host-');

      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      expect(services[0].service_name).toBe('smb');

      const adminEdges = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1);
    });

    it('F03: failed auth [-] creates TESTED_CRED edge with confidence 0.0', () => {
      const output = `SMB  10.10.10.5  445  DC01  [-] ACME\\testuser STATUS_LOGON_FAILURE`;
      const finding = parseNxc(output);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].username).toBe('testuser');
      const testedEdges = finding.edges.filter(e => e.properties.type === 'TESTED_CRED');
      expect(testedEdges.length).toBe(1);
      expect(testedEdges[0].properties.confidence).toBe(0.0);
    });

    it('F03: failed auth does not produce VALID_ON or ADMIN_TO edges', () => {
      const output = `SMB  10.10.10.5  445  DC01  [-] ACME\\admin ACCESS_DENIED`;
      const finding = parseNxc(output);
      const validOn = finding.edges.filter(e => e.properties.type === 'VALID_ON');
      const adminTo = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(validOn.length).toBe(0);
      expect(adminTo.length).toBe(0);
    });

    it('extracts host metadata from [*] info lines', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False) (Null Auth:True)',
      ].join('\n');
      const finding = parseNxc(output);

      const host = finding.nodes.find(n => n.type === 'host');
      expect(host).toBeDefined();
      expect(host!.hostname).toBe('WINTERFELL');
      expect(host!.domain_name).toBe('north.sevenkingdoms.local');
      expect(host!.os).toBe('Windows 10 / Server 2019 Build 17763 x64');
      expect(host!.null_session).toBe(true);
      expect(host!.label).toBe('WINTERFELL');

      const svc = finding.nodes.find(n => n.type === 'service');
      expect(svc).toBeDefined();
      expect(svc!.smb_signing).toBe(true);
      expect(svc!.smbv1).toBe(false);
    });

    it('creates NULL_SESSION edge when Null Auth is True', () => {
      const output = [
        'SMB         10.3.10.12      445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True) (Null Auth:True)',
      ].join('\n');
      const finding = parseNxc(output);

      const nullEdges = finding.edges.filter(e => e.properties.type === 'NULL_SESSION');
      expect(nullEdges).toHaveLength(1);
      expect(nullEdges[0].source).toBe('host-10-3-10-12');
      expect(nullEdges[0].target).toBe('svc-10-3-10-12-445');
    });

    it('does not create NULL_SESSION edge when Null Auth is False', () => {
      const output = [
        'SMB         10.3.10.13      445    CASTELBLACK      [*] Windows 10 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False) (Null Auth:False)',
      ].join('\n');
      const finding = parseNxc(output);

      const nullEdges = finding.edges.filter(e => e.properties.type === 'NULL_SESSION');
      expect(nullEdges).toHaveLength(0);
    });

    it('extracts users from --users enumeration table', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False) (Null Auth:True)',
        'SMB         10.3.10.11      445    WINTERFELL       [+] north.sevenkingdoms.local\\:',
        'SMB         10.3.10.11      445    WINTERFELL       -Username-                    -Last PW Set-       -BadPW- -Description-',
        'SMB         10.3.10.11      445    WINTERFELL       Guest                         <never>             0       Built-in account for guest access to the computer/domain',
        'SMB         10.3.10.11      445    WINTERFELL       arya.stark                    2025-07-26 19:35:06 0       Arya Stark',
        'SMB         10.3.10.11      445    WINTERFELL       jon.snow                      2025-07-26 19:35:29 0       Jon Snow',
        'SMB         10.3.10.11      445    WINTERFELL       sql_svc                       2025-07-26 19:35:38 0       sql service',
        'SMB         10.3.10.11      445    WINTERFELL       [*] Enumerated 4 local users: NORTH',
      ].join('\n');
      const finding = parseNxc(output);

      const users = finding.nodes.filter(n => n.type === 'user');
      // Guest is skipped, so 3 users
      expect(users).toHaveLength(3);
      expect(users.map(u => u.username).sort()).toEqual(['arya.stark', 'jon.snow', 'sql_svc']);

      // Each user has domain from the [*] info line
      expect(users.every(u => u.domain_name === 'north.sevenkingdoms.local')).toBe(true);

      // Each user has MEMBER_OF_DOMAIN edge
      const memberEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(memberEdges).toHaveLength(3);

      // Domain node was created
      const domains = finding.nodes.filter(n => n.type === 'domain');
      expect(domains).toHaveLength(1);
      expect(domains[0].domain_name).toBe('north.sevenkingdoms.local');
    });

    it('extracts password from AD description field', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False) (Null Auth:True)',
        'SMB         10.3.10.11      445    WINTERFELL       [+] north.sevenkingdoms.local\\:',
        'SMB         10.3.10.11      445    WINTERFELL       -Username-                    -Last PW Set-       -BadPW- -Description-',
        'SMB         10.3.10.11      445    WINTERFELL       samwell.tarly                 2025-07-26 19:35:32 0       Samwell Tarly (Password : Heartsbane)',
        'SMB         10.3.10.11      445    WINTERFELL       [*] Enumerated 1 local users: NORTH',
      ].join('\n');
      const finding = parseNxc(output);

      // Credential node
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds).toHaveLength(1);
      expect(creds[0].cred_user).toBe('samwell.tarly');
      expect(creds[0].cred_domain).toBe('north.sevenkingdoms.local');
      expect(creds[0].cred_type).toBe('plaintext');
      expect(creds[0].cred_value).toBe('Heartsbane');

      // OWNS_CRED edge
      const ownsCred = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsCred).toHaveLength(1);

      // User node should also exist with description
      const user = finding.nodes.find(n => n.type === 'user' && n.username === 'samwell.tarly');
      expect(user).toBeDefined();
      expect(user!.description).toBe('Samwell Tarly (Password : Heartsbane)');
    });

    it('handles combined info + users + shares output', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False) (Null Auth:True)',
        'SMB         10.3.10.11      445    WINTERFELL       [+] north.sevenkingdoms.local\\:',
        'SMB         10.3.10.11      445    WINTERFELL       -Username-                    -Last PW Set-       -BadPW- -Description-',
        'SMB         10.3.10.11      445    WINTERFELL       arya.stark                    2025-07-26 19:35:06 0       Arya Stark',
        'SMB         10.3.10.11      445    WINTERFELL       [*] Enumerated 1 local users: NORTH',
        'SMB         10.3.10.11      445    WINTERFELL       IPC$  READ',
      ].join('\n');
      const finding = parseNxc(output);

      // Should have host, service, user, domain, share
      expect(finding.nodes.filter(n => n.type === 'host')).toHaveLength(1);
      expect(finding.nodes.filter(n => n.type === 'service')).toHaveLength(1);
      expect(finding.nodes.filter(n => n.type === 'user')).toHaveLength(1);
      expect(finding.nodes.filter(n => n.type === 'domain')).toHaveLength(1);
      expect(finding.nodes.filter(n => n.type === 'share')).toHaveLength(1);

      // Edges: RUNS, NULL_SESSION, MEMBER_OF_DOMAIN, RELATED
      expect(finding.edges.filter(e => e.properties.type === 'RUNS')).toHaveLength(1);
      expect(finding.edges.filter(e => e.properties.type === 'NULL_SESSION')).toHaveLength(1);
      expect(finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN')).toHaveLength(1);
      expect(finding.edges.filter(e => e.properties.type === 'RELATED')).toHaveLength(1);
    });

    it('extracts Linux OS from SMB info line', () => {
      const output = [
        'SMB  10.10.10.20  445  LINUX01  [*] Linux 5.10.0-kali7-amd64 x86_64 (name:LINUX01) (domain:) (signing:False) (SMBv1:False)',
      ].join('\n');
      const finding = parseNxc(output);

      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].os).toBe('Linux 5.10.0-kali7-amd64 x86_64');
    });

    it('extracts Samba OS from SMB info line', () => {
      const output = [
        'SMB  10.10.10.30  445  SAMBA01  [*] Samba 4.13.13-Debian (name:SAMBA01) (domain:WORKGROUP) (signing:False) (SMBv1:True)',
      ].join('\n');
      const finding = parseNxc(output);

      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].os).toBe('Samba 4.13.13-Debian');
    });

    it('extracts SAM dump hashes from --sam output', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)',
        'SMB         10.3.10.11      445    WINTERFELL       [+] north.sevenkingdoms.local\\admin:Password123',
        'SMB         10.3.10.11      445    WINTERFELL       [+] Dumping SAM hashes',
        'SMB         10.3.10.11      445    WINTERFELL       Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'SMB         10.3.10.11      445    WINTERFELL       jsnow:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
      ].join('\n');
      const finding = parseNxc(output);

      const creds = finding.nodes.filter(n => n.type === 'credential' && n.cred_type === 'ntlm');
      expect(creds).toHaveLength(2);
      expect(creds[0].cred_material_kind).toBe('ntlm_hash');
      expect(creds[0].cred_usable_for_auth).toBe(true);
      expect(creds[0].cred_evidence_kind).toBe('dump');

      // DUMPED_FROM edges
      const dumpEdges = finding.edges.filter(e => e.properties.type === 'DUMPED_FROM');
      expect(dumpEdges).toHaveLength(2);

      // OWNS_CRED edges for SAM
      const ownsEdges = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsEdges.length).toBeGreaterThanOrEqual(2);
    });

    it('extracts LSA secrets from --lsa output', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)',
        'SMB         10.3.10.11      445    WINTERFELL       [+] north.sevenkingdoms.local\\admin:Password123',
        'SMB         10.3.10.11      445    WINTERFELL       [+] Dumping LSA secrets',
        'SMB         10.3.10.11      445    WINTERFELL       NORTH\\svc_backup:BackupP@ss!',
      ].join('\n');
      const finding = parseNxc(output);

      const creds = finding.nodes.filter(n => n.type === 'credential' && n.cred_evidence_kind === 'dump' && n.label?.includes('LSA'));
      expect(creds).toHaveLength(1);
      expect(creds[0].cred_type).toBe('plaintext');
      expect(creds[0].cred_value).toBe('BackupP@ss!');
      expect(creds[0].cred_user).toBe('svc_backup');
    });

    it('extracts spider_plus file listings', () => {
      const output = [
        'SMB         10.3.10.11      445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)',
        'SMB         10.3.10.11      445    WINTERFELL       [*] \\\\10.3.10.11\\Backups\\db_backup.sql (1024)',
        'SMB         10.3.10.11      445    WINTERFELL       [*] \\\\10.3.10.11\\Backups\\config.xml (512)',
        'SMB         10.3.10.11      445    WINTERFELL       [*] \\\\10.3.10.11\\Public\\readme.txt (256)',
      ].join('\n');
      const finding = parseNxc(output);

      const shares = finding.nodes.filter(n => n.type === 'share');
      expect(shares.length).toBeGreaterThanOrEqual(2);
      const backupShare = shares.find(s => s.share_name === 'Backups');
      expect(backupShare).toBeDefined();
      expect(backupShare!.spider_files).toBeDefined();
      expect((backupShare!.spider_files as string[]).length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('parseCertipy', () => {
    it('extracts CA and certificate template infrastructure nodes from JSON', () => {
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
      const cas = finding.nodes.filter(n => n.type === 'ca');
      const templates = finding.nodes.filter(n => n.type === 'cert_template');
      expect(cas.length).toBe(1);
      expect(templates.length).toBe(1);
      expect(cas[0].id).toBe('ca-acme-ca');
      expect(templates[0].id).toBe('cert-template-usertemplate');

      const escEdges = finding.edges.filter(e => e.properties.type === 'ESC1');
      expect(escEdges.length).toBe(1);
      const enrollEdges = finding.edges.filter(e => e.properties.type === 'CAN_ENROLL');
      expect(enrollEdges.length).toBe(1);
      expect(enrollEdges[0].target).toBe('cert-template-usertemplate');
      const principal = finding.nodes.find(n => n.id === 'group-acme-domain-users');
      expect(principal?.type).toBe('group');
    });

    it('deduplicates principals that resolve to the same canonical ID', () => {
      const data = {
        'Certificate Templates': {
          'VulnTemplate': {
            'Enrollee Supplies Subject': true,
            'Client Authentication': true,
            'Extended Key Usage': ['Client Authentication'],
            '[!] Vulnerabilities': {
              'ESC1': { 'Description': 'Enrollee supplies subject' },
            },
            'Enrollment Permissions': {
              'Enrollment Rights': ['ACME\\Domain Users', 'acme\\Domain Users'],
            },
          },
        },
      };

      const finding = parseCertipy(JSON.stringify(data));
      const groups = finding.nodes.filter(n => n.type === 'group');
      expect(groups.length).toBe(1);
      // Both principals resolve to same canonical ID → single ESC1 edge (deduplicated)
      const escEdges = finding.edges.filter(e => e.properties.type === 'ESC1');
      expect(escEdges.length).toBe(1);
      // CAN_ENROLL deduplicates too (same source → same target)
      const enrollEdges = finding.edges.filter(e => e.properties.type === 'CAN_ENROLL');
      expect(enrollEdges.length).toBe(1);
    });

    it('handles non-JSON certipy output', () => {
      const output = 'Template Name : VulnTemplate\nSome other data\nTemplate Name : SafeTemplate';
      const finding = parseCertipy(output);
      const templates = finding.nodes.filter(n => n.type === 'cert_template');
      expect(templates.length).toBe(2);
      expect(templates.some(t => t.id === 'cert-template-vulntemplate')).toBe(true);
    });

    it('handles empty JSON', () => {
      const finding = parseCertipy('{}');
      expect(finding.nodes.length).toBe(0);
    });

    it('creates edges for ESC5 and ESC13 vulnerability types', () => {
      const data = {
        'Certificate Templates': {
          'MisconfigTemplate': {
            'Enrollee Supplies Subject': false,
            '[!] Vulnerabilities': {
              'ESC5': { 'Description': 'PKI object misconfiguration' },
              'ESC13': { 'Description': 'Issuance policy abuse' },
            },
            'Enrollment Permissions': {
              'Enrollment Rights': ['ACME\\Domain Users'],
            },
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const esc5Edges = finding.edges.filter(e => e.properties.type === 'ESC5');
      const esc13Edges = finding.edges.filter(e => e.properties.type === 'ESC13');
      expect(esc5Edges.length).toBe(1);
      expect(esc13Edges.length).toBe(1);
      expect(esc5Edges[0].target).toBe('cert-template-misconfigtemplate');
      expect(esc13Edges[0].target).toBe('cert-template-misconfigtemplate');
      const enrollEdges = finding.edges.filter(e => e.properties.type === 'CAN_ENROLL');
      expect(enrollEdges.length).toBe(1);
    });

    it('creates ISSUED_BY edges from templates to their CA', () => {
      const data = {
        'Certificate Authorities': {
          'ACME-CA': {
            'CA Name': 'ACME-CA',
            'Certificate Templates': ['UserTemplate', 'MachineTemplate'],
          },
        },
        'Certificate Templates': {
          'UserTemplate': {
            'Enrollee Supplies Subject': true,
            'Extended Key Usage': ['Client Authentication'],
          },
          'MachineTemplate': {
            'Enrollee Supplies Subject': false,
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const issuedBy = finding.edges.filter(e => e.properties.type === 'ISSUED_BY');
      expect(issuedBy.length).toBe(2);
      expect(issuedBy[0].source).toBe('cert-template-usertemplate');
      expect(issuedBy[0].target).toBe('ca-acme-ca');
      expect(issuedBy[1].source).toBe('cert-template-machinetemplate');
      expect(issuedBy[1].target).toBe('ca-acme-ca');
    });

    it('creates OPERATES_CA edge from domain to CA when DNS Name present', () => {
      const data = {
        'Certificate Authorities': {
          'ACME-CA': {
            'CA Name': 'ACME-CA',
            'DNS Name': 'dc01.acme.corp',
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const operatesCA = finding.edges.filter(e => e.properties.type === 'OPERATES_CA');
      expect(operatesCA.length).toBe(1);
      expect(operatesCA[0].target).toBe('ca-acme-ca');
      const domainNode = finding.nodes.find(n => n.type === 'domain');
      expect(domainNode).toBeDefined();
      expect(domainNode!.domain_name).toBe('acme.corp');
      expect(operatesCA[0].source).toBe(domainNode!.id);
    });

    it('creates CAN_ENROLL edges even without vulnerabilities', () => {
      const data = {
        'Certificate Templates': {
          'SafeTemplate': {
            'Enrollee Supplies Subject': false,
            'Enrollment Permissions': {
              'Enrollment Rights': ['ACME\\Domain Users'],
            },
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const enrollEdges = finding.edges.filter(e => e.properties.type === 'CAN_ENROLL');
      expect(enrollEdges.length).toBe(1);
      expect(enrollEdges[0].target).toBe('cert-template-safetemplate');
      const escEdges = finding.edges.filter(e => e.properties.type.startsWith('ESC'));
      expect(escEdges.length).toBe(0);
    });

    it('extracts enforce_encrypt_icert_request=false on CA (ESC11)', () => {
      const data = {
        'Certificate Authorities': {
          'ACME-CA': {
            'DNS Name': 'dc01.acme.corp',
            'IF_ENFORCEENCRYPTICERTREQUEST': false,
            'Certificate Templates': [],
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const ca = finding.nodes.find(n => n.type === 'ca');
      expect(ca).toBeDefined();
      expect((ca as Record<string, unknown>).enforce_encrypt_icert_request).toBe(false);
    });

    it('extracts enforce_encrypt_icert_request=true on CA', () => {
      const data = {
        'Certificate Authorities': {
          'ACME-CA': {
            'DNS Name': 'dc01.acme.corp',
            'IF_ENFORCEENCRYPTICERTREQUEST': true,
            'Certificate Templates': [],
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const ca = finding.nodes.find(n => n.type === 'ca');
      expect(ca).toBeDefined();
      expect((ca as Record<string, unknown>).enforce_encrypt_icert_request).toBe(true);
    });

    it('extracts ct_flag_no_security_extension from ESC9 vulnerability (ESC9)', () => {
      const data = {
        'Certificate Templates': {
          'VulnTemplate': {
            'Enrollee Supplies Subject': false,
            '[!] Vulnerabilities': { 'ESC9': { 'Description': 'CT_FLAG_NO_SECURITY_EXTENSION flag set' } },
            'Enrollment Permissions': { 'Enrollment Rights': ['ACME\\Domain Users'] },
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const tmpl = finding.nodes.find(n => n.type === 'cert_template');
      expect(tmpl).toBeDefined();
      expect((tmpl as Record<string, unknown>).ct_flag_no_security_extension).toBe(true);
    });

    it('extracts issuance_policy_oid and group_link from ESC13 template', () => {
      const data = {
        'Certificate Templates': {
          'PolicyTemplate': {
            'Enrollee Supplies Subject': false,
            'msPKI-Certificate-Policy': '1.3.6.1.4.1.311.21.8.999',
            'Issuance Policies': {
              '1.3.6.1.4.1.311.21.8.999': {
                'Linked Group': 'CN=HighPrivGroup,CN=Users,DC=acme,DC=corp',
              },
            },
            'Enrollment Permissions': { 'Enrollment Rights': ['ACME\\Domain Users'] },
          },
        },
      };
      const finding = parseCertipy(JSON.stringify(data));
      const tmpl = finding.nodes.find(n => n.type === 'cert_template');
      expect(tmpl).toBeDefined();
      expect((tmpl as Record<string, unknown>).issuance_policy_oid).toBe('1.3.6.1.4.1.311.21.8.999');
      expect((tmpl as Record<string, unknown>).issuance_policy_group_link).toBe('CN=HighPrivGroup,CN=Users,DC=acme,DC=corp');
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
      expect(parseOutput('nxc', '')).not.toBeNull();
      expect(parseOutput('netexec', '')).not.toBeNull();
      expect(parseOutput('nmap-xml', '<nmaprun></nmaprun>')).not.toBeNull();
      expect(parseOutput('impacket-secretsdump', '')).not.toBeNull();
    });
  });

  describe('getSupportedParsers', () => {
    it('returns a list of supported parser names', () => {
      const parsers = getSupportedParsers();
      expect(parsers).toContain('nmap');
      expect(parsers).toContain('nxc');
      expect(parsers).toContain('certipy');
      expect(parsers).toContain('secretsdump');
      expect(parsers).toContain('kerbrute');
      expect(parsers).toContain('hashcat');
      expect(parsers).toContain('responder');
      expect(parsers.length).toBeGreaterThanOrEqual(10);
    });
  });

  // =============================================
  // Secretsdump Parser
  // =============================================
  describe('parseSecretsdump', () => {
    const sampleSAM = [
      'Impacket v0.11.0 - Copyright 2023 Fortra',
      '',
      '[*] Target system bootKey: 0x1234abcd...',
      '[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)',
      'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
      'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
      'DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
      '[*] Dumping cached domain logon information (domain/username:hash)',
      '[*] Cleaning up...',
    ].join('\n');

    const sampleNTDS = [
      'Impacket v0.11.0 - Copyright 2023 Fortra',
      '',
      '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
      '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
      'Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::',
      'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::',
      'ACME\\jdoe:1103:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
      'DC01$:1000:aad3b435b51404eeaad3b435b51404ee:1111111111111111111111111111111a:::',
      '[*] Kerberos keys grabbed',
      '[*] Cleaning up...',
    ].join('\n');

    it('extracts SAM hashes as credential nodes', () => {
      const finding = parseSecretsdump(sampleSAM);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(3);
      expect(creds[0].cred_type).toBe('ntlm');
      expect(creds[0].cred_user).toBe('Administrator');
    });

    it('extracts NTDS domain credentials', () => {
      const finding = parseSecretsdump(sampleNTDS);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      // 3 user accounts (Administrator, krbtgt, jdoe) — machine account DC01$ skipped
      expect(creds.length).toBe(3);
    });

    it('skips machine accounts ($ suffix)', () => {
      const finding = parseSecretsdump(sampleNTDS);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      const machineAcct = creds.find(c => String(c.cred_user).includes('$'));
      expect(machineAcct).toBeUndefined();
    });

    it('creates user nodes for domain accounts', () => {
      const finding = parseSecretsdump(sampleNTDS);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBeGreaterThanOrEqual(3);
    });

    it('supports DOMAIN/user account formatting', () => {
      const slashSample = [
        'ACME/jdoe:1103:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
      ].join('\n');
      const finding = parseSecretsdump(slashSample);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].id).toBe('user-acme-jdoe');
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds[0].cred_material_kind).toBe('ntlm_hash');
      expect(creds[0].cred_usable_for_auth).toBe(true);
      expect(creds[0].cred_evidence_kind).toBe('dump');
    });

    it('creates OWNS_CRED edges from user to credential', () => {
      const finding = parseSecretsdump(sampleNTDS);
      const ownsCred = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsCred.length).toBe(3);
    });

    it('flags krbtgt as privileged', () => {
      const finding = parseSecretsdump(sampleNTDS);
      const krbtgt = finding.nodes.find(n => n.type === 'credential' && n.cred_user === 'krbtgt');
      expect(krbtgt).toBeDefined();
      expect(krbtgt!.privileged).toBe(true);
    });

    it('handles empty output', () => {
      const finding = parseSecretsdump('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('uses context.domain as fallback when no domain in output', () => {
      const noDomainSAM = [
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
      ].join('\n');
      const finding = parseSecretsdump(noDomainSAM, 'test-agent', { domain: 'acme.local' });
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(2);
      expect(creds[0].cred_domain).toBe('acme.local');
      expect(creds[0].cred_domain_source).toBe('parser_context');
      expect(creds[1].cred_domain).toBe('acme.local');
    });

    it('prefers explicit domain over context.domain', () => {
      const withDomain = 'ACME\\jdoe:1103:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const finding = parseSecretsdump(withDomain, 'test-agent', { domain: 'other.local' });
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds[0].cred_domain).toBe('acme');
      expect(creds[0].cred_domain_source).toBe('explicit');
    });

    it('does NOT create MEMBER_OF_DOMAIN from context.domain for unqualified SAM lines', () => {
      const noDomainSAM = 'jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const finding = parseSecretsdump(noDomainSAM, 'test-agent', { domain: 'acme.local' });
      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      // Unqualified SAM accounts must NOT get MEMBER_OF_DOMAIN from context fallback
      expect(domEdges.length).toBe(0);
      // But cred_domain is still set as a soft hint
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds[0].cred_domain).toBe('acme.local');
      expect(creds[0].cred_domain_source).toBe('parser_context');
      // Context domain node is still emitted for graph completeness
      const domains = finding.nodes.filter(n => n.type === 'domain');
      expect(domains.length).toBe(1);
      expect(domains[0].domain_name).toBe('acme.local');
    });

    it('creates DUMPED_FROM edges when context.source_host is set', () => {
      const sam = 'jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const finding = parseSecretsdump(sam, 'test-agent', { source_host: '10.10.10.5' });
      const dumpEdges = finding.edges.filter(e => e.properties.type === 'DUMPED_FROM');
      expect(dumpEdges.length).toBe(1);
      expect(dumpEdges[0].target).toBe('host-10-10-10-5');
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].label).toBe('10.10.10.5');
    });

    it('creates DUMPED_FROM but NOT MEMBER_OF_DOMAIN for unqualified SAM lines with full context', () => {
      const sam = [
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
      ].join('\n');
      const finding = parseSecretsdump(sam, 'test-agent', { domain: 'acme.local', source_host: '10.10.10.5' });
      const dumpEdges = finding.edges.filter(e => e.properties.type === 'DUMPED_FROM');
      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(dumpEdges.length).toBe(2);
      // Unqualified SAM lines must NOT produce MEMBER_OF_DOMAIN from context
      expect(domEdges.length).toBe(0);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.every(c => c.dump_source_host === '10.10.10.5')).toBe(true);
      // Credential cred_domain is still set as a hint
      expect(creds.every(c => c.cred_domain === 'acme.local')).toBe(true);
    });

    it('creates MEMBER_OF_DOMAIN for NTDS lines with explicit DOMAIN prefix', () => {
      const ntds = 'ACME\\jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const finding = parseSecretsdump(ntds, 'test-agent', { source_host: '10.10.10.5' });
      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(1);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds[0].cred_domain).toBe('acme');
      expect(creds[0].cred_domain_source).toBe('explicit');
    });

    it('preserves existing behavior without context', () => {
      const finding = parseSecretsdump(sampleNTDS);
      const dumpEdges = finding.edges.filter(e => e.properties.type === 'DUMPED_FROM');
      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(dumpEdges.length).toBe(0);
      // Only ACME\\jdoe should produce MEMBER_OF_DOMAIN (explicit domain)
      expect(domEdges.length).toBe(1);
    });

    it('source_host stub node includes ip property when source_host is an IP', () => {
      const sam = 'jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const finding = parseSecretsdump(sam, 'test-agent', { source_host: '10.10.10.5' });
      const host = finding.nodes.find(n => n.type === 'host');
      expect(host?.ip).toBe('10.10.10.5');
      expect(host?.hostname).toBeUndefined();
    });

    it('source_host stub node includes hostname property when source_host is a hostname', () => {
      const sam = 'jdoe:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const finding = parseSecretsdump(sam, 'test-agent', { source_host: 'dc01.acme.local' });
      const host = finding.nodes.find(n => n.type === 'host');
      expect(host?.hostname).toBe('dc01.acme.local');
      expect(host?.ip).toBeUndefined();
    });
  });

  // =============================================
  // Kerbrute Parser
  // =============================================
  describe('parseKerbrute', () => {
    const sampleUserenum = [
      '    __             __               __',
      '   / /_____  _____/ /_  _______  __/ /____',
      '  / //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\',
      ' / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/',
      '/_/|_|\\___/_/  /_.___/_/   \\__,_/\\__/\\___/',
      '',
      'Version: v1.0.3',
      '',
      '2026/03/21 10:00:00 >  Using KDC(s):',
      '2026/03/21 10:00:00 >   dc01.acme.local:88',
      '',
      '2026/03/21 10:00:01 >  [+] VALID USERNAME:\tjdoe@acme.local',
      '2026/03/21 10:00:01 >  [+] VALID USERNAME:\tadmin@acme.local',
      '2026/03/21 10:00:01 >  [+] VALID USERNAME:\tsvc_sql@acme.local',
      '2026/03/21 10:00:02 >  Done! Tested 500 usernames, 3 valid.',
    ].join('\n');

    const sampleSpray = [
      '2026/03/21 10:00:00 >  Using KDC(s):',
      '2026/03/21 10:00:00 >   dc01.acme.local:88',
      '2026/03/21 10:00:01 >  [+] VALID LOGIN:\tjdoe@acme.local:Summer2026!',
      '2026/03/21 10:00:02 >  [+] VALID LOGIN:\tsvc_sql@acme.local:Summer2026!',
      '2026/03/21 10:00:03 >  Done! Tested 100 logins, 2 successes.',
    ].join('\n');

    it('extracts valid usernames from userenum', () => {
      const finding = parseKerbrute(sampleUserenum);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(3);
      expect(users.map(u => u.username).sort()).toEqual(['admin', 'jdoe', 'svc_sql']);
    });

    it('creates MEMBER_OF_DOMAIN edges from userenum', () => {
      const finding = parseKerbrute(sampleUserenum);
      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(3);
    });

    it('creates domain node from UPN domain', () => {
      const finding = parseKerbrute(sampleUserenum);
      const domains = finding.nodes.filter(n => n.type === 'domain');
      expect(domains.length).toBe(1);
      expect(domains[0].domain_name).toBe('acme.local');
    });

    it('extracts credentials from password spray', () => {
      const finding = parseKerbrute(sampleSpray);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(2);
      expect(creds[0].cred_type).toBe('plaintext');
      expect(creds[0].cred_material_kind).toBe('plaintext_password');
      expect(creds[0].cred_usable_for_auth).toBe(true);
      expect(creds[0].cred_evidence_kind).toBe('spray_success');
    });

    it('creates OWNS_CRED edges from spray successes', () => {
      const finding = parseKerbrute(sampleSpray);
      const ownsCred = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsCred.length).toBe(2);
    });

    it('handles empty output', () => {
      const finding = parseKerbrute('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('handles passwords containing colons', () => {
      const colonSpray = [
        '2026/03/21 10:00:01 >  [+] VALID LOGIN:\tjdoe@acme.local:Summer:2026!',
      ].join('\n');
      const finding = parseKerbrute(colonSpray);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].cred_value).toBe('Summer:2026!');
      expect(creds[0].cred_domain).toBe('acme.local');
    });

    it('F09: rejects single-char remainder as empty password', () => {
      // Simulates a VALID LOGIN where colon is at end of remainder: "user@domain:"
      const edgeCaseSpray = [
        '2026/03/21 10:00:01 >  [+] VALID LOGIN:\tjdoe@acme.local:',
      ].join('\n');
      const finding = parseKerbrute(edgeCaseSpray);
      // Should produce a user but no credential (empty password)
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(0);
    });
  });

  // =============================================
  // Hashcat Parser
  // =============================================
  describe('parseHashcat', () => {
    const sampleNTLM = [
      'fc525c9683e8fe067095ba2ddc971889:Password123',
      '31d6cfe0d16ae931b73c59d7e0c089c0:',
      'abcdef0123456789abcdef0123456789:Welcome1!',
    ].join('\n');

    const sampleKerberoast = [
      '$krb5tgs$23$*svc_sql$ACME.LOCAL$acme.local/svc_sql*$aabbccdd...:SqlPass123',
    ].join('\n');

    const sampleNTLMv2 = [
      'jdoe::ACME:1122334455667788:aabbccddee:0101000000:OfficePass1',
    ].join('\n');

    it('extracts cracked NTLM hashes', () => {
      const finding = parseHashcat(sampleNTLM);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      // 2 cracked (skip empty plaintext)
      expect(creds.length).toBe(2);
      expect(creds[0].cred_type).toBe('plaintext');
      expect(creds[0].cred_value).toBe('Password123');
      expect(creds[0].cred_material_kind).toBe('plaintext_password');
      expect(creds[0].cred_usable_for_auth).toBe(true);
      expect(creds[0].cred_evidence_kind).toBe('crack');
    });

    it('extracts username from Kerberoast hash', () => {
      const finding = parseHashcat(sampleKerberoast);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].cred_user).toBe('svc_sql');
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      const ownsCred = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsCred.length).toBe(1);
    });

    it('extracts username from NTLMv2 hash', () => {
      const finding = parseHashcat(sampleNTLMv2);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].username).toBe('jdoe');
    });

    it('handles empty output', () => {
      const finding = parseHashcat('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('uses context.domain for plain NTLM hashes without domain', () => {
      const ntlm = 'fc525c9683e8fe067095ba2ddc971889:Password123';
      const finding = parseHashcat(ntlm, 'test-agent', { domain: 'acme.local' });
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      // Plain NTLM has no username, so domain doesn't apply to user
      // But if a username were present, domain would be set
      expect(creds[0].cred_domain).toBe('acme.local');
    });

    it('preserves explicit domain from Kerberoast hash over context', () => {
      const kerberoast = '$krb5tgs$23$*svc_sql$ACME.LOCAL$acme.local/svc_sql*$aabbccdd...:SqlPass123';
      const finding = parseHashcat(kerberoast, 'test-agent', { domain: 'other.local' });
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds[0].cred_domain).toBe('ACME.LOCAL');
      expect(creds[0].cred_domain_source).toBe('explicit');
    });

    it('preserves behavior without context', () => {
      const finding = parseHashcat(sampleNTLM);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(2);
      expect(creds[0].cred_domain).toBeUndefined();
    });

    it('rejects long non-hashcat input via preamble check', () => {
      const junkLines = Array.from({ length: 25 }, (_, i) => `This is irrelevant log line ${i + 1}`);
      const finding = parseHashcat(junkLines.join('\n'));
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('F05: skips whitespace-only plaintext values', () => {
      const output = [
        'fc525c9683e8fe067095ba2ddc971889:Password123',
        'abcdef0123456789abcdef0123456789:   ',
        '1234567890abcdef1234567890abcdef:\t',
      ].join('\n');
      const finding = parseHashcat(output);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1); // Only Password123
      expect(creds[0].cred_value).toBe('Password123');
    });
  });

  // =============================================
  // Responder Parser
  // =============================================
  describe('parseResponder', () => {
    const sampleOutput = [
      '[*] [LLMNR]  Poisoned answer sent to 10.10.10.5 for name fileserv',
      '[SMB] NTLMv2-SSP Client   : 10.10.10.5',
      '[SMB] NTLMv2-SSP Username : ACME\\jdoe',
      '[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:aabbccddee:0101000000',
      '',
      '[*] [LLMNR]  Poisoned answer sent to 10.10.10.6 for name printer',
      '[SMB] NTLMv2-SSP Client   : 10.10.10.6',
      '[SMB] NTLMv2-SSP Username : ACME\\svc_backup',
      '[SMB] NTLMv2-SSP Hash     : svc_backup::ACME:aabbccdd11223344:eeff0011:0202000000',
    ].join('\n');

    it('extracts credential nodes from captured hashes', () => {
      const finding = parseResponder(sampleOutput);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(2);
      expect(creds[0].cred_type).toBe('ntlmv2_challenge');
      expect(creds[0].cred_material_kind).toBe('ntlmv2_challenge');
      expect(creds[0].cred_usable_for_auth).toBe(false);
      expect(creds[0].cred_evidence_kind).toBe('capture');
    });

    it('extracts user nodes from usernames', () => {
      const finding = parseResponder(sampleOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(2);
      expect(users.map(u => u.username).sort()).toEqual(['jdoe', 'svc_backup']);
    });

    it('extracts host nodes from client IPs', () => {
      const finding = parseResponder(sampleOutput);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(2);
    });

    it('creates OWNS_CRED edges from user to credential', () => {
      const finding = parseResponder(sampleOutput);
      const ownsCred = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsCred.length).toBe(2);
    });

    it('does not create HAS_SESSION edges for passive captures', () => {
      const finding = parseResponder(sampleOutput);
      const sessions = finding.edges.filter(e => e.properties.type === 'HAS_SESSION');
      expect(sessions.length).toBe(0);
    });

    it('normalizes domain dots to hyphens in user IDs', () => {
      const domainOutput = [
        '[SMB] NTLMv2-SSP Client   : 10.10.10.5',
        '[SMB] NTLMv2-SSP Username : acme.local\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::acme.local:aabb:ccdd:0101',
      ].join('\n');
      const finding = parseResponder(domainOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users[0].id).toBe('user-acme-local-jdoe');
    });

    it('records capture provenance on credential nodes', () => {
      const finding = parseResponder(sampleOutput);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds[0].observed_from_ip).toBe('10.10.10.5');
    });

    it('uses canonical user IDs across kerbrute and responder', () => {
      const kerbruteFinding = parseKerbrute([
        '2026/03/21 10:00:01 >  [+] VALID USERNAME:\tjdoe@acme.local',
      ].join('\n'));
      const responderFinding = parseResponder([
        '[SMB] NTLMv2-SSP Client   : 10.10.10.5',
        '[SMB] NTLMv2-SSP Username : ACME.LOCAL\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::ACME.LOCAL:1122334455667788:aabbccddee:0101000000',
      ].join('\n'));

      const kerbruteUser = kerbruteFinding.nodes.find(n => n.type === 'user' && n.username === 'jdoe');
      const responderUser = responderFinding.nodes.find(n => n.type === 'user' && n.username === 'jdoe');
      expect(kerbruteUser?.id).toBe('user-acme-local-jdoe');
      expect(responderUser?.id).toBe(kerbruteUser?.id);
    });

    it('uses canonical user IDs across hashcat and kerbrute', () => {
      const kerbruteFinding = parseKerbrute([
        '2026/03/21 10:00:01 >  [+] VALID USERNAME:\tjdoe@acme.local',
      ].join('\n'));
      const hashcatFinding = parseHashcat([
        'jdoe::ACME.LOCAL:1122334455667788:aabbccddee:0101000000:OfficePass1',
      ].join('\n'));

      const kerbruteUser = kerbruteFinding.nodes.find(n => n.type === 'user' && n.username === 'jdoe');
      const hashcatUser = hashcatFinding.nodes.find(n => n.type === 'user' && n.username === 'jdoe');
      expect(hashcatUser?.id).toBe(kerbruteUser?.id);
    });

    it('handles empty output', () => {
      const finding = parseResponder('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('parses NTLMv1-SSP captures', () => {
      const v1Output = [
        '[SMB] NTLMv1-SSP Client   : 10.10.10.7',
        '[SMB] NTLMv1-SSP Username : CORP\\legacy_svc',
        '[SMB] NTLMv1-SSP Hash     : legacy_svc::CORP:aabb:ccdd:0101',
      ].join('\n');
      const finding = parseResponder(v1Output);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].label).toMatch(/^NTLMv1:/);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].username).toBe('legacy_svc');
    });

    it('F01: NTLMv1 captures produce ntlmv1_challenge cred_type and material_kind', () => {
      const v1Output = [
        '[SMB] NTLMv1-SSP Client   : 10.10.10.7',
        '[SMB] NTLMv1-SSP Username : CORP\\legacy_svc',
        '[SMB] NTLMv1-SSP Hash     : legacy_svc::CORP:aabb:ccdd:0101',
      ].join('\n');
      const finding = parseResponder(v1Output);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].cred_type).toBe('ntlmv1_challenge');
      expect(creds[0].cred_material_kind).toBe('ntlmv1_challenge');
      expect(creds[0].cred_usable_for_auth).toBe(false);
    });

    it('F01: NTLMv2 captures still produce ntlmv2_challenge', () => {
      const v2Output = [
        '[SMB] NTLMv2-SSP Client   : 10.10.10.5',
        '[SMB] NTLMv2-SSP Username : ACME\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:aabbccddee:0101000000',
      ].join('\n');
      const finding = parseResponder(v2Output);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].cred_type).toBe('ntlmv2_challenge');
      expect(creds[0].cred_material_kind).toBe('ntlmv2_challenge');
    });

    it('parses UPN format usernames (user@domain)', () => {
      const upnOutput = [
        '[SMB] NTLMv2-SSP Client   : 10.10.10.8',
        '[SMB] NTLMv2-SSP Username : jdoe@acme.local',
        '[SMB] NTLMv2-SSP Hash     : jdoe::acme.local:1122:3344:5566',
      ].join('\n');
      const finding = parseResponder(upnOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].username).toBe('jdoe');
      expect(users[0].domain_name).toBe('acme.local');
    });
  });

  // =============================================
  // ldapsearch / ldapdomaindump Parser
  // =============================================
  describe('parseLdapsearch', () => {
    const sampleLdif = [
      'dn: CN=John Doe,CN=Users,DC=acme,DC=local',
      'objectClass: top',
      'objectClass: person',
      'objectClass: user',
      'sAMAccountName: jdoe',
      'displayName: John Doe',
      'userAccountControl: 512',
      'memberOf: CN=Domain Admins,CN=Users,DC=acme,DC=local',
      'memberOf: CN=IT Staff,OU=Groups,DC=acme,DC=local',
      'servicePrincipalName: MSSQLSvc/db01.acme.local:1433',
      'adminCount: 1',
      '',
      'dn: CN=svc_backup,CN=Users,DC=acme,DC=local',
      'objectClass: top',
      'objectClass: person',
      'objectClass: user',
      'sAMAccountName: svc_backup',
      'userAccountControl: 4260352',
      '',
      'dn: CN=Domain Admins,CN=Users,DC=acme,DC=local',
      'objectClass: top',
      'objectClass: group',
      'sAMAccountName: Domain Admins',
      'adminCount: 1',
      '',
      'dn: CN=DC01,OU=Domain Controllers,DC=acme,DC=local',
      'objectClass: top',
      'objectClass: computer',
      'sAMAccountName: DC01$',
      'dNSHostName: dc01.acme.local',
      'operatingSystem: Windows Server 2019',
      '',
    ].join('\n');

    it('extracts user nodes from LDIF output', () => {
      const finding = parseLdapsearch(sampleLdif);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(2);
      expect(users[0].username).toBe('jdoe');
      expect(users[0].domain_name).toBe('acme.local');
      expect(users[0].display_name).toBe('John Doe');
    });

    it('extracts group nodes from LDIF output', () => {
      const finding = parseLdapsearch(sampleLdif);
      const groups = finding.nodes.filter(n => n.type === 'group');
      // Domain Admins (from group entry) + IT Staff (from memberOf)
      expect(groups.length).toBeGreaterThanOrEqual(2);
      expect(groups.some(g => g.label === 'Domain Admins')).toBe(true);
    });

    it('extracts host nodes from computer objects', () => {
      const finding = parseLdapsearch(sampleLdif);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].hostname).toBe('dc01.acme.local');
      expect(hosts[0].os).toBe('Windows Server 2019');
      expect(hosts[0].domain_joined).toBe(true);
    });

    it('creates MEMBER_OF edges from memberOf attributes', () => {
      const finding = parseLdapsearch(sampleLdif);
      const memberOf = finding.edges.filter(e => e.properties.type === 'MEMBER_OF');
      expect(memberOf.length).toBe(2); // jdoe -> Domain Admins, jdoe -> IT Staff
    });

    it('detects has_spn from servicePrincipalName', () => {
      const finding = parseLdapsearch(sampleLdif);
      const jdoe = finding.nodes.find(n => n.type === 'user' && n.username === 'jdoe');
      expect(jdoe?.has_spn).toBe(true);
    });

    it('detects asrep_roastable from userAccountControl', () => {
      const finding = parseLdapsearch(sampleLdif);
      // svc_backup has UAC 4260352 which includes 0x400000 (DONT_REQUIRE_PREAUTH)
      const svcBackup = finding.nodes.find(n => n.type === 'user' && n.username === 'svc_backup');
      expect(svcBackup?.asrep_roastable).toBe(true);
    });

    it('parses ldapdomaindump JSON format', () => {
      const ldapdomaindump = JSON.stringify([
        {
          attributes: {
            objectClass: ['top', 'person', 'user'],
            sAMAccountName: 'admin',
            distinguishedName: 'CN=admin,CN=Users,DC=acme,DC=local',
            userAccountControl: '512',
            servicePrincipalName: ['HTTP/web01.acme.local'],
            adminCount: '1',
          },
        },
        {
          attributes: {
            objectClass: ['top', 'computer'],
            sAMAccountName: 'WEB01$',
            distinguishedName: 'CN=WEB01,OU=Servers,DC=acme,DC=local',
            dNSHostName: 'web01.acme.local',
            operatingSystem: 'Windows Server 2022',
          },
        },
      ]);
      const finding = parseLdapsearch(ldapdomaindump);
      const users = finding.nodes.filter(n => n.type === 'user');
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(users.length).toBe(1);
      expect(users[0].has_spn).toBe(true);
      expect(users[0].privileged).toBe(true);
      expect(hosts.length).toBe(1);
      expect(hosts[0].hostname).toBe('web01.acme.local');
    });

    it('handles empty/malformed input', () => {
      expect(parseLdapsearch('').nodes.length).toBe(0);
      expect(parseLdapsearch('random garbage\nno ldap here').nodes.length).toBe(0);
    });

    it('parses realistic AD computer with user+computer objectClass as host (LDIF)', () => {
      const realisticComputer = [
        'dn: CN=DC01,OU=Domain Controllers,DC=acme,DC=local',
        'objectClass: top',
        'objectClass: person',
        'objectClass: organizationalPerson',
        'objectClass: user',
        'objectClass: computer',
        'sAMAccountName: DC01$',
        'dNSHostName: dc01.acme.local',
        'operatingSystem: Windows Server 2019',
        '',
      ].join('\n');

      const finding = parseLdapsearch(realisticComputer);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(hosts.length).toBe(1);
      expect(hosts[0].hostname).toBe('dc01.acme.local');
      expect(hosts[0].domain_joined).toBe(true);
      expect(users.length).toBe(0);
    });

    it('parses realistic AD computer with user+computer objectClass as host (JSON)', () => {
      const data = JSON.stringify([{
        attributes: {
          objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
          sAMAccountName: 'DC01$',
          distinguishedName: 'CN=DC01,OU=Domain Controllers,DC=acme,DC=local',
          dNSHostName: 'dc01.acme.local',
          operatingSystem: 'Windows Server 2019',
        },
      }]);

      const finding = parseLdapsearch(data);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(hosts.length).toBe(1);
      expect(hosts[0].hostname).toBe('dc01.acme.local');
      expect(users.length).toBe(0);
    });
  });

  // =============================================
  // enum4linux-ng Parser
  // =============================================
  describe('parseEnum4linux', () => {
    const sampleJson = JSON.stringify({
      target: { host: '10.10.10.5' },
      domain_info: { domain: 'ACME' },
      os_info: { os: 'Windows Server 2019', hostname: 'DC01' },
      session_check: { null_session_allowed: true },
      users: {
        '500': { username: 'Administrator' },
        '1103': { username: 'jdoe' },
      },
      groups: {
        '512': { groupname: 'Domain Admins', members: [{ name: 'Administrator' }] },
      },
      shares: {
        'IPC$': { access: { mapping: 'OK', readable: true } },
        'SYSVOL': { access: { mapping: 'OK', readable: true } },
      },
    });

    it('extracts host + SMB service from JSON output', () => {
      const finding = parseEnum4linux(sampleJson);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(hosts.length).toBe(1);
      expect(hosts[0].ip).toBe('10.10.10.5');
      expect(hosts[0].os).toBe('Windows Server 2019');
      expect(services.length).toBe(1);
      expect(services[0].service_name).toBe('smb');
    });

    it('extracts users from JSON output', () => {
      const finding = parseEnum4linux(sampleJson);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(2);
      expect(users.map(u => u.username).sort()).toEqual(['Administrator', 'jdoe']);
    });

    it('extracts shares with read permissions', () => {
      const finding = parseEnum4linux(sampleJson);
      const shares = finding.nodes.filter(n => n.type === 'share');
      expect(shares.length).toBe(2);
      expect(shares.every(s => s.readable === true)).toBe(true);
    });

    it('detects null session capability', () => {
      const finding = parseEnum4linux(sampleJson);
      const host = finding.nodes.find(n => n.type === 'host');
      expect(host?.null_session).toBe(true);
      const nullEdges = finding.edges.filter(e => e.properties.type === 'NULL_SESSION');
      expect(nullEdges.length).toBe(1);
    });

    it('creates MEMBER_OF edges for group memberships', () => {
      const finding = parseEnum4linux(sampleJson);
      const memberOf = finding.edges.filter(e => e.properties.type === 'MEMBER_OF');
      expect(memberOf.length).toBe(1); // Administrator -> Domain Admins
    });

    it('parses text-mode output', () => {
      const textOutput = [
        '  Target: 10.10.10.20',
        '  [+] Domain: CORP',
        '  [+] Null session established',
        '  500: CORP\\Administrator (SidTypeUser)',
        '  1103: CORP\\svc_sql (SidTypeUser)',
        '  513: CORP\\Domain Users (SidTypeGroup)',
      ].join('\n');
      const finding = parseEnum4linux(textOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      const groups = finding.nodes.filter(n => n.type === 'group');
      expect(users.length).toBe(2);
      expect(groups.length).toBe(1);
      expect(finding.nodes.find(n => n.type === 'host')?.ip).toBe('10.10.10.20');
    });

    it('handles empty/malformed input', () => {
      expect(parseEnum4linux('').nodes.length).toBe(0);
      expect(parseEnum4linux('no useful data').nodes.length).toBe(0);
    });

    it('creates user nodes for group members not in data.users', () => {
      const jsonData = JSON.stringify({
        target: { host: '10.10.10.5' },
        domain_info: { domain: 'ACME' },
        users: {
          '500': { username: 'Administrator' },
        },
        groups: {
          '512': { groupname: 'Domain Admins', members: [{ name: 'Administrator' }, { name: 'sneaky_admin' }] },
        },
      });
      const finding = parseEnum4linux(jsonData);
      const users = finding.nodes.filter(n => n.type === 'user');
      const usernames = users.map(u => u.username);
      expect(usernames).toContain('sneaky_admin');
      const memberEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF');
      expect(memberEdges.length).toBe(2);
    });

    it('emits both node and edge when node ID matches edge key pattern (M5 regression)', () => {
      // Craft input where a node ID like "user-admin--MEMBER_OF_DOMAIN--domain-acme-local"
      // could collide with an edge dedup key if seenNodes was used for both.
      // With the fix, seenEdges is separate so no collision occurs.
      const jsonData = {
        target: { host: '10.10.10.5' },
        domain_info: { domain: 'ACME.LOCAL' },
        users: {
          '500': { username: 'Administrator' },
        },
      };
      const finding = parseEnum4linux(JSON.stringify(jsonData));
      // Must have user node AND MEMBER_OF_DOMAIN edge
      const users = finding.nodes.filter(n => n.type === 'user');
      const memberEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(users.length).toBe(1);
      expect(memberEdges.length).toBe(1);
    });

    it('handles IPv6 target in text mode', () => {
      const textOutput = [
        '  Target: 2001:db8::1',
        '  [+] Domain: CORP',
        '  500: CORP\\Administrator (SidTypeUser)',
      ].join('\n');
      const finding = parseEnum4linux(textOutput);
      const host = finding.nodes.find(n => n.type === 'host');
      expect(host).toBeDefined();
      expect(host!.ip).toBe('2001:db8::1');
      expect(host!.id).toBe('host-2001-db8--1');
      const svc = finding.nodes.find(n => n.type === 'service');
      expect(svc).toBeDefined();
      expect(svc!.id).toBe('svc-2001-db8--1-445');
    });

    it('handles IPv6 target in JSON mode', () => {
      const jsonData = JSON.stringify({
        target: { host: '2001:db8::2' },
        domain_info: { domain: 'CORP' },
        shares: {
          'DATA': { access: { mapping: 'OK', readable: true } },
        },
      });
      const finding = parseEnum4linux(jsonData);
      const host = finding.nodes.find(n => n.type === 'host');
      expect(host).toBeDefined();
      expect(host!.ip).toBe('2001:db8::2');
      expect(host!.id).toBe('host-2001-db8--2');
      const svc = finding.nodes.find(n => n.type === 'service');
      expect(svc!.id).toBe('svc-2001-db8--2-445');
      const share = finding.nodes.find(n => n.type === 'share');
      expect(share).toBeDefined();
      expect(share!.id).toContain('2001-db8--2');
    });
  });

  // =============================================
  // Rubeus Parser
  // =============================================
  describe('parseRubeus', () => {
    const kerberoastOutput = [
      '[*] Action: Kerberoasting',
      '',
      '[*] SamAccountName         : svc_sql',
      '[*] DistinguishedName      : CN=svc_sql,CN=Users,DC=acme,DC=local',
      '[*] ServicePrincipalName   : MSSQLSvc/db01.acme.local:1433',
      '[*] Hash                   : $krb5tgs$23$*svc_sql$ACME.LOCAL$acme.local/svc_sql*$aabbccdd1122',
      '',
      '[*] SamAccountName         : svc_http',
      '[*] ServicePrincipalName   : HTTP/web01.acme.local',
      '[*] Hash                   : $krb5tgs$23$*svc_http$ACME.LOCAL$acme.local/svc_http*$eeff0011',
    ].join('\n');

    it('extracts kerberoast TGS hashes as credential nodes', () => {
      const finding = parseRubeus(kerberoastOutput);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(2);
      expect(creds[0].cred_type).toBe('kerberos_tgs');
      expect(creds[0].cred_material_kind).toBe('kerberos_tgs');
      expect(creds[0].cred_usable_for_auth).toBe(false);
      expect(creds[0].cred_evidence_kind).toBe('dump');
    });

    it('sets has_spn: true on roasted user nodes', () => {
      const finding = parseRubeus(kerberoastOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(2);
      expect(users.every(u => u.has_spn === true)).toBe(true);
    });

    it('extracts AS-REP hashes as credential nodes', () => {
      const asrepOutput = [
        '[*] Action: AS-REP Roasting',
        '',
        '[*] User                   : jdoe',
        '[*] Hash                   : $krb5asrep$jdoe@ACME.LOCAL:aabbccdd1122',
      ].join('\n');
      const finding = parseRubeus(asrepOutput);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].cred_type).toBe('kerberos_tgs');
      expect(creds[0].cred_usable_for_auth).toBe(false);
    });

    it('sets asrep_roastable: true on AS-REP user nodes', () => {
      const asrepOutput = [
        '[*] User                   : jdoe',
        '[*] Hash                   : $krb5asrep$jdoe@ACME.LOCAL:aabbccdd1122',
      ].join('\n');
      const finding = parseRubeus(asrepOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].asrep_roastable).toBe(true);
    });

    it('extracts captured TGTs from monitor output', () => {
      const monitorOutput = [
        '[*] User                  : ACME\\jdoe',
        '[*] LUID                  : 0x3e7',
        '[*] Service               : krbtgt/ACME.LOCAL',
        '[*] Base64EncodedTicket   : doIFqDCCBaSgAwIBBaEDAgE=',
      ].join('\n');
      const finding = parseRubeus(monitorOutput);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      expect(creds[0].cred_type).toBe('kerberos_tgt');
      expect(creds[0].cred_material_kind).toBe('kerberos_tgt');
      expect(creds[0].cred_usable_for_auth).toBe(true);
      expect(creds[0].cred_evidence_kind).toBe('capture');
    });

    it('creates OWNS_CRED edges for captured tickets', () => {
      const monitorOutput = [
        '[*] User                  : ACME\\jdoe',
        '[*] Service               : krbtgt/ACME.LOCAL',
        '[*] Base64EncodedTicket   : doIFqDCCBaSgAwIBBaEDAgE=',
      ].join('\n');
      const finding = parseRubeus(monitorOutput);
      const ownsCred = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsCred.length).toBe(1);
    });

    it('skips machine accounts in monitor output', () => {
      const monitorOutput = [
        '[*] User                  : ACME\\DC01$',
        '[*] Service               : krbtgt/ACME.LOCAL',
        '[*] Base64EncodedTicket   : doIFqDCCBaSgAwIBBaEDAgE=',
      ].join('\n');
      const finding = parseRubeus(monitorOutput);
      const users = finding.nodes.filter(n => n.type === 'user');
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(users.length).toBe(0);
      expect(creds.length).toBe(0);
    });

    it('handles empty output', () => {
      const finding = parseRubeus('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });
  });

  // =============================================
  // gobuster / feroxbuster / ffuf Parser
  // =============================================
  describe('parseWebDirEnum', () => {
    it('parses gobuster text output paths and status codes', () => {
      const gobusterOutput = [
        'Url:                     http://10.10.10.5:8080',
        '/index.html (Status: 200) [Size: 1234]',
        '/admin (Status: 301) [Size: 456]',
        '/api (Status: 200) [Size: 789]',
      ].join('\n');
      const finding = parseWebDirEnum(gobusterOutput);
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      expect(services[0].discovered_paths).toHaveLength(3);
      expect(services[0].port).toBe(8080);
    });

    it('parses feroxbuster text output', () => {
      const feroxOutput = [
        '200 GET 100l 200w 5000c http://10.10.10.5/index.html',
        '301 GET 10l 20w 300c http://10.10.10.5/login',
        '403 GET 5l 10w 200c http://10.10.10.5/secret',
      ].join('\n');
      const finding = parseWebDirEnum(feroxOutput);
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      expect(services[0].discovered_paths).toHaveLength(3);
      expect(services[0].has_login_form).toBe(true);
    });

    it('parses ffuf JSON output', () => {
      const ffufJson = JSON.stringify({
        results: [
          { url: 'http://10.10.10.5/api', status: 200, length: 1234 },
          { url: 'http://10.10.10.5/login', status: 302, length: 100 },
        ],
      });
      const finding = parseWebDirEnum(ffufJson);
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      expect(services[0].discovered_paths).toHaveLength(2);
    });

    it('detects login form from path patterns', () => {
      const output = [
        '/index.html (Status: 200) [Size: 1234]',
        '/wp-login.php (Status: 200) [Size: 5678]',
      ].join('\n');
      const finding = parseWebDirEnum(output);
      const services = finding.nodes.filter(n => n.type === 'service');
      // No target URL header, so only a service node without host context
      const svc = services.find(s => s.has_login_form === true);
      expect(svc).toBeDefined();
    });

    it('returns service enrichment node with discovered_paths', () => {
      const output = [
        'Url:                     http://10.10.10.5',
        '/robots.txt (Status: 200) [Size: 100]',
      ].join('\n');
      const finding = parseWebDirEnum(output);
      const svc = finding.nodes.find(n => n.type === 'service');
      expect(svc).toBeDefined();
      const paths = svc!.discovered_paths as Array<{ path: string; status: number; size?: number }>;
      expect(paths).toHaveLength(1);
      expect(paths[0].path).toBe('/robots.txt');
      expect(paths[0].status).toBe(200);
    });

    it('auto-detects format (JSON vs text)', () => {
      // JSON (ffuf)
      const jsonResult = parseOutput('ffuf', JSON.stringify({ results: [{ url: 'http://t/a', status: 200, length: 1 }] }));
      expect(jsonResult).not.toBeNull();
      expect(jsonResult!.nodes.length).toBeGreaterThan(0);

      // Text (gobuster)
      const textResult = parseOutput('gobuster', '/path (Status: 200) [Size: 100]');
      expect(textResult).not.toBeNull();
    });

    it('handles empty output', () => {
      const finding = parseWebDirEnum('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });
  });

  // =============================================
  // Updated registry tests
  // =============================================
  describe('getSupportedParsers (updated)', () => {
    it('includes all new parser aliases', () => {
      const parsers = getSupportedParsers();
      expect(parsers).toContain('ldapsearch');
      expect(parsers).toContain('ldapdomaindump');
      expect(parsers).toContain('ldap');
      expect(parsers).toContain('enum4linux');
      expect(parsers).toContain('enum4linux-ng');
      expect(parsers).toContain('rubeus');
      expect(parsers).toContain('gobuster');
      expect(parsers).toContain('feroxbuster');
      expect(parsers).toContain('ffuf');
      expect(parsers).toContain('dirbuster');
      expect(parsers.length).toBeGreaterThanOrEqual(20);
    });

    it('includes scoutsuite parser', () => {
      const parsers = getSupportedParsers();
      expect(parsers).toContain('scoutsuite');
    });

    it('returns a Finding for scoutsuite via parseOutput', () => {
      expect(parseOutput('scoutsuite', '{}')).not.toBeNull();
    });
  });

  describe('parseOutput dispatches new parsers', () => {
    it('dispatches ldapsearch aliases', () => {
      expect(parseOutput('ldapsearch', '')).not.toBeNull();
      expect(parseOutput('ldapdomaindump', '')).not.toBeNull();
      expect(parseOutput('ldap', '')).not.toBeNull();
    });

    it('dispatches enum4linux aliases', () => {
      expect(parseOutput('enum4linux', '')).not.toBeNull();
      expect(parseOutput('enum4linux-ng', '')).not.toBeNull();
    });

    it('dispatches rubeus', () => {
      expect(parseOutput('rubeus', '')).not.toBeNull();
    });

    it('dispatches web dir enum aliases', () => {
      expect(parseOutput('gobuster', '')).not.toBeNull();
      expect(parseOutput('feroxbuster', '')).not.toBeNull();
      expect(parseOutput('ffuf', '')).not.toBeNull();
      expect(parseOutput('dirbuster', '')).not.toBeNull();
    });
  });

  // =============================================
  // Domain alias resolution
  // =============================================
  describe('domain alias resolution', () => {

    it('NXC parser resolves NetBIOS domain to FQDN via domain_aliases', () => {
      const nxcOutput = [
        'SMB   10.10.10.1  445  WINTERFELL  [*] Windows Server 2019 (name:WINTERFELL) (domain:NORTH) (signing:True) (SMBv1:False)',
        'SMB   10.10.10.1  445  WINTERFELL  [+] NORTH\\samwell.tarly:Heartsbane1',
      ].join('\n');
      const aliases = { 'NORTH': 'north.sevenkingdoms.local' };
      const finding = parseNxc(nxcOutput, 'test-agent', { domain_aliases: aliases });

      // User node should use FQDN domain in its ID
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].id).toBe('user-north-sevenkingdoms-local-samwell-tarly');
      expect(users[0].domain_name).toBe('north.sevenkingdoms.local');

      // Domain node should use FQDN
      const domains = finding.nodes.filter(n => n.type === 'domain');
      expect(domains.length).toBe(1);
      expect(domains[0].id).toBe('domain-north-sevenkingdoms-local');

      // MEMBER_OF_DOMAIN edge should connect to FQDN domain
      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(1);
      expect(domEdges[0].target).toBe('domain-north-sevenkingdoms-local');
    });

    it('NXC parser falls back to lowercased NetBIOS when no alias match', () => {
      const nxcOutput = [
        'SMB   10.10.10.1  445  WINTERFELL  [*] Windows Server 2019 (name:WINTERFELL) (domain:NORTH) (signing:True) (SMBv1:False)',
        'SMB   10.10.10.1  445  WINTERFELL  [+] NORTH\\samwell.tarly:Heartsbane1',
      ].join('\n');
      // No aliases at all
      const finding = parseNxc(nxcOutput, 'test-agent');
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users[0].id).toBe('user-north-samwell-tarly');
    });

    it('secretsdump resolves NetBIOS DOMAIN\\user prefix via domain_aliases', () => {
      const ntds = 'NORTH\\samwell.tarly:1103:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::';
      const aliases = { 'NORTH': 'north.sevenkingdoms.local' };
      const finding = parseSecretsdump(ntds, 'test-agent', { domain_aliases: aliases });

      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].id).toBe('user-north-sevenkingdoms-local-samwell-tarly');

      const domEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(1);
      expect(domEdges[0].target).toBe('domain-north-sevenkingdoms-local');
    });

    it('enum4linux JSON path resolves domain via domain_aliases (P2 regression)', () => {
      const jsonData = {
        target: { host: '10.10.10.1', domain: 'NORTH' },
        domain_info: { domain: 'NORTH' },
        users: {
          '500': { username: 'Administrator' },
        },
        groups: {
          '513': { groupname: 'Domain Users' },
        },
      };
      const aliases = { 'NORTH': 'north.sevenkingdoms.local' };
      const finding = parseEnum4linux(JSON.stringify(jsonData), 'test-agent', { domain_aliases: aliases });

      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].id).toBe('user-north-sevenkingdoms-local-administrator');
      expect(users[0].domain_name).toBe('north.sevenkingdoms.local');

      const groups = finding.nodes.filter(n => n.type === 'group');
      expect(groups.length).toBe(1);
      expect(groups[0].domain_name).toBe('north.sevenkingdoms.local');
    });

    it('parseOutput strips ANSI escape codes before parsing (L5 regression)', () => {
      // NXC output with ANSI color codes embedded
      const ansiOutput = [
        '\x1B[32mSMB\x1B[0m  10.10.10.1  445  DC01  \x1B[32m[*]\x1B[0m Windows Server 2019 Build 17763 x64 (name:DC01) (domain:acme.local) (signing:True) (SMBv1:False)',
        '\x1B[32mSMB\x1B[0m  10.10.10.1  445  DC01  \x1B[32m[+]\x1B[0m acme.local\\admin:Password1 (Pwn3d!)',
      ].join('\n');

      const finding = parseOutput('nxc', ansiOutput);
      expect(finding).not.toBeNull();
      const hosts = finding!.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBeGreaterThanOrEqual(1);
      expect(hosts[0].ip).toBe('10.10.10.1');
    });

    it('enum4linux resolves RID-cycled domain via domain_aliases', () => {
      const e4lOutput = [
        '[+] Target: 10.10.10.1',
        '[+] Domain: NORTH',
        '500: NORTH\\Administrator (SidTypeUser)',
        '513: NORTH\\Domain Users (SidTypeGroup)',
      ].join('\n');
      const aliases = { 'NORTH': 'north.sevenkingdoms.local' };
      const finding = parseEnum4linux(e4lOutput, 'test-agent', { domain_aliases: aliases });

      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(1);
      expect(users[0].id).toBe('user-north-sevenkingdoms-local-administrator');

      const groups = finding.nodes.filter(n => n.type === 'group');
      expect(groups.length).toBe(1);
      expect(groups[0].domain_name).toBe('north.sevenkingdoms.local');
    });
  });

  // =============================================
  // testssl Text-Mode Fallback
  // =============================================
  describe('parseTestssl — text mode fallback', () => {
    it('extracts target and vulnerabilities from raw text output', () => {
      const textOutput = [
        'Start 2026-04-01 10:00:00        -->> 10.10.10.5:443 (10.10.10.5) <<--',
        '',
        'Testing protocols via sockets',
        'Testing vulnerabilities',
        '',
        'heartbleed (CVE-2014-0160)                     VULNERABLE',
        'CCS (CVE-2014-0224)                            NOT ok',
        '',
        'Testing 10.10.10.5 on 10.10.10.5:443',
      ].join('\n');
      const finding = parseTestssl(textOutput);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].ip).toBe('10.10.10.5');
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      expect(services[0].port).toBe(443);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBeGreaterThanOrEqual(1);
      expect(vulns.some(v => v.cve === 'CVE-2014-0160')).toBe(true);
      const vulnEdges = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      expect(vulnEdges.length).toBeGreaterThanOrEqual(1);
    });
  });

  // =============================================
  // Nuclei JSON Array Format
  // =============================================
  describe('parseNuclei — JSON array format', () => {
    it('parses a single JSON array containing multiple findings', () => {
      const entries = [
        { 'template-id': 'tech-detect', host: 'https://10.10.10.5', 'matched-at': 'https://10.10.10.5', type: 'http', info: { name: 'Nginx Detect', severity: 'info' } },
        { 'template-id': 'cve-2021-1234', host: 'https://10.10.10.5', 'matched-at': 'https://10.10.10.5/vuln', type: 'http', info: { name: 'Test CVE', severity: 'high' }, 'matcher-name': 'CVE-2021-1234' },
      ];
      const finding = parseNuclei(JSON.stringify(entries));
      expect(finding.nodes.length).toBeGreaterThan(0);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('parseLinpeas', () => {
    it('parses host with SUID binaries', () => {
      const output = [
        'Hostname: target-box',
        '═══════════════════════════════╣ SUID ╠═══════════════════════════════',
        '-rwsr-xr-x 1 root root 12345 Jan 1 2024 /usr/bin/python3',
      ].join('\n');

      const finding = parseLinpeas(output, 'test');
      expect(finding.nodes.length).toBe(1);
      const host = finding.nodes[0];
      expect(host.type).toBe('host');
      expect(host.has_suid_root).toBe(true);
      expect(host.suid_binaries).toContain('/usr/bin/python3');
    });

    it('extracts kernel version', () => {
      const output = 'Linux version 5.15.0-91-generic (buildd@lcy02-amd64-116)\n';
      const finding = parseLinpeas(output, 'test', { source_host: 'host-test' });
      const host = finding.nodes[0];
      expect(host.kernel_version).toBe('5.15.0-91-generic');
    });

    it('detects docker socket access', () => {
      const output = [
        '═══════════════════════════════╣ Interesting ╠═══════════════════════════════',
        '/var/run/docker.sock',
      ].join('\n');
      const finding = parseLinpeas(output, 'test', { source_host: 'host-test' });
      expect(finding.nodes[0].docker_socket_accessible).toBe(true);
    });

    it('returns empty finding for empty output', () => {
      const finding = parseLinpeas('', 'test', { source_host: 'host-test' });
      expect(finding.nodes.length).toBe(1);
      expect(finding.nodes[0].type).toBe('host');
    });
  });

  describe('parseNikto', () => {
    it('parses text mode output', () => {
      const output = [
        '+ Target IP:          10.10.10.5',
        '+ Target Port:        80',
        '+ Server: Apache/2.4.49',
        '+ OSVDB-3233: /icons/: Directory indexing found',
        '+ OSVDB-3092: /admin/: Admin directory found',
      ].join('\n');

      const finding = parseNikto(output);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      const services = finding.nodes.filter(n => n.type === 'service');
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');

      expect(hosts.length).toBeGreaterThanOrEqual(1);
      expect(services.length).toBeGreaterThanOrEqual(1);
      expect(vulns.length).toBeGreaterThanOrEqual(1);
    });

    it('parses JSON mode output', () => {
      const data = {
        ip: '10.10.10.5',
        port: 443,
        ssl: true,
        banner: 'nginx/1.18.0',
        vulnerabilities: [
          { id: 'OSVDB-1234', msg: 'Test vulnerability', url: '/vuln' },
        ],
      };

      const finding = parseNikto(JSON.stringify(data));
      expect(finding.nodes.length).toBeGreaterThan(0);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBeGreaterThanOrEqual(1);
    });

    it('returns empty for empty input', () => {
      const finding = parseNikto('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });
  });

  describe('parsePacu', () => {
    it('parses IAM users and roles', () => {
      const data = {
        AccountId: '123456789012',
        IAMUsers: [
          { Arn: 'arn:aws:iam::123456789012:user/admin', UserName: 'admin' },
        ],
        IAMRoles: [
          {
            Arn: 'arn:aws:iam::123456789012:role/EC2Role', RoleName: 'EC2Role',
            AssumeRolePolicyDocument: {
              Statement: [{
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::123456789012:user/admin' },
                Action: 'sts:AssumeRole',
              }],
            },
          },
        ],
      };

      const finding = parsePacu(JSON.stringify(data));
      const identities = finding.nodes.filter(n => n.type === 'cloud_identity');
      expect(identities.length).toBeGreaterThanOrEqual(2);

      const assumeEdges = finding.edges.filter(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumeEdges.length).toBeGreaterThanOrEqual(1);
    });

    it('returns empty for invalid JSON', () => {
      const finding = parsePacu('not json');
      expect(finding.nodes.length).toBe(0);
    });
  });

  describe('parseProwler', () => {
    it('parses prowler OCSF JSON-lines findings', () => {
      const line = JSON.stringify({
        StatusExtended: 'S3 bucket my-bucket is publicly accessible',
        Severity: 'critical',
        ServiceName: 's3',
        ResourceArn: 'arn:aws:s3:::my-bucket',
        ResourceId: 'my-bucket',
        AccountId: '123456789012',
        Region: 'us-east-1',
        CheckID: 's3_bucket_public_access',
        Status: 'FAIL',
      });

      const finding = parseProwler(line);
      expect(finding.nodes.length).toBeGreaterThan(0);
      const resources = finding.nodes.filter(n => n.type === 'cloud_resource');
      expect(resources.length).toBeGreaterThanOrEqual(1);
    });

    it('parses multiple lines', () => {
      const lines = [
        JSON.stringify({ ResourceArn: 'arn:aws:s3:::bucket1', ResourceId: 'bucket1', Status: 'PASS', Severity: 'low', ServiceName: 's3' }),
        JSON.stringify({ ResourceArn: 'arn:aws:s3:::bucket2', ResourceId: 'bucket2', Status: 'FAIL', Severity: 'high', ServiceName: 's3', CheckID: 'check-1' }),
      ].join('\n');

      const finding = parseProwler(lines);
      expect(finding.nodes.length).toBeGreaterThanOrEqual(2);
    });

    it('returns empty for non-JSON', () => {
      const finding = parseProwler('not json');
      expect(finding.nodes.length).toBe(0);
    });
  });

  // ===========================================================================
  // ScoutSuite Parser
  // ===========================================================================

  describe('parseScoutSuite', () => {
    it('parses IAM users + roles with trust policies', () => {
      const data = {
        provider_code: 'aws',
        account_id: '123456789012',
        services: {
          iam: {
            users: {
              items: {
                'user-1': { arn: 'arn:aws:iam::123456789012:user/admin', name: 'admin', mfa_enabled: false },
              },
            },
            roles: {
              items: {
                'role-1': {
                  arn: 'arn:aws:iam::123456789012:role/LambdaExec',
                  name: 'LambdaExec',
                  assume_role_policy_document: {
                    Statement: [{ Effect: 'Allow', Principal: { AWS: ['arn:aws:iam::999999999999:role/CrossAcct'] } }],
                  },
                },
              },
            },
          },
        },
      };

      const finding = parseScoutSuite(JSON.stringify(data));
      const identities = finding.nodes.filter(n => n.type === 'cloud_identity');
      expect(identities.length).toBeGreaterThanOrEqual(3); // admin, LambdaExec, CrossAcct
      const assumesEdges = finding.edges.filter(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumesEdges.length).toBe(1);
    });

    it('strips JS assignment wrapper', () => {
      const data = { provider_code: 'aws', account_id: '111', services: { iam: { users: { items: { 'u': { arn: 'arn:aws:iam::111:user/x', name: 'x' } } } } } };
      const finding = parseScoutSuite(`scoutsuite_results = ${JSON.stringify(data)};`);
      expect(finding.nodes.length).toBeGreaterThanOrEqual(1);
    });

    it('parses S3 buckets with public flag', () => {
      const data = {
        provider_code: 'aws', account_id: '123',
        services: {
          s3: { buckets: { items: { 'b1': { name: 'my-public-bucket', arn: 'arn:aws:s3:::my-public-bucket', acls_public: true } } } },
        },
      };
      const finding = parseScoutSuite(JSON.stringify(data));
      const s3 = finding.nodes.find(n => n.type === 'cloud_resource' && (n as any).resource_type === 's3_bucket');
      expect(s3).toBeDefined();
      expect((s3 as any).public).toBe(true);
    });

    it('parses security findings as vulnerability nodes', () => {
      const data = {
        provider_code: 'aws', account_id: '123',
        services: {
          s3: {
            findings: {
              'bucket-no-encryption': {
                level: 'danger', flagged_items: 1, description: 'Bucket without encryption',
                items: ['buckets.my-bucket'],
              },
            },
          },
        },
      };
      const finding = parseScoutSuite(JSON.stringify(data));
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBe(1);
      const vulnEdges = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      expect(vulnEdges.length).toBe(1);
    });

    it('parses Lambda functions with execution role', () => {
      const data = {
        provider_code: 'aws', account_id: '123',
        services: {
          awslambda: {
            functions: {
              items: {
                'fn-1': { name: 'my-function', arn: 'arn:aws:lambda:us-east-1:123:function:my-function', role: 'arn:aws:iam::123:role/lambda-role' },
              },
            },
          },
        },
      };
      const finding = parseScoutSuite(JSON.stringify(data));
      const lambdas = finding.nodes.filter(n => n.type === 'cloud_resource' && (n as any).resource_type === 'lambda');
      expect(lambdas.length).toBe(1);
      const managedBy = finding.edges.filter(e => e.properties.type === 'MANAGED_BY');
      expect(managedBy.length).toBe(1);
    });

    it('returns empty for invalid JSON', () => {
      const finding = parseScoutSuite('not json');
      expect(finding.nodes.length).toBe(0);
    });
  });

  // ===========================================================================
  // CloudFox Parser
  // ===========================================================================

  describe('parseCloudFox', () => {
    it('parses role trust entries', () => {
      const data = [
        {
          Type: 'RoleTrust',
          RoleArn: 'arn:aws:iam::111111111111:role/target-role',
          TrustedPrincipal: 'arn:aws:iam::222222222222:role/source-role',
        },
      ];
      const finding = parseCloudFox(JSON.stringify(data));
      const identities = finding.nodes.filter(n => n.type === 'cloud_identity');
      expect(identities.length).toBe(2);
      const assumesEdges = finding.edges.filter(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumesEdges.length).toBe(1);
    });

    it('parses permission entries with POLICY_ALLOWS', () => {
      const data = [
        {
          Type: 'Permission',
          PrincipalArn: 'arn:aws:iam::111:user/attacker',
          Action: 'iam:PassRole',
          Resource: 'arn:aws:iam::111:role/admin',
        },
      ];
      const finding = parseCloudFox(JSON.stringify(data));
      const policies = finding.nodes.filter(n => n.type === 'cloud_policy');
      expect(policies.length).toBe(1);
      const allows = finding.edges.filter(e => e.properties.type === 'POLICY_ALLOWS');
      expect(allows.length).toBe(1);
      const hasPolicy = finding.edges.filter(e => e.properties.type === 'HAS_POLICY');
      expect(hasPolicy.length).toBe(1);
    });

    it('parses inventory entries with attached role', () => {
      const data = [
        {
          Name: 'my-lambda',
          AWSService: 'lambda',
          Arn: 'arn:aws:lambda:us-east-1:111:function:my-lambda',
          Role: 'arn:aws:iam::111:role/lambda-exec',
          Region: 'us-east-1',
          AccountId: '111',
        },
      ];
      const finding = parseCloudFox(JSON.stringify(data));
      const resources = finding.nodes.filter(n => n.type === 'cloud_resource');
      expect(resources.length).toBeGreaterThanOrEqual(1);
      const managedBy = finding.edges.filter(e => e.properties.type === 'MANAGED_BY');
      expect(managedBy.length).toBe(1);
    });

    it('returns empty for invalid JSON', () => {
      const finding = parseCloudFox('not json');
      expect(finding.nodes.length).toBe(0);
    });
  });

  // ===========================================================================
  // Terraform State Parser
  // ===========================================================================

  describe('parseTerraformState', () => {
    it('parses EC2 instances with host linkage', () => {
      const state = {
        version: 4,
        resources: [
          {
            type: 'aws_instance',
            name: 'web',
            instances: [{
              attributes: {
                id: 'i-abc123',
                private_ip: '10.0.1.50',
                tags: { Name: 'web-server' },
                iam_instance_profile: 'web-profile',
                metadata_options: [{ http_tokens: 'optional' }],
              },
            }],
          },
        ],
      };
      const finding = parseTerraformState(JSON.stringify(state));
      const resources = finding.nodes.filter(n => n.type === 'cloud_resource');
      expect(resources.length).toBe(1);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      const runsOn = finding.edges.filter(e => e.properties.type === 'RUNS_ON');
      expect(runsOn.length).toBe(1);
      const managedBy = finding.edges.filter(e => e.properties.type === 'MANAGED_BY');
      expect(managedBy.length).toBe(1);
    });

    it('parses IAM roles with trust policy', () => {
      const state = {
        version: 4,
        resources: [
          {
            type: 'aws_iam_role',
            name: 'lambda-exec',
            instances: [{
              attributes: {
                arn: 'arn:aws:iam::123:role/lambda-exec',
                name: 'lambda-exec',
                assume_role_policy: JSON.stringify({
                  Statement: [{ Effect: 'Allow', Principal: { AWS: ['arn:aws:iam::999:root'] } }],
                }),
              },
            }],
          },
        ],
      };
      const finding = parseTerraformState(JSON.stringify(state));
      const identities = finding.nodes.filter(n => n.type === 'cloud_identity');
      expect(identities.length).toBe(2); // role + trusted principal
      const assumes = finding.edges.filter(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumes.length).toBe(1);
    });

    it('parses lambda functions with execution role', () => {
      const state = {
        version: 4,
        resources: [
          {
            type: 'aws_lambda_function',
            name: 'processor',
            instances: [{
              attributes: {
                arn: 'arn:aws:lambda:us-east-1:123:function:processor',
                function_name: 'processor',
                role: 'arn:aws:iam::123:role/lambda-role',
              },
            }],
          },
        ],
      };
      const finding = parseTerraformState(JSON.stringify(state));
      const lambdas = finding.nodes.filter(n => n.type === 'cloud_resource');
      expect(lambdas.length).toBe(1);
      const managedBy = finding.edges.filter(e => e.properties.type === 'MANAGED_BY');
      expect(managedBy.length).toBe(1);
    });

    it('parses terraform show -json format', () => {
      const showJson = {
        values: {
          root_module: {
            resources: [
              {
                type: 'aws_s3_bucket',
                name: 'data',
                values: { bucket: 'my-data-bucket', arn: 'arn:aws:s3:::my-data-bucket', region: 'us-east-1' },
              },
            ],
          },
        },
      };
      const finding = parseTerraformState(JSON.stringify(showJson));
      const resources = finding.nodes.filter(n => n.type === 'cloud_resource');
      expect(resources.length).toBe(1);
      expect(resources[0].label).toBe('my-data-bucket');
    });

    it('parses policy attachments', () => {
      const state = {
        version: 4,
        resources: [
          {
            type: 'aws_iam_role_policy_attachment',
            name: 'attach',
            instances: [{
              attributes: {
                role: 'lambda-exec',
                policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess',
              },
            }],
          },
        ],
      };
      const finding = parseTerraformState(JSON.stringify(state));
      const policies = finding.nodes.filter(n => n.type === 'cloud_policy');
      expect(policies.length).toBe(1);
      const hasPolicy = finding.edges.filter(e => e.properties.type === 'HAS_POLICY');
      expect(hasPolicy.length).toBe(1);
    });

    it('returns empty for invalid JSON', () => {
      const finding = parseTerraformState('not json at all');
      expect(finding.nodes.length).toBe(0);
    });
  });

  // ===========================================================================
  // enumerate-iam Parser
  // ===========================================================================

  describe('parseEnumerateIam', () => {
    it('parses confirmed API calls into identity + policy', () => {
      const output = [
        '[INFO] -- Account ID: 123456789012',
        '[INFO] -- ARN: arn:aws:iam::123456789012:user/testuser',
        '[INFO] iam.list_users() worked!',
        '[INFO] s3.list_buckets() worked!',
        '[INFO] sts.get_caller_identity() worked!',
        '[INFO] ec2.describe_instances() returned an error',
      ].join('\n');

      const finding = parseEnumerateIam(output);
      expect(finding.nodes.length).toBe(2); // identity + policy
      const identity = finding.nodes.find(n => n.type === 'cloud_identity');
      expect(identity).toBeDefined();
      expect((identity as any).policies_enumerated).toBe(true);
      const policy = finding.nodes.find(n => n.type === 'cloud_policy');
      expect(policy).toBeDefined();
      expect((policy as any).actions).toContain('iam:list_users');
      expect((policy as any).actions).toContain('s3:list_buckets');
      expect((policy as any).actions).toHaveLength(3);
      const hasPolicy = finding.edges.filter(e => e.properties.type === 'HAS_POLICY');
      expect(hasPolicy.length).toBe(1);
    });

    it('returns empty when no API calls confirmed', () => {
      const output = '[INFO] Starting enumeration...\n[ERROR] No permissions found';
      const finding = parseEnumerateIam(output);
      expect(finding.nodes.length).toBe(0);
    });

    it('uses context cloud_account when no inline account ID', () => {
      const output = '[INFO] iam.get_user() worked!';
      const finding = parseEnumerateIam(output, 'test', { cloud_account: '999888777666' } as any);
      expect(finding.nodes.length).toBe(2);
    });
  });

  // ===========================================================================
  // Burp Suite XML Parser
  // ===========================================================================

  describe('parseBurp', () => {
    const sampleBurpXml = `<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="2026-01-01T00:00:00Z">
  <issue>
    <serialNumber>1234</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="10.10.10.5">http://10.10.10.5</host>
    <path>/login</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>SQL injection vulnerability found.</issueBackground>
  </issue>
  <issue>
    <serialNumber>1235</serialNumber>
    <type>5244416</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="10.10.10.5">http://10.10.10.5</host>
    <path>/search</path>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueBackground>XSS found in search parameter.</issueBackground>
  </issue>
  <issue>
    <serialNumber>1236</serialNumber>
    <type>6291712</type>
    <name>Information disclosure - emails</name>
    <host ip="10.10.10.6">https://10.10.10.6:8443</host>
    <path>/about</path>
    <severity>Information</severity>
    <confidence>Tentative</confidence>
  </issue>
</issues>`;

    it('extracts host nodes from Burp XML', () => {
      const finding = parseBurp(sampleBurpXml);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(2);
      expect(hosts.map(h => h.label).sort()).toEqual(['10.10.10.5', '10.10.10.6']);
    });

    it('extracts service nodes with correct ports', () => {
      const finding = parseBurp(sampleBurpXml);
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(2);
      const labels = services.map(s => s.label).sort();
      expect(labels).toEqual(['http/80', 'https/8443']);
    });

    it('creates webapp nodes via webappOriginId', () => {
      const finding = parseBurp(sampleBurpXml);
      const webapps = finding.nodes.filter(n => n.type === 'webapp');
      expect(webapps.length).toBe(2);
    });

    it('creates vulnerability nodes with correct type classification', () => {
      const finding = parseBurp(sampleBurpXml);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBe(3);
      const types = vulns.map(v => (v as Record<string, unknown>).vuln_type).sort();
      expect(types).toEqual(['info-disclosure', 'sqli', 'xss']);
    });

    it('maps severity to CVSS correctly', () => {
      const finding = parseBurp(sampleBurpXml);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      const sqli = vulns.find(v => (v as Record<string, unknown>).vuln_type === 'sqli');
      expect((sqli as Record<string, unknown>).cvss).toBe(7.5);
      const info = vulns.find(v => (v as Record<string, unknown>).vuln_type === 'info-disclosure');
      expect((info as Record<string, unknown>).cvss).toBe(1.0);
    });

    it('maps confidence levels correctly', () => {
      const finding = parseBurp(sampleBurpXml);
      const vulnEdges = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      const highConf = vulnEdges.find(e => e.properties.confidence === 0.95);
      expect(highConf).toBeDefined();
      const tentConf = vulnEdges.find(e => e.properties.confidence === 0.5);
      expect(tentConf).toBeDefined();
    });

    it('creates RUNS, HOSTS, and VULNERABLE_TO edges', () => {
      const finding = parseBurp(sampleBurpXml);
      const runs = finding.edges.filter(e => e.properties.type === 'RUNS');
      const hosts = finding.edges.filter(e => e.properties.type === 'HOSTS');
      const vulnTo = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      expect(runs.length).toBe(2);
      expect(hosts.length).toBe(2);
      expect(vulnTo.length).toBe(3);
    });

    it('deduplicates host and service nodes across issues', () => {
      const finding = parseBurp(sampleBurpXml);
      // Two issues target 10.10.10.5 — should have exactly 1 host node for it
      const hosts = finding.nodes.filter(n => n.type === 'host' && n.label === '10.10.10.5');
      expect(hosts.length).toBe(1);
    });

    it('handles empty input gracefully', () => {
      const finding = parseBurp('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('handles malformed XML gracefully', () => {
      const finding = parseBurp('<not-valid>xml');
      expect(finding.nodes.length).toBe(0);
    });

    it('is accessible via parseOutput', () => {
      const finding = parseOutput('burp', sampleBurpXml);
      expect(finding).not.toBeNull();
      expect(finding!.nodes.length).toBeGreaterThan(0);
    });
  });

  // ===========================================================================
  // ZAP XML Parser
  // ===========================================================================

  describe('parseZap', () => {
    const sampleZapXml = `<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0" generated="2026-01-01">
  <site name="http://10.10.10.7" host="10.10.10.7" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <alert>Cross Site Scripting (Reflected)</alert>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <cweid>79</cweid>
        <wascid>8</wascid>
        <desc>XSS found.</desc>
        <instances>
          <instance>
            <uri>http://10.10.10.7/search?q=test</uri>
            <method>GET</method>
            <param>q</param>
            <attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
          </instance>
          <instance>
            <uri>http://10.10.10.7/feedback?msg=test</uri>
            <method>POST</method>
            <param>msg</param>
          </instance>
        </instances>
      </alertitem>
      <alertitem>
        <pluginid>10202</pluginid>
        <alert>Absence of Anti-CSRF Tokens</alert>
        <riskcode>1</riskcode>
        <confidence>1</confidence>
        <cweid>352</cweid>
        <desc>No anti-CSRF tokens found.</desc>
        <instances>
          <instance>
            <uri>http://10.10.10.7/login</uri>
            <method>POST</method>
          </instance>
        </instances>
      </alertitem>
    </alerts>
  </site>
  <site name="https://10.10.10.8:443" host="10.10.10.8" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>90033</pluginid>
        <alert>Server Side Request Forgery</alert>
        <riskcode>3</riskcode>
        <confidence>3</confidence>
        <cweid>918</cweid>
        <desc>SSRF vulnerability.</desc>
        <instances>
          <instance>
            <uri>https://10.10.10.8/api/fetch?url=http://169.254.169.254</uri>
            <method>GET</method>
            <param>url</param>
          </instance>
        </instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>`;

    it('extracts host nodes from ZAP XML', () => {
      const finding = parseZap(sampleZapXml);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(2);
      expect(hosts.map(h => h.label).sort()).toEqual(['10.10.10.7', '10.10.10.8']);
    });

    it('extracts service nodes with correct protocols', () => {
      const finding = parseZap(sampleZapXml);
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(2);
      const labels = services.map(s => s.label).sort();
      expect(labels).toEqual(['http/80', 'https/443']);
    });

    it('creates webapp nodes per site', () => {
      const finding = parseZap(sampleZapXml);
      const webapps = finding.nodes.filter(n => n.type === 'webapp');
      expect(webapps.length).toBe(2);
    });

    it('creates vulnerability nodes with CWE', () => {
      const finding = parseZap(sampleZapXml);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBe(3);
      const xss = vulns.find(v => (v as Record<string, unknown>).vuln_type === 'xss');
      expect(xss).toBeDefined();
      expect((xss as Record<string, unknown>).cwe).toBe('CWE-79');
    });

    it('classifies vuln types correctly', () => {
      const finding = parseZap(sampleZapXml);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      const types = vulns.map(v => (v as Record<string, unknown>).vuln_type).sort();
      expect(types).toEqual(['csrf', 'ssrf', 'xss']);
    });

    it('maps risk codes to CVSS', () => {
      const finding = parseZap(sampleZapXml);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      const ssrf = vulns.find(v => v.label === 'Server Side Request Forgery');
      expect((ssrf as Record<string, unknown>).cvss).toBe(7.5); // riskcode 3
      const csrf = vulns.find(v => v.label === 'Absence of Anti-CSRF Tokens');
      expect((csrf as Record<string, unknown>).cvss).toBe(2.5); // riskcode 1
    });

    it('collects affected_paths from instances', () => {
      const finding = parseZap(sampleZapXml);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      const xss = vulns.find(v => (v as Record<string, unknown>).vuln_type === 'xss');
      const paths = (xss as Record<string, unknown>).affected_paths as string[];
      expect(paths).toBeDefined();
      expect(paths.length).toBe(2);
      expect(paths).toContain('/search');
      expect(paths).toContain('/feedback');
    });

    it('creates RUNS, HOSTS, and VULNERABLE_TO edges', () => {
      const finding = parseZap(sampleZapXml);
      const runs = finding.edges.filter(e => e.properties.type === 'RUNS');
      const hosts = finding.edges.filter(e => e.properties.type === 'HOSTS');
      const vulnTo = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      expect(runs.length).toBe(2);
      expect(hosts.length).toBe(2);
      expect(vulnTo.length).toBe(3);
    });

    it('handles empty input gracefully', () => {
      const finding = parseZap('');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('is accessible via parseOutput with alias', () => {
      const finding = parseOutput('owasp-zap', sampleZapXml);
      expect(finding).not.toBeNull();
      expect(finding!.nodes.length).toBeGreaterThan(0);
    });
  });

  // ===========================================================================
  // SQLMap Text Parser
  // ===========================================================================

  describe('parseSqlmap', () => {
    const sampleSqlmapText = `
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.4#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-01-01/
[12:00:01] [INFO] testing URL 'http://10.10.10.9/vulnerable.php?id=1'
[12:00:02] [INFO] testing connection to the target URL
[12:00:05] [INFO] the back-end DBMS is MySQL
[12:00:06] [INFO] Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5321=5321

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x71,0x71),NULL,NULL-- -

[12:00:06] [INFO] Parameter: id (GET) is vulnerable. identified injection point(s)
[12:00:10] [INFO] fetching database users
[12:00:11] [INFO] retrieved: 'root@localhost'
[12:00:12] [INFO] cracked password 'toor123' for user 'root'
[12:00:13] [INFO] cracked password 'pass456' for user 'webapp_user'
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests
`;

    it('extracts target URL and creates host/service/webapp nodes', () => {
      const finding = parseSqlmap(sampleSqlmapText);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].label).toBe('10.10.10.9');
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
      const webapps = finding.nodes.filter(n => n.type === 'webapp');
      expect(webapps.length).toBe(1);
    });

    it('creates SQLi vulnerability node with correct properties', () => {
      const finding = parseSqlmap(sampleSqlmapText);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBeGreaterThanOrEqual(1);
      const sqli = vulns[0] as Record<string, unknown>;
      expect(sqli.vuln_type).toBe('sqli');
      expect(sqli.dbms).toBe('MySQL');
      expect(sqli.exploitable).toBe(true);
      expect(sqli.cvss).toBe(8.5);
    });

    it('extracts cracked credentials with normalized fields', () => {
      const finding = parseSqlmap(sampleSqlmapText);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(2);
      const labels = creds.map(c => c.label).sort();
      expect(labels).toEqual(['root:password', 'webapp_user:password']);
      // Verify normalized credential fields
      const cred = creds[0] as Record<string, unknown>;
      expect(cred.cred_material_kind).toBe('plaintext_password');
      expect(cred.cred_type).toBe('plaintext');
      expect(cred.cred_usable_for_auth).toBe(true);
      expect(cred.cred_user).toBeDefined();
      // Should NOT have non-standard aliases
      expect(cred.material_kind).toBeUndefined();
      expect(cred.hash).toBeUndefined();
    });

    it('creates EXPLOITS edges from vulnerability to credentials', () => {
      const finding = parseSqlmap(sampleSqlmapText);
      const exploits = finding.edges.filter(e => e.properties.type === 'EXPLOITS');
      expect(exploits.length).toBeGreaterThanOrEqual(2);
    });

    it('creates VULNERABLE_TO edges', () => {
      const finding = parseSqlmap(sampleSqlmapText);
      const vulnTo = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      expect(vulnTo.length).toBeGreaterThanOrEqual(1);
    });

    it('handles empty input gracefully', () => {
      const finding = parseSqlmap('');
      expect(finding.nodes.length).toBe(0);
    });

    it('handles output with no injection found', () => {
      const noInjection = `[INFO] testing URL 'http://10.10.10.9/safe.php?id=1'
[INFO] all tested parameters do not appear to be injectable`;
      const finding = parseSqlmap(noInjection);
      // Should still create host/service/webapp from URL but no vulns
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBe(0);
    });

    it('parses JSON format', () => {
      const jsonOutput = JSON.stringify({
        url: 'http://10.10.10.10/api?param=1',
        dbms: 'PostgreSQL',
        vulnerabilities: [
          { parameter: 'param', type: 'GET', title: 'error-based' }
        ],
        users: ['pg_admin@localhost'],
      });
      const finding = parseSqlmap(jsonOutput);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBe(1);
      expect((vulns[0] as Record<string, unknown>).dbms).toBe('PostgreSQL');
    });

    it('is accessible via parseOutput', () => {
      const finding = parseOutput('sqlmap', sampleSqlmapText);
      expect(finding).not.toBeNull();
      expect(finding!.nodes.length).toBeGreaterThan(0);
    });
  });

  // ===========================================================================
  // WPScan JSON Parser
  // ===========================================================================

  describe('parseWpscan', () => {
    const sampleWpscanJson = JSON.stringify({
      target_url: 'http://10.10.10.11/wordpress/',
      effective_url: 'http://10.10.10.11/',
      interesting_findings: [
        { url: 'http://10.10.10.11/readme.html', type: 'headers', to_s: 'WordPress readme found' }
      ],
      version: {
        number: '6.4.2',
        status: 'outdated',
        vulnerabilities: [
          {
            title: 'WordPress 6.4.2 - Authenticated Blind SSRF',
            fixed_in: '6.4.3',
            references: { cve: ['2024-12345'] }
          }
        ]
      },
      plugins: {
        'contact-form-7': {
          slug: 'contact-form-7',
          version: { number: '5.8.1' },
          vulnerabilities: [
            {
              title: 'Contact Form 7 < 5.9 - Unauthenticated File Upload',
              fixed_in: '5.9',
              references: { cve: ['2024-67890'] }
            }
          ]
        }
      },
      themes: {
        'twentytwentyfour': {
          slug: 'twentytwentyfour',
          version: { number: '1.0' },
          vulnerabilities: []
        }
      },
      users: {
        'admin': { id: 1, slug: 'admin', status: 'active' },
        'editor': { id: 2, slug: 'editor', status: 'active' }
      },
      password_attack: {
        'admin': [{ password: 'admin123' }]
      }
    });

    it('creates WordPress-enriched webapp node', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const webapps = finding.nodes.filter(n => n.type === 'webapp');
      expect(webapps.length).toBe(1);
      const wa = webapps[0] as Record<string, unknown>;
      expect(wa.cms_type).toBe('wordpress');
      expect(wa.technology).toBe('WordPress');
      expect(wa.version).toBe('6.4.2');
    });

    it('extracts host and service nodes', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].label).toBe('10.10.10.11');
      const services = finding.nodes.filter(n => n.type === 'service');
      expect(services.length).toBe(1);
    });

    it('extracts core WordPress vulnerabilities with CVE', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      const coreVuln = vulns.find(v => v.label!.includes('Blind SSRF'));
      expect(coreVuln).toBeDefined();
      expect((coreVuln as Record<string, unknown>).cve).toBe('CVE-2024-12345');
      expect((coreVuln as Record<string, unknown>).vuln_type).toBe('cms-vuln');
    });

    it('extracts plugin vulnerabilities', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      const pluginVuln = vulns.find(v => v.label!.includes('Contact Form'));
      expect(pluginVuln).toBeDefined();
      expect((pluginVuln as Record<string, unknown>).cve).toBe('CVE-2024-67890');
      expect((pluginVuln as Record<string, unknown>).affected_component).toBe('plugin-contact-form-7@5.8.1');
    });

    it('extracts enumerated users', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(2);
      expect(users.map(u => u.label).sort()).toEqual(['admin', 'editor']);
    });

    it('creates POTENTIAL_AUTH edges for enumerated users', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const potAuth = finding.edges.filter(e => e.properties.type === 'POTENTIAL_AUTH');
      expect(potAuth.length).toBe(2);
    });

    it('extracts cracked passwords with normalized credential fields', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds.length).toBe(1);
      const cred = creds[0] as Record<string, unknown>;
      expect(cred.cred_user).toBe('admin');
      expect(cred.cred_material_kind).toBe('plaintext_password');
      expect(cred.cred_type).toBe('plaintext');
      expect(cred.cred_value).toBe('admin123');
      expect(cred.cred_usable_for_auth).toBe(true);
      // Should NOT have non-standard aliases
      expect(cred.material_kind).toBeUndefined();
    });

    it('creates VALID_ON edge for cracked password', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const validOn = finding.edges.filter(e => e.properties.type === 'VALID_ON');
      expect(validOn.length).toBe(1);
    });

    it('creates VULNERABLE_TO edges for all vulnerabilities', () => {
      const finding = parseWpscan(sampleWpscanJson);
      const vulnTo = finding.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
      expect(vulnTo.length).toBe(2); // core + plugin (theme has empty vulns)
    });

    it('handles empty input gracefully', () => {
      const finding = parseWpscan('');
      expect(finding.nodes.length).toBe(0);
    });

    it('handles JSON with no vulnerabilities', () => {
      const minimal = JSON.stringify({
        target_url: 'http://10.10.10.12/',
        effective_url: 'http://10.10.10.12/',
        version: { number: '6.5.0' },
      });
      const finding = parseWpscan(minimal);
      const webapps = finding.nodes.filter(n => n.type === 'webapp');
      expect(webapps.length).toBe(1);
      const vulns = finding.nodes.filter(n => n.type === 'vulnerability');
      expect(vulns.length).toBe(0);
    });

    it('is accessible via parseOutput', () => {
      const finding = parseOutput('wpscan', sampleWpscanJson);
      expect(finding).not.toBeNull();
      expect(finding!.nodes.length).toBeGreaterThan(0);
    });
  });

  // ===========================================================================
  // Parser registration
  // ===========================================================================

  describe('parser registration', () => {
    it('getSupportedParsers includes new web parsers', () => {
      const supported = getSupportedParsers();
      expect(supported).toContain('burp');
      expect(supported).toContain('burp-suite');
      expect(supported).toContain('zap');
      expect(supported).toContain('owasp-zap');
      expect(supported).toContain('sqlmap');
      expect(supported).toContain('wpscan');
    });
  });
});
