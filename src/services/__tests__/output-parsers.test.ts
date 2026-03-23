import { describe, it, expect } from 'vitest';
import { parseNmapXml, parseNxc, parseCertipy, parseSecretsdump, parseKerbrute, parseHashcat, parseResponder, parseOutput, getSupportedParsers } from '../output-parsers.js';

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

  describe('parseNxc', () => {
    it('extracts admin access from Pwn3d! output', () => {
      const output = `SMB  10.10.10.5  445  ACME\\jdoe  [+]  (Pwn3d!)`;
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
      const output = `SMB  10.10.10.5  445  ACME\\scanner  [+]  Windows Server 2019`;
      const finding = parseNxc(output);

      const validOnEdges = finding.edges.filter(e => e.properties.type === 'VALID_ON');
      expect(validOnEdges.length).toBe(1);
      expect(finding.nodes.some(n => n.type === 'service' && n.service_name === 'smb')).toBe(true);
    });

    it('handles multi-line output', () => {
      const output = [
        'SMB  10.10.10.5  445  ACME\\admin  [+]  (Pwn3d!)',
        'SMB  10.10.10.6  445  ACME\\admin  [+]  Windows Server 2016',
        'SMB  10.10.10.7  445  ACME\\admin  [-]  Access denied',
      ].join('\n');

      const finding = parseNxc(output);
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(3); // All matched hosts are recorded

      // But only successful auth produces edges
      const adminEdges = finding.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1); // Only Pwn3d! line
      const validOnEdges = finding.edges.filter(e => e.properties.type === 'VALID_ON');
      expect(validOnEdges.length).toBe(2); // Both [+] lines produce VALID_ON edges
    });

    it('connects enumerated shares back to the host and SMB service', () => {
      const output = `SMB  10.10.10.5  445  IPC$  READ, WRITE`;
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
        'SMB  10.10.10.5  445  ACME\\scanner  [+]  Windows Server 2019',
        'SMB  10.10.10.5  445  ACME\\scanner  [+]  Windows Server 2019',
        'SMB  10.10.10.5  445  IPC$  READ',
        'SMB  10.10.10.5  445  IPC$  READ',
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
      const escEdges = finding.edges.filter(e => e.properties.type === 'ESC1');
      expect(escEdges.length).toBe(2);
      expect(escEdges[0].source).toBe(escEdges[1].source);
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
  });
});
