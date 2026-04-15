import { describe, it, expect } from 'vitest';
import {
  parseGetNPUsers,
  parseGetUserSPNs,
  parseGetTGT,
  parseGetST,
  parseSmbclient,
  parseWmiexec,
  parsePsexec,
} from '../parsers/impacket-suite.js';

describe('Impacket Suite Parsers', () => {
  describe('parseGetNPUsers', () => {
    it('extracts AS-REP hashes and user nodes', () => {
      const output = [
        'Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies',
        '',
        '$krb5asrep$23$jdoe@ACME.LOCAL:abc123def456abc123def456abc123de$hashcontinuation',
        '$krb5asrep$23$svc_sql@ACME.LOCAL:111222333444555666777888999aaabb$morehash',
      ].join('\n');

      const finding = parseGetNPUsers(output);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users).toHaveLength(2);
      expect(users.map(u => u.username).sort()).toEqual(['jdoe', 'svc_sql']);
      expect(users[0].asrep_roastable).toBe(true);

      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds).toHaveLength(2);
      expect(creds[0].cred_type).toBe('kerberos_tgs');
      expect(creds[0].cred_usable_for_auth).toBe(false);

      // Domain node
      const domains = finding.nodes.filter(n => n.type === 'domain');
      expect(domains).toHaveLength(1);
      expect(domains[0].domain_name).toBe('acme.local');

      // AS_REP_ROASTABLE edges
      const roastEdges = finding.edges.filter(e => e.properties.type === 'AS_REP_ROASTABLE');
      expect(roastEdges).toHaveLength(2);

      // OWNS_CRED edges
      const ownsEdges = finding.edges.filter(e => e.properties.type === 'OWNS_CRED');
      expect(ownsEdges).toHaveLength(2);
    });

    it('returns empty finding for no matches', () => {
      const finding = parseGetNPUsers('No entries found.\n[-] No users found.');
      expect(finding.nodes).toHaveLength(0);
      expect(finding.edges).toHaveLength(0);
    });
  });

  describe('parseGetUserSPNs', () => {
    it('extracts Kerberoast hashes', () => {
      const output = [
        'Impacket v0.12.0',
        '$krb5tgs$23$*sqlsvc$ACME.LOCAL$MSSQLSvc/db01.acme.local:1433*$aabb1122aabb1122aabb1122aabb1122$hashdata',
      ].join('\n');

      const finding = parseGetUserSPNs(output);
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users).toHaveLength(1);
      expect(users[0].username).toBe('sqlsvc');
      expect(users[0].has_spn).toBe(true);

      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds).toHaveLength(1);
      expect(creds[0].cred_type).toBe('kerberos_tgs');

      const kerbEdges = finding.edges.filter(e => e.properties.type === 'KERBEROASTABLE');
      expect(kerbEdges).toHaveLength(1);
    });

    it('extracts SPN table entries (no hashes)', () => {
      const output = [
        'ServicePrincipalName                  Name      MemberOf',
        'sqlsvc    MSSQLSvc/db01.acme.local:1433    CN=Domain Users',
        'websvc    HTTP/web01.acme.local             CN=Domain Users',
      ].join('\n');

      const finding = parseGetUserSPNs(output, 'test', { domain: 'acme.local' });
      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users).toHaveLength(2);
      expect(users.every(u => u.has_spn)).toBe(true);
    });
  });

  describe('parseGetTGT', () => {
    it('extracts TGT credential on success', () => {
      const output = [
        'Impacket v0.12.0',
        '[*] Saving ticket in admin.ccache',
      ].join('\n');

      const finding = parseGetTGT(output, 'test', { domain: 'acme.local' });
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds).toHaveLength(1);
      expect(creds[0].cred_type).toBe('kerberos_tgt');
      expect(creds[0].cred_usable_for_auth).toBe(true);
      expect(creds[0].valid_until).toBeDefined();

      const users = finding.nodes.filter(n => n.type === 'user');
      expect(users).toHaveLength(1);
      expect(users[0].username).toBe('admin');
    });

    it('returns empty finding on failure', () => {
      const output = '[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN';
      const finding = parseGetTGT(output);
      expect(finding.nodes).toHaveLength(0);
    });
  });

  describe('parseGetST', () => {
    it('extracts service ticket credential', () => {
      const output = '[*] Saving ticket in sqlsvc.ccache';
      const finding = parseGetST(output, 'test', { domain: 'acme.local' });
      const creds = finding.nodes.filter(n => n.type === 'credential');
      expect(creds).toHaveLength(1);
      expect(creds[0].cred_type).toBe('kerberos_tgs');
      expect(creds[0].cred_usable_for_auth).toBe(true);
    });

    it('returns empty on failure', () => {
      const finding = parseGetST('[-] Error getting service ticket');
      expect(finding.nodes).toHaveLength(0);
    });
  });

  describe('parseSmbclient', () => {
    it('extracts share listing', () => {
      const output = [
        '    Sharename       Type      Comment',
        '    ---------       ----      -------',
        '    ADMIN$          Disk      Remote Admin',
        '    C$              Disk      Default share',
        '    IPC$            IPC       Remote IPC',
        '    Backups         Disk      ',
        '    Public          Disk      Public files',
      ].join('\n');

      const finding = parseSmbclient(output, 'test', { source_host: '10.10.10.5' });
      const shares = finding.nodes.filter(n => n.type === 'share');
      // IPC$ excluded
      expect(shares).toHaveLength(4);
      expect(shares.map(s => s.share_name).sort()).toEqual(['ADMIN$', 'Backups', 'C$', 'Public']);

      // Host node created
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts).toHaveLength(1);
      expect(hosts[0].ip).toBe('10.10.10.5');
    });

    it('returns empty for no shares', () => {
      const finding = parseSmbclient('NT_STATUS_ACCESS_DENIED');
      expect(finding.nodes).toHaveLength(0);
    });
  });

  describe('parseWmiexec', () => {
    it('detects successful execution', () => {
      const output = [
        'Impacket v0.12.0 - ACME/admin@10.10.10.5',
        '[*] SMBv3.0 dialect used',
        'Launching semi-interactive shell',
        'C:\\>whoami',
        'acme\\admin',
      ].join('\n');

      const finding = parseWmiexec(output, 'test', { source_host: '10.10.10.5', domain: 'acme.local' });
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts).toHaveLength(1);
      expect(hosts[0].ip).toBe('10.10.10.5');
    });

    it('returns empty for failed execution', () => {
      const finding = parseWmiexec('[-] Error connecting to target');
      expect(finding.nodes).toHaveLength(0);
    });
  });

  describe('parsePsexec', () => {
    it('detects successful execution via SVCManager', () => {
      const output = [
        'Impacket v0.12.0 - ACME/admin@10.10.10.5',
        '[*] Requesting shares on 10.10.10.5.....',
        '[*] Found writable share ADMIN$',
        '[*] Opening SVCManager on 10.10.10.5.....',
        '[*] Creating service',
        'Microsoft Windows [Version 10.0.17763.1]',
        'C:\\Windows\\system32>whoami',
      ].join('\n');

      const finding = parsePsexec(output, 'test', { source_host: '10.10.10.5', domain: 'acme.local' });
      const hosts = finding.nodes.filter(n => n.type === 'host');
      expect(hosts).toHaveLength(1);
    });
  });
});
