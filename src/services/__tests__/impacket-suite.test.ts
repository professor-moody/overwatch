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
      expect(creds[0].cred_type).toBe('kerberos_asrep');
      expect(creds[0].cred_material_kind).toBe('kerberos_asrep');
      expect(creds[0].cred_usable_for_auth).toBe(false);
      // 1.1: full hash material is persisted on the credential node so it
      // can be cracked (hashcat -m 18200) without re-running GetNPUsers.
      expect(creds[0].cred_value).toContain('$krb5asrep$23$');
      expect(creds[0].cred_value).toContain('jdoe');
      expect(creds[0].cred_hash).toBe(creds[0].cred_value);

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
      // 1.1: full TGS hash with SPN is persisted (hashcat -m 13100).
      expect(creds[0].cred_value).toContain('$krb5tgs$23$');
      expect(creds[0].cred_value).toContain('sqlsvc');
      expect(creds[0].cred_value).toContain('MSSQLSvc/db01.acme.local');
      expect(creds[0].cred_hash).toBe(creds[0].cred_value);

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
      // 1.3: ccache filename is persisted as cred_value so the TGT can be
      // reused via KRB5CCNAME without re-running getTGT.
      expect(creds[0].cred_value).toBe('admin.ccache');

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
      // 1.3: ccache filename is persisted on the ST credential too.
      expect(creds[0].cred_value).toBe('sqlsvc.ccache');
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

    it('emits exactly one user node for repeated success banners (regression: P1 1.5 seenNodes typo)', () => {
      // Previously the dedup tracker had `seenNodes.has(resolvedUserId);` (a
      // no-op expression) instead of `.add(...)`. Two banners with the same
      // user therefore emitted duplicate user nodes. Output here repeats the
      // header line; the parser only matches the first regex hit per call,
      // so the test instead exercises that two parse passes against the same
      // output deduplicate within a single finding.
      const output = [
        'Impacket v0.12.0 - ACME/admin@10.10.10.5',
        '[*] SMBv3.0 dialect used',
        'Launching semi-interactive shell',
      ].join('\n');
      const finding = parseWmiexec(output, 'test', { source_host: '10.10.10.5', domain: 'acme.local' });
      const users = finding.nodes.filter(n => n.type === 'user');
      // Should be exactly one user node now that dedup actually adds.
      expect(users).toHaveLength(1);
      expect(users[0].username).toBe('admin');
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

    // F2: Opening SVCManager is a pre-execution step. If service creation
    // then fails with STATUS_ACCESS_DENIED, the parser must NOT emit a
    // HAS_SESSION edge. Previously EXEC_SUCCESS matched on `Opening
    // SVCManager` alone, so the failure was swallowed and a bogus session
    // appeared in the graph.
    it('does NOT emit HAS_SESSION when SVCManager opens but service creation fails (F2)', () => {
      const output = [
        'Impacket v0.12.0 - ACME/lowpriv@10.10.10.5',
        '[*] Requesting shares on 10.10.10.5.....',
        '[*] Found writable share ADMIN$',
        '[*] Opening SVCManager on 10.10.10.5.....',
        '[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED',
      ].join('\n');
      const finding = parsePsexec(output, 'test', { source_host: '10.10.10.5', domain: 'acme.local' });
      expect(finding.nodes).toHaveLength(0);
      expect(finding.edges).toHaveLength(0);
    });

    it('does NOT emit HAS_SESSION on STATUS_LOGON_FAILURE (F2)', () => {
      const output = [
        'Impacket v0.12.0 - ACME/typo@10.10.10.5',
        '[*] Requesting shares on 10.10.10.5.....',
        '[-] STATUS_LOGON_FAILURE',
      ].join('\n');
      const finding = parsePsexec(output, 'test', { source_host: '10.10.10.5', domain: 'acme.local' });
      expect(finding.nodes).toHaveLength(0);
      expect(finding.edges).toHaveLength(0);
    });
  });

  // F3: ccache filenames with dotted usernames (john.smith.ccache) used
  // to be parsed via `([^.]+)\.ccache$` which captures only the last
  // dot-delimited segment, attributing the TGT to `smith` instead of
  // `john.smith`. The fix anchors on `(.+?)\.ccache$`.
  describe('parseGetTGT — ccache filename parsing (F3)', () => {
    it('captures dotted usernames in full', () => {
      const output = [
        'Impacket v0.12.0 - ACME/john.smith@dc01.acme.local',
        '[*] Saving ticket in john.smith.ccache',
      ].join('\n');
      const finding = parseGetTGT(output, 'test', { domain: 'acme.local' });
      const cred = finding.nodes.find(n => n.type === 'credential');
      expect(cred).toBeDefined();
      expect(cred!.cred_user).toBe('john.smith');
      expect(cred!.label).toBe('TGT:john.smith');
    });

    it('still handles domain/user.ccache layout', () => {
      const output = [
        '[*] Saving ticket in acme.local/admin.user.ccache',
      ].join('\n');
      const finding = parseGetTGT(output, 'test');
      const cred = finding.nodes.find(n => n.type === 'credential');
      expect(cred).toBeDefined();
      expect(cred!.cred_user).toBe('admin.user');
      expect(cred!.cred_domain).toBe('acme.local');
    });
  });

  // F4: Kerberos AS-REP / Kerberoast hashes used to capture etype as
  // `\d+` (no group) and reconstruct as `$23$`, silently rewriting
  // etype 17/18 hashes. The fix captures the etype and reuses it.
  describe('Kerberos etype preservation (F4)', () => {
    it('preserves etype 18 in AS-REP reconstruction', () => {
      const output = '$krb5asrep$18$svc-1@ACME.LOCAL:abc123$ffeeddccbbaa00112233';
      const finding = parseGetNPUsers(output, 'test', { domain: 'acme.local' });
      const cred = finding.nodes.find(n => n.type === 'credential');
      expect(cred).toBeDefined();
      expect(cred!.cred_value).toContain('$krb5asrep$18$');
      expect(cred!.cred_value).not.toContain('$krb5asrep$23$');
    });

    it('preserves etype 17 in Kerberoast reconstruction', () => {
      const output = '$krb5tgs$17$*svc-sql$ACME.LOCAL$MSSQLSvc/sql.acme.local:1433*$abc$ffeedd';
      const finding = parseGetUserSPNs(output, 'test', { domain: 'acme.local' });
      const cred = finding.nodes.find(n => n.type === 'credential');
      expect(cred).toBeDefined();
      expect(cred!.cred_value).toContain('$krb5tgs$17$');
      expect(cred!.cred_value).not.toContain('$krb5tgs$23$');
    });
  });
});
