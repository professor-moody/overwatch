import { describe, it, expect } from 'vitest';
import { buildBloodHoundSidMap, parseBloodHoundFile, normalizeSharpHoundCE } from '../bloodhound-ingest.js';

describe('BloodHound Ingestion', () => {

  describe('parseBloodHoundFile', () => {

    it('parses computers.json into host nodes', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: {
              name: 'DC01.ACME.LOCAL',
              operatingsystem: 'Windows Server 2019',
              enabled: true,
              unconstraineddelegation: true,
              domain: 'acme.local',
            },
            Status: { Connectable: true },
            Aces: [],
            LocalAdmins: [],
            RemoteDesktopUsers: [],
            PSRemoteUsers: [],
            DcomUsers: [],
            AllowedToDelegate: [],
            AllowedToAct: [],
          },
        ],
        meta: { type: 'computers', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      expect(result).not.toBeNull();
      const hostNodes = result.finding!.nodes.filter(n => n.type === 'host');
      expect(hostNodes.length).toBe(1);

      const node = hostNodes[0];
      expect(node.type).toBe('host');
      expect(node.label).toBe('DC01.ACME.LOCAL');
      expect(node.os).toBe('Windows Server 2019');
      expect(node.alive).toBe(true);
      expect(node.unconstrained_delegation).toBe(true);
      expect(node.domain_joined).toBe(true);
    });

    it('parses users.json into user nodes', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500',
            Properties: {
              name: 'ADMINISTRATOR@ACME.LOCAL',
              displayname: 'Built-in Administrator',
              enabled: true,
              admincount: true,
              hasspn: false,
              dontreqpreauth: false,
              sid: 'S-1-5-21-1234-5678-9012-500',
              domain: 'acme.local',
            },
            Aces: [],
          },
        ],
        meta: { type: 'users', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(result).not.toBeNull();
      const userNodes = result.finding!.nodes.filter(n => n.type === 'user');
      expect(userNodes.length).toBe(1);

      const node = userNodes[0];
      expect(node.type).toBe('user');
      expect(node.label).toBe('ADMINISTRATOR@ACME.LOCAL');
      expect(node.privileged).toBe(true);
      expect(node.enabled).toBe(true);
    });

    it('normalizes admincount integer to boolean', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1234',
            Properties: {
              name: 'SVCADMIN@ACME.LOCAL',
              admincount: 1,
              sid: 'S-1-5-21-1234-5678-9012-1234',
              domain: 'acme.local',
            },
            Aces: [],
          },
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1235',
            Properties: {
              name: 'NORMALUSER@ACME.LOCAL',
              admincount: 0,
              sid: 'S-1-5-21-1234-5678-9012-1235',
              domain: 'acme.local',
            },
            Aces: [],
          },
        ],
        meta: { type: 'users', count: 2, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(result).not.toBeNull();
      const nodes = result.finding!.nodes;
      const admin = nodes.find(n => n.label === 'SVCADMIN@ACME.LOCAL');
      const normal = nodes.find(n => n.label === 'NORMALUSER@ACME.LOCAL');
      // admincount: 1 → privileged: true (boolean, not integer)
      expect(admin!.privileged).toBe(true);
      expect(typeof admin!.privileged).toBe('boolean');
      // admincount: 0 → privileged: false (boolean)
      expect(normal!.privileged).toBe(false);
      expect(typeof normal!.privileged).toBe('boolean');
    });

    it('parses groups.json into group nodes', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-512',
            Properties: {
              name: 'DOMAIN ADMINS@ACME.LOCAL',
              admincount: true,
              sid: 'S-1-5-21-1234-5678-9012-512',
              domain: 'acme.local',
            },
            Members: [
              { ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500', ObjectType: 'User' },
            ],
            Aces: [],
          },
        ],
        meta: { type: 'groups', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'groups.json');
      expect(result).not.toBeNull();
      const groupNodes = result.finding!.nodes.filter(n => n.type === 'group');
      expect(groupNodes.length).toBe(1);
      expect(groupNodes[0].type).toBe('group');

      // Should have a MEMBER_OF edge
      const memberEdges = result.finding!.edges.filter(e => e.properties.type === 'MEMBER_OF');
      expect(memberEdges.length).toBe(1);
    });

    it('extracts ACE edges', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'DC01.ACME.LOCAL' },
            Aces: [
              {
                PrincipalSID: 'S-1-5-21-1234-5678-9012-512',
                PrincipalType: 'Group',
                RightName: 'GenericAll',
                IsInherited: false,
              },
              {
                PrincipalSID: 'S-1-5-21-1234-5678-9012-500',
                PrincipalType: 'User',
                RightName: 'WriteDacl',
                IsInherited: true,
              },
            ],
          },
        ],
        meta: { type: 'computers', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      expect(result).not.toBeNull();

      const genericAll = result.finding!.edges.filter(e => e.properties.type === 'GENERIC_ALL');
      expect(genericAll.length).toBe(1);

      const writeDacl = result.finding!.edges.filter(e => e.properties.type === 'WRITE_DACL');
      expect(writeDacl.length).toBe(1);
      expect(writeDacl[0].properties.inherited).toBe(true);
    });

    it('extracts session edges', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'WS01.ACME.LOCAL' },
            Sessions: [
              { UserSID: 'S-1-5-21-1234-5678-9012-500', ComputerSID: 'S-1-5-21-1234-5678-9012-1001' },
            ],
            Aces: [],
          },
        ],
        meta: { type: 'computers', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      const sessionEdges = result.finding!.edges.filter(e => e.properties.type === 'HAS_SESSION');
      expect(sessionEdges.length).toBe(1);
      expect(sessionEdges[0].properties.confidence).toBe(0.9);
    });

    it('extracts LocalAdmins edges', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'WS01.ACME.LOCAL' },
            LocalAdmins: [
              { ObjectIdentifier: 'S-1-5-21-1234-5678-9012-512', ObjectType: 'Group' },
            ],
            Aces: [],
          },
        ],
        meta: { type: 'computers', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      const adminEdges = result.finding!.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1);
    });

    it('extracts delegation edges', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'DC01.ACME.LOCAL' },
            AllowedToDelegate: ['S-1-5-21-1234-5678-9012-1002'],
            AllowedToAct: [
              { ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1003', ObjectType: 'Computer' },
            ],
            Aces: [],
          },
        ],
        meta: { type: 'computers', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');

      const delegatesTo = result.finding!.edges.filter(e => e.properties.type === 'DELEGATES_TO');
      expect(delegatesTo.length).toBe(1);

      const allowedToAct = result.finding!.edges.filter(e => e.properties.type === 'ALLOWED_TO_ACT');
      expect(allowedToAct.length).toBe(1);
    });

    it('handles invalid JSON gracefully', () => {
      const result = parseBloodHoundFile('not json', 'bad.json');
      expect(result).not.toBeNull();
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('handles missing data array gracefully', () => {
      const result = parseBloodHoundFile(JSON.stringify({ meta: { type: 'users' } }), 'empty.json');
      expect(result).not.toBeNull();
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('returns null finding for empty data arrays', () => {
      const bhData = {
        data: [],
        meta: { type: 'users', count: 0, version: 5 },
      };
      const result = parseBloodHoundFile(JSON.stringify(bhData), 'empty.json');
      expect(result.finding).toBeNull();
    });

    it('extracts RDP and PSRemote edges', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'WS01.ACME.LOCAL' },
            RemoteDesktopUsers: [
              { ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1100', ObjectType: 'User' },
            ],
            PSRemoteUsers: [
              { ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1200', ObjectType: 'Group' },
            ],
            Aces: [],
          },
        ],
        meta: { type: 'computers', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      const rdp = result.finding!.edges.filter(e => e.properties.type === 'CAN_RDPINTO');
      expect(rdp.length).toBe(1);

      const ps = result.finding!.edges.filter(e => e.properties.type === 'CAN_PSREMOTE');
      expect(ps.length).toBe(1);
    });

    it('parses domains.json', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012',
            Properties: {
              name: 'ACME.LOCAL',
              functionallevel: '2016',
              domain: 'acme.local',
            },
            Aces: [],
            Trusts: [],
          },
        ],
        meta: { type: 'domains', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'domains.json');
      expect(result).not.toBeNull();
      expect(result.finding!.nodes[0].type).toBe('domain');
      expect(result.finding!.nodes[0].functional_level).toBe('2016');
    });

    it('parses enterprise CAs into canonical ca nodes', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'CA-OBJECT-1',
          Properties: { name: 'ACME-CA', caname: 'ACME-CA' },
          Aces: [],
        }],
        meta: { type: 'enterprisecas', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'enterprisecas.json');
      expect(result.finding!.nodes[0].type).toBe('ca');
      expect(result.finding!.nodes[0].id).toBe('ca-acme-ca');
      expect(result.finding!.nodes[0].ca_kind).toBe('enterprise_ca');
    });

    it('parses certificate templates into canonical cert_template nodes', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'TEMPLATE-1',
          Properties: {
            name: 'UserTemplate',
            templatename: 'UserTemplate',
            enrolleesuppliessubject: true,
            eku: ['Client Authentication'],
          },
          Aces: [],
        }],
        meta: { type: 'certtemplates', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'certtemplates.json');
      expect(result.finding!.nodes[0].type).toBe('cert_template');
      expect(result.finding!.nodes[0].id).toBe('cert-template-usertemplate');
      expect(result.finding!.nodes[0].enrollee_supplies_subject).toBe(true);
    });

    it('parses PKI stores into canonical pki_store nodes', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'STORE-1',
          Properties: { name: 'NTAuthCertificates' },
          Aces: [],
        }],
        meta: { type: 'ntauthstores', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'ntauthstores.json');
      expect(result.finding!.nodes[0].type).toBe('pki_store');
      expect(result.finding!.nodes[0].id).toBe('pki-store-ntauth-store-ntauthcertificates');
      expect(result.finding!.nodes[0].pki_store_kind).toBe('ntauth_store');
    });

    it('maps explicit ADCS ACE rights onto existing edge types', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'CA-OBJECT-1',
          Properties: { name: 'ACME-CA' },
          Aces: [{
            PrincipalSID: 'S-1-5-21-1234-5678-9012-512',
            PrincipalType: 'Group',
            RightName: 'ManageCA',
            IsInherited: false,
          }],
        }],
        meta: { type: 'enterprisecas', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'enterprisecas.json');
      const edge = result.finding!.edges.find(e => e.properties.type === 'GENERIC_ALL');
      expect(edge).toBeDefined();
      expect(edge!.target).toBe('ca-acme-ca');
    });

    it('maps ADCS relation arrays using the shared SID map', () => {
      const domains = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012',
          Properties: { name: 'CORP.LOCAL', domain: 'corp.local' },
          Aces: [],
        }],
        meta: { type: 'domains', count: 1, version: 5 },
      });
      const templates = JSON.stringify({
        data: [{
          ObjectIdentifier: 'TEMPLATE-1',
          Properties: { name: 'UserTemplate', templatename: 'UserTemplate' },
          PublishedTo: [{ ObjectIdentifier: 'S-1-5-21-1234-5678-9012', ObjectType: 'Domain' }],
          Aces: [],
        }],
        meta: { type: 'certtemplates', count: 1, version: 5 },
      });

      const { sidMap } = buildBloodHoundSidMap([
        { raw: domains, filename: 'domains.json' },
        { raw: templates, filename: 'certtemplates.json' },
      ]);
      const result = parseBloodHoundFile(templates, 'certtemplates.json', { sidMap });
      const related = result.finding!.edges.find(e => e.properties.type === 'RELATED');

      expect(related).toBeDefined();
      expect(related!.source).toBe('cert-template-usertemplate');
      expect(related!.target).toBe('domain-corp-local');
    });

    it('resolves typed ADCS relation refs canonically without a shared SID map', () => {
      const templates = JSON.stringify({
        data: [{
          ObjectIdentifier: 'TEMPLATE-1',
          Properties: { name: 'UserTemplate', templatename: 'UserTemplate' },
          PublishedTo: [{ ObjectIdentifier: 'CORP.LOCAL', ObjectType: 'Domain' }],
          Aces: [],
        }],
        meta: { type: 'certtemplates', count: 1, version: 5 },
      });

      const result = parseBloodHoundFile(templates, 'certtemplates.json');
      const related = result.finding!.edges.find(e => e.properties.type === 'RELATED');

      expect(related).toBeDefined();
      expect(related!.target).toBe('domain-corp-local');
    });

    it('warns on unknown ADCS BloodHound object types without failing parsing', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'WEIRD-ADCS-1',
          Properties: { name: 'Odd ADCS Object' },
        }],
        meta: { type: 'adcsmysteryobjects', count: 1, version: 5 },
      };

      const result = parseBloodHoundFile(JSON.stringify(bhData), 'adcsmysteryobjects.json');
      expect(result.finding).toBeNull();
      expect(result.errors.some(err => err.includes("unknown BloodHound type 'adcsmysteryobjects'"))).toBe(true);
    });

    // =============================================
    // Canonical ID Tests (P1 cross-source composition)
    // =============================================

    it('user node with samaccountname+domain gets canonical userId()', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1105',
          Properties: {
            name: 'JSMITH@CORP.LOCAL',
            samaccountname: 'jsmith',
            domain: 'corp.local',
            enabled: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 5 },
      };
      const result = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      // Should match parser-utils userId('jsmith', 'corp.local') = 'user-corp-local-jsmith'
      expect(result.finding!.nodes[0].id).toBe('user-corp-local-jsmith');
    });

    it('computer node with name gets canonical hostname-based ID', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
          Properties: {
            name: 'DC01.CORP.LOCAL',
            domain: 'corp.local',
            operatingsystem: 'Windows Server 2022',
          },
          Aces: [],
        }],
        meta: { type: 'computers', count: 1, version: 5 },
      };
      const result = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      // normalizeKeyPart('DC01.CORP.LOCAL') → 'dc01-corp-local'
      expect(result.finding!.nodes[0].id).toBe('host-dc01-corp-local');
    });

    it('domain node gets canonical domainId()', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012',
          Properties: { name: 'CORP.LOCAL', domain: 'corp.local' },
          Aces: [],
        }],
        meta: { type: 'domains', count: 1, version: 5 },
      };
      const result = parseBloodHoundFile(JSON.stringify(bhData), 'domains.json');
      // domainId('CORP.LOCAL') = 'domain-corp-local'
      expect(result.finding!.nodes[0].id).toBe('domain-corp-local');
    });

    it('node without identity fields falls back to SID-based ID', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-XXXX',
          Properties: {},  // no samaccountname, name, or domain
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 5 },
      };
      const result = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(result.finding!.nodes[0].id).toMatch(/^bh-user-/);
    });

    it('all BH nodes carry bh_sid property', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1105',
            Properties: { name: 'JSMITH@CORP.LOCAL', samaccountname: 'jsmith', domain: 'corp.local' },
            Aces: [],
          },
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'WS01.CORP.LOCAL', domain: 'corp.local' },
            Aces: [],
          },
        ],
        meta: { type: 'users', count: 2, version: 5 },
      };
      const result = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      // Stub domain nodes don't carry bh_sid; filter to BH-sourced nodes only
      const bhNodes = result.finding!.nodes.filter(n => n.type !== 'domain' || n.bh_sid);
      expect(bhNodes.length).toBeGreaterThan(0);
      for (const node of bhNodes) {
        expect(node.bh_sid).toBeDefined();
        expect(typeof node.bh_sid).toBe('string');
      }
    });

    it('uses a shared SID map to resolve cross-file references to canonical IDs', () => {
      const users = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1105',
          Properties: {
            name: 'JSMITH@CORP.LOCAL',
            samaccountname: 'jsmith',
            domain: 'corp.local',
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 5 },
      });
      const computers = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
          Properties: { name: 'WS01.CORP.LOCAL', domain: 'corp.local' },
          Sessions: [
            { UserSID: 'S-1-5-21-1234-5678-9012-1105', ComputerSID: 'S-1-5-21-1234-5678-9012-1001' },
          ],
          Aces: [],
        }],
        meta: { type: 'computers', count: 1, version: 5 },
      });

      const { sidMap } = buildBloodHoundSidMap([
        { raw: computers, filename: 'computers.json' },
        { raw: users, filename: 'users.json' },
      ]);
      const result = parseBloodHoundFile(computers, 'computers.json', { sidMap });
      const sessionEdge = result.finding!.edges.find(e => e.properties.type === 'HAS_SESSION');

      expect(sessionEdge).toBeDefined();
      expect(sessionEdge!.source).toBe('user-corp-local-jsmith');
      expect(sessionEdge!.target).toBe('host-ws01-corp-local');
    });

    it('builds the same SID map regardless of file order', () => {
      const users = {
        raw: JSON.stringify({
          data: [{
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1105',
            Properties: {
              name: 'JSMITH@CORP.LOCAL',
              samaccountname: 'jsmith',
              domain: 'corp.local',
            },
            Aces: [],
          }],
          meta: { type: 'users', count: 1, version: 5 },
        }),
        filename: 'users.json',
      };
      const computers = {
        raw: JSON.stringify({
          data: [{
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
            Properties: { name: 'WS01.CORP.LOCAL', domain: 'corp.local' },
            Aces: [],
          }],
          meta: { type: 'computers', count: 1, version: 5 },
        }),
        filename: 'computers.json',
      };

      const forward = buildBloodHoundSidMap([users, computers]).sidMap;
      const reverse = buildBloodHoundSidMap([computers, users]).sidMap;

      expect(Object.fromEntries(forward)).toEqual(Object.fromEntries(reverse));
    });
  });

  // =============================================
  // SharpHound CE Format Support
  // =============================================
  describe('SharpHound CE format', () => {

    it('detects CE format by meta.version >= 5', () => {
      const ceData = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500',
          Properties: {
            SAMAccountName: 'Administrator',
            Domain: 'acme.local',
            Enabled: true,
            AdminCount: true,
            DisplayName: 'Built-in Administrator',
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 6 },
      });

      const result = normalizeSharpHoundCE(ceData, 'users.json');
      expect(result.wasCE).toBe(true);
      // Verify properties were lowercased
      const normalized = JSON.parse(result.normalized);
      const props = normalized.data[0].Properties;
      expect(props.samaccountname).toBe('Administrator');
      expect(props.domain).toBe('acme.local');
      expect(props.enabled).toBe(true);
      expect(props.admincount).toBe(true);
      expect(props.displayname).toBe('Built-in Administrator');
    });

    it('detects CE format by PascalCase property heuristic', () => {
      const ceData = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500',
          Properties: {
            SAMAccountName: 'jdoe',
            Domain: 'corp.local',
            HasSPN: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 4 }, // version < 5 but PascalCase
      });

      const result = normalizeSharpHoundCE(ceData, 'users.json');
      expect(result.wasCE).toBe(true);
    });

    it('does not flag classic format as CE', () => {
      const classicData = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500',
          Properties: {
            samaccountname: 'jdoe',
            domain: 'corp.local',
            hasspn: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 4 },
      });

      const result = normalizeSharpHoundCE(classicData, 'users.json');
      expect(result.wasCE).toBe(false);
    });

    it('parseBloodHoundFile processes CE users.json end-to-end', () => {
      const ceData = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500',
          Properties: {
            Name: 'ADMINISTRATOR@ACME.LOCAL',
            SAMAccountName: 'Administrator',
            Domain: 'acme.local',
            Enabled: true,
            AdminCount: true,
            DisplayName: 'Built-in Admin',
            HasSPN: false,
            DontReqPreauth: false,
          },
          Aces: [],
        }, {
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1103',
          Properties: {
            Name: 'SVC_SQL@ACME.LOCAL',
            SAMAccountName: 'svc_sql',
            Domain: 'acme.local',
            Enabled: true,
            HasSPN: true,
            DontReqPreauth: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 2, version: 6 },
      });

      const { finding, errors, wasCE } = parseBloodHoundFile(ceData, 'users.json');
      expect(wasCE).toBe(true);
      expect(errors.length).toBe(0);
      expect(finding).not.toBeNull();

      const users = finding!.nodes.filter(n => n.type === 'user');
      expect(users.length).toBe(2);

      // Label comes from props.name ('ADMINISTRATOR@ACME.LOCAL') after CE normalization
      const admin = users.find(n => n.label?.includes('ADMINISTRATOR'));
      expect(admin).toBeDefined();
      expect(admin!.privileged).toBe(true);
      expect(admin!.display_name).toBe('Built-in Admin');

      const svcSql = users.find(n => n.label?.includes('SVC_SQL'));
      expect(svcSql).toBeDefined();
      expect(svcSql!.has_spn).toBe(true);
      expect(svcSql!.asrep_roastable).toBe(true);
    });

    it('parseBloodHoundFile processes CE computers.json end-to-end', () => {
      const ceData = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
          Properties: {
            Name: 'DC01.ACME.LOCAL',
            OperatingSystem: 'Windows Server 2022',
            Enabled: true,
            UnconstrainedDelegation: true,
            Domain: 'acme.local',
          },
          Status: { Connectable: true },
          Aces: [],
          LocalAdmins: [{
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-512',
            ObjectType: 'Group',
          }],
        }],
        meta: { type: 'computers', count: 1, version: 6 },
      });

      const { finding, wasCE } = parseBloodHoundFile(ceData, 'computers.json');
      expect(wasCE).toBe(true);
      expect(finding).not.toBeNull();

      const hosts = finding!.nodes.filter(n => n.type === 'host');
      expect(hosts.length).toBe(1);
      expect(hosts[0].os).toBe('Windows Server 2022');
      expect(hosts[0].alive).toBe(true);

      const adminEdges = finding!.edges.filter(e => e.properties.type === 'ADMIN_TO');
      expect(adminEdges.length).toBe(1);
    });

    it('parseBloodHoundFile processes CE groups.json with members', () => {
      const ceData = JSON.stringify({
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-512',
          Properties: {
            SAMAccountName: 'Domain Admins',
            Domain: 'acme.local',
            AdminCount: true,
          },
          Members: [{
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-500',
            ObjectType: 'User',
          }],
          Aces: [],
        }],
        meta: { type: 'groups', count: 1, version: 5 },
      });

      const { finding, wasCE } = parseBloodHoundFile(ceData, 'groups.json');
      expect(wasCE).toBe(true);
      expect(finding).not.toBeNull();

      const groups = finding!.nodes.filter(n => n.type === 'group');
      expect(groups.length).toBe(1);
      expect(groups[0].privileged).toBe(true);

      const memberOf = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF');
      expect(memberOf.length).toBe(1);
    });

    it('handles malformed JSON gracefully', () => {
      const result = normalizeSharpHoundCE('not json', 'bad.json');
      expect(result.wasCE).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('handles missing data array gracefully', () => {
      const result = normalizeSharpHoundCE(JSON.stringify({ meta: { type: 'users' } }), 'empty.json');
      expect(result.wasCE).toBe(false);
    });
  });

  // =============================================
  // MEMBER_OF_DOMAIN edge creation
  // =============================================
  describe('MEMBER_OF_DOMAIN edges', () => {

    it('creates MEMBER_OF_DOMAIN edge for users with domain property', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1103',
          Properties: {
            samaccountname: 'jdoe',
            domain: 'acme.local',
            enabled: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(finding).not.toBeNull();
      const domEdges = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(1);
      expect(domEdges[0].source).toBe('user-acme-local-jdoe');
      expect(domEdges[0].target).toBe('domain-acme-local');
    });

    it('creates MEMBER_OF_DOMAIN edge for hosts with domain property', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
          Properties: {
            name: 'DC01.ACME.LOCAL',
            domain: 'acme.local',
            operatingsystem: 'Windows Server 2019',
            enabled: true,
          },
          Status: { Connectable: true },
          Aces: [],
          LocalAdmins: [],
          RemoteDesktopUsers: [],
          PSRemoteUsers: [],
          DcomUsers: [],
          AllowedToDelegate: [],
          AllowedToAct: [],
        }],
        meta: { type: 'computers', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'computers.json');
      expect(finding).not.toBeNull();
      const domEdges = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(1);
      expect(domEdges[0].target).toBe('domain-acme-local');
    });

    it('creates MEMBER_OF_DOMAIN edge for groups with domain property', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-512',
          Properties: {
            name: 'DOMAIN ADMINS@ACME.LOCAL',
            domain: 'acme.local',
            admincount: true,
          },
          Members: [],
          Aces: [],
        }],
        meta: { type: 'groups', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'groups.json');
      expect(finding).not.toBeNull();
      const domEdges = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(1);
      expect(domEdges[0].target).toBe('domain-acme-local');
    });

    it('does NOT create MEMBER_OF_DOMAIN edge for nodes without domain property', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1103',
          Properties: {
            samaccountname: 'localuser',
            enabled: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(finding).not.toBeNull();
      const domEdges = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(0);
    });

    it('emits stub domain node alongside MEMBER_OF_DOMAIN edge (P1 regression)', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1103',
          Properties: {
            samaccountname: 'jdoe',
            domain: 'acme.local',
            enabled: true,
          },
          Aces: [],
        }],
        meta: { type: 'users', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(finding).not.toBeNull();
      // Stub domain node must exist so single-file imports pass validation
      const domainNodes = finding!.nodes.filter(n => n.type === 'domain');
      expect(domainNodes.length).toBe(1);
      expect(domainNodes[0].id).toBe('domain-acme-local');
      expect(domainNodes[0].domain_name).toBe('acme.local');
    });

    it('deduplicates stub domain nodes across multiple objects in same file', () => {
      const bhData = {
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1103',
            Properties: { samaccountname: 'jdoe', domain: 'acme.local', enabled: true },
            Aces: [],
          },
          {
            ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1104',
            Properties: { samaccountname: 'jsmith', domain: 'acme.local', enabled: true },
            Aces: [],
          },
        ],
        meta: { type: 'users', count: 2, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'users.json');
      expect(finding).not.toBeNull();
      const domainNodes = finding!.nodes.filter(n => n.type === 'domain');
      // Only one stub domain node despite two users in the same domain
      expect(domainNodes.length).toBe(1);
      // But two MEMBER_OF_DOMAIN edges
      const domEdges = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(2);
    });

    it('extracts netbios_name from BH domain objects (OQ regression)', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012',
          Properties: {
            name: 'CORP.CONTOSO.COM',
            domain: 'corp.contoso.com',
            functionallevel: '2016',
            netbiosname: 'OLDNAME',
          },
          Aces: [],
          Links: [],
          ChildObjects: [],
          Trusts: [],
        }],
        meta: { type: 'domains', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'domains.json');
      expect(finding).not.toBeNull();
      const domNode = finding!.nodes.find(n => n.type === 'domain');
      expect(domNode).toBeDefined();
      expect(domNode!.netbios_name).toBe('OLDNAME');
    });

    it('does NOT create MEMBER_OF_DOMAIN edge for domain-type nodes', () => {
      const bhData = {
        data: [{
          ObjectIdentifier: 'S-1-5-21-1234-5678-9012',
          Properties: {
            name: 'ACME.LOCAL',
            domain: 'acme.local',
            functionallevel: '2016',
          },
          Aces: [],
          Links: [],
          ChildObjects: [],
          Trusts: [],
        }],
        meta: { type: 'domains', count: 1, version: 4 },
      };
      const { finding } = parseBloodHoundFile(JSON.stringify(bhData), 'domains.json');
      expect(finding).not.toBeNull();
      const domEdges = finding!.edges.filter(e => e.properties.type === 'MEMBER_OF_DOMAIN');
      expect(domEdges.length).toBe(0);
    });
  });
});
