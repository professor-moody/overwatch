import { describe, it, expect } from 'vitest';
import { buildBloodHoundSidMap, parseBloodHoundFile } from '../bloodhound-ingest.js';

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
      expect(result.finding!.nodes.length).toBe(1);

      const node = result.finding!.nodes[0];
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
      expect(result.finding!.nodes.length).toBe(1);

      const node = result.finding!.nodes[0];
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
      expect(result.finding!.nodes.length).toBe(1);
      expect(result.finding!.nodes[0].type).toBe('group');

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
      for (const node of result.finding!.nodes) {
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
});
