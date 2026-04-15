import { describe, it, expect } from 'vitest';
import { parseAzureHoundFile } from '../azurehound-ingest.js';

describe('AzureHound Ingest', () => {
  describe('parseAzureHoundFile', () => {
    it('extracts user nodes from AzureHound users JSON', () => {
      const data = {
        kind: 'azusers',
        data: [
          {
            Properties: {
              id: 'user-obj-1',
              userPrincipalName: 'alice@contoso.com',
              displayName: 'Alice Smith',
              accountEnabled: true,
              tenantId: 'tenant-1',
            },
          },
          {
            Properties: {
              id: 'user-obj-2',
              userPrincipalName: 'bob@contoso.com',
              displayName: 'Bob Jones',
              accountEnabled: false,
              tenantId: 'tenant-1',
            },
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'users.json');
      expect(finding.nodes.length).toBe(2);
      expect(finding.nodes[0].type).toBe('cloud_identity');
      expect(finding.nodes[0].label).toBe('Alice Smith');
      expect(finding.nodes[0].enabled).toBe(true);
      expect(finding.nodes[1].enabled).toBe(false);
    });

    it('extracts group nodes with member edges', () => {
      const data = {
        kind: 'azgroups',
        data: [
          {
            Properties: {
              id: 'grp-1',
              displayName: 'Admins',
            },
            Members: [
              { ObjectIdentifier: 'user-obj-1', ObjectType: 'User', displayName: 'Alice' },
            ],
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'groups.json');
      const groups = finding.nodes.filter(n => n.type === 'group');
      const identities = finding.nodes.filter(n => n.type === 'cloud_identity');
      expect(groups.length).toBe(1);
      expect(groups[0].label).toBe('Admins');
      expect(identities.length).toBe(1);

      const memberEdges = finding.edges.filter(e => e.properties.type === 'MEMBER_OF');
      expect(memberEdges.length).toBe(1);
    });

    it('extracts service principals with ASSUMES_ROLE edge to app', () => {
      const data = {
        kind: 'azserviceprincipals',
        data: [
          {
            Properties: {
              id: 'sp-1',
              displayName: 'MyApp SP',
              appId: 'app-1',
              tenantId: 'tenant-1',
            },
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'sps.json');
      expect(finding.nodes.length).toBe(2); // SP node + stub app node
      expect(finding.nodes.find(n => n.principal_type === 'service_account')).toBeTruthy();
      expect(finding.nodes.find(n => n.principal_type === 'app')).toBeTruthy();
      const assumesEdges = finding.edges.filter(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumesEdges.length).toBe(1);
      expect(assumesEdges[0].target).toContain('app-1');
    });

    it('extracts role assignments with HAS_POLICY edges', () => {
      const data = {
        kind: 'azroleassignments',
        data: [
          {
            Properties: {
              principalId: 'user-obj-1',
              roleDefinitionName: 'Global Administrator',
              roleDefinitionId: 'role-def-1',
            },
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'roles.json');
      const policies = finding.nodes.filter(n => n.type === 'cloud_policy');
      expect(policies.length).toBe(1);
      expect(policies[0].label).toBe('Global Administrator');

      const policyEdges = finding.edges.filter(e => e.properties.type === 'HAS_POLICY');
      expect(policyEdges.length).toBe(1);
    });

    it('infers kind from filename when kind field is absent', () => {
      const data = {
        data: [
          { Properties: { id: 'u1', displayName: 'Test User', accountEnabled: true } },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'azurehound_users_export.json');
      expect(finding.nodes.length).toBe(1);
      expect(finding.nodes[0].type).toBe('cloud_identity');
    });

    it('handles empty input gracefully', () => {
      const { finding } = parseAzureHoundFile('{}', 'empty.json');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('handles malformed JSON gracefully', () => {
      const { finding } = parseAzureHoundFile('not json at all', 'bad.json');
      expect(finding.nodes.length).toBe(0);
      expect(finding.edges.length).toBe(0);
    });

    it('deduplicates nodes by ID', () => {
      const data = {
        kind: 'azusers',
        data: [
          { Properties: { id: 'same-id', displayName: 'User A', accountEnabled: true } },
          { Properties: { id: 'same-id', displayName: 'User B', accountEnabled: true } },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'users.json');
      expect(finding.nodes.length).toBe(1);
    });

    it('role assignment HAS_POLICY edge lands on the same node as the user', () => {
      const { finding: userFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azusers',
        data: [{ Properties: { id: 'user-obj-1', displayName: 'Alice', userPrincipalName: 'alice@contoso.com' } }],
      }), 'users.json');

      const { finding: roleFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azroleassignments',
        data: [{ Properties: { principalId: 'user-obj-1', roleDefinitionName: 'Global Administrator' } }],
      }), 'roles.json');

      const userNodeId = userFinding.nodes[0].id;
      const policyEdge = roleFinding.edges.find(e => e.properties.type === 'HAS_POLICY');
      expect(policyEdge).toBeTruthy();
      expect(policyEdge!.source).toBe(userNodeId);
    });

    it('app role assignment ASSUMES_ROLE edge lands on the same node as the SP', () => {
      const { finding: spFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azserviceprincipals',
        data: [{ Properties: { id: 'sp-obj-1', displayName: 'MyApp SP' } }],
      }), 'sps.json');

      const { finding: appRoleFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azapproleassignments',
        data: [{ Properties: { principalId: 'sp-obj-1', resourceId: 'target-sp-1' } }],
      }), 'approles.json');

      const spNodeId = spFinding.nodes[0].id;
      const assumesEdge = appRoleFinding.edges.find(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumesEdge).toBeTruthy();
      expect(assumesEdge!.source).toBe(spNodeId);
    });

    it('two groups with the same displayName but different object IDs produce distinct nodes', () => {
      const data = {
        kind: 'azgroups',
        data: [
          { Properties: { id: 'grp-1', displayName: 'Admins' } },
          { Properties: { id: 'grp-2', displayName: 'Admins' } },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'groups.json');
      const groups = finding.nodes.filter(n => n.type === 'group');
      expect(groups.length).toBe(2);
      expect(groups[0].id).not.toBe(groups[1].id);
    });

    it('group member edges resolve to the same node IDs as entity files', () => {
      const { finding: userFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azusers',
        data: [{ Properties: { id: 'user-1', displayName: 'Alice' } }],
      }), 'users.json');

      const { finding: groupFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azgroups',
        data: [{
          Properties: { id: 'grp-1', displayName: 'Admins' },
          Members: [{ ObjectIdentifier: 'user-1', ObjectType: 'User', displayName: 'Alice' }],
        }],
      }), 'groups.json');

      const userNodeId = userFinding.nodes[0].id;
      const memberEdge = groupFinding.edges.find(e => e.properties.type === 'MEMBER_OF');
      expect(memberEdge).toBeTruthy();
      expect(memberEdge!.source).toBe(userNodeId);
    });

    it('role assignment for a group principal uses the same ID as the group node', () => {
      const { finding: groupFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azgroups',
        data: [{ Properties: { id: 'grp-1', displayName: 'Admins' } }],
      }), 'groups.json');

      const { finding: roleFinding } = parseAzureHoundFile(JSON.stringify({
        kind: 'azroleassignments',
        data: [{ Properties: { principalId: 'grp-1', roleDefinitionName: 'Reader' } }],
      }), 'roles.json');

      const groupNodeId = groupFinding.nodes[0].id;
      const policyEdge = roleFinding.edges.find(e => e.properties.type === 'HAS_POLICY');
      expect(policyEdge).toBeTruthy();
      expect(policyEdge!.source).toBe(groupNodeId);
    });

    // ========================================================
    // P1 regression: SP emits stub app node for ASSUMES_ROLE target
    // ========================================================

    it('SP with appId creates stub app node so the ASSUMES_ROLE edge is valid', () => {
      const data = {
        kind: 'azserviceprincipals',
        data: [
          {
            Properties: {
              id: 'sp-1',
              displayName: 'MyApp SP',
              appId: 'app-1',
              tenantId: 'tenant-1',
            },
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'sps.json');
      const appNode = finding.nodes.find(n => n.principal_type === 'app');
      expect(appNode).toBeDefined();
      expect(appNode!.id).toContain('app-1');
      expect(appNode!.provider).toBe('azure');

      // ASSUMES_ROLE edge target should match the app node ID
      const assumesEdge = finding.edges.find(e => e.properties.type === 'ASSUMES_ROLE');
      expect(assumesEdge).toBeDefined();
      expect(assumesEdge!.target).toBe(appNode!.id);
    });

    it('SP without appId does not create an ASSUMES_ROLE edge or app node', () => {
      const data = {
        kind: 'azserviceprincipals',
        data: [
          {
            Properties: {
              id: 'sp-no-app',
              displayName: 'Standalone SP',
              tenantId: 'tenant-1',
            },
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'sps.json');
      expect(finding.nodes.length).toBe(1);
      expect(finding.edges.length).toBe(0);
    });

    it('does not duplicate app node if app was already seen (e.g. from apps file)', () => {
      // Simulate: apps file processed first, then SPs file — the SP parser only
      // creates the stub if the app wasn't already in the same finding (single-file scope).
      // In multi-file ingestion, the app node from the apps file takes precedence.
      const data = {
        kind: 'azserviceprincipals',
        data: [
          {
            Properties: { id: 'sp-1', displayName: 'SP 1', appId: 'shared-app', tenantId: 't1' },
          },
          {
            Properties: { id: 'sp-2', displayName: 'SP 2', appId: 'shared-app', tenantId: 't1' },
          },
        ],
      };

      const { finding } = parseAzureHoundFile(JSON.stringify(data), 'sps.json');
      const appNodes = finding.nodes.filter(n => n.principal_type === 'app');
      // Only one stub app node, not duplicated
      expect(appNodes.length).toBe(1);
    });

    // ========================================================
    // P1 regression: unsupported kinds produce warnings
    // ========================================================

    it('returns a warning for unsupported AzureHound kind', () => {
      const data = {
        kind: 'azdevices',
        data: [
          { Properties: { id: 'device-1', displayName: 'Laptop01' } },
        ],
      };

      const result = parseAzureHoundFile(JSON.stringify(data), 'devices.json');
      expect(result.finding.nodes.length).toBe(0);
      expect(result.finding.edges.length).toBe(0);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('unsupported');
      expect(result.warnings[0]).toContain('azdevices');
    });

    it('returns a warning for completely unknown kind', () => {
      const data = {
        kind: 'azconditionalaccess',
        data: [
          { Properties: { id: 'ca-1', displayName: 'Policy 1' } },
          { Properties: { id: 'ca-2', displayName: 'Policy 2' } },
        ],
      };

      const result = parseAzureHoundFile(JSON.stringify(data), 'ca.json');
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('2 item(s)');
    });

    it('does not warn for supported kinds', () => {
      const data = {
        kind: 'azusers',
        data: [{ Properties: { id: 'u1', displayName: 'User' } }],
      };

      const result = parseAzureHoundFile(JSON.stringify(data), 'users.json');
      expect(result.warnings.length).toBe(0);
    });

    it('returns a warning for malformed JSON', () => {
      const result = parseAzureHoundFile('not json', 'bad.json');
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('failed to parse JSON');
    });
  });
});
