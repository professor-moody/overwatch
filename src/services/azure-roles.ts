// ============================================================
// Azure built-in RBAC role → action-set mapping table.
//
// The IAM simulator needs to know what actions a role grants
// before it can answer "can principal X do Y on resource Z?".
// AzureHound only carries the role *name*; we expand a curated
// set of common built-in roles here. Roles not in this table
// are marked `permission_expansion: 'enumerated_only'` so
// downstream consumers do not silently treat them as empty.
//
// Source: Microsoft Azure built-in roles documentation
// https://learn.microsoft.com/azure/role-based-access-control/built-in-roles
//
// Wildcards follow Azure semantics: `*` matches any segment.
// ============================================================

export interface AzureRoleDef {
  /** Canonical Azure built-in role name. */
  name: string;
  /** Action patterns granted (Azure-style with wildcards). */
  actions: string[];
  /** DataActions granted (subset of resource-data actions). */
  data_actions?: string[];
  /** notActions / notDataActions if any. */
  not_actions?: string[];
}

const ROLES: AzureRoleDef[] = [
  // === Core management plane ===
  {
    name: 'Owner',
    actions: ['*'],
  },
  {
    name: 'Contributor',
    actions: ['*'],
    not_actions: [
      'Microsoft.Authorization/*/Delete',
      'Microsoft.Authorization/*/Write',
      'Microsoft.Authorization/elevateAccess/Action',
      'Microsoft.Blueprint/blueprintAssignments/write',
      'Microsoft.Blueprint/blueprintAssignments/delete',
      'Microsoft.Compute/galleries/share/action',
    ],
  },
  {
    name: 'Reader',
    actions: ['*/read'],
  },
  {
    name: 'User Access Administrator',
    actions: [
      '*/read',
      'Microsoft.Authorization/*',
      'Microsoft.Support/*',
    ],
  },

  // === Storage ===
  {
    name: 'Storage Account Contributor',
    actions: [
      'Microsoft.Authorization/*/read',
      'Microsoft.Insights/alertRules/*',
      'Microsoft.Network/*/read',
      'Microsoft.ResourceHealth/availabilityStatuses/read',
      'Microsoft.Resources/deployments/*',
      'Microsoft.Resources/subscriptions/resourceGroups/read',
      'Microsoft.Storage/storageAccounts/*',
      'Microsoft.Support/*',
    ],
  },
  {
    name: 'Storage Blob Data Owner',
    actions: ['Microsoft.Storage/storageAccounts/blobServices/containers/*'],
    data_actions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*'],
  },
  {
    name: 'Storage Blob Data Contributor',
    actions: [
      'Microsoft.Storage/storageAccounts/blobServices/containers/delete',
      'Microsoft.Storage/storageAccounts/blobServices/containers/read',
      'Microsoft.Storage/storageAccounts/blobServices/containers/write',
    ],
    data_actions: [
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete',
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read',
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write',
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action',
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action',
    ],
  },
  {
    name: 'Storage Blob Data Reader',
    actions: ['Microsoft.Storage/storageAccounts/blobServices/containers/read'],
    data_actions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'],
  },

  // === Key Vault ===
  {
    name: 'Key Vault Administrator',
    actions: ['Microsoft.KeyVault/*'],
    data_actions: ['Microsoft.KeyVault/vaults/*'],
  },
  {
    name: 'Key Vault Secrets Officer',
    actions: [],
    data_actions: ['Microsoft.KeyVault/vaults/secrets/*'],
  },
  {
    name: 'Key Vault Secrets User',
    actions: [],
    data_actions: ['Microsoft.KeyVault/vaults/secrets/getSecret/action'],
  },
  {
    name: 'Key Vault Crypto Officer',
    actions: [],
    data_actions: ['Microsoft.KeyVault/vaults/keys/*'],
  },
  {
    name: 'Key Vault Crypto User',
    actions: [],
    data_actions: [
      'Microsoft.KeyVault/vaults/keys/read',
      'Microsoft.KeyVault/vaults/keys/decrypt/action',
      'Microsoft.KeyVault/vaults/keys/encrypt/action',
      'Microsoft.KeyVault/vaults/keys/sign/action',
      'Microsoft.KeyVault/vaults/keys/verify/action',
      'Microsoft.KeyVault/vaults/keys/wrap/action',
      'Microsoft.KeyVault/vaults/keys/unwrap/action',
    ],
  },

  // === Compute ===
  {
    name: 'Virtual Machine Contributor',
    actions: [
      'Microsoft.Authorization/*/read',
      'Microsoft.Compute/availabilitySets/*',
      'Microsoft.Compute/locations/*',
      'Microsoft.Compute/virtualMachines/*',
      'Microsoft.Compute/virtualMachineScaleSets/*',
      'Microsoft.Compute/disks/write',
      'Microsoft.Compute/disks/read',
      'Microsoft.Compute/disks/delete',
      'Microsoft.DevTestLab/schedules/*',
      'Microsoft.Insights/alertRules/*',
      'Microsoft.Network/*/read',
      'Microsoft.Network/loadBalancers/*/join/action',
      'Microsoft.Network/networkInterfaces/*',
      'Microsoft.Network/publicIPAddresses/*/join/action',
      'Microsoft.Network/publicIPAddresses/read',
      'Microsoft.Network/virtualNetworks/read',
      'Microsoft.Network/virtualNetworks/subnets/join/action',
      'Microsoft.RecoveryServices/locations/*',
      'Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/*/read',
      'Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/write',
      'Microsoft.RecoveryServices/Vaults/backupPolicies/read',
      'Microsoft.RecoveryServices/Vaults/backupPolicies/write',
      'Microsoft.RecoveryServices/Vaults/read',
      'Microsoft.ResourceHealth/availabilityStatuses/read',
      'Microsoft.Resources/deployments/*',
      'Microsoft.Resources/subscriptions/resourceGroups/read',
      'Microsoft.SqlVirtualMachine/*',
      'Microsoft.Storage/storageAccounts/listKeys/action',
      'Microsoft.Storage/storageAccounts/read',
      'Microsoft.Support/*',
    ],
  },
  {
    name: 'Virtual Machine Administrator Login',
    actions: ['Microsoft.Network/publicIPAddresses/read', 'Microsoft.Network/virtualNetworks/read', 'Microsoft.Compute/virtualMachines/*/read'],
    data_actions: [
      'Microsoft.Compute/virtualMachines/login/action',
      'Microsoft.Compute/virtualMachines/loginAsAdmin/action',
    ],
  },
  {
    name: 'Virtual Machine User Login',
    actions: ['Microsoft.Network/publicIPAddresses/read', 'Microsoft.Network/virtualNetworks/read', 'Microsoft.Compute/virtualMachines/*/read'],
    data_actions: ['Microsoft.Compute/virtualMachines/login/action'],
  },

  // === Network ===
  {
    name: 'Network Contributor',
    actions: [
      'Microsoft.Authorization/*/read',
      'Microsoft.Insights/alertRules/*',
      'Microsoft.Network/*',
      'Microsoft.ResourceHealth/availabilityStatuses/read',
      'Microsoft.Resources/deployments/*',
      'Microsoft.Resources/subscriptions/resourceGroups/read',
      'Microsoft.Support/*',
    ],
  },

  // === Database ===
  {
    name: 'SQL DB Contributor',
    actions: [
      'Microsoft.Authorization/*/read',
      'Microsoft.Insights/alertRules/*',
      'Microsoft.ResourceHealth/availabilityStatuses/read',
      'Microsoft.Resources/deployments/*',
      'Microsoft.Resources/subscriptions/resourceGroups/read',
      'Microsoft.Sql/locations/*/read',
      'Microsoft.Sql/servers/databases/*',
      'Microsoft.Sql/servers/read',
      'Microsoft.Support/*',
    ],
  },

  // === Identity / AAD-adjacent ===
  {
    name: 'Application Administrator',
    actions: [
      'Microsoft.Directory/applications/*',
      'Microsoft.Directory/applicationPolicies/*',
      'Microsoft.Directory/servicePrincipals/*',
      'Microsoft.Directory/auditLogs/allProperties/read',
      'Microsoft.Directory/signInReports/allProperties/read',
    ],
  },
  {
    name: 'Cloud Application Administrator',
    actions: [
      'Microsoft.Directory/applications/*',
      'Microsoft.Directory/applicationPolicies/*',
      'Microsoft.Directory/servicePrincipals/*',
    ],
  },
  {
    name: 'Privileged Role Administrator',
    actions: [
      'Microsoft.Directory/roleAssignments/*',
      'Microsoft.Directory/roleDefinitions/*',
      'Microsoft.Authorization/roleAssignments/*',
      'Microsoft.Authorization/roleDefinitions/*',
    ],
  },

  // === Misc commonly-seen ===
  {
    name: 'Log Analytics Contributor',
    actions: [
      '*/read',
      'Microsoft.OperationalInsights/workspaces/*',
      'Microsoft.Insights/*',
      'Microsoft.Resources/deployments/*',
    ],
  },
  {
    name: 'Monitoring Contributor',
    actions: [
      '*/read',
      'Microsoft.AlertsManagement/*',
      'Microsoft.Insights/*',
    ],
  },
];

const ROLE_INDEX: Map<string, AzureRoleDef> = new Map(ROLES.map(r => [r.name.toLowerCase(), r]));

/**
 * Look up an Azure built-in role by name (case-insensitive).
 * Returns undefined for unknown roles — caller should mark the
 * policy node `permission_expansion: 'enumerated_only'`.
 */
export function lookupAzureRole(roleName: string): AzureRoleDef | undefined {
  if (!roleName) return undefined;
  return ROLE_INDEX.get(roleName.trim().toLowerCase());
}

/**
 * Combined effective actions (control plane + data plane). NotActions
 * are returned separately so the simulator can subtract them after
 * computing matches.
 */
export function expandAzureRole(roleName: string): {
  actions: string[];
  not_actions: string[];
  expanded: boolean;
} {
  const def = lookupAzureRole(roleName);
  if (!def) return { actions: [], not_actions: [], expanded: false };
  const actions = [...def.actions, ...(def.data_actions || [])];
  return { actions, not_actions: def.not_actions || [], expanded: true };
}
