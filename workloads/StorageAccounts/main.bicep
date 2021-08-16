@maxLength(24)
@description('Optional. Name of the Storage Account. If no name is provided, then unique name will be created.')
param storageAccountName string = ''

@description('Optional. Location for all resources.')
param location string = resourceGroup().location

@description('Optional. Array of role assignment objects that contain the \'roleDefinitionIdOrName\' and \'principalId\' to define RBAC role assignments on this resource. In the roleDefinitionIdOrName attribute, you can provide either the display name of the role definition, or it\'s fully qualified ID in the following format: \'/providers/Microsoft.Authorization/roleDefinitions/c2f4ef07-c644-48eb-af81-4b1b4947fb11\'')
param roleAssignments array = []

@allowed([
  'None'
  'SystemAssigned'
  'UserAssigned'
  'SystemAssigned, UserAssigned'
  'UserAssigned, SystemAssigned'
])
@description('Optional. Type of managed service identity.')
param managedServiceIdentity string = 'None'

@description('Optional. Mandatory \'managedServiceIdentity\' contains UserAssigned. The identy to assign to the resource.')
param userAssignedIdentities object = {}

@allowed([
  'Storage'
  'StorageV2'
  'BlobStorage'
  'FileStorage'
  'BlockBlobStorage'
])
@description('Optional. Type of Storage Account to create.')
param storageAccountKind string = 'StorageV2'

@allowed([
  'Standard_LRS'
  'Standard_GRS'
  'Standard_RAGRS'
  'Standard_ZRS'
  'Premium_LRS'
  'Premium_ZRS'
  'Standard_GZRS'
  'Standard_RAGZRS'
])
@description('Optional. Storage Account Sku Name.')
param storageAccountSku string = 'Standard_GRS'

@allowed([
  'Hot'
  'Cool'
])
@description('Optional. Storage Account Access Tier.')
param storageAccountAccessTier string = 'Hot'

@description('Optional. Provides the identity based authentication settings for Azure Files.')
param azureFilesIdentityBasedAuthentication object = {}

@description('Optional. Virtual Network Identifier used to create a service endpoint.')
param vNetId string = ''

@description('Optional. Configuration Details for private endpoints.')
param privateEndpoints array = []

@description('Optional. Networks ACLs, this value contains IPs to whitelist and/or Subnet information.')
param networkAcls object = {}

@description('Optional. Blob containers to create.')
param blobContainers array = []

@description('Optional. Indicates whether DeleteRetentionPolicy is enabled for the Blob service.')
param deleteRetentionPolicy bool = true

@description('Optional. Indicates the number of days that the deleted blob should be retained. The minimum specified value can be 1 and the maximum value can be 365.')
param deleteRetentionPolicyDays int = 7

@description('Optional. Automatic Snapshot is enabled if set to true.')
param automaticSnapshotPolicyEnabled bool = false

@description('Optional. Indicates whether public access is enabled for all blobs or containers in the storage account.')
param allowBlobPublicAccess bool = true

@description('Optional. File shares to create.')
param fileShares array = []

@description('Optional. Queues to create.')
param queues array = []

@description('Optional. Tables to create.')
param tables array = []

@allowed([
  'TLS1_0'
  'TLS1_1'
  'TLS1_2'
])
@description('Optional. Set the minimum TLS version on request to storage.')
param minimumTlsVersion string = 'TLS1_2'

@description('Optional. If true, enables move to archive tier and auto-delete')
param enableArchiveAndDelete bool = false

@description('Optional. If true, enables Hierarchical Namespace for the storage account')
param enableHierarchicalNamespace bool = false

@description('Optional. Set up the amount of days after which the blobs will be moved to archive tier')
param moveToArchiveAfter int = 30

@description('Optional. Set up the amount of days after which the blobs will be deleted')
param deleteBlobsAfter int = 1096

@description('Optional. Switch to lock storage from deletion.')
param lockForDeletion bool = false

@description('Optional. Tags of the resource.')
param tags object = {}

@description('Optional. Customer Usage Attribution id (GUID). This GUID must be previously registered')
param cuaId string = ''

@description('Optional. SAS token validity length. Usage: \'PT8H\' - valid for 8 hours; \'P5D\' - valid for 5 days; \'P1Y\' - valid for 1 year. When not provided, the SAS token will be valid for 8 hours.')
param sasTokenValidityLength string = 'PT8H'

@description('Generated. Do not provide a value! This date value is used to generate a SAS token to access the modules.')
param baseTime string = utcNow('u')

var moduleName = 'Storage Account'
var maxNameLength = 24
var uniqueStoragenameUntrim = uniqueString(concat(moduleName, baseTime))
var uniqueStoragename = ((length(uniqueStoragenameUntrim) > maxNameLength) ? substring(uniqueStoragenameUntrim, 0, maxNameLength) : uniqueStoragenameUntrim)
var storageAccountName_var = (empty(storageAccountName) ? uniqueStoragename : storageAccountName)
var accountSasProperties = {
  signedServices: 'bt'
  signedPermission: 'racuw'
  signedExpiry: dateTimeAdd(baseTime, sasTokenValidityLength)
  signedResourceTypes: 'co'
  signedProtocol: 'https'
}
var virtualNetworkRules = {
  virtualNetworkRules: [for j in range(0, (empty(networkAcls) ? 0 : length(networkAcls.virtualNetworkRules))): {
    id: '${vNetId}/subnets/${networkAcls.virtualNetworkRules[j].subnet}'
  }]
}
var networkAcls_var = {
  bypass: (empty(networkAcls) ? json('null') : networkAcls.bypass)
  defaultAction: (empty(networkAcls) ? json('null') : networkAcls.defaultAction)
  virtualNetworkRules: (empty(networkAcls) ? json('null') : virtualNetworkRules.virtualNetworkRules)
  ipRules: (empty(networkAcls) ? json('null') : ((length(networkAcls.ipRules) == 0) ? json('null') : networkAcls.ipRules))
}
var azureFilesIdentityBasedAuthentication_var = azureFilesIdentityBasedAuthentication
var saBaseProperties = {
  encryption: {
    keySource: 'Microsoft.Storage'
    services: {
      blob: (((storageAccountKind == 'BlockBlobStorage') || (storageAccountKind == 'BlobStorage') || (storageAccountKind == 'StorageV2') || (storageAccountKind == 'Storage')) ? json('{"enabled": true}') : json('null'))
      file: (((storageAccountKind == 'FileStorage') || (storageAccountKind == 'StorageV2') || (storageAccountKind == 'Storage')) ? json('{"enabled": true}') : json('null'))
    }
  }
  accessTier: storageAccountAccessTier
  supportsHttpsTrafficOnly: true
  isHnsEnabled: ((!enableHierarchicalNamespace) ? json('null') : enableHierarchicalNamespace)
  minimumTlsVersion: minimumTlsVersion
  networkAcls: (empty(networkAcls) ? json('null') : networkAcls_var)
  allowBlobPublicAccess: allowBlobPublicAccess
}
var saOptIdBasedAuthProperties = {
  azureFilesIdentityBasedAuthentication: azureFilesIdentityBasedAuthentication_var
}
var saProperties = (empty(azureFilesIdentityBasedAuthentication) ? saBaseProperties : union(saBaseProperties, saOptIdBasedAuthProperties))
var builtInRoleNames = {
  'Avere Contributor': '/providers/Microsoft.Authorization/roleDefinitions/4f8fab4f-1852-4a58-a46a-8eaf358af14a'
  'Avere Operator': '/providers/Microsoft.Authorization/roleDefinitions/c025889f-8102-4ebf-b32c-fc0c6f0c6bd9'
  'Backup Contributor': '/providers/Microsoft.Authorization/roleDefinitions/5e467623-bb1f-42f4-a55d-6e525e11384b'
  'Backup Operator': '/providers/Microsoft.Authorization/roleDefinitions/00c29273-979b-4161-815c-10b084fb9324'
  'Backup Reader': '/providers/Microsoft.Authorization/roleDefinitions/a795c7a0-d4a2-40c1-ae25-d81f01202912'
  'Classic Storage Account Contributor': '/providers/Microsoft.Authorization/roleDefinitions/86e8f5dc-a6e9-4c67-9d15-de283e8eac25'
  'Classic Storage Account Key Operator Service Role': '/providers/Microsoft.Authorization/roleDefinitions/985d6b00-f706-48f5-a6fe-d0ca12fb668d'
  'Data Box Contributor': '/providers/Microsoft.Authorization/roleDefinitions/add466c9-e687-43fc-8d98-dfcf8d720be5'
  'Data Box Reader': '/providers/Microsoft.Authorization/roleDefinitions/028f4ed7-e2a9-465e-a8f4-9c0ffdfdc027'
  'Data Lake Analytics Developer': '/providers/Microsoft.Authorization/roleDefinitions/47b7735b-770e-4598-a7da-8b91488b4c88'
  'Reader and Data Access': '/providers/Microsoft.Authorization/roleDefinitions/c12c1c16-33a1-487b-954d-41c89c60f349'
  'Storage Account Contributor': '/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab'
  'Storage Account Key Operator Service Role': '/providers/Microsoft.Authorization/roleDefinitions/81a9662b-bebf-436f-a333-f67b29880f12'
  'Storage Blob Data Contributor': '/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  'Storage Blob Data Owner': '/providers/Microsoft.Authorization/roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  'Storage Blob Data Reader': '/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
  'Storage Blob Delegator': '/providers/Microsoft.Authorization/roleDefinitions/db58b8e5-c6ad-4a2a-8342-4190687cbf4a'
  'Storage File Data SMB Share Contributor': '/providers/Microsoft.Authorization/roleDefinitions/0c867c2a-1d8c-454a-a3db-ab2ea1bdc8bb'
  'Storage File Data SMB Share Elevated Contributor': '/providers/Microsoft.Authorization/roleDefinitions/a7264617-510b-434b-a828-9731dc254ea7'
  'Storage File Data SMB Share Reader': '/providers/Microsoft.Authorization/roleDefinitions/aba4ae5f-2193-4029-9191-0cb91df5e314'
  'Storage Queue Data Contributor': '/providers/Microsoft.Authorization/roleDefinitions/974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  'Storage Queue Data Message Processor': '/providers/Microsoft.Authorization/roleDefinitions/8a0f0c08-91a1-4084-bc3d-661d67233fed'
  'Storage Queue Data Message Sender': '/providers/Microsoft.Authorization/roleDefinitions/c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'
  'Storage Queue Data Reader': '/providers/Microsoft.Authorization/roleDefinitions/19e7f393-937e-4f77-808e-94535e297925'
  'Storage Table Data Contributor': '/providers/Microsoft.Authorization/roleDefinitions/0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  'Storage Table Data Reader': '/providers/Microsoft.Authorization/roleDefinitions/76199698-9eea-4c19-bc75-cec21354c6b6'
}

module pid_cuaId './nested_pid_cuaId.bicep' = if (!empty(cuaId)) {
  name: 'pid-${cuaId}'
  params: {}
}

resource storageAccountName_resource 'Microsoft.Storage/storageAccounts@2019-06-01' = {
  name: storageAccountName_var
  location: location
  kind: storageAccountKind
  sku: {
    name: storageAccountSku
  }
  identity: {
    type: managedServiceIdentity
    userAssignedIdentities: (empty(userAssignedIdentities) ? json('null') : userAssignedIdentities)
  }
  tags: tags
  properties: saProperties
}

resource storageAccountName_Microsoft_Authorization_storageDoNotDelete 'Microsoft.Storage/storageAccounts/providers/locks@2016-09-01' = if (lockForDeletion) {
  name: '${storageAccountName_var}/Microsoft.Authorization/storageDoNotDelete'
  properties: {
    level: 'CannotDelete'
  }
  dependsOn: [
    storageAccountName_resource
  ]
}

module name_location_Storage_PrivateEndpoints './nested_name_location_Storage_PrivateEndpoints.bicep' = [for (item, i) in privateEndpoints: {
  name: '${uniqueString(deployment().name, location)}-Storage-PrivateEndpoints-${i}'
  params: {
    privateEndpointResourceId: storageAccountName_resource.id
    privateEndpointVnetLocation: (empty(privateEndpoints) ? 'dummy' : reference(split(item.subnetResourceId, '/subnets/')[0], '2020-06-01', 'Full').location)
    privateEndpoint: item
    tags: tags
  }
  dependsOn: [
    storageAccountName_resource
  ]
}]

module name_location_Storage_Rbac './nested_name_location_Storage_Rbac.bicep' = [for (item, i) in roleAssignments: {
  name: '${uniqueString(deployment().name, location)}-Storage-Rbac-${i}'
  params: {
    roleAssignment: item
    builtInRoleNames: builtInRoleNames
    storageAccountName: storageAccountName_var
  }
  dependsOn: [
    storageAccountName_resource
  ]
}]

resource storageAccountName_default 'Microsoft.Storage/storageAccounts/blobServices@2019-06-01' = if (!empty(blobContainers)) {
  parent: storageAccountName_resource
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: deleteRetentionPolicy
      days: deleteRetentionPolicyDays
    }
    automaticSnapshotPolicyEnabled: automaticSnapshotPolicyEnabled
  }
}

resource blobContainers_storageAccountName_default_dummy_storageAccountName_default_blobContainers_name 'Microsoft.Storage/storageAccounts/blobServices/containers@2019-06-01' = [for item in blobContainers: if (!empty(blobContainers)) {
  name: (empty(blobContainers) ? '${storageAccountName_var}/default/dummy' : '${storageAccountName_var}/default/${item.name}')
  properties: {
    publicAccess: item.publicAccess
  }
  dependsOn: [
    storageAccountName_resource
  ]
}]

resource blobContainers_storageAccountName_default_dummy_storageAccountName_default_blobContainers_name_default 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2019-06-01' = [for item in blobContainers: if (!empty(blobContainers)) {
  name: '${(empty(blobContainers) ? '${storageAccountName_var}/default/dummy' : '${storageAccountName_var}/default/${item.name}')}/default'
  properties: {
    immutabilityPeriodSinceCreationInDays: (contains(item, 'WORMRetention') ? item.WORMRetention : 365)
    allowProtectedAppendWrites: (contains(item, 'allowProtectedAppendWrites') ? item.allowProtectedAppendWrites : true())
  }
  dependsOn: [
    '${storageAccountName_resource.id}/blobServices/default/containers/${(empty(blobContainers) ? 'dummy' : item.name)}'
  ]
}]

resource Microsoft_Storage_storageAccounts_managementPolicies_storageAccountName_default 'Microsoft.Storage/storageAccounts/managementPolicies@2019-06-01' = if (enableArchiveAndDelete) {
  parent: storageAccountName_resource
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'retention-policy'
          type: 'Lifecycle'
          definition: {
            actions: {
              baseBlob: {
                tierToArchive: {
                  daysAfterModificationGreaterThan: moveToArchiveAfter
                }
                delete: {
                  daysAfterModificationGreaterThan: deleteBlobsAfter
                }
              }
              snapshot: {
                delete: {
                  daysAfterCreationGreaterThan: deleteBlobsAfter
                }
              }
            }
            filters: {
              blobTypes: [
                'blockBlob'
              ]
            }
          }
        }
      ]
    }
  }
}

module name_location_Storage_Container_blobContainers_dummy './nested_name_location_Storage_Container_blobContainers_dummy.bicep' = [for (item, i) in blobContainers: {
  name: '${uniqueString(deployment().name, location)}-Storage-Container-${(empty(blobContainers) ? 'dummy' : i)}'
  params: {
    blobContainer: item
    builtInRoleNames: builtInRoleNames
    storageAccountName: storageAccountName_var
  }
  dependsOn: [
    blobContainers_storageAccountName_default_dummy_storageAccountName_default_blobContainers_name
  ]
}]

resource fileShares_storageAccountName_default_dummy_storageAccountName_default_fileShares_name 'Microsoft.Storage/storageAccounts/fileServices/shares@2019-06-01' = [for item in fileShares: if (!empty(fileShares)) {
  name: (empty(fileShares) ? '${storageAccountName_var}/default/dummy' : '${storageAccountName_var}/default/${item.name}')
  properties: {
    shareQuota: item.shareQuota
  }
  dependsOn: [
    storageAccountName_resource
  ]
}]

module name_location_Storage_FileShare_fileShares_dummy './nested_name_location_Storage_FileShare_fileShares_dummy.bicep' = [for (item, i) in fileShares: {
  name: '${uniqueString(deployment().name, location)}-Storage-FileShare-${(empty(fileShares) ? 'dummy' : i)}'
  params: {
    fileShare: item
    builtInRoleNames: builtInRoleNames
    storageAccountName: storageAccountName_var
  }
  dependsOn: [
    fileShares_storageAccountName_default_dummy_storageAccountName_default_fileShares_name
  ]
}]

resource queues_storageAccountName_default_dummy_storageAccountName_default_queues_name 'Microsoft.Storage/storageAccounts/queueServices/queues@2019-06-01' = [for item in queues: if (!empty(queues)) {
  name: (empty(queues) ? '${storageAccountName_var}/default/dummy' : '${storageAccountName_var}/default/${item.name}')
  properties: {
    metadata: (contains(item, 'metadata') ? item.metadata : json('null'))
  }
  dependsOn: [
    storageAccountName_resource
  ]
}]

module name_location_Storage_Queue_queues_dummy './nested_name_location_Storage_Queue_queues_dummy.bicep' = [for (item, i) in queues: {
  name: '${uniqueString(deployment().name, location)}-Storage-Queue-${(empty(queues) ? 'dummy' : i)}'
  params: {
    queue: item
    builtInRoleNames: builtInRoleNames
    storageAccountName: storageAccountName_var
  }
  dependsOn: [
    queues_storageAccountName_default_dummy_storageAccountName_default_queues_name
  ]
}]

resource tables_storageAccountName_default_dummy_storageAccountName_default_tables 'Microsoft.Storage/storageAccounts/tableServices/tables@2019-06-01' = [for item in tables: {
  name: (empty(tables) ? '${storageAccountName_var}/default/dummy' : '${storageAccountName_var}/default/${item}')
  dependsOn: [
    storageAccountName_resource
  ]
}]

output storageAccountResourceId string = storageAccountName_resource.id
output storageAccountRegion string = location
output storageAccountName string = storageAccountName_var
output storageAccountResourceGroup string = resourceGroup().name
output storageAccountSasToken securestring = listAccountSas(storageAccountName_var, '2019-04-01', accountSasProperties).accountSasToken
output storageAccountAccessKey securestring = listKeys(storageAccountName_var, '2016-12-01').keys[0].value
output storageAccountPrimaryBlobEndpoint string = reference('Microsoft.Storage/storageAccounts/${storageAccountName_var}', '2019-04-01').primaryEndpoints.blob
output blobContainers array = blobContainers
output fileShares array = fileShares
output queues array = queues
output tables array = tables
output assignedIdentityID string = (contains(managedServiceIdentity, 'SystemAssigned') ? reference(resourceId('Microsoft.Storage/storageAccounts', storageAccountName), '2019-06-01', 'full').identity.principalId : '')
