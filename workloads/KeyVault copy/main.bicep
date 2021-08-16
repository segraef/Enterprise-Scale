@maxLength(24)
@description('Optional. Name of the Key Vault. If no name is provided, then unique name will be created.')
param keyVaultName string = ''

@description('Optional. Location for all resources.')
param location string = resourceGroup().location

@description('Optional. Array of access policies object')
param accessPolicies array = []

@description('Optional. All secrets [{"secretName":"","secretValue":""} wrapped in a secure object]')
@secure()
param secretsObject object = {
  secrets: []
}

@description('Optional. All keys [{"keyName":"","keyType":"","keyOps":"","keySize":"","curvename":""} wrapped in a secure object]')
@secure()
param keysObject object = {
  keys: []
}

@allowed([
  true
  false
])
@description('Optional. Specifies if the vault is enabled for deployment by script or compute')
param enableVaultForDeployment bool = true

@allowed([
  true
  false
])
@description('Optional. Specifies if the vault is enabled for a template deployment')
param enableVaultForTemplateDeployment bool = true

@allowed([
  true
  false
])
@description('Optional. Specifies if the azure platform has access to the vault for enabling disk encryption scenarios.')
param enableVaultForDiskEncryption bool = true

@description('Optional. Switch to enable/disable Key Vault\'s soft delete feature.')
param enableSoftDelete bool = true

@description('Optional. softDelete data retention days. It accepts >=7 and <=90.')
param softDeleteRetentionInDays int = 90

@description('Optional. Property that controls how data actions are authorized. When true, the key vault will use Role Based Access Control (RBAC) for authorization of data actions, and the access policies specified in vault properties will be ignored (warning: this is a preview feature). When false, the key vault will use the access policies specified in vault properties, and any policy stored on Azure Resource Manager will be ignored. If null or not specified, the vault is created with the default value of false. Note that management actions are always authorized with RBAC.')
param enableRbacAuthorization bool = false

@description('Optional. The vault\'s create mode to indicate whether the vault need to be recovered or not. - recover or default.')
param createMode string = 'default'

@description('Optional. Provide \'true\' to enable Key Vault\'s purge protection feature.')
param enablePurgeProtection bool = false

@allowed([
  'Premium'
  'Standard'
])
@description('Optional. Specifies the SKU for the vault')
param vaultSku string = 'Premium'

@description('Optional. Service endpoint object information')
param networkAcls object = {}

@description('Optional. Virtual Network resource identifier, if networkAcls is passed, this value must be passed as well')
param vNetId string = ''

@description('Optional. The name of the Diagnostic setting.')
param diagnosticSettingName string = 'service'

@minValue(0)
@maxValue(365)
@description('Optional. Specifies the number of days that logs will be kept for; a value of 0 will retain data indefinitely.')
param diagnosticLogsRetentionInDays int = 365

@description('Optional. Resource identifier of the Diagnostic Storage Account.')
param diagnosticStorageAccountId string = ''

@description('Optional. Resource identifier of Log Analytics.')
param workspaceId string = ''

@description('Optional. Resource ID of the event hub authorization rule for the Event Hubs namespace in which the event hub should be created or streamed to.')
param eventHubAuthorizationRuleId string = ''

@description('Optional. Name of the event hub within the namespace to which logs are streamed. Without this, an event hub is created for each log category.')
param eventHubName string = ''

@description('Optional. Switch to lock Key Vault from deletion.')
param lockForDeletion bool = false

@description('Optional. Array of role assignment objects that contain the \'roleDefinitionIdOrName\' and \'principalId\' to define RBAC role assignments on this resource. In the roleDefinitionIdOrName attribute, you can provide either the display name of the role definition, or its fully qualified ID in the following format: \'/providers/Microsoft.Authorization/roleDefinitions/c2f4ef07-c644-48eb-af81-4b1b4947fb11\'')
param roleAssignments array = []

@description('Optional. Configuration Details for private endpoints.')
param privateEndpoints array = []

@description('Optional. Resource tags.')
param tags object = {}

@description('Optional. Customer Usage Attribution id (GUID). This GUID must be previously registered')
param cuaId string = ''

@description('Generated. Do not provide a value! This date value is used to generate a SAS token to access the modules.')
param baseTime string = utcNow('u')

var moduleName = 'Key Vault'
var maxNameLength = 24
var uniqueKeyVaultNameUntrim = uniqueString(concat(moduleName, baseTime))
var uniqueKeyVaultName = ((length(uniqueKeyVaultNameUntrim) > maxNameLength) ? substring(uniqueKeyVaultNameUntrim, 0, maxNameLength) : uniqueKeyVaultNameUntrim)
var keyVaultName_var = (empty(keyVaultName) ? uniqueKeyVaultName : keyVaultName)
var deployServiceEndpoint = (!empty(networkAcls))
var virtualNetworkRules = {
  virtualNetworkRules: [for j in range(0, ((!deployServiceEndpoint) ? 0 : length(networkAcls.virtualNetworkRules))): {
    id: '${vNetId}/subnets/${networkAcls.virtualNetworkRules[j].subnet}'
  }]
}
var networkAcls_var = {
  bypass: ((!deployServiceEndpoint) ? json('null') : networkAcls.bypass)
  defaultAction: ((!deployServiceEndpoint) ? json('null') : networkAcls.defaultAction)
  virtualNetworkRules: ((!deployServiceEndpoint) ? json('null') : ((length(networkAcls.virtualNetworkRules) == 0) ? emptyArray : virtualNetworkRules.virtualNetworkRules))
  ipRules: ((!deployServiceEndpoint) ? json('null') : ((length(networkAcls.ipRules) == 0) ? emptyArray : networkAcls.ipRules))
}
var emptyArray = []
var diagnosticsMetrics = [
  {
    category: 'AllMetrics'
    timeGrain: null
    enabled: true
    retentionPolicy: {
      enabled: true
      days: diagnosticLogsRetentionInDays
    }
  }
]
var diagnosticsLogs = [
  {
    category: 'AuditEvent'
    enabled: true
    retentionPolicy: {
      enabled: true
      days: diagnosticLogsRetentionInDays
    }
  }
]
var builtInRoleNames = {
  Owner: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
  Contributor: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'
  Reader: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
  'Key Vault Administrator (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483'
  'Key Vault Certificates Officer (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/a4417e6f-fecd-4de8-b567-7b0420556985'
  'Key Vault Contributor': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/f25e0fa2-a7c8-4377-a976-54943a77a395'
  'Key Vault Crypto Officer (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/14b46e9e-c2b7-41b4-b07b-48a6ebf60603'
  'Key Vault Crypto Service Encryption User (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/e147488a-f6f5-4113-8e2d-b22465e65bf6'
  'Key Vault Crypto User (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424'
  'Key Vault Reader (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/21090545-7ca7-4776-b22c-e363652d74d2'
  'Key Vault Secrets Officer (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
  'Key Vault Secrets User (preview)': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6'
  'Log Analytics Contributor': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293'
  'Log Analytics Reader': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/73c42c96-874c-492b-b04d-ab87d138a893'
  'Managed Application Contributor Role': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/641177b8-a67a-45b9-a033-47bc880bb21e'
  'Managed Application Operator Role': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/c7393b34-138c-406f-901b-d8cf2b17e6ae'
  'Managed Applications Reader': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/b9331d33-8a36-4f8c-b097-4f54124fdb44'
  'Monitoring Contributor': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
  'Monitoring Metrics Publisher': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb'
  'Monitoring Reader': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/43d0d8ad-25c7-4714-9337-8ba259a9fe05'
  'Resource Policy Contributor': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/36243c78-bf99-498c-9df9-86d9f8d28608'
  'User Access Administrator': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
  'Azure Service Deploy Release Management Contributor': '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/21d96096-b162-414a-8302-d8354f9d91b2'
  masterreader: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/a48d7796-14b4-4889-afef-fbb65a93e5a2'
}

resource keyVaultName_resource 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: keyVaultName_var
  location: location
  tags: tags
  properties: {
    enabledForDeployment: enableVaultForDeployment
    enabledForTemplateDeployment: enableVaultForTemplateDeployment
    enabledForDiskEncryption: enableVaultForDiskEncryption
    enableSoftDelete: enableSoftDelete
    softDeleteRetentionInDays: softDeleteRetentionInDays
    enableRbacAuthorization: enableRbacAuthorization
    createMode: createMode
    enablePurgeProtection: ((!enablePurgeProtection) ? json('null') : enablePurgeProtection)
    tenantId: subscription().tenantId
    accessPolicies: accessPolicies
    sku: {
      name: vaultSku
      family: 'A'
    }
    networkAcls: ((!deployServiceEndpoint) ? json('null') : networkAcls_var)
  }
}

resource keyVaultName_Microsoft_Authorization_keyVaultDoNotDelete 'Microsoft.KeyVault/vaults/providers/locks@2016-09-01' = if (lockForDeletion) {
  name: '${keyVaultName_var}/Microsoft.Authorization/keyVaultDoNotDelete'
  properties: {
    level: 'CannotDelete'
  }
  dependsOn: [
    keyVaultName_resource
  ]
}

resource keyVaultName_Microsoft_Insights_diagnosticSettingName 'Microsoft.KeyVault/vaults/providers/diagnosticsettings@2017-05-01-preview' = if ((!empty(diagnosticStorageAccountId)) || (!empty(workspaceId)) || (!empty(eventHubAuthorizationRuleId)) || (!empty(eventHubName))) {
  name: '${keyVaultName_var}/Microsoft.Insights/${diagnosticSettingName}'
  location: location
  properties: {
    storageAccountId: (empty(diagnosticStorageAccountId) ? json('null') : diagnosticStorageAccountId)
    workspaceId: (empty(workspaceId) ? json('null') : workspaceId)
    eventHubAuthorizationRuleId: (empty(eventHubAuthorizationRuleId) ? json('null') : eventHubAuthorizationRuleId)
    eventHubName: (empty(eventHubName) ? json('null') : eventHubName)
    metrics: ((empty(diagnosticStorageAccountId) && empty(workspaceId) && empty(eventHubAuthorizationRuleId) && empty(eventHubName)) ? json('null') : diagnosticsMetrics)
    logs: ((empty(diagnosticStorageAccountId) && empty(workspaceId) && empty(eventHubAuthorizationRuleId) && empty(eventHubName)) ? json('null') : diagnosticsLogs)
  }
  dependsOn: [
    keyVaultName_resource
  ]
}

resource secretsObject_secrets_keyVaultName_secretEntity_keyVaultName_secretsObject_secrets_secretName 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = [for i in range(0, length(secretsObject.secrets)): if (!empty(secretsObject.secrets)) {
  name: (empty(secretsObject.secrets) ? '${keyVaultName_var}/secretEntity' : '${keyVaultName_var}/${secretsObject.secrets[i].secretName}')
  properties: {
    value: secretsObject.secrets[i].secretValue
  }
  dependsOn: [
    keyVaultName_resource
  ]
}]

resource keysObject_keys_keyVaultName_keyEntity_keyVaultName_keysObject_keys_keyName 'Microsoft.KeyVault/vaults/keys@2019-09-01' = [for i in range(0, length(keysObject.keys)): if (!empty(keysObject.keys)) {
  name: (empty(keysObject.keys) ? '${keyVaultName_var}/keyEntity' : '${keyVaultName_var}/${keysObject.keys[i].keyName}')
  location: location
  properties: {
    kty: keysObject.keys[i].keyType
    keyOps: keysObject.keys[i].keyOps
    keySize: keysObject.keys[i].keySize
    curveName: keysObject.keys[i].curveName
  }
  dependsOn: [
    keyVaultName_resource
  ]
}]

module name_location_KeyVault_PrivateEndpoints './nested_name_location_KeyVault_PrivateEndpoints.bicep' = [for (item, i) in privateEndpoints: {
  name: '${uniqueString(deployment().name, location)}-KeyVault-PrivateEndpoints-${i}'
  params: {
    privateEndpointResourceId: keyVaultName_resource.id
    privateEndpointVnetLocation: (empty(privateEndpoints) ? 'dummy' : reference(split(item.subnetResourceId, '/subnets/')[0], '2020-06-01', 'Full').location)
    privateEndpoint: item
    tags: tags
  }
  dependsOn: [
    keyVaultName_resource
  ]
}]

module rbac_name './nested_rbac_name.bicep' = [for (item, i) in roleAssignments: {
  name: 'rbac-${deployment().name}${i}'
  params: {
    roleAssignment: item
    builtInRoleNames: builtInRoleNames
    keyVaultName: keyVaultName_var
  }
  dependsOn: [
    keyVaultName_resource
  ]
}]

output keyVaultResourceId string = keyVaultName_resource.id
output keyVaultResourceGroup string = resourceGroup().name
output keyVaultName string = keyVaultName_var
output keyVaultUrl string = reference(keyVaultName_resource.id, '2016-10-01').vaultUri
