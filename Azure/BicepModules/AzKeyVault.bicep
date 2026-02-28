@description('Region for resource')
param location string = resourceGroup().location

@description('Azure key vault resource name. Needs to be globaly unique.')
@maxLength(24)
param vaultName string

@description('Tenant ID for the Azure Active Directory that should be used for authenticating requests to the key vault.')
param tenantId string = tenant().tenantId

@description('Permit Azure Virtual Machines to retrieve secrets from key vault.')
param enableVmAccess bool = true

@description('Permit Azure Resource Manager to retrieve secrets from key vault.')
param enableARMAccess bool = true

@description('Permit Azure Disk Encryption to retrieve secrets from key vault.')
param enableDiskAccess bool = false

@description('Sku name for the key vault.')
@allowed([
  'standard'
  'premium'
])
param skuName string = 'standard'

@description('the id for the role defintion, to define what permission should be assigned')
param roleDefinitionId string = '00482a5a-887f-4fb3-b363-3b7fe8e74483'

@description('the id of the principal that would get the permission')
param principalId string = ''

@description('Principal type of the assignee.')
@allowed([
  'Device'
  'ForeignGroup'
  'Group'
  'ServicePrincipal'
  'User'
])
param principalType string = 'User'


//#######################################################################################################################################

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: vaultName
  location: location
  properties: {
    enabledForDeployment: enableVmAccess
    enabledForTemplateDeployment: enableARMAccess
    enabledForDiskEncryption: enableDiskAccess
    enableRbacAuthorization: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: [
        {
          value: '81.92.73.67'
        }
      ]
    }
    softDeleteRetentionInDays: 30
    tenantId: tenantId
    sku: {
      name: skuName
      family: 'A'
    }
  }
}


resource roleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = if (!empty(principalId)) {
  scope: keyVault
  name: roleDefinitionId
}


resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  scope: keyVault
  name: guid(keyVault.id, principalId, roleDefinition.id)
  properties: {
    roleDefinitionId: roleDefinition.id
    principalId: principalId
    principalType: principalType
  }
}


output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVault object = keyVault
