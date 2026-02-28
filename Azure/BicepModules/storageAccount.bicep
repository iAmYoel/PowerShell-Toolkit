@description('Resource group location of all resources')
param stLocation string

@description('Globally unique storage account name')
@minLength(3)
@maxLength(24)
param stName string

@description('Storage account kind')
param stKind string = 'StorageV2'

@description('Storage account SKU name')
@allowed([
  'Premium_LRS'
  'Premium_ZRS'
  'Standard_GRS'
  'Standard_GZRS'
  'Standard_LRS'
  'Standard_RAGRS'
  'Standard_RAGZRS'
  'Standard_ZRS'
])
param stSkuName string = 'Standard_LRS'

@description('Storage account access tier')
param stAccessTier string = 'Hot'





//##########################################################################################


resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: stName
  location: stLocation
  kind: stKind
  sku: {
    name: stSkuName
  }
  properties: {
    dnsEndpointType: 'Standard'
    defaultToOAuthAuthentication: false
    publicNetworkAccess: 'Enabled'
    allowCrossTenantReplication: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: true
    allowSharedKeyAccess: true
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
      defaultAction: 'Allow'
    }
    supportsHttpsTrafficOnly: true
    encryption: {
      requireInfrastructureEncryption: false
      services: {
        file: {
          keyType: 'Account'
          enabled: true
        }
        table: {
          keyType: 'Account'
          enabled: true
        }
        queue: {
          keyType: 'Account'
          enabled: true
        }
        blob: {
          keyType: 'Account'
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    accessTier: stAccessTier
  }
}

output storageAccount object = storageAccount
