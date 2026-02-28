@description('Resource group location of all resources')
param stName string

@description('File services name')
param fsName string = 'avd-fslogix'

@description('File services delete retention policy')
param fsDelRetentionPolicy bool = true

@description('File services delete retention days')
param fsDelRetentionDays int = 7

@description('File share access tier')
@allowed([
  'Cool'
  'Hot'
  'Premium'
  'TransactionOptimized'
])
param fsAccesTier string = 'TransactionOptimized'

@description('File share enabled protocols')
@allowed([
  'NFS'
  'SMB'
])
param fsProtocols string = 'SMB'

@description('File share share quota')
//@maxValue(102400)
@allowed([
  5120
  102400
])
param fsShareQuota int = 5120


//##########################################################################################


resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' existing = {
  name: stName
}


resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2022-09-01' = {
  name: 'default'
  parent: storageAccount
  properties: {
    shareDeleteRetentionPolicy: {
      enabled: fsDelRetentionPolicy
      days: fsDelRetentionDays
    }
  }
}


resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2022-09-01' = {
  name: fsName
  parent: fileService
  properties: {
    accessTier: fsAccesTier
    enabledProtocols: fsProtocols
    shareQuota: fsShareQuota
    //shareQuota: ((storageAccount.properties.largeFileSharesState == 'Enabled') ? fsShareQuota : ((fsShareQuota <= 5120) ? fsShareQuota : 5120))
  }
}

output fileShare object = fileShare
