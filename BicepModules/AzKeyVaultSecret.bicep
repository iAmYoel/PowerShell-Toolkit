@description('Azure key vault')
param KeyVaultName string

@description('Key Vault Secret name')
param secretName string

@description('Free text field for describing the secret content.')
@maxLength(255)
param contentType string

@description('The secret value to save.')
@secure()
param secretValue string


//#######################################################################################################################################

resource keyVaultSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  name: '${KeyVaultName}/${secretName}'
  properties: {
    contentType: contentType
    value: secretValue
  }
}


output secretName string = keyVaultSecret.name
output secretId string = keyVaultSecret.id
output secret object = keyVaultSecret
