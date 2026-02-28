@description('Region location of all resources')
param location string = resourceGroup().location

@description('Virtual Network name')
param vnetName string

@description('Virtual Network IP range prefix address and CIDR')
param vnetPrefixAddress string


//###################################################################################################


resource vnet 'Microsoft.Network/virtualNetworks@2022-07-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetPrefixAddress
      ]
    }
  }
}

output vnetId string = vnet.id
output vnetName string = vnet.name
output vnet object = vnet

