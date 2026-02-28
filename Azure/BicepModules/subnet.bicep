
@description('Virtual Network name')
param vnetName string

@description('Subnet name')
param subnetName string

@description('Subnet address and CIDR')
param subnetAddress string

@description('Subnet address and CIDR')
param subnetNsgId string = ''

//###################################################################################################

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2022-07-01' = {
  name: '${vnetName}/${subnetName}'
  properties: {
    addressPrefix: subnetAddress
    networkSecurityGroup: {
      id: ((!empty(subnetNsgId)) ? subnetNsgId : null)
    }
  }
}

output id string = subnet.id
output name string = subnet.name
output properties object = subnet
