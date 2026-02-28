@description('Region location of all resources')
param location string = resourceGroup().location

@description('The name of the network security group resource')
param nsgName string


@description('Network Security Group config for Azure Virtual Desktop')
param nsgParam object = {
  properties: {
    securityRules: [
      {
        name: 'AllowRDPInBound_RTS'
        properties: {
          priority: 300
          access: 'Allow'
          direction: 'Inbound'
          destinationPortRange: '3389'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '81.92.73.67'
          destinationAddressPrefix: '*'
          description: 'Allow RDP connections from RTS IP.'
        }
      }
    ]
  }
}

//#######################################################################################################################################

resource nsg 'Microsoft.Network/networkSecurityGroups@2022-07-01' = {
  name: nsgName
  location: location
  properties: nsgParam.properties
}

output nsgName string = nsg.name
output nsgId string = nsg.id
output nsg object = nsg
