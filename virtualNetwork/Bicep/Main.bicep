@description('Region location of all resources')
param location string = resourceGroup().location

@description('The name of the virtual network resource')
param vnetName string = 'vnet01'

@description('The ip address prefix of the virtual network resource, i.e 10.0.0.0/8')
param vnetPrefixAddress string = '172.16.0.0/16'

@description('The name of the sibnet')
param snetName string = '${vnetName}-snet01'

@description('The ip address prefix of the subnet, i.e 10.0.0.0/8')
param snetPrefixAddress string = '172.16.0.0/24'

@description('If a network security is to be created and associated to the subnet')
param deployNSG bool = false

@description('The name of the Network Security Group resource')
param nsgName string = 'nsg01'

//#######################################################################################################################################


module nsg '../../BicepModules/networkSecurityGroup.bicep' = if (deployNSG) {
  name: '${deployment().name}-nsg'
  params: {
    location: location
    nsgName: nsgName
  }
}



module vnet '../../BicepModules/virtualNetwork.bicep' = {
  name: '${deployment().name}-vnet'
  params: {
    vnetPrefixAddress: vnetPrefixAddress
    location: location
    vnetName: vnetName
  }
}



module subnet '../../BicepModules/subnet.bicep' = {
  name: '${deployment().name}-snet'
  params: {
    vnetName: vnet.outputs.vnetName
    subnetAddress: snetPrefixAddress
    subnetName: snetName
    subnetNsgId: nsg.outputs.nsgId
  }
}


output nsg object = nsg.outputs.nsg
output nsgName string = nsg.outputs.nsgName
output nsgId string = nsg.outputs.nsgId
output vnet object = vnet.outputs.vnet
output vnetName string = vnet.outputs.vnetName
output vnetId string = vnet.outputs.vnetId
output subnet object = subnet.outputs.properties
output subnetName string = subnet.outputs.name
output subnetId string = subnet.outputs.id
