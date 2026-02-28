@description('Resource group location of all resources')
param vmLocation string

@description('Default VM name prefix')
@maxLength(11)
param vmNamePrefix string

@description('VM and computer name')
@maxLength(15)
param vmName string = '${vmNamePrefix}-img'

@description('VM NIC resource name')
param vmNicName string = '${vmName}-nic0'

@description('VM Public IP resource name')
param vmPipName string = '${vmName}-pip'

@description('VM Public IP resource name')
param vmPublicDnsName string = '${vmName}.${vmLocation}.cloudapp.azure.com'

@description('VM OS disk resource name')
param vmOsDiskName string = '${vmName}-disk0'

@description('VM OS disk type')
@allowed([
  'Premium_LRS'
  'Premium_ZRS'
  'PremiumV2_LRS'
  'Standard_LRS'
  'StandardSSD_LRS'
  'StandardSSD_ZRS'
  'UltraSSD_LRS'
])
param vmOsDiskType string = 'StandardSSD_LRS'

@description('VM NIC subnet resource id')
param vmNicSubnetId string

@description('VM image offer')
param vmImgOffer string = 'windows-11'

@description('VM image sku')
param vmImgSku string = 'win11-22h2-avd'

@description('VM Local administrator username')
param vmLocalAdminUser string = 'adminuser'

@description('VM Local administrator password')
@minLength(8)
@maxLength(123)
@secure()
param vmLocalAdminPass string

@description('If a network security is to be created and associated to the subnet')
param deployVmNsg bool = false

@description('The name of the Network Security Group resource')
param vmNsgName string = '${vmName}-nsg'


@description('Virutal Machine NIC config')
param vmNicParam object = {
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            properties: {
              deleteOption: 'Delete'
            }
          }
        }
      }
    ]
  }
}



@description('Public IP Address config')
param vmPipParam object = {
  sku: {
    name: 'Basic'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}



@description('Virtual Machine Config')
param vmParam object = {
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2ms'
    }
    osProfile: {
      windowsConfiguration: {
        enableAutomaticUpdates: false
        provisionVMAgent: true
        patchSettings: {
          enableHotpatching: false
          patchMode: 'Manual'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'microsoftwindowsdesktop'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkApiVersion: '2022-07-01'
      networkInterfaceConfigurations: [
        {
          properties: {
            ipConfigurations: [
              {
                name: 'ipconfig1'
                properties:{
                  publicIPAddressConfiguration: {
                    sku: {
                      name: 'Basic'
                      tier: 'Regional'
                    }
                    properties: {
                      deleteOption: 'Delete'
                      publicIPAddressVersion: 'IPv4'
                      publicIPAllocationMethod: 'Dynamic'
                    }
                  }
                }
              }
            ]
          }
        }
      ]
      networkInterfaces: [
        {
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
    licenseType: 'Windows_Client'
  }
}





//##########################################################################################



module vmNsg 'networkSecurityGroup.bicep' = if (deployVmNsg) {
  name: '${deployment().name}-nsg'
  params: {
    location: vmLocation
    nsgName: vmNsgName
  }
}






resource virtualMachinePip 'Microsoft.Network/publicIPAddresses@2022-07-01' = {
  name: vmPipName
  location: vmLocation
  sku: {
    name: vmPipParam.sku.name
  }
  properties: {
    publicIPAllocationMethod: vmPipParam.properties.publicIPAllocationMethod
    dnsSettings: {
      domainNameLabel: vmName
      fqdn: vmPublicDnsName
    }
  }
}






resource virtualMachineNic 'Microsoft.Network/networkInterfaces@2022-07-01' = {
  name: vmNicName
  location: vmLocation
  properties: {
    networkSecurityGroup: ((deployVmNsg) ? {id: vmNsg.outputs.nsgId} : null)
    ipConfigurations: [
      {
        name: vmNicParam.properties.ipConfigurations[0].name
        properties: {
          privateIPAllocationMethod: vmNicParam.properties.ipConfigurations[0].properties.privateIPAllocationMethod
          subnet: {
            id: vmNicSubnetId
          }
          publicIPAddress: {
            id: virtualMachinePip.id
            properties: {
              deleteOption: vmNicParam.properties.ipConfigurations[0].properties.publicIPAddress.properties.deleteOption
            }
          }
        }
      }
    ]
  }
}





resource virtualMachine 'Microsoft.Compute/virtualMachines@2022-11-01' =  {
  name: vmName
  location: vmLocation
  properties: {
    hardwareProfile: {
      vmSize: vmParam.properties.hardwareProfile.vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: vmLocalAdminUser
      adminPassword: vmLocalAdminPass
      windowsConfiguration: {
        enableAutomaticUpdates: vmParam.properties.osProfile.windowsConfiguration.enableAutomaticUpdates
        provisionVMAgent: vmParam.properties.osProfile.windowsConfiguration.provisionVMAgent
/*         patchSettings: {
          enableHotpatching: vmParam.properties.osProfile.windowsConfiguration.patchSettings.enableHotpatching
          patchMode: vmParam.properties.osProfile.windowsConfiguration.patchSettings.patchMode
        } */
      }
    }
    storageProfile: {
      imageReference: {
        publisher: vmParam.properties.storageProfile.imageReference.publisher
        offer: vmImgOffer
        sku: vmImgSku
        version: vmParam.properties.storageProfile.imageReference.version
      }
      osDisk: {
        name: vmOsDiskName
        createOption: vmParam.properties.storageProfile.osDisk.createOption
        managedDisk: {
          storageAccountType: vmOsDiskType
        }
        deleteOption: vmParam.properties.storageProfile.osDisk.deleteOption
      }
    }
    networkProfile: {
/*       networkApiVersion: vmParam.properties.networkProfile.networkApiVersion
      networkInterfaceConfigurations: [
        {
          name: vmNicName
          properties: {
            ipConfigurations: [
              {
                name: vmParam.properties.networkProfile.networkInterfaceConfigurations[0].properties.ipConfigurations[0].name
                properties:{
                  subnet: {
                    id: vmNicSubnetId
                  }
                  publicIPAddressConfiguration: {
                    name: vmPipName
                    sku: {
                      name: vmParam.properties.networkProfile.networkInterfaceConfigurations[0].properties.ipConfigurations[0].properties.publicIPAddressConfiguration.sku.name
                      //tier: vmParam.properties.networkProfile.networkInterfaceConfigurations[0].properties.ipConfigurations[0].properties.publicIPAddressConfiguration.sku.tier
                    }
                    properties: {
                      deleteOption: vmParam.properties.networkProfile.networkInterfaceConfigurations[0].properties.ipConfigurations[0].properties.publicIPAddressConfiguration.properties.deleteOption
                      publicIPAddressVersion: vmParam.properties.networkProfile.networkInterfaceConfigurations[0].properties.ipConfigurations[0].properties.publicIPAddressConfiguration.properties.publicIPAddressVersion
                      publicIPAllocationMethod: vmParam.properties.networkProfile.networkInterfaceConfigurations[0].properties.ipConfigurations[0].properties.publicIPAddressConfiguration.properties.PublicIPAllocationMethod
                      dnsSettings: {
                        domainNameLabel: vmPublicDnsName
                      }
                    }
                  }
                }
              }
            ]
          }
        }
      ] */
      networkInterfaces: [
        {
          id: virtualMachineNic.id
          properties: {
            deleteOption: vmParam.properties.networkProfile.networkInterfaces[0].properties.deleteOption
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: vmParam.properties.diagnosticsProfile.bootDiagnostics.enabled
      }
    }
    licenseType: vmParam.properties.licenseType
  }
}




output virtualMachineNic object = virtualMachineNic
output virtualMachine object = virtualMachine
