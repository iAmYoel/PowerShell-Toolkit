@description('Location of all resources')
param location string = resourceGroup().location




@description('Virtual Network config for Azure Virtual Desktop')
param avdVirtualNetworkSettings object = {
  name: 'avd-vnet01'
  location: location
  addressPrefixes: [
    {
      name: 'avd-vnet01-prefix01'
      addressPrefix: '10.0.0.0/16'
    }
  ]
  subnets: [
    {
      name: 'avd-vnet01-snet01'
      addressPrefix: '10.0.0.0/24'
    }
  ]
}




@description('Azure Virtual Desktop Host Pool config')
param avdHostPoolSettings object = {
  name: 'avd-hostpool'
  location: location
  properties: [
    {
      friendlyName: 'AVD Host Pool'
      hostPoolType: 'Pooled'
      loadBalancerType: 'BreadthFirst'
      preferredAppGroupType: 'Desktop'
    }
  ]
}






@description('Azure Virtual Desktop Workspaces config')
param avdWorkSpacesSettings object = {
  name: 'avd-workspace'
  location: location
  properties: [
    {
      friendlyName: 'AVD WorkSpace'
    }
  ]
}





@description('Azure Virtual Desktop Session Host VM')
param avdVmSettings object = {
  count: 1
  namePrefix: 'avd-sh'
  location: location
  properties: [
    {
      hardwareProfile: {
        vmSize: 'Standard_A2_v2'
      }
      osProfile: {
        computerName: 'computerName'
        adminUsername: 'adminUsername'
        adminPassword: 'adminPassword'
      }
      storageProfile: {
        imageReference: {
          publisher: 'MicrosoftWindowsDesktop'
          offer: ''
          sku: ''
          version: 'latest'
        }
        osDisk: {
          name: 'name'
          caching: 'ReadWrite'
          createOption: 'FromImage'
        }
      }
      networkProfile: {
        networkInterfaces: [
          {
            id: 'id'
          }
        ]
      }
      diagnosticsProfile: {
        bootDiagnostics: {
          enabled: true
          storageUri:  'storageUri'
        }
      }
    }
  ]
}






//#######################################################################################################################################




resource avdVirtualNetwork 'Microsoft.Network/virtualNetworks@2022-01-01' = {
  name: avdVirtualNetworkSettings.name
  location: avdVirtualNetworkSettings.location
  properties: {
    addressSpace: {
      addressPrefixes: [
        avdVirtualNetworkSettings.addressPrefixes[0].addressprefix
      ]
    }
    subnets: [
      {
        name: avdVirtualNetworkSettings.subnets[0].name
        properties: {
          addressPrefix: avdVirtualNetworkSettings.subnets[0].addressPrefix
        }
      }
    ]
  }
}




resource avdHostPool 'Microsoft.DesktopVirtualization/hostPools@2021-07-12' = {
  name: avdHostPoolSettings.name
  location: avdHostPoolSettings.location
  properties: {
    friendlyName: avdHostPoolSettings.properties[0].friendlyName
    hostPoolType:  avdHostPoolSettings.properties[0].hostPoolType
    loadBalancerType: avdHostPoolSettings.properties[0].loadBalancerType
    preferredAppGroupType: avdHostPoolSettings.properties[0].preferredAppGroupType
  }
}




/*
resource avdWorkSpace 'Microsoft.DesktopVirtualization/workspaces@2021-07-12' = {
  name: avdWorkSpacesSettings.name
  location: avdWorkSpacesSettings.location
  properties: {
    friendlyName: avdWorkSpacesSettings.properties[0].friendlyName
  }
}
*/


// format('{0:00},($i+1))


resource avdVm 'Microsoft.Compute/virtualMachines@2022-03-01' = [for i in range(0, (avdVmSettings.count - 1)): {
  name: '${avdVmSettings.namePrefix}${format('{0:00}',(i + 1))}'
  location: location
  properties: {
    hardwareProfile: {
      vmSize: avdVmSettings.properties[0].hardwareProfile[0].vmSize
    }
    osProfile: {
      computerName: 'computerName'
      adminUsername: 'adminUsername'
      adminPassword: 'adminPassword'
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsDesktop'
        offer: ''
        sku: ''
        version: 'latest'
      }
      osDisk: {
        name: 'name'
        caching: 'ReadWrite'
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: 'id'

        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        storageUri:  'storageUri'
      }
    }
  }
}
