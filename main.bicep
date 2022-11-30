@description('Location of all resources')
param location string = resourceGroup().location

@description('Default VM name prefix')
param vmNamePrefix string = 'avd-sh'

@description('Amount of VMs to be deployed')
param vmCount int = 2





@description('Network Security Group config for Azure Virtual Desktop')
param avdNSGParam object = {
  name: 'avd-vnet01-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowRDPInBound'
        properties: {
          priority: 300
          access: 'Allow'
          direction: 'Inbound'
          destinationPortRange: '3389'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '81.92.73.67'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}





@description('Virtual Network config for Azure Virtual Desktop')
param avdVirtualNetworkParam object = {
  name: 'avd-vnet01'
  location: location
  addressPrefixes: [
    {
      name: 'avd-vnet01-prefix01'
      addressPrefix: '172.16.0.0/24'
    }
  ]
  subnets: [
    {
      name: 'avd-vnet01-snet01'
      addressPrefix: '172.16.0.0/26'
    }
  ]
}




@description('Azure Virtual Desktop Host Pool config')
param avdHostPoolParam object = {
  name: 'avd-hp01'
  location: location
  properties: [
    {
      friendlyName: 'AVD Hostpool'
      hostPoolType: 'Pooled'
      loadBalancerType: 'BreadthFirst'
      preferredAppGroupType: 'Desktop'
    }
  ]
}





/*
(@description('Azure Virtual Desktop Workspaces config')
param avdWorkSpacesParam object = {
  name: 'avd-workspace'
  location: location
  properties: [
    {
      friendlyName: 'AVD WorkSpace'
    }
  ]
})
*/




@description('Azure Virtual Desktop VM NIC config')
param avdVmNicParam object = {
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}





@description('Azure Virtual Desktop Session Host VM Config')
param avdVmParam object = {
  location: location
  properties: {
      hardwareProfile: {
        vmSize: 'Standard_B2ms'
      }
      osProfile: {
        adminUsername: 'adminUsername'
        adminPassword: 'Hallon20!'
      }
      storageProfile: {
        imageReference: {
          publisher: 'MicrosoftWindowsDesktop'
          offer: 'Windows-11'
          sku: 'win11-21h2-avd'
          version: 'latest'
        }
        osDisk: {
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
          enabled: false
          storageUri:  'storageUri'
        }
      }
  }
}







/* @description('Azure Virtual Desktop Session Host VM Domain Join Extension Config')
param avdVmDomainJoinExtParam object = {
  name: 'DomainJoinExtension'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'JsonADDomainExtension'
    typeHandlerVersion: '1.3'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {
      Name: 'test.local'
      OUPath: "[parameters('ouPath')]"
      User: "[concat(parameters('domainToJoin'), '\\', parameters('domainUsername'))]",
      Restart: 'true'
      Options: ''
    }
    protectedSettings: {
      Password: ''
    }
  }
}
 */



/*

param avdStorageAccParam object = {
  name: 'avdstorageaccount${uniqueString(resourceGroup().id)}'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_RAGRS'
  }
  properties: {
    accessTier: 'Hot'
  }
}

*/




//#######################################################################################################################################

// Nedan är inte färdig
resource aaddsDomain 'Microsoft.AAD/domainServices@2021-05-01' = {
  name: ''
  location: ''
  properties: {
    domainName: ''
    filteredSync: 'Disabled'
    domainConfigurationType: 'FullySynced'
    notificationSettings: {
      notifyGlobalAdmins: 'Enabled'
      notifyDcAdmins: 'Enabled'
      additionalRecipients: []
    }
    replicaSets: [
      {
        subnetId:
        location:''
      }
    ]
    domainSecuritySettings: {
      tlsV1: 'Enabled'
      ntlmV1: 'Disabled'
      syncNtlmPasswords: 'Enabled'
      syncOnPremPasswords: 'Enabled'
      kerberosRc4Encryption: 'Enabled'
      kerberosArmoring: 'Disabled'
    }
    sku: 'standard'
  }
}

// Nedan är inte färdig
resource aaddsVirtualNetwork 'Microsoft.Network/virtualNetworks@2022-05-01' = {
  name: 'aadds-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'Subnet-1'
        properties: {
          addressPrefix: '10.0.0.0/24'
        }
      }
      {
        name: 'Subnet-2'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
    ]
  }
}










// Nedan är ej testad
resource avdstorageacc 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: avdStorageAccParam.name
  location: avdStorageAccParam.location
  kind: avdStorageAccParam.kind
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  properties: {
    dnsEndpointType: 'Standard'
    defaultToOAuthAuthentication: false
    publicNetworkAccess: 'Enabled'
    allowCrossTenantReplication: true
    azureFilesIdentityBasedAuthentication: {
      directoryServiceOptions: 'AADDS'
      activeDirectoryProperties: {
        domainName: ''
        domainGuid: ''
      }
    }
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
    accessTier: 'Hot'
  }
}










resource avdNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: avdNSGParam.name
  location: avdNSGParam.location
  properties: {
    securityRules: [
      {
        name: avdNSGParam.properties.securityRules[0].name
        properties: {
          priority: avdNSGParam.properties.securityRules[0].properties.priority
          access: avdNSGParam.properties.securityRules[0].properties.access
          direction: avdNSGParam.properties.securityRules[0].properties.direction
          destinationPortRange: avdNSGParam.properties.securityRules[0].properties.destinationPortRange
          protocol: avdNSGParam.properties.securityRules[0].properties.protocol
          sourcePortRange: avdNSGParam.properties.securityRules[0].properties.sourcePortRange
          sourceAddressPrefix: avdNSGParam.properties.securityRules[0].properties.sourceAddressPrefix
          destinationAddressPrefix: avdNSGParam.properties.securityRules[0].properties.destinationaddressprefix
        }
      }
    ]
  }
}






resource avdVirtualNetwork 'Microsoft.Network/virtualNetworks@2022-01-01' = {
  name: avdVirtualNetworkParam.name
  location: avdVirtualNetworkParam.location
  properties: {
    addressSpace: {
      addressPrefixes: [
        avdVirtualNetworkParam.addressPrefixes[0].addressprefix
      ]
    }
    subnets: [
      {
        name: avdVirtualNetworkParam.subnets[0].name
        properties: {
          addressPrefix: avdVirtualNetworkParam.subnets[0].addressPrefix
          networkSecurityGroup: {
            id: avdNSG.id
          }
        }
      }
    ]
  }
}






resource avdHostPool 'Microsoft.DesktopVirtualization/hostPools@2021-07-12' = {
  name: avdHostPoolParam.name
  location: avdHostPoolParam.location
  properties: {
    friendlyName: avdHostPoolParam.properties[0].friendlyName
    hostPoolType:  avdHostPoolParam.properties[0].hostPoolType
    loadBalancerType: avdHostPoolParam.properties[0].loadBalancerType
    preferredAppGroupType: avdHostPoolParam.properties[0].preferredAppGroupType
  }
}




// Nedan är ej testad
resource avdSharedImageGallery 'Microsoft.Compute/galleries@2022-03-03' = {
  name:
  location:
  properties: {
    description:
  }
}








/* Ej testad
resource avdWorkSpace 'Microsoft.DesktopVirtualization/workspaces@2021-07-12' = {
  name: avdWorkSpacesParam.name
  location: avdWorkSpacesParam.location
  properties: {
    friendlyName: avdWorkSpacesParam.properties[0].friendlyName
  }
}
*/


// format('{0:00},($i+1))





/* Funkar, behövs vid skapand av VM i resursen nedan
resource avdVmNic 'Microsoft.Network/networkInterfaces@2021-02-01' = [for i in range(0, vmCount): {
  name: '${vmNamePrefix}${format('{0:00}',(i + 1))}-nic1'
  location: avdVmNicParam.location
  properties: {
    ipConfigurations: [
      {
        name: avdVmNicParam.properties.ipConfigurations[0].name
        properties: {
          privateIPAllocationMethod: avdVmNicParam.properties.ipConfigurations[0].properties.privateIPAllocationMethod
          subnet: {
            id: avdVirtualNetwork.properties.subnets[0].id
          }
        }
      }
    ]
  }
}]
*/






/* Funkar
resource avdVm 'Microsoft.Compute/virtualMachines@2022-03-01' = [for i in range(0, vmCount): {
  name: '${vmNamePrefix}${format('{0:00}',(i + 1))}'
  location: avdVmParam.location
  properties: {
    hardwareProfile: {
      vmSize: avdVmParam.properties.hardwareProfile.vmSize
    }
    osProfile: {
      computerName: '${vmNamePrefix}${format('{0:00}',(i + 1))}'
      adminUsername: avdVmParam.properties.osProfile.adminUsername
      adminPassword: avdVmParam.properties.osProfile.adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: avdVmParam.properties.storageProfile.imageReference.publisher
        offer: avdVmParam.properties.storageProfile.imageReference.offer
        sku: avdVmParam.properties.storageProfile.imageReference.sku
        version: avdVmParam.properties.storageProfile.imageReference.version
      }
      osDisk: {
        name: '${vmNamePrefix}${format('{0:00}',(i + 1))}-disk1'
        caching: avdVmParam.properties.storageProfile.osDisk.caching
        createOption: avdVmParam.properties.storageProfile.osDisk.createOption
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: avdVmNic[i].id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: avdVmParam.properties.diagnosticsProfile.bootDiagnostics.enabled
        //storageUri:  avdVmParam.properties.diagnosticsProfile.bootDiagnostics.storageUri
      }
    }
  }
}]
*/







/* Ej testad
resource avdVmDomainJoinExt 'Microsoft.Compute/virtualMachines/extensions@2022-03-01' = [for i in range(0, vmCount): {
  parent: avdVm[i]
  name: avdVmDomainJoinExtParam.name
  location: avdVmDomainJoinExtParam.location
  properties: {
    publisher: avdVmDomainJoinExtParam.properties.publisher
    type: avdVmDomainJoinExtParam.properties.type
    typeHandlerVersion: avdVmDomainJoinExtParam.properties.typeHandlerVersion
    autoUpgradeMinorVersion: avdVmDomainJoinExtParam.properties.autoUpgradeMinorVersion
    enableAutomaticUpgrade: avdVmDomainJoinExtParam.properties.enableAutomaticUpgrade
    settings: {
      Name: avdVmDomainJoinExtParam.properties.settings.Name
      OUPath: avdVmDomainJoinExtParam.properties.settings.OUPath
      User: avdVmDomainJoinExtParam.properties.settings.User
      Restart: avdVmDomainJoinExtParam.properties.settings.Restart
      Options: avdVmDomainJoinExtParam.properties.settings.Options
    }
    protectedSettings: {
      Password: avdVmDomainJoinExtParam.properties.protectedSettings.Password
    }
  }
}]
*/





