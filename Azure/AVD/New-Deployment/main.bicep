@description('Object for current resource group')
param currentRg object = resourceGroup()

@description('The name of the avd vnet resource')
param avdVnetName string

@description('The name of the avd subnet resource')
param avdSnetName string

@description('The name of the Azure Active Directory Directory Services domain')
param avdAaddsDomainName string

@description('The distinguished name of the OU Path where VM are to be deployed in.')
param avdAaddsOuPath string

@description('The name of the Azure Key Vault resource')
param avdKeyVaultName string

@description('The object id of the user that is deploying this template')
param userObjectId string

@description('The prefix for the Virtual Machine name')
param avdVmNamePrefix string = 'avd'

@description('The password for the local administrator account of the Virtual Machine')
@minLength(8)
@maxLength(123)
@secure()
param avdVmLocalAdminPass string

@description('The UPN of the domain user to be used for domain joining session hosts.')
param avdVmJoinerUPN string

@description('The password for the domain user')
@secure()
param avdVmJoinerPass string



@description('Azure Virtual Desktop Host Pool config')
param avdHostPoolParam object = {
  name: '${deployment().name}-avdHp'
  params: {
      hpFriendlyName: 'Main host pool'
      hpLocation: currentRg.location
      hpName: 'avd-hp01'
      hpType: 'Pooled'
      hpLBType: 'BreadthFirst'
      hpAppGroupType: 'Desktop'
      hpWsName: 'avd-ws01'
      hpWsFriendlyName: 'Work resources'
      hpWsDescription: 'Main workspace for avd-hp01'
    }
}



@description('Virtual machine Config')
param avdVmParam object = {
  name: '${deployment().name}-vm'
  params: {
    vmLocation: currentRg.location
    vmLocalAdminPass: avdVmLocalAdminPass
    vmNamePrefix: avdVmNamePrefix
  }
}



@description('Storage account config')
param avdStAccParam object = {
  name: '${deployment().name}-storageAccount'
  params: {
    stLocation: currentRg.location
    stName: 'rtsyoeltestst'
  }
}



@description('Azure file share config')
param avdFileShareParam object = {
  name: '${deployment().name}-stFileShare'
  params: {
    fsName: 'avd-fslogix'
    fsShareQuota: 5120
  }
}



@description('Azure Compute Gallery config')
param imgGalleryParam object = {
  name: 'AVDGallery01'
  location: currentRg.location
  properties: {
    description: 'Main image gallery for AVD hostpool ${avdHostPoolParam.name}'
  }
}


@description('VM Image Definition config')
param imgDefinitionParam object = {
  name: 'avd-definition01'
  location: currentRg.location
  properties: {
    architecture: 'x64'
    description: 'Main image definition for AVD'
    features: [
      {
          name: 'DiskControllerTypes'
          value: 'SCSI'
      }
    ]
    hyperVGeneration: 'V2'
    osState: 'Generalized'
    osType: 'Windows'
    identifier: {
      offer: 'RTS'
      publisher: 'AVD'
    }
  }
}


//#######################################################################################################################################

resource avdVnet 'Microsoft.Network/virtualNetworks@2022-07-01' existing = {
  name: avdVnetName
}

resource avdSubnet 'Microsoft.Network/virtualNetworks/subnets@2022-07-01' existing = {
  name: avdSnetName
  parent: avdVnet
}

module avdKeyVault '../../BicepModules/AzKeyVault.bicep' = {
  name: avdKeyVaultName
  params: {
    location: currentRg.location
    vaultName: avdKeyVaultName
    principalId: userObjectId
  }
}


module localSecret '../../BicepModules/AzKeyVaultSecret.bicep' = {
  name: '${avdVmNamePrefix}-LocalAdmin'
  dependsOn: [
    avdKeyVault
  ]
  params: {
    contentType: 'Windows Password'
    KeyVaultName: avdKeyVaultName
    secretName: '${avdVmNamePrefix}-LocalAdmin'
    secretValue: avdVmLocalAdminPass
  }
}



module domainSecret '../../BicepModules/AzKeyVaultSecret.bicep' = {
  name: '${avdVmNamePrefix}-vmjoiner'
  dependsOn: [
    avdKeyVault
  ]
  params: {
    contentType: 'Windows Password'
    KeyVaultName: avdKeyVaultName
    secretName: '${avdVmNamePrefix}-vmjoiner'
    secretValue: avdVmJoinerPass
  }
}




module avdImgVm '../../BicepModules/virtualMachine.bicep' = {
  name: avdVmParam.name
  params: {
    vmLocation: avdVmParam.params.vmLocation
    vmLocalAdminPass: avdVmParam.params.vmLocalAdminPass
    vmNamePrefix: avdVmParam.params.vmNamePrefix
    vmNicSubnetId: avdSubnet.id
  }
}




module avdHostPool '../../BicepModules/avd-hostpool.bicep' = {
  name: avdHostPoolParam.name
  params: {
    hpAppGroupType: avdHostPoolParam.params.hpAppGroupType
    hpFriendlyName: avdHostPoolParam.params.hpFriendlyName
    hpLBType: avdHostPoolParam.params.hpLBType
    hpLocation: avdHostPoolParam.params.hpLocation
    hpName: avdHostPoolParam.params.hpName
    hpType: avdHostPoolParam.params.hpType
    hpWsName: avdHostPoolParam.params.hpWsName
    hpWsFriendlyName: avdHostPoolParam.params.hpWsFriendlyName
    hpWsDescription: avdHostPoolParam.params.hpWsDescription
  }
}





module avdStAcc '../../BicepModules/storageAccount.bicep' = {
  name: avdStAccParam.name
  params: {
    stName: avdStAccParam.params.stName
    stLocation: avdStAccParam.params.stLocation
  }
}



module avdFileShare '../../BicepModules/FileShare.bicep' = {
  name: avdFileShareParam.name
  dependsOn: [
    avdStAcc
  ]
  params: {
    stName: avdStAccParam.params.stName
    fsName: avdFileShareParam.params.fsName
    fsShareQuota: avdFileShareParam.params.fsShareQuota
  }
}



module avdTSpecs '../../BicepModules/templateSpec.bicep' = {
  name: 'avdTSpecDeployment'
  dependsOn: [
    localSecret
    domainSecret
  ]
  params: {
    location: currentRg.location
    avdAaddsDomainName: avdAaddsDomainName
    avdAaddsOUPath: avdAaddsOuPath
    avdHpName: avdHostPool.outputs.avdHpName
    avdImageRefId: avdImageDefinition.id
    avdKeyVaultName: avdKeyVault.outputs.keyVaultName
    avdRgName: currentRg.name
    avdSubnetName: avdSubnet.name
    avdVnetId: avdVnet.id
    avdVnetName: avdVnet.name
    avdVnetRgName: currentRg.name
    domainSecretName: domainSecret.outputs.secretName
    domainUPN: avdVmJoinerUPN
    localSecretName: localSecret.outputs.secretName
    vmNamePrefix: avdVmParam.params.vmNamePrefix
  }
}



resource avdImageGallery 'Microsoft.Compute/galleries@2022-03-03' = {
  name: imgGalleryParam.name
  location: imgGalleryParam.location
  properties: {
    description: imgGalleryParam.properties.description
  }
}



resource avdImageDefinition 'Microsoft.Compute/galleries/images@2022-03-03' = {
  name: imgDefinitionParam.name
  location: imgDefinitionParam.location
  parent: avdImageGallery
  properties: {
    architecture: imgDefinitionParam.properties.architecture
    description: imgDefinitionParam.properties.description
    features: [
      {
          name: imgDefinitionParam.properties.features[0].name
          value: imgDefinitionParam.properties.features[0].value
      }
    ]
    hyperVGeneration: imgDefinitionParam.properties.hyperVGeneration
    osState: imgDefinitionParam.properties.osState
    osType: imgDefinitionParam.properties.osType
    identifier: {
      offer: imgDefinitionParam.properties.identifier.offer
      publisher: imgDefinitionParam.properties.identifier.publisher
      sku: avdImgVm.outputs.virtualMachine.properties.storageProfile.imageReference.sku
    }
  }
}




