param location string
param vmNamePrefix string
param avdSubnetName string
param avdVnetId string
param avdVnetName string
param avdVnetRgName string
param avdImageRefId string
param avdHpName string
param avdRgName string
param avdAaddsOUPath string
param avdAaddsDomainName string
param avdKeyVaultId string
param domainUPN string
param domainSecretName string
param localSecretName string

param imageDeployTSpecName string = 'avd-tspec-image-deploy'
param linkedTSpecName string = 'avd-tspec-linked-customvm'
param avdshTSpecName string = 'avd-tspec-avdsh-deploy'


//#######################################################################################################################################

resource imageDeployTSpec 'Microsoft.Resources/templateSpecs@2022-02-01' = {
  name: imageDeployTSpecName
  location: location
  properties: {
    description: 'A basic templateSpec - creates a storage account.'
    displayName: 'Storage account (Standard_LRS)'
  }
}


resource linkedTSpec 'Microsoft.Resources/templateSpecs@2022-02-01' = {
  name: linkedTSpecName
  location: location
  properties: {
    description: 'A basic templateSpec - creates a storage account.'
    displayName: 'Storage account (Standard_LRS)'
  }
}


resource avdshTSpec 'Microsoft.Resources/templateSpecs@2022-02-01' = {
  name: avdshTSpecName
  location: location
  properties: {
    description: 'A basic templateSpec - creates a storage account.'
    displayName: 'Storage account (Standard_LRS)'
  }
}


resource imageDeployTSpecVersion 'Microsoft.Resources/templateSpecs/versions@2022-02-01' = {
  parent: imageDeployTSpec
  name: '1.0'
  location: location
  properties: {
    description: ''
    mainTemplate: {
        '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        'contentVersion': '1.0.0.0'
        'parameters': {
            'location': {
                'type': 'string'
                'defaultValue': location
            }
            'networkInterfaceName': {
                'type': 'string'
                'defaultValue': '${vmNamePrefix}-img-nic01'
            }
            'subnetName': {
                'type': 'string'
                'defaultValue': avdSubnetName
            }
            'virtualNetworkId': {
                'type': 'string'
                'defaultValue': avdVnetId
            }
            'publicIpAddressName': {
                'type': 'string'
                'defaultValue': '${vmNamePrefix}-img-pip'
            }
            'publicIpAddressType': {
                'type': 'string'
                'defaultValue': 'dynamic'
            }
            'publicIpAddressSku': {
                'type': 'string'
                'defaultValue': 'Basic'
            }
            'pipDeleteOption': {
                'type': 'string'
                'defaultValue': 'Delete'
            }
            'virtualMachineName': {
                'type': 'string'
                'defaultValue': '${vmNamePrefix}-img'
            }
            'virtualMachineComputerName': {
                'type': 'string'
                'defaultValue': '${vmNamePrefix}-img'
            }
            'osDiskType': {
                'type': 'string'
                'defaultValue': 'StandardSSD_LRS'
            }
            'osDiskDeleteOption': {
                'type': 'string'
                'defaultValue': 'Delete'
            }
            'dataDisks': {
                'type': 'array'
                'defaultValue': [
                    {
                        'lun': 0
                        'createOption': 'fromImage'
                        'deleteOption': 'Delete'
                        'caching': 'None'
                        'writeAcceleratorEnabled': false
                        'id': null
                        'name': null
                        'storageAccountType': 'StandardSSD_LRS'
                        'diskSizeGB': null
                        'diskEncryptionSet': null
                    }
                ]
            }
            'virtualMachineSize': {
                'type': 'string'
                'defaultValue': 'Standard_B2ms'
            }
            'nicDeleteOption': {
                'type': 'string'
                'defaultValue': 'Delete'
            }
            'adminUsername': {
                'type': 'string'
                'defaultValue': 'adminuser'
            }
            'adminPassword': {
                'type': 'secureString'
            }
            'patchMode': {
                'type': 'string'
                'defaultValue': 'Manual'
            }
            'enableHotpatching': {
                'type': 'bool'
                'defaultValue': false
            }
        }
        'variables': {
            'vnetId': '[parameters(\'virtualNetworkId\')]'
            'subnetRef': '[concat(variables(\'vnetId\'), \'/subnets/\', parameters(\'subnetName\'))]'
            'imageReference': avdImageRefId
            'pipFqdn': '[concat(parameters(\'VirtualMachineName\'), \'.${location}.cloudapp.azure.com\')]'
        }
        'resources': [
            {
                'name': '[parameters(\'networkInterfaceName\')]'
                'type': 'Microsoft.Network/networkInterfaces'
                'apiVersion': '2021-03-01'
                'location': '[parameters(\'location\')]'
                'dependsOn': [
                    '[concat(\'Microsoft.Network/publicIpAddresses/\', parameters(\'publicIpAddressName\'))]'
                ]
                'properties': {
                    'ipConfigurations': [
                        {
                            'name': 'ipconfig1'
                            'properties': {
                                'subnet': {
                                    'id': '[variables(\'subnetRef\')]'
                                }
                                'privateIPAllocationMethod': 'Dynamic'
                                'publicIpAddress': {
                                    'id': '[resourceId(resourceGroup().name, \'Microsoft.Network/publicIpAddresses\', parameters(\'publicIpAddressName\'))]'
                                    'properties': {
                                        'deleteOption': '[parameters(\'pipDeleteOption\')]'
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            {
                'name': '[parameters(\'publicIpAddressName\')]'
                'type': 'Microsoft.Network/publicIpAddresses'
                'apiVersion': '2020-08-01'
                'location': '[parameters(\'location\')]'
                'properties': {
                    'publicIpAllocationMethod': '[parameters(\'publicIpAddressType\')]'
                    'dnsSettings': {
                        'domainNameLabel': '[parameters(\'virtualMachineName\')]'
                        'fqdn': '[variables(\'pipFqdn\')]'
                    }
                }
                'sku': {
                    'name': '[parameters(\'publicIpAddressSku\')]'
                }
            }
            {
                'name': '[parameters(\'virtualMachineName\')]'
                'type': 'Microsoft.Compute/virtualMachines'
                'apiVersion': '2022-03-01'
                'location': '[parameters(\'location\')]'
                'dependsOn': [
                    '[concat(\'Microsoft.Network/networkInterfaces/\', parameters(\'networkInterfaceName\'))]'
                ]
                'properties': {
                    'hardwareProfile': {
                        'vmSize': '[parameters(\'virtualMachineSize\')]'
                    }
                    'storageProfile': {
                        'osDisk': {
                            'createOption': 'fromImage'
                            'managedDisk': {
                                'storageAccountType': '[parameters(\'osDiskType\')]'
                            }
                            'deleteOption': '[parameters(\'osDiskDeleteOption\')]'
                        }
                        'imageReference': {
                            'id': '[variables(\'imageReference\')]'
                        }
                        'copy': [
                            {
                                'name': 'dataDisks'
                                'count': '[length(parameters(\'dataDisks\'))]'
                                'input': {
                                    'lun': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].lun]'
                                    'createOption': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].createOption]'
                                    'caching': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].caching]'
                                    'diskSizeGB': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].diskSizeGB]'
                                    'managedDisk': {
                                        'id': '[coalesce(parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].id, if(equals(parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].name, json(\'null\')), json(\'null\'), resourceId(\'Microsoft.Compute/disks\', parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].name)))]'
                                        'storageAccountType': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].storageAccountType]'
                                    }
                                    'deleteOption': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].deleteOption]'
                                    'writeAcceleratorEnabled': '[parameters(\'dataDisks\')[copyIndex(\'dataDisks\')].writeAcceleratorEnabled]'
                                }
                            }
                        ]
                    }
                    'networkProfile': {
                        'networkInterfaces': [
                            {
                                'id': '[resourceId(\'Microsoft.Network/networkInterfaces\', parameters(\'networkInterfaceName\'))]'
                                'properties': {
                                    'deleteOption': '[parameters(\'nicDeleteOption\')]'
                                }
                            }
                        ]
                    }
                    'osProfile': {
                        'computerName': '[parameters(\'virtualMachineComputerName\')]'
                        'adminUsername': '[parameters(\'adminUsername\')]'
                        'adminPassword': '[parameters(\'adminPassword\')]'
                        'windowsConfiguration': {
                            'enableAutomaticUpdates': false
                            'provisionVmAgent': true
                            'patchSettings': {
                                'enableHotpatching': '[parameters(\'enableHotpatching\')]'
                                'patchMode': '[parameters(\'patchMode\')]'
                            }
                        }
                    }
                    'licenseType': 'Windows_Client'
                }
            }
        ]
        'outputs': {
            'adminUsername': {
                'type': 'string'
                'value': '[parameters(\'adminUsername\')]'
            }
        }
    }
  }
}


resource linkedTSpecVersion 'Microsoft.Resources/templateSpecs/versions@2022-02-01' = {
  parent: linkedTSpec
  name: '1.0'
  location: location
  properties: {
    description: ''
    mainTemplate: {
        '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        'contentVersion': '1.0.0.0'
        'parameters': {
            'artifactsLocation': {
                'type': 'string'
                'metadata': {
                    'description': 'The base URI where artifacts required by this template are located.'
                }
            }
            'availabilityOption': {
                'type': 'string'
                'metadata': {
                    'description': 'The availability option for the VMs.'
                }
                'defaultValue': 'None'
                'allowedValues': [
                    'None'
                    'AvailabilitySet'
                    'AvailabilityZone'
                ]
            }
            'availabilitySetName': {
                'type': 'string'
                'metadata': {
                    'description': 'The name of avaiability set to be used when create the VMs.'
                }
                'defaultValue': ''
            }
            'availabilityZones': {
                'type': 'array'
                'metadata': {
                    'description': 'The availability zones to equally distribute VMs amongst'
                }
                'defaultValue': []
            }
            'vmGalleryImageOffer': {
                'type': 'string'
                'metadata': {
                    'description': '(Required when vmImageType = Gallery) Gallery image Offer.'
                }
                'defaultValue': ''
            }
            'vmGalleryImagePublisher': {
                'type': 'string'
                'metadata': {
                    'description': '(Required when vmImageType = Gallery) Gallery image Publisher.'
                }
                'defaultValue': ''
            }
            'vmGalleryImageHasPlan': {
                'type': 'bool'
                'metadata': {
                    'description': 'Whether the VM image has a plan or not'
                }
                'defaultValue': false
            }
            'vmGalleryImageSKU': {
                'type': 'string'
                'metadata': {
                    'description': '(Required when vmImageType = Gallery) Gallery image SKU.'
                }
                'defaultValue': ''
            }
            'vmGalleryImageVersion': {
                'type': 'string'
                'metadata': {
                    'description': '(Required when vmImageType = Gallery) Gallery image version.'
                }
                'defaultValue': ''
            }
            'rdshPrefix': {
                'type': 'string'
                'metadata': {
                    'description': 'This prefix will be used in combination with the VM number to create the VM name. This value includes the dash, so if using “rdsh” as the prefix, VMs would be named “rdsh-0”, “rdsh-1”, etc. You should use a unique prefix to reduce name collisions in Active Directory.'
                }
                'defaultValue': '[take(toLower(resourceGroup().name),10)]'
            }
            'rdshNumberOfInstances': {
                'type': 'int'
                'metadata': {
                    'description': 'Number of session hosts that will be created and added to the hostpool.'
                }
            }
            'rdshVMDiskType': {
                'type': 'string'
                'allowedValues': [
                    'Premium_LRS'
                    'StandardSSD_LRS'
                    'Standard_LRS'
                ]
                'metadata': {
                    'description': 'The VM disk type for the VM: HDD or SSD.'
                }
            }
            'rdshVmSize': {
                'type': 'string'
                'metadata': {
                    'description': 'The size of the session host VMs.'
                }
                'defaultValue': 'Standard_A2'
            }
            'rdshVmDiskSizeGB': {
                'type': 'int'
                'metadata': {
                    'description': 'The size of the disk on the vm in GB'
                }
                'defaultValue': 0
            }
            'rdshHibernate': {
                'type': 'bool'
                'metadata': {
                    'description': 'Whether or not the VM is hibernate enabled'
                }
                'defaultValue': false
            }
            'enableAcceleratedNetworking': {
                'type': 'bool'
                'metadata': {
                    'description': 'Enables Accelerated Networking feature, notice that VM size must support it, this is supported in most of general purpose and compute-optimized instances with 2 or more vCPUs, on instances that supports hyperthreading it is required minimum of 4 vCPUs.'
                }
                'defaultValue': false
            }
            'administratorAccountUsername': {
                'type': 'string'
                'metadata': {
                    'description': 'The username for the domain admin.'
                }
            }
            'administratorAccountPassword': {
                'type': 'securestring'
                'metadata': {
                    'description': 'The password that corresponds to the existing domain username.'
                }
            }
            'vmAdministratorAccountUsername': {
                'type': 'string'
                'metadata': {
                    'description': 'A username to be used as the virtual machine administrator account. The vmAdministratorAccountUsername and  vmAdministratorAccountPassword parameters must both be provided. Otherwise, domain administrator credentials provided by administratorAccountUsername and administratorAccountPassword will be used.'
                }
                'defaultValue': ''
            }
            'vmAdministratorAccountPassword': {
                'type': 'securestring'
                'metadata': {
                    'description': 'The password associated with the virtual machine administrator account. The vmAdministratorAccountUsername and  vmAdministratorAccountPassword parameters must both be provided. Otherwise, domain administrator credentials provided by administratorAccountUsername and administratorAccountPassword will be used.'
                }
                'defaultValue': ''
            }
            'vhds': {
                'type': 'string'
                'metadata': {
                    'description': 'The URL to store unmanaged disks.'
                }
            }
            'subnet-id': {
                'type': 'string'
                'metadata': {
                    'description': 'The unique id of the subnet for the nics.'
                }
            }
            'rdshImageSourceId': {
                'type': 'string'
                'defaultValue': ''
                'metadata': {
                    'description': 'Resource ID of the image.'
                }
            }
            'location': {
                'type': 'string'
                'defaultValue': ''
                'metadata': {
                    'description': 'Location for all resources to be created in.'
                }
            }
            'createNetworkSecurityGroup': {
                'type': 'bool'
                'metadata': {
                    'description': 'Whether to create a new network security group or use an existing one'
                }
                'defaultValue': false
            }
            'networkSecurityGroupId': {
                'type': 'string'
                'metadata': {
                    'description': 'The resource id of an existing network security group'
                }
                'defaultValue': ''
            }
            'networkSecurityGroupRules': {
                'type': 'array'
                'metadata': {
                    'description': 'The rules to be given to the new network security group'
                }
                'defaultValue': []
            }
            'networkInterfaceTags': {
                'type': 'object'
                'metadata': {
                    'description': 'The tags to be assigned to the network interfaces'
                }
                'defaultValue': {}
            }
            'networkSecurityGroupTags': {
                'type': 'object'
                'metadata': {
                    'description': 'The tags to be assigned to the network security groups'
                }
                'defaultValue': {}
            }
            'virtualMachineTags': {
                'type': 'object'
                'metadata': {
                    'description': 'The tags to be assigned to the virtual machines'
                }
                'defaultValue': {}
            }
            'imageTags': {
                'type': 'object'
                'metadata': {
                    'description': 'The tags to be assigned to the images'
                }
                'defaultValue': {}
            }
            'vmInitialNumber': {
                'type': 'int'
                'metadata': {
                    'description': 'VM name prefix initial number.'
                }
                'defaultValue': 0
            }
            '_guidValue': {
                'type': 'string'
                'defaultValue': '[newGuid()]'
            }
            'hostpoolName': {
                'type': 'string'
                'metadata': {
                    'description': 'The name of the hostpool'
                }
            }
            'hostpoolResourceGroup': {
                'type': 'string'
                'metadata': {
                    'description': 'The name of the hostpool resource group'
                }
            }
            'ouPath': {
                'type': 'string'
                'metadata': {
                    'description': 'OUPath for the domain join'
                }
                'defaultValue': ''
            }
            'domain': {
                'type': 'string'
                'metadata': {
                    'description': 'Domain to join'
                }
                'defaultValue': ''
            }
            'aadJoin': {
                'type': 'bool'
                'metadata': {
                    'description': 'IMPORTANT: You can use this parameter for the test purpose only as AAD Join is public preview. True if AAD Join, false if AD join'
                }
                'defaultValue': false
            }
            'intune': {
                'type': 'bool'
                'metadata': {
                    'description': 'IMPORTANT: Please don\'t use this parameter as intune enrollment is not supported yet. True if intune enrollment is selected.  False otherwise'
                }
                'defaultValue': false
            }
            'bootDiagnostics': {
                'type': 'object'
                'metadata': {
                    'description': 'Boot diagnostics object taken as body of Diagnostics Profile in VM creation'
                }
                'defaultValue': {
                    'enabled': false
                }
            }
            'userAssignedIdentity': {
                'type': 'string'
                'metadata': {
                    'description': 'The name of user assigned identity that will assigned to the VMs. This is an optional parameter.'
                }
                'defaultValue': ''
            }
            'customConfigurationTemplateUrl': {
                'type': 'string'
                'metadata': {
                    'description': 'ARM template that contains custom configurations to be run after the virtual machines are created.'
                }
                'defaultValue': ''
            }
            'customConfigurationParameterUrl': {
                'type': 'string'
                'metadata': {
                    'description': 'Url to the ARM template parameter file for the customConfigurationTemplateUrl parameter. This input will be used when the template is ran after the VMs have been deployed.'
                }
                'defaultValue': ''
            }
            'SessionHostConfigurationVersion': {
                'type': 'string'
                'metadata': {
                    'description': 'Session host configuration version of the host pool.'
                }
                'defaultValue': ''
            }
            'systemData': {
                'type': 'object'
                'metadata': {
                    'description': 'System data is used for internal purposes, such as support preview features.'
                }
                'defaultValue': {}
            }
            'securityType': {
                'type': 'string'
                'metadata': {
                    'description': 'Specifies the SecurityType of the virtual machine. It is set as TrustedLaunch to enable UefiSettings. Default: UefiSettings will not be enabled unless this property is set as TrustedLaunch.'
                }
                'defaultValue': ''
            }
            'secureBoot': {
                'type': 'bool'
                'metadata': {
                    'description': 'Specifies whether secure boot should be enabled on the virtual machine.'
                }
                'defaultValue': false
            }
            'vTPM': {
                'type': 'bool'
                'metadata': {
                    'description': 'Specifies whether vTPM (Virtual Trusted Platform Module) should be enabled on the virtual machine.'
                }
                'defaultValue': false
            }
            'wvdApiVersion': {
                'type': 'string'
                'metadata': {
                    'description': 'WVD api version'
                }
            }
        }
        'variables': {
            'emptyArray': []
            'domain': '[if(equals(parameters(\'domain\'), \'\'), last(split(parameters(\'administratorAccountUsername\'), \'@\')), parameters(\'domain\'))]'
            'storageAccountType': '[parameters(\'rdshVMDiskType\')]'
            'newNsgName': '[concat(parameters(\'rdshPrefix\'), \'nsg-\', parameters(\'_guidValue\'))]'
            'newNsgDeploymentName': '[concat(\'NSG-linkedTemplate-\', parameters(\'_guidValue\'))]'
            'nsgId': '[if(parameters(\'createNetworkSecurityGroup\'), resourceId(\'Microsoft.Network/networkSecurityGroups\', variables(\'newNsgName\')), parameters(\'networkSecurityGroupId\'))]'
            'isVMAdminAccountCredentialsProvided': '[and(not(equals(parameters(\'vmAdministratorAccountUsername\'), \'\')), not(equals(parameters(\'vmAdministratorAccountPassword\'), \'\')))]'
            'vmAdministratorUsername': '[if(variables(\'isVMAdminAccountCredentialsProvided\'), parameters(\'vmAdministratorAccountUsername\'), first(split(parameters(\'administratorAccountUsername\'), \'@\')))]'
            'vmAdministratorPassword': '[if(variables(\'isVMAdminAccountCredentialsProvided\'), parameters(\'vmAdministratorAccountPassword\'), parameters(\'administratorAccountPassword\'))]'
            'vmAvailabilitySetResourceId': {
                'id': '[resourceId(\'Microsoft.Compute/availabilitySets/\', parameters(\'availabilitySetName\'))]'
            }
            'planInfoEmpty': '[or(empty(parameters(\'vmGalleryImageSKU\')), empty(parameters(\'vmGalleryImagePublisher\')), empty(parameters(\'vmGalleryImageOffer\')))]'
            'marketplacePlan': {
                'name': '[parameters(\'vmGalleryImageSKU\')]'
                'publisher': '[parameters(\'vmGalleryImagePublisher\')]'
                'product': '[parameters(\'vmGalleryImageOffer\')]'
                'version': '[if(empty(parameters(\'vmGalleryImageVersion\')), \'latest\', parameters(\'vmGalleryImageVersion\'))]'
            }
            'vmPlan': '[if(or(variables(\'planInfoEmpty\'), not(parameters(\'vmGalleryImageHasPlan\'))), json(\'null\'), variables(\'marketplacePlan\'))]'
            'vmIdentityType': '[if(parameters(\'aadJoin\'), if(not(empty(parameters(\'userAssignedIdentity\'))), \'SystemAssigned, UserAssigned\', \'SystemAssigned\'), if(not(empty(parameters(\'userAssignedIdentity\'))), \'UserAssigned\', \'None\'))]'
            'vmIdentityTypeProperty': {
                'type': '[variables(\'vmIdentityType\')]'
            }
            'vmUserAssignedIdentityProperty': {
                'userAssignedIdentities': {
                    '[resourceID(\'Microsoft.ManagedIdentity/userAssignedIdentities/\',parameters(\'userAssignedIdentity\'))]': {}
                }
            }
            'vmIdentity': '[if(not(empty(parameters(\'userAssignedIdentity\'))), union(variables(\'vmIdentityTypeProperty\'), variables(\'vmUserAssignedIdentityProperty\')), variables(\'vmIdentityTypeProperty\'))]'
            'postDeploymentCustomConfigurationTemplateProperty': {
                'mode': 'Incremental'
                'templateLink': {
                    'uri': '[parameters(\'customConfigurationTemplateUrl\')]'
                    'contentVersion': '1.0.0.0'
                }
            }
            'postDeploymentCustomConfigurationParameterProperty': {
                'parametersLink': {
                    'uri': '[parameters(\'customConfigurationParameterUrl\')]'
                }
            }
            'customConfigurationParameter': '[if(empty(parameters(\'customConfigurationParameterUrl\')), variables(\'postDeploymentCustomConfigurationTemplateProperty\'), union(variables(\'postDeploymentCustomConfigurationTemplateProperty\'), variables(\'postDeploymentCustomConfigurationParameterProperty\')))]'
            'securityProfile': {
                'uefiSettings': {
                    'secureBootEnabled': '[parameters(\'secureBoot\')]'
                    'vTpmEnabled': '[parameters(\'vTPM\')]'
                }
                'securityType': '[parameters(\'securityType\')]'
            }
            'countOfSelectedAZ': '[length(parameters(\'availabilityZones\'))]'
        }
        'resources': [
            {
                'apiVersion': '2018-05-01'
                'name': '[variables(\'newNsgDeploymentName\')]'
                'type': 'Microsoft.Resources/deployments'
                'properties': {
                    'mode': 'Incremental'
                    'template': {
                        '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                        'contentVersion': '1.0.0.0'
                        'resources': [
                            {
                                'condition': '[parameters(\'createNetworkSecurityGroup\')]'
                                'type': 'Microsoft.Network/networkSecurityGroups'
                                'apiVersion': '2019-02-01'
                                'name': '[variables(\'newNsgName\')]'
                                'location': '[parameters(\'location\')]'
                                'tags': '[parameters(\'networkSecurityGroupTags\')]'
                                'properties': {
                                    'securityRules': '[parameters(\'networkSecurityGroupRules\')]'
                                }
                            }
                        ]
                    }
                }
            }
            {
                'apiVersion': '2018-11-01'
                'type': 'Microsoft.Network/networkInterfaces'
                'name': '[concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')), \'-nic\')]'
                'location': '[parameters(\'location\')]'
                'tags': '[parameters(\'networkInterfaceTags\')]'
                'dependsOn': [
                    '[variables(\'newNsgDeploymentName\')]'
                ]
                'copy': {
                    'name': 'rdsh-nic-loop'
                    'count': '[parameters(\'rdshNumberOfInstances\')]'
                }
                'properties': {
                    'ipConfigurations': [
                        {
                            'name': 'ipconfig'
                            'properties': {
                                'privateIPAllocationMethod': 'Dynamic'
                                'subnet': {
                                    'id': '[parameters(\'subnet-id\')]'
                                }
                            }
                        }
                    ]
                    'enableAcceleratedNetworking': '[parameters(\'enableAcceleratedNetworking\')]'
                    'networkSecurityGroup': '[if(empty(parameters(\'networkSecurityGroupId\')), json(\'null\'), json(concat(\'{"id": "\', variables(\'nsgId\'), \'"}\')))]'
                }
            }
            {
                'apiVersion': '2021-07-01'
                'type': 'Microsoft.Compute/virtualMachines'
                'name': '[concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')))]'
                'location': '[parameters(\'location\')]'
                'tags': '[parameters(\'virtualMachineTags\')]'
                'plan': '[variables(\'vmPlan\')]'
                'dependsOn': [
                    '[concat(\'Microsoft.Network/networkInterfaces/\', parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')), \'-nic\')]'
                ]
                'copy': {
                    'name': 'rdsh-vm-loop'
                    'count': '[parameters(\'rdshNumberOfInstances\')]'
                }
                'identity': '[variables(\'vmIdentity\')]'
                'properties': {
                    'hardwareProfile': {
                        'vmSize': '[parameters(\'rdshVmSize\')]'
                    }
                    'availabilitySet': '[if(equals(parameters(\'availabilityOption\'), \'AvailabilitySet\'), variables(\'vmAvailabilitySetResourceId\'), json(\'null\'))]'
                    'osProfile': {
                        'computerName': '[concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')))]'
                        'adminUsername': '[variables(\'vmAdministratorUsername\')]'
                        'adminPassword': '[variables(\'vmAdministratorPassword\')]'
                    }
                    'securityProfile': '[if(equals(parameters(\'securityType\'), \'TrustedLaunch\'), variables(\'securityProfile\'), json(\'null\'))]'
                    'storageProfile': {
                        'osDisk': {
                            'createOption': 'FromImage'
                            'managedDisk': {
                                'storageAccountType': '[variables(\'storageAccountType\')]'
                            }
                        }
                        'imageReference': {
                            'id': '[parameters(\'rdshImageSourceId\')]'
                        }
                    }
                    'networkProfile': {
                        'networkInterfaces': [
                            {
                                'id': '[resourceId(\'Microsoft.Network/networkInterfaces\',concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')), \'-nic\'))]'
                            }
                        ]
                    }
                    'diagnosticsProfile': {
                        'bootDiagnostics': '[parameters(\'bootDiagnostics\')]'
                    }
                    'licenseType': 'Windows_Client'
                }
                'zones': '[if(equals(parameters(\'availabilityOption\'), \'AvailabilityZone\'), array(parameters(\'availabilityZones\')[mod(copyIndex(\'rdsh-vm-loop\'),variables(\'countOfSelectedAZ\'))]), variables(\'emptyArray\'))]'
            }
            {
                'apiVersion': '2021-07-01'
                'type': 'Microsoft.Compute/virtualMachines/extensions'
                'name': '[concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')), \'/\', \'Microsoft.PowerShell.DSC\')]'
                'location': '[parameters(\'location\')]'
                'dependsOn': [
                    'rdsh-vm-loop'
                ]
                'copy': {
                    'name': 'rdsh-dsc-loop'
                    'count': '[parameters(\'rdshNumberOfInstances\')]'
                }
                'properties': {
                    'publisher': 'Microsoft.Powershell'
                    'type': 'DSC'
                    'typeHandlerVersion': '2.73'
                    'autoUpgradeMinorVersion': true
                    'settings': {
                        'modulesUrl': '[parameters(\'artifactsLocation\')]'
                        'configurationFunction': 'Configuration.ps1\\AddSessionHost'
                        'properties': {
                            'hostPoolName': '[parameters(\'hostpoolName\')]'
                            'registrationInfoToken': '[reference(resourceId(parameters(\'hostpoolResourceGroup\'), \'Microsoft.DesktopVirtualization/hostPools\', parameters(\'hostpoolName\')), parameters(\'wvdApiVersion\')).registrationInfo.token]'
                            'aadJoin': '[parameters(\'aadJoin\')]'
                            'UseAgentDownloadEndpoint': true
                            'aadJoinPreview': '[and(contains(parameters(\'systemData\'), \'aadJoinPreview\'), parameters(\'systemData\').aadJoinPreview)]'
                            'mdmId': '[if(parameters(\'intune\'), \'0000000a-0000-0000-c000-000000000000\', \'\')]'
                            'sessionHostConfigurationLastUpdateTime': '[parameters(\'SessionHostConfigurationVersion\')]'
                        }
                    }
                }
            }
            {
                'condition': '[and(parameters(\'aadJoin\'), contains(parameters(\'systemData\'), \'aadJoinPreview\'), not(parameters(\'systemData\').aadJoinPreview))]'
                'apiVersion': '2021-07-01'
                'type': 'Microsoft.Compute/virtualMachines/extensions'
                'name': '[concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')), \'/\', \'AADLoginForWindows\')]'
                'location': '[parameters(\'location\')]'
                'dependsOn': [
                    'rdsh-dsc-loop'
                ]
                'copy': {
                    'name': 'rdsh-aad-join-loop'
                    'count': '[parameters(\'rdshNumberOfInstances\')]'
                }
                'properties': {
                    'publisher': 'Microsoft.Azure.ActiveDirectory'
                    'type': 'AADLoginForWindows'
                    'typeHandlerVersion': '1.0'
                    'autoUpgradeMinorVersion': true
                    'settings': '[if(parameters(\'intune\'), createObject(\'mdmId\',\'0000000a-0000-0000-c000-000000000000\'), json(\'null\'))]'
                }
            }
            {
                'condition': '[not(parameters(\'aadJoin\'))]'
                'apiVersion': '2021-07-01'
                'type': 'Microsoft.Compute/virtualMachines/extensions'
                'name': '[concat(parameters(\'rdshPrefix\'), add(copyindex(), parameters(\'vmInitialNumber\')), \'/\', \'joindomain\')]'
                'location': '[parameters(\'location\')]'
                'dependsOn': [
                    'rdsh-dsc-loop'
                ]
                'copy': {
                    'name': 'rdsh-domain-join-loop'
                    'count': '[parameters(\'rdshNumberOfInstances\')]'
                }
                'properties': {
                    'publisher': 'Microsoft.Compute'
                    'type': 'JsonADDomainExtension'
                    'typeHandlerVersion': '1.3'
                    'autoUpgradeMinorVersion': true
                    'settings': {
                        'name': '[variables(\'domain\')]'
                        'ouPath': '[parameters(\'ouPath\')]'
                        'user': '[parameters(\'administratorAccountUsername\')]'
                        'restart': 'true'
                        'options': '3'
                    }
                    'protectedSettings': {
                        'password': '[parameters(\'administratorAccountPassword\')]'
                    }
                }
            }
            {
                'condition': '[not(empty(parameters(\'customConfigurationTemplateUrl\')))]'
                'type': 'Microsoft.Resources/deployments'
                'apiVersion': '2020-10-01'
                'name': 'post-deployment-custom-configurations'
                'dependsOn': [
                    'rdsh-dsc-loop'
                    'rdsh-aad-join-loop'
                    'rdsh-domain-join-loop'
                ]
                'properties': '[variables(\'customConfigurationParameter\')]'
            }
        ]
        'outputs': {}
    }
  }
}


resource avdshTSpecVersion 'Microsoft.Resources/templateSpecs/versions@2022-02-01' = {
    parent: avdshTSpec
    name: '1.0'
    location: location
    properties: {
        description: ''
        mainTemplate: {
            '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
            'contentVersion': '1.0.0.0'
            'parameters': {
                'hostpoolName': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The name of the Hostpool to be created.'
                    }
                    'defaultValue': avdHpName
                }
                'hostpoolResourceGroup': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The resource group of the host pool to be updated. Used when the host pool was created empty.'
                    }
                    'defaultValue': avdRgName
                }
                'hostpoolLocation': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The location of the host pool to be updated. Used when the host pool was created empty.'
                    }
                    'defaultValue': location
                }
                'vmTemplateName': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The name of the customvm template.'
                    }
                    'defaultValue': avdshTSpecName
                }
                'vmTemplateVersion': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The version of the customvm template.'
                    }
                    'defaultValue': '1.0'
                }
                'administratorDomainUsername': {
                    'type': 'string'
                    'metadata': {
                        'description': 'A username in the domain that has privileges to join the session hosts to the domain. For example, \'vmjoiner@contoso.com\'.'
                    }
                    'defaultValue': domainUPN
                }
                'administratorDomainPassword': {
                    'type': 'securestring'
                    'metadata': {
                        'description': 'The password that corresponds to the existing domain username.'
                    }
                }
                'vmAdministratorAccountUsername': {
                    'type': 'string'
                    'metadata': {
                        'description': 'A username to be used as the virtual machine administrator account. The vmAdministratorAccountUsername and  vmAdministratorAccountPassword parameters must both be provided. Otherwise, domain administrator credentials provided by administratorDomainUsername and administratorDomainPassword will be used.'
                    }
                    'defaultValue': 'adminuser'
                }
                'vmAdministratorAccountPassword': {
                    'type': 'securestring'
                    'metadata': {
                        'description': 'The password associated with the virtual machine administrator account. The vmAdministratorAccountUsername and  vmAdministratorAccountPassword parameters must both be provided. Otherwise, domain administrator credentials provided by administratorDomainUsername and administratorDomainPassword will be used.'
                    }
                }
                'vmResourceGroup': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The resource group of the session host VMs.'
                    }
                    'defaultValue': avdRgName
                }
                'vmLocation': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The location of the session host VMs.'
                    }
                    'defaultValue': location
                }
                'vmSize': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The size of the session host VMs.'
                    }
                    'defaultValue': 'Standard_D4s_v3'
                }
                'vmInitialNumber': {
                    'type': 'int'
                    'metadata': {
                        'description': 'VM name prefix initial number.'
                    }
                    'defaultValue': 0
                }
                'vmNumberOfInstances': {
                    'type': 'int'
                    'metadata': {
                        'description': 'Number of session hosts that will be created and added to the hostpool.'
                    }
                    'defaultValue': 1
                }
                'vmNamePrefix': {
                    'type': 'string'
                    'metadata': {
                        'description': 'This prefix will be used in combination with the VM number to create the VM name. If using \'rdsh\' as the prefix, VMs would be named \'rdsh-0\', \'rdsh-1\', etc. You should use a unique prefix to reduce name collisions in Active Directory.'
                    }
                    'defaultValue': vmNamePrefix
                }
                'vnetResourceGroupName': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The resource group containing the existing virtual network.'
                    }
                    'defaultValue': avdRgName
                }
                'existingVnetName': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The name of the virtual network the VMs will be connected to.'
                    }
                    'defaultValue': avdVnetName
                }
                'existingSubnetName': {
                    'type': 'string'
                    'metadata': {
                        'description': 'The subnet the VMs will be placed in.'
                    }
                    'defaultValue': avdSubnetName
                }
                'wvdApiVersion': {
                    'type': 'string'
                    'metadata': {
                        'description': 'WVD api version'
                    }
                    'defaultValue': '2019-12-10-preview'
                }
                'utcValue': {
                    'type': 'string'
                    'defaultValue': '[utcNow(\'u\')]'
                }
            }
            'variables': {
                'utcTime': '[dateTimeAdd(parameters(\'utcValue\'), \'PT2H\')]'
                'artifactsLocation': 'https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_09-08-2022.zip'
                'hostpoolProperties': {
                    'registrationInfo': {
                        'expirationTime': '[variables(\'utcTime\')]'
                        'registrationTokenOperation': 'Update'
                    }
                }
                'availabilityOption': 'None'
                'availabilitySetName': ''
                'createAvailabilitySet': false
                'availabilitySetUpdateDomainCount': 5
                'availabilitySetFaultDomainCount': 2
                'availabilityZones': []
                'vmDiskSizeGB': 0
                'vmHibernate': false
                'vmGalleryImageOffer': ''
                'vmGalleryImagePublisher': ''
                'vmGalleryImageSKU': ''
                'vmGalleryImageVersion': ''
                'vmGalleryImageHasPlan': false
                'vmCustomImageSourceId': avdImageRefId
                'vmDiskType': 'Premium_LRS'
                'createNetworkSecurityGroup': false
                'networkSecurityGroupId': ''
                'networkSecurityGroupRules': []
                'deploymentId': ''
                'ouPath': avdAaddsOUPath
                'domain': avdAaddsDomainName
                'aadJoin': false
                'intune': false
                'bootDiagnostics': {
                    'enabled': true
                }
                'userAssignedIdentity': ''
                'customConfigurationTemplateUrl': ''
                'customConfigurationParameterUrl': ''
                'systemData': {
                    'hostpoolUpdateFeature': false
                    'aadJoinPreview': false
                    'sessionHostConfigurationVersion': ''
                }
                'securityType': 'Standard'
                'secureBoot': false
                'vTPM': false
                'rdshPrefix': '[concat(parameters(\'vmNamePrefix\'),\'-\')]'
                'vhds': '[concat(\'vhds\',\'/\', variables(\'rdshPrefix\'))]'
                'subnet-id': '[resourceId(parameters(\'vnetResourceGroupName\'),\'Microsoft.Network/virtualNetworks/subnets\',parameters(\'existingVnetName\'), parameters(\'existingSubnetName\'))]'
                'vmTemplateRG': '[parameters(\'hostpoolResourceGroup\')]'
                'vmTemplateName': '[parameters(\'vmTemplateName\')]'
                'vmTemplateVersion': '[parameters(\'vmTemplateVersion\')]'
                'rdshVmNamesOutput': {
                    'copy': [
                        {
                            'name': 'rdshVmNamesCopy'
                            'count': '[parameters(\'vmNumberOfInstances\')]'
                            'input': {
                                'name': '[concat(variables(\'rdshPrefix\'), add(parameters(\'vmInitialNumber\'), copyIndex(\'rdshVmNamesCopy\')))]'
                            }
                        }
                    ]
                }
            }
            'resources': [
                {
                    'apiVersion': '2018-05-01'
                    'name': '[concat(\'UpdateHostPool-\', variables(\'deploymentId\'))]'
                    'type': 'Microsoft.Resources/deployments'
                    'resourceGroup': '[parameters(\'hostpoolResourceGroup\')]'
                    'condition': '[not(empty(parameters(\'hostpoolResourceGroup\')))]'
                    'properties': {
                        'mode': 'Incremental'
                        'template': {
                            '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                            'contentVersion': '1.0.0.0'
                            'resources': [
                                {
                                    'name': '[parameters(\'hostpoolName\')]'
                                    'apiVersion': '[parameters(\'wvdApiVersion\')]'
                                    'location': '[parameters(\'hostpoolLocation\')]'
                                    'type': 'Microsoft.DesktopVirtualization/hostpools'
                                    'properties': '[variables(\'hostpoolProperties\')]'
                                }
                            ]
                        }
                    }
                }
                {
                    'apiVersion': '2018-05-01'
                    'name': '[concat(\'AVSet-linkedTemplate-\', variables(\'deploymentId\'))]'
                    'type': 'Microsoft.Resources/deployments'
                    'resourceGroup': '[parameters(\'vmResourceGroup\')]'
                    'condition': '[and(equals(variables(\'availabilityOption\'), \'AvailabilitySet\'), variables(\'createAvailabilitySet\'))]'
                    'properties': {
                        'mode': 'Incremental'
                        'template': {
                            '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                            'contentVersion': '1.0.0.0'
                            'resources': [
                                {
                                    'apiVersion': '2018-10-01'
                                    'type': 'Microsoft.Compute/availabilitySets'
                                    'name': '[variables(\'availabilitySetName\')]'
                                    'location': '[parameters(\'vmLocation\')]'
                                    'properties': {
                                        'platformUpdateDomainCount': '[variables(\'availabilitySetUpdateDomainCount\')]'
                                        'platformFaultDomainCount': '[variables(\'availabilitySetFaultDomainCount\')]'
                                    }
                                    'sku': {
                                        'name': 'Aligned'
                                    }
                                }
                            ]
                        }
                    }
                    'dependsOn': [
                        '[concat(\'UpdateHostPool-\', variables(\'deploymentId\'))]'
                    ]
                }
                {
                    'apiVersion': '2020-06-01'
                    'name': '[concat(\'vmCreation-linkedTemplate-\', variables(\'deploymentId\'))]'
                    'resourceGroup': '[parameters(\'vmResourceGroup\')]'
                    'dependsOn': [
                        '[concat(\'AVSet-linkedTemplate-\', variables(\'deploymentId\'))]'
                    ]
                    'type': 'Microsoft.Resources/deployments'
                    'properties': {
                        'mode': 'Incremental'
                        'templateLink': {
                            'id': '[resourceId(variables(\'vmTemplateRG\'), \'Microsoft.Resources/templateSpecs/versions\', variables(\'vmTemplateName\'), variables(\'vmTemplateVersion\'))]'
                        }
                        'parameters': {
                            'artifactsLocation': {
                                'value': '[variables(\'artifactsLocation\')]'
                            }
                            'availabilityOption': {
                                'value': '[variables(\'availabilityOption\')]'
                            }
                            'availabilitySetName': {
                                'value': '[variables(\'availabilitySetName\')]'
                            }
                            'availabilityZones': {
                                'value': '[variables(\'availabilityZones\')]'
                            }
                            'vmGalleryImageOffer': {
                                'value': '[variables(\'vmGalleryImageOffer\')]'
                            }
                            'vmGalleryImagePublisher': {
                                'value': '[variables(\'vmGalleryImagePublisher\')]'
                            }
                            'vmGalleryImageHasPlan': {
                                'value': '[variables(\'vmGalleryImageHasPlan\')]'
                            }
                            'vmGalleryImageSKU': {
                                'value': '[variables(\'vmGalleryImageSKU\')]'
                            }
                            'vmGalleryImageVersion': {
                                'value': '[variables(\'vmGalleryImageVersion\')]'
                            }
                            'rdshPrefix': {
                                'value': '[variables(\'rdshPrefix\')]'
                            }
                            'rdshNumberOfInstances': {
                                'value': '[parameters(\'vmNumberOfInstances\')]'
                            }
                            'rdshVMDiskType': {
                                'value': '[variables(\'vmDiskType\')]'
                            }
                            'rdshVmSize': {
                                'value': '[parameters(\'vmSize\')]'
                            }
                            'rdshVmDiskSizeGB': {
                                'value': '[variables(\'vmDiskSizeGB\')]'
                            }
                            'rdshHibernate': {
                                'value': '[variables(\'vmHibernate\')]'
                            }
                            'enableAcceleratedNetworking': {
                                'value': false
                            }
                            'vmAdministratorAccountUsername': {
                                'value': '[parameters(\'vmAdministratorAccountUsername\')]'
                            }
                            'vmAdministratorAccountPassword': {
                                'value': '[parameters(\'vmAdministratorAccountPassword\')]'
                            }
                            'administratorAccountUsername': {
                                'value': '[parameters(\'administratorDomainUsername\')]'
                            }
                            'administratorAccountPassword': {
                                'value': '[parameters(\'administratorDomainPassword\')]'
                            }
                            'subnet-id': {
                                'value': '[variables(\'subnet-id\')]'
                            }
                            'vhds': {
                                'value': '[variables(\'vhds\')]'
                            }
                            'rdshImageSourceId': {
                                'value': '[variables(\'vmCustomImageSourceId\')]'
                            }
                            'location': {
                                'value': '[parameters(\'vmLocation\')]'
                            }
                            'createNetworkSecurityGroup': {
                                'value': '[variables(\'createNetworkSecurityGroup\')]'
                            }
                            'networkSecurityGroupId': {
                                'value': '[variables(\'networkSecurityGroupId\')]'
                            }
                            'networkSecurityGroupRules': {
                                'value': '[variables(\'networkSecurityGroupRules\')]'
                            }
                            'vmInitialNumber': {
                                'value': '[parameters(\'vmInitialNumber\')]'
                            }
                            'hostpoolResourceGroup': {
                                'value': '[parameters(\'hostpoolResourceGroup\')]'
                            }
                            'hostpoolName': {
                                'value': '[parameters(\'hostpoolName\')]'
                            }
                            'domain': {
                                'value': '[variables(\'domain\')]'
                            }
                            'ouPath': {
                                'value': '[variables(\'ouPath\')]'
                            }
                            'aadJoin': {
                                'value': '[variables(\'aadJoin\')]'
                            }
                            'intune': {
                                'value': '[variables(\'intune\')]'
                            }
                            'bootDiagnostics': {
                                'value': '[variables(\'bootDiagnostics\')]'
                            }
                            '_guidValue': {
                                'value': '[variables(\'deploymentId\')]'
                            }
                            'userAssignedIdentity': {
                                'value': '[variables(\'userAssignedIdentity\')]'
                            }
                            'customConfigurationTemplateUrl': {
                                'value': '[variables(\'customConfigurationTemplateUrl\')]'
                            }
                            'customConfigurationParameterUrl': {
                                'value': '[variables(\'customConfigurationParameterUrl\')]'
                            }
                            'SessionHostConfigurationVersion': {
                                'value': '[if(contains(variables(\'systemData\'), \'hostpoolUpdate\'), variables(\'systemData\').sessionHostConfigurationVersion, \'\')]'
                            }
                            'systemData': {
                                'value': '[variables(\'systemData\')]'
                            }
                            'securityType': {
                                'value': '[variables(\'securityType\')]'
                            }
                            'secureBoot': {
                                'value': '[variables(\'secureBoot\')]'
                            }
                            'vTPM': {
                                'value': '[variables(\'vTPM\')]'
                            }
                            'wvdApiVersion': {
                                'value': '[parameters(\'wvdApiVersion\')]'
                            }
                        }
                    }
                }
            ]
            'outputs': {
                'rdshVmNamesObject': {
                    'value': '[variables(\'rdshVmNamesOutput\')]'
                    'type': 'object'
                }
            }
        }
    }
}

