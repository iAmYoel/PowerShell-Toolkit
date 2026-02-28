# Standard variables
$stdLocation            = "WestEurope"
$azSubscriptionId       = "ee19e81a-df2a-4660-a66b-9fe0cd423c01"

# Resource Group
$rgName                 = "RG-Yoel-Abraham"
$rgLocation             = $stdLocation

# Subnet in Virtual Network
$subnetName             = "avd-subnet"
$subnetAddrPref         = "10.0.0.0/24"

# Virtual Network
$vnetName               = "vnet-avd"
$vnetRgName             = $rgName
$vnetLocation           = $stdLocation
$vnetAddrPref           = "10.0.0.0/16"

# WvdHostPool
$avdPoolName            = "Test-WVD-Pool"
$avdFriendlyName        = "Test Pool Friendly Name"
$avdWorkSpaceName       = "Test-Workspace-Name"
$avdPoolType            = "Pooled"                      # <Pooled|Personal>
$avdLoadBalancerType    = "BreadthFirst"                # <BreadthFirst|DepthFirst|Persistent>
$avdLocation            = $stdLocation
$avdAppGroupName        = "Test-AppGroup-Name"
$avdAppGroupType        = "Desktop"                     # <Desktop>|<Application>

# Registration token
$regInfoRGName  = $rgName
$regInfoExpTime = $((Get-Date).ToUniversalTime().AddHours(4).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))

# VM
[int32]$vmCount             = 1
$vmNamePrefix               = "AVD-SH"
$vmSize                     = "Standard_B2ms"
$vmLocation                 = $stdLocation
$vmVNet                     = $vnetName
$vmSubnetName               = $subnetName
$vmLocalAdminUsername       = "LocalAdminUser"
$vmLocalAdminSecurePassword = ConvertTo-SecureString "Hallon20!" -AsPlainText -Force





##########################################################################################################################################################





Install-Module -Name Az.DesktopVirtualization -Verbose -Force
Install-Module -Name Az.Network -Verbose -Force
Install-Module -Name Az.Resources -Verbose -Force
Install-Module -Name Az.Compute -Verbose -Force
Connect-AzAccount

Set-AzContext -Subscription $azSubscriptionId -Force


# 1. Create a resource group
$rgParam = @{
    Name        = $rgName
    Location    = $rgLocation
}
New-AzResourceGroup @rgParam




# 2.1 Create Subnet config for vnet
$subnetParam = @{
    Name            = $subnetName
    AddressPrefix   = $subnetAddrPref
}
$subnetConfig = New-AzVirtualNetworkSubnetConfig @subnetParam




# 2.2 Create a virtual network with subnet config
$vnetParam = @{
    Name                = $vnetName
    ResourceGroupName   = $vnetRgName
    Location            = $vnetLocation
    AddressPrefix       = $vnetAddrPref
    Subnet              = $subnetConfig
}
$AzVNet = New-AzVirtualNetwork @vnetParam





# 3.1 Create a WVD host pool

# Register subscription with Microsoft.DesktopVirtualization service
Register-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization

$avdHostPoolParam = @{
    Name                    = $avdPoolName
    #FriendlyName            = $avdFriendlyName
    ResourceGroupName       = $rgName
    WorkspaceName           = $avdWorkSpaceName
    HostPoolType            = $avdPoolType
    LoadBalancerType        = $avdLoadBalancerType
    Location                = $avdLocation
    DesktopAppGroupName     = $avdAppGroupName
    PreferredAppGroupType   = $avdAppGroupType
}

New-AzWvdHostPool @avdHostPoolParam
New-AzWvdHostPool   -Name $avdPoolName `
                    -FriendlyName $avdFriendlyName `
                    -ResourceGroupName $rgName `
                    -WorkspaceName $avdWorkSpaceName `
                    -HostPoolType $avdPoolType `
                    -LoadBalancerType $avdLoadBalancerType `
                    -Location $avdLocation `
                    -DesktopAppGroupName $avdAppGroupName `
                    -PreferredAppGroupType $avdAppGroupType


# 3.2 Create registration token
$regInfoParam = @{
    ResourceGroupName   = $regInfoRGName
    HostPoolName        = $avdPoolName
    ExpirationTime      = $regInfoExpTime
}
$regToken = New-AzWvdRegistrationInfo @regInfoParam




# 4. Create VM from Azure Image Gallery
$i = 0
do{
    $i++
    $vmName = $($vmNamePrefix + ("{0:d2}" -f $i))
    $vmNICName = $vmName + "-nic01"

    $vmNIC = New-AzNetworkInterface -Name $vmNICName -ResourceGroupName $rgName -Location $vmLocation -SubnetId $AzVNet.Subnets[0].Id

    $vmCredential = New-Object System.Management.Automation.PSCredential ($vmLocalAdminUsername, $vmLocalAdminSecurePassword)

    $VirtualMachine = New-AzVMConfig -VMName $vmName -VMSize $vmSize
    $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmName -Credential $vmCredential -ProvisionVMAgent -EnableAutoUpdate
    $VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $vmNIC.Id
    $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'Windows-11' -Skus 'win11-21h2-avd' -Version latest

    $vmParam = @{
        VM                  = $VirtualMachine
        ResourceGroupName   = $rgName
        Location            = $vmLocation
    }

    New-AzVm @vmParam

}until($i = $vmCount)

# 5. Assign users to the Windows Virtual Desktop Applications group
New-AzRoleAssignment -ObjectId <usergroupobjectid> -RoleDefinitionName "Desktop Virtualization User" -ResourceName <hostpoolname+"-DAG"> -ResourceGroupName <resourcegroupname> -ResourceType 'Microsoft.DesktopVirtualization/applicationGroups'

# 6. Setup the Windows Virtual Desktop Workspace
# 7.




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