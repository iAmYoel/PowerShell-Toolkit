$tenantname = "[My Awesome WVD Tenant]"
$tenantid = "[AAD Directory ID]"
$subscriptionid = "[My Azure Subscription ID]"

Install-Module -Name AzureAD
Install-Module -Name Microsoft.RDInfra.RDPowerShell

# Manually consent to Server App in https://rdweb.wvd.microsoft.com/

    ### Create Windows Virtual Desktop Tenant
# Login using a TenantCreator
Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com"

# Create AVD Tenant
New-RdsTenant -Name $tenantname -AadTenantId $tenantid -AzureSubscriptionId $subscriptionid


    ###  Provision a Windows Virtual Desktop Host Pool
# Create a service principal in Azure Active Directory
$aadContext = Connect-AzureAD # Need to be Global Administrator
$svcPrincipal = New-AzureADApplication -AvailableToOtherTenants $true -DisplayName "Windows Virtual Desktop Svc Principal"
$svcPrincipalCreds = New-AzureADApplicationPasswordCredential -ObjectId $svcPrincipal.ObjectId

# Sign in with the service principal
$creds = New-Object System.Management.Automation.PSCredential($svcPrincipal.AppId, (ConvertTo-SecureString $svcPrincipalCreds.Value -AsPlainText -Force))
Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com" -Credential $creds -ServicePrincipal -AadTenantId $aadContext.TenantId.Guid

# Create host pool
$hostpoolname = "hostpool-1"
New-RdsHostPool -TenantName $tenantname -Name $hostpoolname

    ### Add session hosts to the host pool
# Deploy an VM image from https://docs.microsoft.com/en-us/azure/virtual-desktop/overview#supported-virtual-machine-os-images

# Create a registration token to be used to register VMs to WVD
$RegFile = "c:\temp\RegistrationFile.txt"
New-RdsRegistrationInfo -TenantName $tenantname -HostPoolName $hostpoolname -ExpirationHours 24 | Select-Object -ExpandProperty Token | Out-File -FilePath $RegFile

# Download and install Virtual Desktop Agent on VM to be registered to host pool from https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv
# Use token from registration file

# Download the Windows Virtual Desktop Agent Bootloader and install that on the VMs from https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH
# Reboot VMs after installation

# Get a list of app groups in session host pool
Get-RdsAppGroup -TenantName $tenantname -HostPoolName $hostpoolname

# Set name of application group and add use to group
$AppGroupName = "Desktop Application Group"
Add-RdsAppGroupUser -TenantName $tenantname -HostPoolName $hostpoolname -UserPrincipalName "firstname.lastname@contoso.com" -AppGroupName $AppGroupName