<#
.SYNOPSIS
Setup a NDES server and configure Certificate Authority for Intune SCEP Integration.

.DESCRIPTION
Configures a NDES server and a Certificate Authority (using a seperate script) to be prepared for use with Intune SCEP.

Steps
1. Make sure that NDES Service Account has the necessary permissions on the NDES server.
2. Send separate script 'Create-NdesCertificateTemplate.ps1' to CA server to be run for CA Template creation and necessary permission delegations.
3. Install and configure NDES roles on the NDES server.
4. Configure IIS.
5. Download and install Entra App Proxy Connector.
6. Create new Entra Proxy App in Entra ID.
7. Requests a new certificate for the NDES server from the CA with the newly created CA Server Template.
8. Setting SPN.
9. Configure IIS HTTPS Binding with newly issued certificate.
10. Download and configure Intune Certificate Connector.

.PARAMETER ServiceAccountCredentials
Credentials for the Service Account used for NDES services

.PARAMETER optionalClientTemplateName
Optional custom name for the client CA Template. Default is 'ScepNdesClient'.

.PARAMETER optionalServerTemplateName
Optional custom name for the server CA Template. Default is 'ScepNdesServer'.

.EXAMPLE
.\Setup-SCEPServer.ps1
Runs script with default CA template names and prompts user for NDES service account credentials.

.EXAMPLE
.\Setup-SCEPServer.ps1 -ServiceAccountCredentials $cred -optionalClientTemplateName 'clientNDES' -optionalServerTemplateName 'serverNDES'
Run script with pre-defined PSCredential object and custom CA certificate template names.

.NOTES
Alternative to test https://www.powershellgallery.com/packages/Install-NdesServer/1.6/Content/Install-NdesServer.ps1

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [PSCredential]
    $ServiceAccountCredentials = (Get-Credential -Message "Please provide NDES Service Account credentials (SamAccountName without NETBIOS\)"),

    [Parameter(Mandatory=$false)]
    [String]
    $optionalClientTemplateName = "ScepNdesClient",

    [Parameter(Mandatory=$false)]
    [String]
    $optionalServerTemplateName = "ScepNdesServer"
)

##*===============================================
##* Functions
##*===============================================
#region Functions
function Install-ScriptModules{
    param(
        [parameter(Mandatory=$true)]
        [string[]]$Modules = @()
    )

    foreach ($Module in $Modules) {
        Write-Host $Module -ForegroundColor Yellow -BackgroundColor Black
        Clear-Variable CurrentModule -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Stop"
        try{
            Import-Module -Name $Module -Force -ErrorAction SilentlyContinue
            $CurrentModule = Get-Module -Name $Module -ErrorAction SilentlyContinue
            IF(!$CurrentModule){
                try{
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
                    try {
                        # Install current missing module
                        Install-Module -Name $Module -Force -Confirm:$false

                        # Import installed module
                        Import-Module -Name $Module -Force -ErrorAction SilentlyContinue
                        # Get imported module
                        $CurrentModule = Get-Module -Name $Module -ErrorAction SilentlyContinue
                        IF(!$CurrentModule){
                            # Log module install failed
                            Write-Host "Failed to get module after installation." -F Yellow -B Black
                            $moduleInstallFailed = $Module
                            Continue
                        }
                    }catch [System.Exception] {
                        Write-Host "Failed to install module." -F Yellow -B Black
                        $moduleInstallFailed = $Module
                        Continue
                    }
                }catch [System.Exception] {
                    Write-Host "Failed to install NuGet Package Provider." -F Yellow -B Black
                    $moduleInstallFailed = $Module
                    Continue
                }
            }ELSE{
                # Log module import success
            }
        }catch{
            $moduleInstallFailed = $true
            Continue
        }
        $ErrorActionPreference = "Continue"
    }

    if ($moduleInstallFailed) {
        Write-Warning "Following modules failed to load: '$($moduleInstallFailed -join ", ")'"
        Break
    }

}

function Assign-LocalPrivilegeRights {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SamAccountName,

        [Parameter(Mandatory=$true)]
        [string[]]
        $Rights = @()
    )
    foreach ($setting in $Rights) {
        Write-Host "Grant $setting permission for $SamAccountName"
        $ErrorActionPreference = "Stop"
        try {
            $tmp = New-TemporaryFile
            secedit /export /cfg "$tmp.inf" | Out-Null
            if ($LASTEXITCODE -eq 0) {
                try {
                    (Get-Content -Encoding ASCII "$tmp.inf") -replace "^$Setting .+", "`$0,$SamAccountName" | Set-Content -Encoding ASCII "$tmp.inf"
                    secedit /import /cfg "$tmp.inf" /db "$tmp.sdb" | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        secedit /configure /db "$tmp.sdb" /cfg "$tmp.inf" | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Remove-Item $tmp* -Force -ErrorAction SilentlyContinue
                        } else {
                            Write-Host "Failed to configure SECEDIT settings." -F Red -B Black
                            Pause
                        }
                    } else {
                        Write-Host "Failed to import edited SECEDIT settings." -F Red -B Black
                        Pause
                    }
                }
                catch {
                    Write-Host "Failed to edit exported SECEDIT settings. Error message: $($_.Exception)" -F Red -B Black
                    Pause
                }
            } else {
                Throw "Failed to export SECEDIT settings."
                Pause
            }
        } catch {
            Write-Host "Failed to create new temporary file. Error message: $($_.Exception)" -F Red -B Black
            Pause
        }
        $ErrorActionPreference = "Continue"
    }
}

function Test-ADAuth {
    param(
            [parameter(Mandatory=$true)]
            [PSCredential]$Credentials
        )

     # Get current domain using logged-on user's credentials
     try {
        $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $Credentials.username, $Credentials.GetNetworkCredential().password) -ErrorAction Stop
     }
     catch {
        Write-Host "Failed to test NDES Service Account authentication. Error message: $($_.Exception)" -F Red -B Black
        Pause
     }

    if ($domain.name -eq $null) {
        return $false
    } else {
        return $true
    }
}

Function Grant-CATemplatePermission {
    [CmdletBinding()]
    Param (
        [Parameter()] $TemplateName,

        [Parameter()] $NTAccountName,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Read","Write","Enroll","AutoEnroll")]
        [string[]]$Permissions = @()
    )

    # Get the Naming Context for the "Configuration" Directory Partition
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    # Set the name for the partition template
    $TemplatePartition = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

    $DirectorySearcherObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$TemplatePartition", "CN=$TemplateName")

    try {
        $SearchResult = $DirectorySearcherObject.FindOne()
    }
    catch {
        Write-Host "Error accessing Template Name: $TemplateName"
        Return
    }

    # Make sure the template exists
    if ($null -ne $SearchResult) {
        $Template = $SearchResult.GetDirectoryEntry()
        $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"
        $ACL = [Ordered]@{}
        foreach ($perm in $Permissions) {
            switch ($perm) {
                "Read"          { $ACL.ReadWrite = @{"Guid" = (New-Object Guid 00000000-0000-0000-0000-000000000000) ; "Rights" = $ACL.ReadWrite.Rights + [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty, GenericExecute"} }
                "Write"         { $ACL.ReadWrite = @{"Guid" = (New-Object Guid 00000000-0000-0000-0000-000000000000) ; "Rights" = $ACL.ReadWrite.Rights + [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty, WriteDacl, WriteOwner"} }
                "Enroll"        { $ACL.$perm = [Ordered]@{"Guid"=(New-Object Guid 0e10c968-78fb-11d2-90d4-00c04f79dc55); "Rights" = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"} }
                "AutoEnroll"    { $ACL.$perm = [Ordered]@{"Guid"=(New-Object Guid a05b8cc2-17bc-4802-a710-e7c15ab866a2); "Rights" = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"} }
            }
        }

        try {
            # Split the NTAccountName to NetBIOS domain name and name
            $Name = $NTAccountName.SubString($NTAccountName.IndexOf("\") + 1)
            $NTObject = Get-ADObject -Filter "SAMAccountName -eq '$Name'" -Server $env:UserDomain
        }
        catch {
            Write-Host "Error parsing user name: $NTAccountName"
            Return
        }

        # Make sure the user exists
        if ($null -ne $NTObject) {
            $objUser = New-Object System.Security.Principal.NTAccount($NTAccountName)

            # Instruct PowerShell to only touch the DACL, otherwise, it may return
            # Exception calling "CommitChanges" with "0" argument(s): "A constraint violation occurred.
            $Template.get_Options().SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'

            foreach ($key in $ACL.Keys) {
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $objUser, $ACL[$key].Rights, $ACEType, $ACL[$key].Guid
                $Template.ObjectSecurity.AddAccessRule($ACE)
            }

            try {
                $Template.commitchanges()
            }
            catch {
                Write-Output "Error granting Enroll permission for $NTAccountName to $TemplateName"
            }
        } else {
            Write-Output "User $NTAccountName not found"
        }
    } else {
        Write-Output "Template $TemplateName not found"
    }
}

Function Grant-CertificateAuthorityPermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidatePattern('S-\d-(?:\d+-){1,14}\d+')]
        [String]$AccountSID
    )

    $CAServerName = (Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).PSChildName

    if ($CAServerName) {
        # Get binary security descriptor of the CA from the registry
        $sd_bin = Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CAServerName" -Name 'Security'

        # Create security descriptor object of it
        $sd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList @($false, $false, $sd_bin, 0)

        # Modify the DACL in place
        $sd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $AccountSID, 514, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None)

        # Convert the security descriptor back to binary form
        $sd_bin_new = [System.Byte[]]::CreateInstance([System.Byte], $sd.BinaryLength)
        $sd.GetBinaryForm($sd_bin_new, 0)

        # Write it back to the registry
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CAServerName" -Name 'Security' -Value $sd_bin_new

        do {
            $answer = Read-Host "Certificate Authority service need to be restarted do you want to do it now? [Y/N]"
        } until ($answer -like "y" -or $answer -like "n")

        if ($answer -like "y") {
            # Restart the certificate services
            Restart-Service -Name CertSvc -Force -Verbose
        } else {
            Write-Warning "It's IMPORTANT to restart the certificate service for the new permissions to take effect. Make sure to not forget to restart!"
            Pause
        }
    } else {
        Write-Warning "Could not find CA server. CA Server permissions were not applied!"
        Pause
    }
}

#endregion
##*===============================================
##* END Functions
##*===============================================

$domain = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain

if (!$domain) {
    Write-Warning "Domain membership was not found for this server"
    Pause
    Break
}

##*===============================================
##* Variables
##*===============================================
#region Variables

$serverTemplate = @"
dn: CN=$serverTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($domain.replace(".",",DC="))
changetype: add
cn: $serverTemplateName
displayName: $serverTemplateName
distinguishedName:
 CN=$serverTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,
 CN=Configuration,DC=$($domain.replace(".",",DC="))
dSCorePropagationData: 20240109133351.0Z
dSCorePropagationData: 16010101000000.0Z
flags: 131649
instanceType: 4
msPKI-Cert-Template-OID:
 1.3.6.1.4.1.311.21.8.13659861.4359492.12666508.6021008.275005.186.13356789.814
 6407
msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.1
msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2
msPKI-Certificate-Name-Flag: 1
msPKI-Enrollment-Flag: 0
msPKI-Minimal-Key-Size: 2048
msPKI-Private-Key-Flag: 16842752
msPKI-RA-Signature: 0
msPKI-Template-Minor-Revision: 4
msPKI-Template-Schema-Version: 2
name: $serverTemplateName
objectCategory:
 CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=$($domain.replace(".",",DC="))
objectClass: top
objectClass: pKICertificateTemplate
pKICriticalExtensions: 2.5.29.15
pKIDefaultCSPs: 2,Microsoft DH SChannel Cryptographic Provider
pKIDefaultCSPs: 1,Microsoft RSA SChannel Cryptographic Provider
pKIDefaultKeySpec: 1
pKIExpirationPeriod:: AIByDl3C/f8=
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
pKIKeyUsage:: oAA=
pKIMaxIssuingDepth: 0
pKIOverlapPeriod:: AICmCv/e//8=
revision: 100
showInAdvancedViewOnly: TRUE
uSNChanged: 12425053
uSNCreated: 12424965
whenChanged: 20240109133352.0Z
whenCreated: 20240109133309.0Z
"@

$clientTemplate = @"
dn: CN=$clientTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($domain.replace(".",",DC="))
changetype: add
cn: $clientTemplateName
displayName: $clientTemplateName
distinguishedName:
 CN=$clientTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN
 =Configuration,DC=$($domain.replace(".",",DC="))
dSCorePropagationData: 20240109133444.0Z
dSCorePropagationData: 20240109090400.0Z
dSCorePropagationData: 16010101000000.0Z
flags: 131642
instanceType: 4
msPKI-Cert-Template-OID:
 1.3.6.1.4.1.311.21.8.13659861.4359492.12666508.6021008.275005.186.10917207.981
 5827
msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2
msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.4
msPKI-Certificate-Application-Policy: 1.3.6.1.4.1.311.10.3.4
msPKI-Certificate-Name-Flag: 1
msPKI-Enrollment-Flag: 9
msPKI-Minimal-Key-Size: 2048
msPKI-Private-Key-Flag: 16842752
msPKI-RA-Signature: 0
msPKI-Template-Minor-Revision: 6
msPKI-Template-Schema-Version: 2
name: $clientTemplateName
objectCategory:
 CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=$($domain.replace(".",",DC="))
objectClass: top
objectClass: pKICertificateTemplate
pKICriticalExtensions: 2.5.29.7
pKICriticalExtensions: 2.5.29.15
pKIDefaultCSPs: 1,Microsoft Enhanced Cryptographic Provider v1.0
pKIDefaultKeySpec: 1
pKIExpirationPeriod:: AIByDl3C/f8=
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.4
pKIExtendedKeyUsage: 1.3.6.1.4.1.311.10.3.4
pKIKeyUsage:: oAA=
pKIMaxIssuingDepth: 0
pKIOverlapPeriod:: AABNFf69//8=
revision: 100
showInAdvancedViewOnly: TRUE
uSNChanged: 12440845
uSNCreated: 12386272
whenChanged: 20240109150805.0Z
whenCreated: 20240109090400.0Z
"@

#endregion
##*===============================================
##* END Variables
##*===============================================

$currentGroupMembership = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object -Process { Write-Output $_.Translate([System.Security.Principal.NTAccount]) }).Value
if ($currentGroupMembership -notcontains "$env:USERDOMAIN\Domain Admins") {
    Write-Warning "The account running this script does not have domain admins permission. This will negatively impact the script may not work as intended."
    Pause

}
if ($currentGroupMembership -notcontains "$env:USERDOMAIN\Enterprise Admins") {
    $notEnterpriseAdmin = $true
    Write-Warning "The account running this script is not an Enterprise Admin. This will be needed later in this script. You will then be asked to provide an Enterprise Admin account."
    Pause
}

# Automatically Self-elevate the script if required - http://www.expta.com/2017/03/how-to-self-elevate-powershell-script.html
###################################################################################################################
    # Auto Elevation
    IF (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        IF ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
            $CommandLine = "-ExecutionPolicy Bypass " + "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
            Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
            Exit
        }
    }

###################################################################################################################

# Install necessary modules
Write-Host "`t Step 1/18 - Installing following modules..." -F Yellow
Install-ScriptModules -Modules ActiveDirectory,PSPKI
Install-ScriptModules -Modules AzureAD
#Install-ScriptModules -Modules Microsoft.Graph.Applications, Microsoft.Graph.Beta.Applications, Microsoft.Graph.Identity.DirectoryManagement


# Get Certification Authority
Write-Host "`t Step 2/18 - Discovering Domain controller and Certificate Authorities in domain..." -F Yellow
$adServer = ($env:LOGONSERVER -replace "\\")
try {
    $caServers = (Get-CertificationAuthority -ErrorAction Stop | where {($_.IsAccessible) -AND ($_.ServiceStatus -like "Running")})
}
catch {
    Write-Host "Failed to discover Certificate Authorities in domain. Error message: $($_.Exception)" -F Red -B Black
    Pause
    Break
}

if ($caServers.Count -ge 2) {
    $caServer = $caServers | Select -ExcludeProperty Certificate | Out-GridView -Title "Choose CA Server" -OutputMode Single
} elseif (!$caServers) {
    Write-Warning "No CA servers discovered"
    Pause
    Break
} else {
    $caServer = $caServers
}


# Testing powershell connectivity to DC and CA
Write-Host "`t Step 2/18 - Testing remote Powershell connectivity to Domain controller and Certificate Authority..." -F Yellow
if (!(Test-WSMan $adServer)) {
    Write-Host "$adServer could not be contacted." -F Red -B Black
    Write-Warning "BREAKING SCRIPT!"
    Pause
    Break
}

if (!(Test-WSMan $caServer.ComputerName)) {
    Write-Host "$($caServer.ComputerName) could not be contacted." -F Red -B Black
    Write-Warning "BREAKING SCRIPT!"
    Pause
    Break
}


# Test user
Write-Host "`t Step 3/18 - Authenticating NDES Service Account..."
 if ($serviceAccount = Get-ADUser $ServiceAccountCredentials.UserName) {
    if (Test-ADAuth -Credentials $ServiceAccountCredentials) {
        Write-Host "NDES Service Account was successfully authenticated!" -F Green -B
    } else {
        Write-Host "NDES Service Account password is incorrect" -F Red -B Black
        Pause
        Break
    }
} else {
    Write-Host "NDES Service Account was not found" -F Red -B Black
    Pause
    Break
}


# Disable IE Enhanced Security
Write-Host "`t Step 4/18 - Disabling IE Enhanced Security..." -F Yellow
try {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -ErrorAction Stop
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -ErrorAction Stop
    Stop-Process -Name Explorer -ErrorAction Stop
}
catch {
    Write-Host "Failed to disable IE Enhanced Security. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please disable it manually and contiune."
    Pause
}

Start-Sleep -Seconds 5


# Add service account to local IIS_IUSRS group
Write-Host "`t Step 5/18 - Adding NDES Service Account to local groups..." -F Yellow

$domainController = Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'"
try {
    if ($domainController) {
        Add-ADGroupMember -Identity IIS_IUSRS -Member $serviceAccount.SamAccountName -ErrorAction Stop
    } else {
        Add-LocalGroupMember -Group IIS_IUSRS -Member "$env:USERDOMAIN\$($serviceAccount.SamAccountName)" -ErrorAction Stop
    }
}
catch {
    Write-Host "Failed to add NDES Service Account to local IIS_USRS group. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually add NDES Service Account to the local IIS_USRS group and continue."
    Pause
}


# Grant service account logon as as service permission on the server
Write-Host "`t Step 6/18 - Granting NDES Service Account 'Log on as Service' permission..." -F Yellow
try {
    Assign-LocalPrivilegeRights -SamAccountName $serviceAccount.SamAccountName -Rights SeServiceLogonRight -ErrorAction Stop
}
catch {
    Write-Host "An error occurred while adding Service Logon Rights. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please grant NDES Service Account 'Log on as Service' permission on this server and continue."
    Pause
}


Write-Host "`t Step 6/18 - Granting the local group IIS_IUSRS 'Impersonate a client after authentication' permission..." -F Yellow

try {
    Assign-LocalPrivilegeRights -SamAccountName IIS_IUSRS -Rights SeImpersonatePrivilege -ErrorAction Stop
}
catch {
    Write-Host "An error occurred while adding Impersonate Privilege Rights. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please grant the local group IIS_IUSRS 'Impersonate a client after authentication' permission on this server and continue."
    Pause
}

# Most probably also requires Allow Log on Locally which is granted default.

# Import Certifcate templates to CA server
## invoke to ad server
Write-Host "`t Step 7/18 - Configuring Certificate Authority..." -F Yellow
Invoke-Command -ComputerName $adServer -ScriptBlock {
    @($Using:serverTemplate, $Using:clientTemplate) | foreach {
        try {
            $file = New-Item -Path $env:TMP -Name certificateTemplate.ldf -ItemType File -Value $_ -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to create temporary file for CA Template. Error message: $($_.Exception)"
            Pause
            Exit 1
        }

        ldifde -i -k -f $file.FullName

        try {
            $file | Remove-Item -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to remove temporary file for CA Template from '$($file.FullName)'. Error message: $($_.Exception)"
        }
    }
}



## invoke to ca serer
#Write-Host "Sending the script 'Create-NdesCertificateTemplates.ps1' to be run on $($caServer.ComputerName)..."
try {
    $certArgs = @($optionalServerTemplateName, "${env:computerName}$", "Read,Enroll,AutoEnroll")
    Invoke-Command -ComputerName $caServer.ComputerName -ScriptBlock ${function:Grant-CATemplatePermission} -ArgumentList $certArgs -ErrorAction Stop
    #Grant-CATemplatePermission -TemplateName $serverTemplateName -NTAccountName "$serverName$" -Permissions Read,Enroll,AutoEnroll

    $certArgs = @($optionalClientTemplateName, $ServiceAccountCredentials.UserName, "Read,Write,Enroll,AutoEnroll")
    Invoke-Command -ComputerName $caServer.ComputerName -ScriptBlock ${function:Grant-CATemplatePermission} -ArgumentList $certArgs -ErrorAction Stop
    #Grant-CATemplatePermission -TemplateName $clientTemplateName -NTAccountName $serviceAccount.SamAccountName -Permissions Read,Write,Enroll,AutoEnroll

    $certArgs = (New-Object System.Security.Principal.NTAccount($ServiceAccountCredentials.UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value
    Invoke-Command -ComputerName $caServer.ComputerName -ScriptBlock ${function:Grant-CertificateAuthorityPermission} -ArgumentList $certArgs -ErrorAction Stop
    #Grant-CertificateAuthorityPermission -AccountSID $serviceAccount.SID.Value

    Invoke-Command -ComputerName $caServer.ComputerName -ScriptBlock {
        Add-CATemplate -Name $Using:optionalServerTemplateName -Confirm:$false
        Add-CATemplate -Name $Using:optionalClientTemplateName -Confirm:$false
    } -ErrorAction Stop
    #Add-CATemplate -Name $serverTemplateName -Confirm:$false
    #Add-CATemplate -Name $clientTemplateName -Confirm:$false
}
catch {
    Write-Host "Failed to invoke script to CA server $($caServer.Computername). Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please run the script 'Create-NdesCertificateTemplates.ps1' manually on $($caServer.ComputerName) and then continue this script. Make sure to use the following parameters when running the script:`n`nCreate-NdesCertificateTemplates.ps1 $certArgs"
    Pause
}


<#
## invoke to ca server
Write-Host "`t Step 7/18 - Configuring Certificate Authority..." -F Yellow
$certArgs = "-ServiceAccountUsername $($serviceAccount.SamAccountName) -serverTemplateName $optionalServerTemplateName -clientTemplateName $optionalClientTemplateName"
if (Test-WSMan $caServer.ComputerName) {
    Write-Host "Sending the script 'Create-NdesCertificateTemplates.ps1' to be run on $($caServer.ComputerName)..."
    try {
        Invoke-Command -ComputerName $caServer.ComputerName -FilePath $PSScriptRoot\Create-NdesCertificateTemplate.ps1 -ArgumentList $certArgs -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to invoke script to CA server $($caServer.Computername). Error message: $($_.Exception)" -F Red -B Black
        Write-Warning "Please run the script 'Create-NdesCertificateTemplates.ps1' manually on $($caServer.ComputerName) and then continue this script. Make sure to use the following parameters when running the script:`n`nCreate-NdesCertificateTemplates.ps1 $certArgs"
        Pause
    }
} else {
    Write-Host "$($caServer.ComputerName) could not be contacted." -F Red -B Black
    Write-Warning "Please run the script 'Create-NdesCertificateTemplates.ps1' manually on $($caServer.ComputerName) and then continue this script. Make sure to use the following parameters when running the script:`n`nCreate-NdesCertificateTemplates.ps1 $certArgs"
    Pause
}
 #>

# Create root ca cert. Needed for upload to clients and connect the SCEP profile to
#certutil -ca.cert C:\temp\root.cer

# Install NDES Roles
Write-Host "`t Step 8/18 - Installing NDES roles..." -F Yellow
$serverRoles = @("AD-Certificate",
                "ADCS-Device-Enrollment",
                "NET-Framework-45-Features",
                "NET-Framework-45-Core",
                "NET-WCF-Services45",
                "NET-WCF-TCP-PortSharing45",
                "Web-Server",
                "Web-WebServer",
                "Web-Common-Http",
                "Web-Default-Doc",
                "Web-Dir-Browsing",
                "Web-Http-Errors",
                "Web-Static-Content",
                "Web-Http-Redirect",
                "Web-Health",
                "Web-Http-Logging",
                "Web-Log-Libraries",
                "Web-Request-Monitor",
                "Web-Http-Tracing",
                "Web-Performance",
                "Web-Stat-Compression",
                "Web-Security",
                "Web-Filtering",
                "Web-Windows-Auth",
                "Web-App-Dev",
                "Web-Net-Ext",
                "Web-Net-Ext45",
                "Web-Asp-Net",
                "Web-Asp-Net45",
                "Web-ISAPI-Ext",
                "Web-ISAPI-Filter",
                "Web-Mgmt-Tools",
                "Web-Mgmt-Console",
                "Web-Mgmt-Compat",
                "Web-Metabase",
                "Web-WMI",
                "NET-Framework-Features",
                "NET-Framework-Core",
                "NET-HTTP-Activation",
                "NET-Framework-45-ASPNET",
                "NET-WCF-HTTP-Activation45",
                "RSAT",
                "RSAT-Role-Tools",
                "RSAT-ADCS",
                "RSAT-ADCS-Mgmt",
                "PowerShell-V2",
                "WAS",
                "WAS-Process-Model",
                "WAS-NET-Environment",
                "WAS-Config-APIs"
                )

try {
    Install-WindowsFeature -Name $serverRoles -IncludeManagementTools -Verbose -ErrorAction Stop
}
catch {
    Write-Host "Failed to install Server roles. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually install following Windows Server roles and continue: `n `
    $($serverRoles -join ", ")"
    Pause
    Break
}


# Configure NDES
Write-Host "`t Step 9/18 - Configuring NDES..." -F Yellow
$ndesServerFqdn = [System.Net.Dns]::GetHostByName($env:computerName).HostName

$params = @{
    #Credential              = $ndesCreds
    ServiceAccountName      = "$env:USERDOMAIN\$($serviceAccount.SamAccountName)"
    ServiceAccountPassword  = $accountPassword
    RAName                  = "$env:USERDOMAIN-NDES-RA"
    #RACountry              = "SV"
    #RACompany              = "$env:USERDOMAIN"
    SigningProviderName     = "Microsoft Strong Cryptographic Provider"
    SigningKeyLength        = 2048
    EncryptionProviderName  = "Microsoft Strong Cryptographic Provider"
    EncryptionKeyLength     = 2048
    Verbose                 = $true
}

if($ndesServerFqdn -notlike $caServer.ComputerName) {
    $params += @{ CAConfig = $caServer.ConfigString }
}

if ($notEnterpriseAdmin) {
    $eaCreds = Get-Credential -Message "Please provide a Enterprise Admin account used ONLY for running the Install-AdcsNetworkDeviceEnrollmentService command for NDES configuration where Enterprise Admin permission is required."
    $params += @{ Credential = $eaCreds }
}

$ErrorActionPreference = "Stop"
try {
    # Requires enterprise admin to configure NDES
    $ndesResult = Invoke-Command -Credential $ndesCreds -ArgumentList -ScriptBlock {
        Install-AdcsNetworkDeviceEnrollmentService @params
    }


    if ($ndesResult.ErrorId -ne 0) {
        Write-Host "A error occurred while configuring NDES. Error message: $($ndesResult.ErrorString)" -F Red -B Black
        Write-Warning "Please manually finish the NDES configuration in Server Manager using the service account with following parameters and continue this script."
        $params
        Pause
    }

}
catch {
    Write-Host "Failed to configure NDES Role. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually finish the NDES configuration in Server Manager using the service account with following parameters and continue this script."
    $params
    Pause

}


try {
    # Set default certificate template to issue from via SCEP
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -Name EncryptionTemplate -Value $optionalClientTemplateName -Force         # For Key encipherment
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -Name SignatureTemplate -Value $optionalClientTemplateName -Force          # For Digital signature
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -Name GeneralPurposeTemplate -Value $optionalClientTemplateName -Force     # For both Key encipherment and Digital signature
}
catch {
    Write-Host "Failed to configure NDES Role. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually change following three registry values and continue this script. `n `
    Key:        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MSCEP `
    Properties: EncryptionTemplate; SignatureTemplate; GeneralPurposeTemplate `
    Value:      $optionalClientTemplateName"
    Pause
}



Write-Host "`t Step 10/18 - Configuring IIS..." -F Yellow
try {
    # Configure request filtering settings in IIS

    Set-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" –value 65534 -Verbose
    Set-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" –value 65534 -Verbose
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength -PropertyType DWORD -Value 65534 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes -PropertyType DWORD -Value 65534 -Force
    & "$env:WinDir\system32\inetsrv\appcmd.exe" "set config /section:requestfiltering /requestlimits.maxurl:65534"
    & "$env:WinDir\system32\inetsrv\appcmd.exe" "set config /section:requestfiltering /requestlimits.maxquerystring:65534"
}
catch {
    Write-Host "Failed to configure IIS. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually set the following Request filtering Feature Settings in IIS, then restart the IIS service and continue this script: `t `
    Maximum URL length: 65534 `
    Maximum query string: 65534"
    Pause
}
$ErrorActionPreference = "Continue"


# Install Entra App Proxy Connector
Write-Host "`t Step 11/18 - Downloading Entra App Proxy Connector..." -F Yellow
$proxyDownloadUrl = "https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller"
$proxyExeFilePath = "$env:USERPROFILE\Downloads\EntraApplicationProxyConnectorInstaller.exe"
try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $proxyDownloadUrl -OutFile $proxyExeFilePath -ErrorAction Stop
    $ProgressPreference = 'Continue'

    Write-Host "`t Step 12/18 - Installing Entra App Proxy Connector..." -F Yellow
    $proc = Start-Process -FilePath $proxyExeFilePath -ArgumentList "/passive" -PassThru -ErrorAction Stop
    Write-Host "IMPORTANT! Make sure to authenticate with a global admin account when the OAuth window appear!" -F Yellow -B Black
    $proc.WaitForExit()
}
catch {
    Write-Host "Failed to download and install Entra Proxy Connector. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please download it manually, install it and then continue this script."
    Pause
}




# Create Entra Proxy App - AzureAD
Write-Host "`t Step 13/18 - Creating Entra Proxy App..." -F Yellow
$ErrorActionPreference = "Stop"
try {
    $entraAppDisplayName = "$env:COMPUTERNAME-NDES"
    Connect-AzureAD

    try {
        $onmicrosoftAddress = (Get-AzureADDomain | where {($_.Name -match "\.onmicrosoft\.com$") -AND ($_.Name -notmatch "\.mail\.onmicrosoft\.com$")}).Name | select -First 1
        $entraAppExternalUrl = "https://$($entraAppDisplayName.ToLower() -replace "[^a-zA-Z]")-$($onmicrosoftAddress -replace "\.onmicrosoft\.com$").msappproxy.net/"

        try {
            New-AzureADApplicationProxyApplication -DisplayName $entraAppDisplayName -ExternalUrl $entraAppExternalUrl -InternalUrl "http://$ndesServerFqdn" -ExternalAuthenticationType Passthru
        }
        catch {
            Write-Host "Failed to get AzureADDomain information. Error message: $($_.Exception)" -F Red -B Black
            $failedEntraProxyApp = $true
        }
    }
    catch {
        Write-Host "Failed to get AzureADDomain information. Error message: $($_.Exception)" -F Red -B Black
        $failedEntraProxyApp = $true
    }
}
catch {
    Write-Host "Failed to authenticate to Entra. Error message: $($_.Exception)" -F Red -B Black
    $failedEntraProxyApp = $true
}
$ErrorActionPreference = "Continue"

if ($failedEntraProxyApp) {
    Write-Warning "Please manually create a Entra Proxy Application with the following settings and continue: `n `
    InternalURL:        http://$ndesServerFqdn `
    ExternalURL:        https://$($entraAppDisplayName.ToLower() -replace "[^a-zA-Z]")-<DEFAULT TENANT NAME>.onmicrosoft.com.msappproxy.net `
    Pre-Authentication: Passthru `
    https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy-add-on-premises-application#add-an-on-premises-app-to-microsoft-entra-id"
    Pause
}


#region Step 13 MgGraph Rewrite
########### STEP 13 REWRITE NOT DONE ############
# Create Entra Proxy App - MgGraph
Write-Host "`t Step 13/18 - Creating Entra Proxy App..." -F Yellow
$ErrorActionPreference = "Stop"
try {
    $entraAppDisplayName = "$env:COMPUTERNAME-NDES-Proxy"
    Connect-MgGraph -Scope Directory.ReadWrite.All

    try {
        $onmicrosoftAddress = ((Get-MgDomain | where {$_.IsInitial}).Id | where {($_.Name -match "\.onmicrosoft\.com$") -AND ($_.Name -notmatch "\.mail\.onmicrosoft\.com$")}).Name | select -First 1
        $entraAppExternalUrl = "https://$($entraAppDisplayName.ToLower() -replace "[^a-zA-Z]")-$($onmicrosoftAddress -replace "\.onmicrosoft\.com$").msappproxy.net/"

        try {
            $applicationTemplateId = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"
            $AppParams = @{
                displayName = "$entraAppDisplayName"
            }

            Invoke-MgInstantiateApplicationTemplate -ApplicationTemplateId $applicationTemplateId -BodyParameter $AppParams
            Start-Sleep -Seconds 20

            try {
                do{
                    $NewAppObject = Get-MgApplication -Filter "DisplayName eq '$entraAppDisplayName'"
                    if(!$NewAppObject) {Start-Sleep -Seconds 5}
                }Until ($NewAppObject)

                $UrlParams = @{
                    identifierUris = @(
                        $entraAppExternalUrl
                    )
                    web = @{
                        redirectUris = @(
                            $entraAppExternalUrl
                        )
                        homePageUrl = $entraAppExternalUrl
                    }
                }

                Update-MgBetaApplication -ApplicationId $NewAppObject.Id -BodyParameter $UrlParams
                Start-Sleep -Seconds 15


            }
            catch {
                <#Do this if a terminating exception happens#>
            }
        }
        catch {
            Write-Host "Failed to get Entra Domain information. Error message: $($_.Exception)" -F Red -B Black
            $failedEntraProxyApp = $true
        }
    }
    catch {
        Write-Host "Failed to get Entra Domain information. Error message: $($_.Exception)" -F Red -B Black
        $failedEntraProxyApp = $true
    }
}
catch {
    Write-Host "Failed to authenticate to Entra. Error message: $($_.Exception)" -F Red -B Black
    $failedEntraProxyApp = $true
}
$ErrorActionPreference = "Continue"

if ($failedEntraProxyApp) {
    Write-Warning "Please manually create a Entra Proxy Application with the following settings and continue: `n `
    InternalURL:        http://$ndesServerFqdn `
    ExternalURL:        https://$($entraAppDisplayName.ToLower() -replace "[^a-zA-Z]")-<DEFAULT TENANT NAME>.onmicrosoft.com.msappproxy.net `
    Pre-Authentication: Passthru"
    Pause
}
#endregion



# Request new certificate for server from imported server template
Write-Host "`t Step 14/18 - Requesting new server certificate..." -F Yellow
try {
    $newCert = Get-Certificate -Template $optionalServerTemplateName -SubjectName "CN=$ndesServerFqdn" -DnsName $ndesServerFqdn,$entraAppExternalUrl -CertStoreLocation cert:\LocalMachine\My -ErrorAction Stop
}
catch {
    Write-Host "Failed to issue certificate request from CA with $optionalServerTemplateName template. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually issue certificate request for this server with the certificate template '$optionalServerTemplateName' with following additonal properties and store it in personal certificate store: `n`
    Common Name: CN=$ndesServerFqdn `
    DNS Name: $ndesServerFqdn `
    DNS Name: $entraAppExternalUrl"
    Pause
}



# Set SPN
Write-Host "`t Step 15/18 - Setting SPN..." -F Yellow
setspn -s http/$ndesServerFqdn $env:USERDNSDOMAIN\$($serviceAccount.SamAccountName)
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to set correct SPN. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually set the following SPN for this server and continue: `n `
    setspn -s http/$ndesServerFqdn $env:USERDNSDOMAIN\$($serviceAccount.SamAccountName)"
    Pause
}



# Set IIS Site HTTPS binding
Write-Host "`t Step 16/18 - Configuring IIS HTTPS binding with new server certificate..." -F Yellow
try {
    #Remove-IISSiteBinding -Name 'Default Web Site' -BindingInformation '*:80:' -Confirm:$false -ErrorAction Stop
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/defaultDocument' -Name 'Enabled' -Value 'False'
    #Remove-Item -Path C:\Inetpub\wwwroot\iisstart.* -Force -Confirm:$false
    New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -CertificateThumbPrint $newCert.Certificate.Thumbprint -CertStoreLocation "Cert:\LocalMachine\My" -Protocol https -ErrorAction Stop
    Restart-Service -Name W3SVC -Force
}
catch {
    Write-Host "Failed to configure https binding. Error message: $($_.Exception)" -F Red -B Black
    Write-Warning "Please manually configure HTTPS binding for Default Web Site with the newly issued certificate and continue. `n `
    Certificate SerialNumber: $($newCert.Certificate.SerialNumber)"
    Pause
}


# reboot server

# Download and install Certificate Connector
Write-Host "`t Step 17/18 - Downloading Intune Certificate Connector..." -F Yellow
$connectorDownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2168535"
$connectorExeFilePath = "$env:USERPROFILE\Downloads\IntuneCertificateConnector.exe"

try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $connectorDownloadUrl -OutFile $connectorExeFilePath -ErrorAction Stop
    $ProgressPreference = 'Continue'

    Write-Host "`t Step 18/18 - Installing Intune Certificate Connector..." -F Yellow
    $proc = Start-Process -FilePath $connectorExeFilePath -ArgumentList "/passive /norestart" -PassThru -ErrorAction Stop
    Write-Host "IMPORTANT! Make sure to authenticate with a Entra Global Admin account when the OAuth window appear!" -F Yellow -B Black
    $proc.WaitForExit()
}
catch {
    Write-Warning "Failed to download and install Intune Certificate Connector. Please download and install it manually."
    Pause
}

# Manually configure Intune Certificate Connector, enable SCEP, use domain account (ndes service account), skip proy settings, choose public cloud, logga in med global admin

Write-Host "`t Done! Please restart the server!" -F Green