<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER Modules
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>

[CmdletBinding()]
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]
    $serverTemplateName = "ScepNdesServer",

    [Parameter(Mandatory=$false)]
    [string]
    $clientTemplateName = "ScepNdesClient",

    [Parameter(Mandatory=$false)]
    [string]
    $NdesServerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$true)]
    [string]
    $ServiceAccountUsername
)

##*===============================================
##* Functions
##*===============================================
#region Functions

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

Import-Module ActiveDirectory -Force

$domain = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain

if (!$domain) {
    Write-Warning "Domain membership was not found for this server".
    Pause
    Exit 1
}

$serviceAccount = Get-ADUser $ServiceAccountUsername

if (!$serviceAccount) {
    Write-Warning "Service Account was not found in domain $domain".
    Pause
    Exit 1
}

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


@($serverTemplate, $clientTemplate) | foreach {
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

try {
    Grant-CATemplatePermission -TemplateName $serverTemplateName -NTAccountName "$serverName$" -Permissions Read,Enroll,AutoEnroll -ErrorAction Stop
    Grant-CATemplatePermission -TemplateName $clientTemplateName -NTAccountName $serviceAccount.SamAccountName -Permissions Read,Write,Enroll,AutoEnroll -ErrorAction Stop

    Grant-CertificateAuthorityPermission -AccountSID $serviceAccount.SID.Value -ErrorAction Stop
}
catch {
    Write-Warning "Failed to grant CA permissions. Error message: $($_.Exception)"
    Pause
}

try {
    Add-CATemplate -Name $serverTemplateName -Confirm:$false -ErrorAction Stop
    Add-CATemplate -Name $clientTemplateName -Confirm:$false -ErrorAction Stop
}
catch {
    Write-Warning "Failed to enable CA templates. Error message: $($_.Exception)"
    Pause
}

Write-Host "`t Done!" -F Green