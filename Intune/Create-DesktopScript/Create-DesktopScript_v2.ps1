[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false, HelpMessage = "Choose which wallpaper type to be customized.")]
    [ValidateSet("DesktopOnly","LockscreenOnly","ALL")]
    [String]$WallpaperType,

    [Parameter(Mandatory = $false, HelpMessage = "Restricts the user from changing wallpaper, choose which scope.")]
    [ValidateSet("DesktopOnly","LockscreenOnly","ALL")]
    [String]$Restrict
)


IF(!$WallpaperType){
    Throw 'The parameter WallpaperType needs to be provided.'
    Pause
    Break
}


$FileName = "Set-WindowsWallpapers"


IF($MyInvocation.MyCommand.CommandType -eq "ExternalScript"){
    $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}ELSE{
    $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
    IF(!$ScriptPath){
        $ScriptPath = "." 
    }
}


Function Browse-File {
    Param(
        [String]$Title = "Choose an image"
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    #$FileBrowser.filter = 'All files (*.png;*.jpg;*.jpeg;*.jpe;*.jfif)|*.png;*.jpg;*.jpeg;*.jpe;*.jfif|PNG file (*.PNG)|*.png|JPEG file (*.jpg;*.jpeg;*.jpe;*.jfif)|*.jpg;*.jpeg;*.jpe;*.jfif' 
    $FileBrowser.filter = 'JPEG file (*.jpg)|*.jpg' 
    $FileBrowser.InitialDirectory = $env:USERPROFILE
    $FileBrowser.Title = $Title
    [void]$FileBrowser.ShowDialog()
    IF(($FileBrowser.FileName) -AND ($FileBrowser.CheckFileExists)){
        return $FileBrowser.FileName
    }ELSE{
        Write-Warning "Invalid file!"
        return $null
    }
}


IF(($WallpaperType -like "ALL") -OR ($WallpaperType -like "DesktopOnly")){
    Write-Verbose "Choose a Desktop wallpaper image" -Verbose

    [String]$DesktopFile = Browse-File -Title "Choose a Desktop wallpaper image"
    If([string]::IsNullOrEmpty($DesktopFile)){
        Break
    }
}


IF(($WallpaperType -like "ALL") -OR ($WallpaperType -like "LockscreenOnly")){
    Write-Verbose "Choose a Lockscreen wallpaper image" -Verbose

    [String]$LockscreenFile = Browse-File -Title "Choose a Lockscreen wallpaper image"
    If([string]::IsNullOrEmpty($LockscreenFile)){
        Break
    }
}


if ($DesktopFile) {
    $DesktopContent = Get-Content -Path $DesktopFile -Encoding Byte
    $DesktopBase64 = [System.Convert]::ToBase64String($DesktopContent)
}

if ($LockscreenFile) {
    $LockscreenContent = Get-Content -Path $LockscreenFile -Encoding Byte
    $LockscreenBase64 = [System.Convert]::ToBase64String($LockscreenContent)
}



$PSScript = @"
<#
.SYNOPSIS
    Creates custom image from embedded base64 code in Windows default desktop wallpaper location.
    Replace the default img100.jpg lockscreen wallpaper image in Windows 10, by creating a new image embedded in this script.
    Default img100.jpg is renamed and kept as backup.
    Option to force and restrict wallpaper on local device using 'PersonalizationCSP'.

.DESCRIPTION
    Backups and replaces the default Windows 10 wallpaper images by creating a new image that is embedded in this script.
    The new image has already been embedded in this script by another script.
    Option to force and restrict wallpaper on local device is available using registry key 'PersonalizationCSP'. 

.PARAMETER WallpaperType
    Chooses which wallpaper to change, Desktop, Lockscreen or both.

.PARAMETER Restrict
    Chooses which wallpaper to force and restrict, Desktop, Lockscreen or both.

.PARAMETER RestoreDefault
    Restores Windows default wallpaper from backup folder.

.EXAMPLE
    .\Set-WindowsWallpapers.ps1

.NOTES
    FileName:           Set-WindowsWallpapers.ps1
    Author:             Yoel Abraham
    Contact:            Yoel.Abraham@rts.se
    Created:            2021-04-13
    Original Link:      https://github.com/MSEndpointMgr/Intune/blob/master/Customization/Set-WindowsDesktopWallpaper.ps1
    Original Author:    Nickolaj Andersen
    Comment:            Heavily modified.
    
#>
[CmdletBinding(SupportsShouldProcess = `$true)]
Param(
    
    [Parameter(Mandatory = `$false, Position = 0, HelpMessage = "Applies custom wallpaper, choose which scope.")]
    [ValidateSet("DesktopOnly","LockscreenOnly","ALL")]
    [String]`$WallpaperType = "$WallpaperType",

    [Parameter(Mandatory = `$false, HelpMessage = "Restricts the user from changing wallpaper, choose which WallpaperType.")]
    [ValidateSet("DesktopOnly","LockscreenOnly","ALL")]
    [String]`$Restrict$(IF($Restrict){" = `"$Restrict`""}),

    [Parameter(Mandatory = `$false, HelpMessage = "Restores default backup, choose which WallpaperType to restore.")]
    [Switch]`$RestoreDefault
    
)


#=============================================================================================================================================================================
#=============================================================================================================================================================================

Begin {
    
    # Author: Z-NERD - https://z-nerd.com/blog/2020/03/31-intune-win32-apps-powershell-script-installer/
    # Restart Powershell script from 32-bit to 64-bit if necessary

    `$argsString = ""
    If (`$ENV:PROCESSOR_ARCHITECTURE -eq "x86") {
        foreach(`$k in `$MyInvocation.BoundParameters.keys)
        {
            switch(`$MyInvocation.BoundParameters[`$k].GetType().Name)
            {
                "SwitchParameter" {if(`$MyInvocation.BoundParameters[`$k].IsPresent) { `$argsString += "-`$k " } }
                "String"          { `$argsString += "-`$k ``"`$(`$MyInvocation.BoundParameters[`$k])``" " }
                "Int32"           { `$argsString += "-`$k `$(`$MyInvocation.BoundParameters[`$k]) " }
                "Boolean"         { `$argsString += "-`$k ``$`$(`$MyInvocation.BoundParameters[`$k]) " }
            }
        }
        Start-Process -FilePath "`$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "`$argsString -File ``"`$PSCommandPath``"" -Wait -NoNewWindow
        Break
    }

    ########################################################################################################

    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    
    IF(!`$WallpaperType){
        Throw 'The parameter WallpaperType needs to be provided.'
        Exit 9999
    }

    # Determine the localized name of the principals required for the functionality of this script
    [String]`$LocalAdministratorsPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate( [System.Security.Principal.NTAccount]).Value
    [String]`$LocalUsersPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate( [System.Security.Principal.NTAccount]).Value
    [String]`$ApplicationPackagesPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-15-2-1').Translate( [System.Security.Principal.NTAccount]).Value -replace "^.*\\"
    [String]`$RestrictedApplicationPackagesPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-15-2-2').Translate( [System.Security.Principal.NTAccount]).Value -replace "^.*\\"
    [String]`$LocalSystemPrincipal = "NT AUTHORITY\SYSTEM"
    [String]`$TrustedInstallerPrincipal = "NT SERVICE\TrustedInstaller"
    

    `$DesktopImageName = "Company-DesktopWallpaper.jpg"
    `$DefaultDesktopImageName = "img0.jpg"
    `$LockScreenImageName = "Company-LockScreenWallpaper.jpg"
    `$DefaultLockScreenImageName = "img100.jpg"
    `$ImagePath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Personalization"
    `$DesktopImagePath = "C:\Windows\Web\Wallpaper\Windows"
    `$LockScreenImagePath = "C:\Windows\Web\Screen"

    # If ImagePath doesn't exists, create folder
    if (!(Test-Path -Path `$ImagePath)) {
        New-Item -Path `$ImagePath -ItemType Directory -Force | Out-Null
    }
   
$(
    if($DesktopBase64){
        "    `$DesktopBase64 = @'
$DesktopBase64
'@"
    }
)
$(
    if($LockscreenBase64){
        if($LockscreenBase64 -like $DesktopBase64){
            "    `$LockScreenBase64 = `$DesktopBase64"
        }else{
            "    `$LockScreenBase64 = @'
$LockscreenBase64
'@"
        }
    }
)
}

#=============================================================================================================================================================================
#=============================================================================================================================================================================

Process {
    
    #region Support functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = `$true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]`$Value,
    
            [parameter(Mandatory = `$true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]`$Severity,
    
            [parameter(Mandatory = `$false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]`$FileName = "WindowsDesktopWallpaper.log"
        )
        # Determine log file location
        `$LogFilePath = Join-Path -Path (Join-Path -Path `$env:windir -ChildPath "Temp") -ChildPath `$FileName
        
        # Construct time stamp for log entry
        `$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        `$Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        `$Context = `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        `$LogText = "<![LOG[`$(`$Value)]LOG]!><time=""`$(`$Time)"" date=""`$(`$Date)"" component=""WindowsDesktopWallpaper"" context=""`$(`$Context)"" type=""`$(`$Severity)"" thread=""`$(`$PID)"" file="""">"
        
        # Output Value as verbose
        Write-Verbose `$Value

        # Add value to log file
        try {
            Out-File -InputObject `$LogText -Append -NoClobber -Encoding Default -FilePath `$LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to `$FileName file. Error message at line `$(`$_.InvocationInfo.ScriptLineNumber): `$(`$_.Exception.Message)"
        }
    }





    function Set-AllUsersRegistry{
        [Cmdletbinding()]
        Param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose action, add, delete or edit.")]
            [ValidateSet("ADD","DELETE","EDIT")]
            [String]`$Action,

            [parameter(Mandatory = `$True, HelpMessage = "Registry key path after HKCU:\")]
            [ValidateNotNullOrEmpty()]
            [String]`$RegPath,

            [parameter(Mandatory = `$False, HelpMessage = "Registry key property name.")]
            [ValidateNotNullOrEmpty()]
            [String]`$RegPropertyName,

            [parameter(Mandatory = `$False, HelpMessage = "Registry key property value.")]
            [ValidateNotNullOrEmpty()]
            [String]`$RegPropertyValue,

            [parameter(Mandatory = `$False, HelpMessage = "Registry key property value type.")]
            [ValidateSet("String","ExpandString","MultiString","Binary","DWORD","QWORD")]
            [String]`$RegPropertyType,

            [parameter(Mandatory = `$False, HelpMessage = "Includes the default profile registry.")]
            [Switch]`$IncludeDefaultProfile
    
        )
        
        IF(`$Action -like "ADD"){
            Write-LogEntry -Value "Starting process to `$Action the registry key property '`$RegPath\`$RegPropertyName' with the value '`$RegPropertyValue' as '`$RegPropertyType' to all users" -Severity 1
        }ELSEIF(`$Action -like "DELETE"){
            IF(`$RegPropertyName){Write-LogEntry -Value "Starting process to `$Action the registry key property '`$RegPath\`$RegPropertyName' from all users" -Severity 1}
            ELSE{Write-LogEntry -Value "Starting process to `$Action the registry key '`$RegPath' from all users" -Severity 1}
        }ELSEIF(`$Action -like "EDIT"){
            Write-LogEntry -Value "Starting process to `$Action the registry key property '`$RegPath\`$RegPropertyName' to the value '`$RegPropertyValue' for all users" -Severity 1
        }

        # Regex pattern for SIDs
        `$PatternSID = 'S-\d-\d+-(\d+-){1,14}\d+`$'
        
        Write-LogEntry -Value "Fetching all known users information an registries" -Severity 1

        try{
            

            # Get Username, SID, and location of ntuser.dat for all users
            `$ProfileList = @()

            IF(`$IncludeDefaultProfile){
                `$DefaultProfile = [Ordered]@{'SID'=".DefaultProfile";'UserHive'="C:\Users\Default\NTUSER.DAT";'UserName'="DefaultProfile"}
                `$ProfileList += New-Object -TypeName PSObject -Property `$DefaultProfile
            }

            `$ProfileList += Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop | Where-Object {`$_.PSChildName -match `$PatternSID} | 
                Select  @{name="SID";expression={`$_.PSChildName}},
                        @{name="UserHive";expression={"`$(`$_.ProfileImagePath)\ntuser.dat"}},
                        @{name="UserName";expression={`$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
            
            
            try{
                # Mapping PSDrive for all users registries
                `$PSDrive = New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction Stop
                
                # Get all user SIDs found in HKEY_USERS
                `$LoadedHives = Get-ChildItem -Name "HKU:" -ErrorAction Stop | Where{`$_.PSChildname -match `$PatternSID} | Select @{name="SID";expression={`$_.PSChildName}}
 
                # Get all users that are not currently logged
                `$UnloadedHives = Compare-Object `$ProfileList.SID `$LoadedHives.SID -ErrorAction Stop | Select @{name="SID";expression={`$_.InputObject}}, UserHive, Username

                # Loop through each profile on the machine
                Foreach (`$item in `$ProfileList) {
                    try{

                        # Load User ntuser.dat if it's not already loaded
                        IF (`$item.SID -in `$UnloadedHives.SID) {
                            reg load HKU\`$(`$Item.SID) `$(`$Item.UserHive) | Out-Null
                        }

                        #####################################################################
                        # This is where you can read/modify a users portion of the registry 
                            
                        Write-LogEntry -Value "Processing user: `$("{0}" -f `$item.UserName)" -Severity 1

                        `$RegPrefix = "HKU:\`$(`$Item.SID)"
                        `$RegFullPath = (Join-Path -Path `$RegPrefix -ChildPath `$RegPath)

                        IF(`$Action -like "ADD"){
                            IF(Get-Item `$RegFullPath -ErrorAction SilentlyContinue){
                                New-ItemProperty -Path `$RegFullPath -Name `$RegPropertyName -Value `$RegPropertyValue -PropertyType `$RegPropertyType -Force -ErrorAction Stop
                            }ELSE{
                                New-Item `$RegFullPath -Force -ErrorAction Stop
                                New-ItemProperty -Path `$RegFullPath -Name `$RegPropertyName -Value `$RegPropertyValue -PropertyType `$RegPropertyType -Force -ErrorAction Stop
                            }
                        }

                        IF(`$Action -like "EDIT"){
                            Set-ItemProperty -Path `$RegFullPath -Name `$RegPropertyName -Value `$RegPropertyValue -Force -ErrorAction Stop
                        }

                        IF(`$Action -like "DELETE"){
                            IF(`$RegPropertyName){
                                Remove-ItemProperty -Path `$RegFullPath -Name `$RegPropertyName -Force -ErrorAction Stop
                            }ELSE{
                                Remove-Item -Path `$RegFullPath -Recurse -Force -ErrorAction Stop
                            }
                        }
        
                        Write-LogEntry -Value "Successfully applied action on user: `$("{0}" -f `$item.UserName)" -Severity 1
                        #####################################################################

                        # Unload ntuser.dat        
                        IF (`$item.SID -in `$UnloadedHives.SID) {
                            ### Garbage collection and closing of ntuser.dat ###
                            [gc]::Collect()
                            reg unload HKU\`$(`$Item.SID) | Out-Null
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to apply action on user '`$("{0}" -f `$item.UserName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                    }
                }

                try{
                    Remove-PSDrive `$PSDrive -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to remove mapped PSDrive. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to map PSDrive for all the users registries. Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to fetch all known users from the registry. Error message: `$(`$_.Exception.Message)" -Severity 3
        }
    }




    Function Set-NTOwner{
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$Path,
    
            [Parameter(Mandatory=`$True)]
            [String]`$Principal
        )
        
        try {
            # Define the principal for owner
            `$PrincipalObject = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList `$Principal -ErrorAction Stop
    
            try {
                # Get a list of folders and files
                `$Item = Get-Item -Path `$Path -Force -ErrorAction Stop
    
                try {
                    # Get the ACL from the item
                    `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
    
                    # Update the in-memory ACL
                    `$Acl.SetOwner(`$PrincipalObject)
                    
                    try {
                        # Set the updated ACL on the target item
                        Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
                    }
                    catch [System.Exception] {
                        throw "Could not set ACL for path. Error Message: `$(`$_)"
                    }
                }
                catch [System.Exception] {
                    throw "Could not get ACL from path. Error Message: `$(`$_)"
                }
            }
            catch [System.Exception] {
                throw "Could not find path. Error Message: `$(`$_)"
            }
        }
        catch [System.Exception] {
            throw "Could not validate principal. Error Message: `$(`$_)"
        }
    }
    
    Function Add-NTAccess{
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$Path,
    
            [Parameter(Mandatory=`$True)]
            [String]`$Principal,
    
            [Parameter(Mandatory=`$True)]
            [ValidateSet("Read","Write","ReadAndExecute","Modify","FullControl")]
            [String]`$Access,
    
            [Parameter(Mandatory=`$False)]
            [ValidateSet("Allow","Deny")]
            [String]`$AccessType = "Allow",
    
            [Parameter(Mandatory=`$False)]
            [ValidateSet(
                "This folder only",
                "This folder, subfolder and files",
                "This folder and subfolders",
                "This folder and files",
                "Subfolders and files only",
                "Subfolders only",
                "Files only",
                "This folder, child folder and child file only",
                "This folder and child folder only",
                "This folder and child file only",
                "Child folder and child file only",
                "Child folder only",
                "Child file only"
            )]
            [String]`$Propagation = "This folder, subfolder and files"
    
        )
    
        `$PropagationRules = @(
    
            New-Object psobject -Property @{Message="This folder only";Inheritance="None";Propagation="None"};
            New-Object psobject -Property @{Message="This folder and files";Inheritance="ObjectInherit";Propagation="None"};
            New-Object psobject -Property @{Message="This folder and child file only";Inheritance="ObjectInherit";Propagation="NoPropagateInherit"};
            New-Object psobject -Property @{Message="Files only";Inheritance="ObjectInherit";Propagation="InheritOnly"};
            New-Object psobject -Property @{Message="Child file only";Inheritance="ObjectInherit";Propagation="InheritOnly,NoPropagateInherit"};
            New-Object psobject -Property @{Message="This folder and subfolders";Inheritance="ContainerInherit";Propagation="None"};
            New-Object psobject -Property @{Message="This folder and child folder only";Inheritance="ContainerInherit";Propagation="NoPropagateInherit"};
            New-Object psobject -Property @{Message="Subfolders only";Inheritance="ContainerInherit";Propagation="InheritOnly"};
            New-Object psobject -Property @{Message="Child folder only";Inheritance="ContainerInherit";Propagation="InheritOnly,NoPropagateInherit"};
            New-Object psobject -Property @{Message="This folder, subfolder and files";Inheritance="ContainerInherit,ObjectInherit";Propagation="None"};
            New-Object psobject -Property @{Message="This folder, child folder and child file only";Inheritance="ContainerInherit","ObjectInherit";Propagation="NoPropagateInherit"};
            New-Object psobject -Property @{Message="Subfolders and files only";Inheritance="ContainerInherit,ObjectInherit";Propagation="InheritOnly"};
            New-Object psobject -Property @{Message="Child folder and child file only";Inheritance="ContainerInherit,ObjectInherit";Propagation="NoPropagateInherit,InheritOnly"}
        
        )
    
        `$Props = `$PropagationRules | where{`$_.Message -like `$Propagation}
        
        try{
            if (!`$Props){throw}
            
            try {
                    # Get a list of folders and files
                    `$Item = Get-Item -Path `$Path -Force -ErrorAction Stop
    
                try {
                    # Define the Principal and Permissions
                    if(`$Item.PSIsContainer){
                        `$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(`$Principal,`$Access,`$props.Inheritance,`$props.Propagation,`$AccessType) -ErrorAction Stop
            
                    }else{
                        `$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(`$Principal,`$Access,`$AccessType) -ErrorAction Stop
            
                    }
    
                    try {
                        # Get the ACL from the item
                        `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
    
                        # Update the in-memory ACL
                        `$Acl.SetAccessRule(`$AccessRule)
                        
                        try {
                            # Set the updated ACL on the target item
                            Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
    
                        }
                        catch [System.Exception] {
                            throw "Could not set ACL for path. Error Message: `$(`$_)"
                        }
                        
                    }
                    catch [System.Exception] {
                        throw "Could not get ACL from path. Error Message: `$(`$_)"
                    }
                }
                catch [System.Exception] {
                    throw "Could not define principal and permissions. Error Message: `$(`$_)"
                }
            }
            catch [System.Exception] {
                throw "Could not find path. Error Message: `$(`$_)"
            }
        }
        catch [System.Exception] {
            throw "Propagation value is invalid."
        }
    }
    
    Function Remove-NTAccess{
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$Path,
    
            [Parameter(Mandatory=`$True)]
            [String]`$Principal,
    
            [Parameter(Mandatory=`$True)]
            [ValidateSet("Read","Write","ReadAndExecute","Modify","FullControl")]
            [String]`$Access,
    
            [Parameter(Mandatory=`$False)]
            [ValidateSet("Allow","Deny")]
            [String]`$AccessType = "Allow"
    
        )
    
        try {
            # Get a list of folders and files
            `$Item = Get-Item -Path `$Path -Force -ErrorAction Stop
    
            try {
                # Define the Principal and Permissions
                `$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(`$Principal,`$Access,`$AccessType) -ErrorAction Stop
    
                try {
                    # Get the ACL from the item
                    `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
    
                    # Update the in-memory ACL
                    `$Acl.RemoveAccessRule(`$AccessRule) | Out-Null
    
                    try {
                        # Set the updated ACL on the target item
                        Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
                    
                    }
                    catch [System.Exception] {  
                        throw "Could not set ACL for path. Error Message: `$(`$_)"
                    }
                }
                catch [System.Exception] {
                    throw "Could not get ACL from path. Error Message: `$(`$_)"
                }
            }
            catch [System.Exception] {
                throw "Could not define principal and permissions. Error Message: `$(`$_)"
            }
        }
        catch [System.Exception] {
            throw "Could not find path. Error Message: `$(`$_)"
        }
    }
    
    Function Purge-NTAccess{
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$Path,
    
            [Parameter(Mandatory=`$True)]
            [String]`$Principal
    
        )
    
        try {
            # Get a list of folders and files
            `$Item = Get-Item -Path `$Path -Force -ErrorAction Stop
    
            try {
                # Define the Principal
                `$PrincipalObject = New-Object System.Security.Principal.Ntaccount (`$Principal) -ErrorAction Stop
    
                try {
                    # Get the ACL from the item
                    `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
    
                    # Update the in-memory ACL
                    `$Acl.PurgeAccessRules(`$PrincipalObject)
    
                    try {
                        # Set the updated ACL on the target item
                        Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
    
                    }
                    catch [System.Exception] {
                        throw "Could not set ACL for path. Error Message: `$(`$_)"
                    }
                }
                catch [System.Exception] {
                    throw "Could not get ACL from path. Error Message: `$(`$_)"
                }
            }
            catch [System.Exception] {
                throw "Could not define principal and permissions. Error Message: `$(`$_)"
            }
        }
        catch [System.Exception] {
            throw "Could not find path. Error Message: `$(`$_)"
        }
    }
    
    Function Purge-NTAllAccess{
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$Path
    
        )
    
        try {
            # Get a list of folders and files
            `$Item = Get-Item -Path `$Path -Force -ErrorAction Stop
    
            try {
                # Get the ACL from the item
                `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
    
                `$Acl.Access | where{`$_.isinherited -eq `$false} | foreach{
                    `$Acl.RemoveAccessRule(
                        `$(
                            if(`$_.identityreference -match "^APPLICATION PACKAGE AUTHORITY\\"){
                                New-Object System.Security.AccessControl.FileSystemAccessRule((`$_.IdentityReference -replace "^APPLICATION PACKAGE AUTHORITY\\"),`$_.FileSystemRights,`$_.AccessControlType)
                            }else{
                                `$_
                            }
                        )
                    ) | Out-Null
                }
    
                try {
                    # Set the updated ACL on the target item
                    Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
    
                }
                catch [System.Exception] {
                    throw "Could not set ACL for path. Error Message: `$(`$_)"
                }
            }
            catch [System.Exception] {
                throw "Could not get ACL from path. Error Message: `$(`$_)"
            }
        }
        catch [System.Exception] {
            throw "Could not find path. Error Message: `$(`$_)"
        }
    }
    
    Function Set-NTInheritance{
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$Path,
    
            [Parameter(Mandatory=`$True)]
            [ValidateSet("Enable","Disable")]
            [String]`$Inheritance,
    
            [Parameter(Mandatory=`$False)]
            [ValidateSet("Retain","Remove")]
            [String]`$ExistingAccess = "Retain"
    
        )
        
        if (`$Inheritance -like "Enable") {
            `$inh = `$False
        }elseif(`$Inheritance -like "Disable"){
            `$inh = `$True
        }
    
        if (`$ExistingAccess -like "Retain") {
            `$acc = `$True
        }elseif(`$ExistingAccess -like "Remove"){
            `$acc = `$False
        }
    
        try {
            # Get a list of folders and files
            `$Item = Get-Item -Path `$Path -Force -ErrorAction Stop
    
            try {
                # Get the ACL from the item
                `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
    
                # Update the in-memory ACL
                `$Acl.SetAccessRuleProtection(`$inh,`$acc)
    
                try {
                    # Set the updated ACL on the target item
                    Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
                    
                    if ((`$inh -eq `$False) -AND (`$acc -eq `$False)) {
                        try {
                            # Get the ACL from the item
                            `$Acl = Get-Acl -Path `$Item -ErrorAction Stop
                            
                            `$Acl.Access | where{`$_.isinherited -eq `$false} | foreach{
                                `$Acl.RemoveAccessRule(
                                    `$(
                                        if(`$_.identityreference -match "^APPLICATION PACKAGE AUTHORITY\\"){
                                            New-Object System.Security.AccessControl.FileSystemAccessRule((`$_.IdentityReference -replace "^APPLICATION PACKAGE AUTHORITY\\"),`$_.FileSystemRights,`$_.AccessControlType)
                                        }else{
                                            `$_
                                        }
                                    )
                                ) | Out-Null
                            }
    
                            try {
                                # Set the updated ACL on the target item
                                Set-Acl -Path `$Item -AclObject `$Acl -ErrorAction Stop
                            }
                            catch [System.Exception] {
                                throw "Could not set ACL for path. Error Message: `$(`$_)"
                            }
                        }
                        catch [System.Exception] {
                            throw "Could not get ACL from path. Error Message: `$(`$_)"
                        }
                    }
                }
                catch [System.Exception] {
                    throw "Could not set ACL for path. Error Message: `$(`$_)"
                }
            }
            catch [System.Exception] {
                throw "Could not get ACL from path. Error Message: `$(`$_)"
            }
        }
        catch [System.Exception] {
            throw "Could not find path. Error Message: `$(`$_)"
        }
    }
    
    #endregion




    #region Functions
    function Lock-WallpaperFile{
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$File
        )

        Set-NTInheritance -Path `$File -Inheritance Disable -ExistingAccess Remove
        Purge-NTAllAccess -Path `$File
        Add-NTAccess -Path `$File -Principal `$LocalSystemPrincipal -Access ReadAndExecute
        Add-NTAccess -Path `$File -Principal `$LocalAdministratorsPrincipal -Access ReadAndExecute
        Add-NTAccess -Path `$File -Principal `$LocalUsersPrincipal -Access ReadAndExecute
        Add-NTAccess -Path `$File -Principal `$TrustedInstallerPrincipal -Access FullControl
        Add-NTAccess -Path `$File -Principal `$ApplicationPackagesPrincipal -Access ReadAndExecute
        Add-NTAccess -Path `$File -Principal `$RestrictedApplicationPackagesPrincipal -Access ReadAndExecute
        Set-NTOwner -Path `$File -Principal `$TrustedInstallerPrincipal
    }




    function Unlock-WallpaperFile{
        param (
            [Parameter(Mandatory=`$True)]
            [String]`$File
        )

        Set-NTOwner -Path `$File -Principal `$LocalAdministratorsPrincipal
        Add-NTAccess -Path `$File -Principal `$LocalSystemPrincipal -Access FullControl
        Add-NTAccess -Path `$File -Principal `$LocalAdministratorsPrincipal -Access FullControl
        
    }





    function Create-Wallpaperfile{
        param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [String]`$Type
        )

        if (`$Type -like "Desktop") {
            `$FilePath = (Join-Path -Path `$DesktopImagePath -ChildPath `$DesktopImageName)
            `$Base64Code = `$DesktopBase64
        }elseif (`$Type -like "Lockscreen") {
            `$FilePath = (Join-Path -Path `$LockScreenImagePath -ChildPath `$LockScreenImageName)
            `$Base64Code = `$LockScreenBase64
        }

        if(`$Base64Code){
            try {

                # Creates a default wallpaper content file from base64 code embedded in this script
                Write-LogEntry -Value "Creating wallpaper file from embedded Base64 code: `$(`$FilePath)" -Severity 1
                `$Content = [System.Convert]::FromBase64String(`$Base64Code)
                Set-Content -Path `$FilePath -Value `$Content -Encoding Byte -ErrorAction Stop
                Lock-WallpaperFile -File `$FilePath
    
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to create wallpaper file from embedded base 64 code. Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }else {
            Write-LogEntry -Value "This script has no embedded Base 64 code for `$Type wallpaper. Wallpaperfile cannot be created." -Severity 3
        }
    }





    function Set-Wallpaper{
        param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [String]`$Type,

            [parameter(Mandatory = `$False, HelpMessage = "Full path to image file.")]
            [String]`$FilePath
        )

        IF(`$Type -like "Desktop"){

            Write-LogEntry -Value "Setting desktop wallpaper..." -Severity 1

            if(`$FilePath){
                `$Path = `$FilePath
            }else {
                `$Path = (Join-Path -Path `$DesktopImagePath -ChildPath `$DesktopImageName)
            }

            # Check if Wallpaper file exists
            if (Test-Path -Path `$Path -PathType Leaf) {
                
                # Set desktop wallpaper
                Set-AllUsersRegistry -Action EDIT -RegPath "Control Panel\Desktop" -RegPropertyName WallPaper -RegPropertyType String -RegPropertyValue `$Path -IncludeDefaultProfile
                
                # Set desktop wallpaper style to fill
                Set-AllUsersRegistry -Action EDIT -RegPath "Control Panel\Desktop" -RegPropertyName WallpaperStyle -RegPropertyType String -RegPropertyValue 10 -IncludeDefaultProfile

                # Disable desktop wallpaper style tile  
                Set-AllUsersRegistry -Action EDIT -RegPath "Control Panel\Desktop" -RegPropertyName TileWallpaper -RegPropertyType String -RegPropertyValue 0 -IncludeDefaultProfile
                
                ## Programmatically set desktop wallpaper to be applied instantly
                Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                
                public class Params
                {
                    [DllImport("User32.dll",CharSet=CharSet.Unicode)]
                    public static extern int SystemParametersInfo (Int32 uAction,
                                                                Int32 uParam,
                                                                String lpvParam,
                                                                Int32 fuWinIni);
                }
`"@
                
                `$SPI_SETDESKWALLPAPER = 0x0014
                `$UpdateIniFile = 0x01
                `$SendChangeEvent = 0x02
                
                `$fWinIni =`$UpdateIniFile -bor `$SendChangeEvent
                
                `$ret =[Params]::SystemParametersInfo(`$SPI_SETDESKWALLPAPER, 0,`$Path,`$fWinIni)

            }else {
                Write-LogEntry "Failed to set `$Type wallpaper. File does not exist: `$Path" -Severity 3
            }

            
        

        }ELSEIF(`$Type -like "Lockscreen"){

            Write-LogEntry -Value "Setting lock screen wallpaper..." -Severity 1

            if(`$FilePath){
                `$Path = `$FilePath
            }else {
                `$Path = (Join-Path -Path `$LockScreenImagePath -ChildPath `$LockScreenImageName)
            }

            `$DefaultFilePath = (Join-Path -Path `$LockScreenImagePath -ChildPath `$DefaultLockScreenImageName)

            # Check if Wallpaper file exists
            if (Test-Path -Path `$Path -PathType Leaf) {
                ## Replace Windows default lockscreen image file with custom image file
                # Set necessary permission on Windows default lock screen image file to be able to change it
                Unlock-WallpaperFile -File `$Path
                Unlock-WallpaperFile -File `$DefaultFilePath

                # Rename Windows default lock screen image file
                Rename-Item -Path `$DefaultFilePath -NewName "img100_Default.jpg" -Force
                
                # Rename Custom image to Windows default name for lock screen image
                Rename-Item -Path `$Path -NewName `$DefaultLockScreenImageName -Force

                # Restore default permission on Windows default lock screen image file after rename
                Lock-WallpaperFile -File (Join-Path -Path `$LockScreenImagePath -ChildPath "img100_Default.jpg")
                Lock-WallpaperFile -File `$DefaultFilePath


                ## Programmatically set lock screen image to be applied instantly
                [Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,ContentType=WindowsRuntime] | Out-Null

                Add-Type -AssemblyName System.Runtime.WindowsRuntime
                `$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { `$_.Name -eq 'AsTask' -and `$_.GetParameters().Count -eq 1 -and `$_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation``1' })[0]

                Function Await(`$WinRtTask, `$ResultType) {
                    `$asTask = `$asTaskGeneric.MakeGenericMethod(`$ResultType)
                    `$netTask = `$asTask.Invoke(`$null, @(`$WinRtTask))
                    `$netTask.Wait(-1) | Out-Null
                    `$netTask.Result
                }

                Function AwaitAction(`$WinRtAction) {
                    `$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { `$_.Name -eq 'AsTask' -and `$_.GetParameters().Count -eq 1 -and !`$_.IsGenericMethod })[0]
                    `$netTask = `$asTask.Invoke(`$null, @(`$WinRtAction))
                    `$netTask.Wait(-1) | Out-Null
                }

                [Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime] | Out-Null

                `$image = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync(`$DefaultFilePath)) ([Windows.Storage.StorageFile])

                AwaitAction ([Windows.System.UserProfile.LockScreen]::SetImageFileAsync(`$image))

            }else {
                Write-LogEntry "Failed to set `$Type wallpaper. File does not exist: `$Path" -Severity 3
            }
        }
    }





    function Restrict-Wallpaper{
        Param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [ValidateNotNullOrEmpty()]
            [String]`$Type
        )

        Write-LogEntry -Value "Restricting `$Type wallpaper..." -Severity 1

        `$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
        IF(`$Type -like "Desktop"){
            `$FilePath = (Join-Path -Path `$DesktopImagePath -ChildPath `$DesktopImageName)
            `$WallpaperPath = "DesktopImagePath"
            `$WallpaperStatus = "DesktopImageStatus"
            `$WallpaperUrl = "DesktopImageUrl"
        }ELSEIF(`$Type -like "Lockscreen"){
            `$FilePath = (Join-Path -Path `$LockScreenImagePath -ChildPath `$DefaultLockScreenImageName)
            `$WallpaperPath = "LockScreenImagePath"
            `$WallpaperStatus = "LockScreenImageStatus"
            `$WallpaperUrl = "LockScreenImageUrl"
        }

        # Check if Wallpaper file exists
        if (Test-Path -Path `$FilePath -PathType Leaf) {
        
            `$WallpaperImageValue = `$FilePath

            try {
                IF (!(Test-Path `$RegKeyPath)) {
                    New-Item -Path `$RegKeyPath -Force -ErrorAction Stop | Out-Null
                }
                    
                try {
                    New-ItemProperty -Path `$RegKeyPath -Name `$WallpaperStatus -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -Path `$RegKeyPath -Name `$WallpaperPath -Value `$WallpaperImageValue -PropertyType STRING -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -Path `$RegKeyPath -Name `$WallpaperUrl -Value `$WallpaperImageValue -PropertyType STRING -Force -ErrorAction Stop | Out-Null

                    RUNDLL32.EXE USER32.DLL, UpdatePerUserSystemParameters 1, True

                }catch [System.Exception] {
                    Write-LogEntry "Failed to set a registry key property" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry "Failed to create registry path registry path: `$(`$RegKeyPath)" -Severity 3
            }
        }else {
            Write-LogEntry "Failed to restrict `$Type wallpaper. File does not exist: `$FilePath" -Severity 3
        }
    }






    function Unrestrict-Wallpaper{
        Param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [ValidateNotNullOrEmpty()]
            [String]`$Type
        )

        Write-LogEntry -Value "Unrestricting `$Type wallpaper..." -Severity 1

        `$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
        IF(`$Type -like "Desktop"){
            `$WallpaperPath = "DesktopImagePath"
            `$WallpaperStatus = "DesktopImageStatus"
            `$WallpaperUrl = "DesktopImageUrl"
        }ELSEIF(`$Type -like "Lockscreen"){
            `$WallpaperPath = "LockScreenImagePath"
            `$WallpaperStatus = "LockScreenImageStatus"
            `$WallpaperUrl = "LockScreenImageUrl"
        }

        Foreach(`$Item in @(`$WallpaperPath,`$WallpaperStatus,`$WallpaperUrl)){
            try {
                IF(Get-ItemProperty -Path `$RegKeyPath -Name `$Item -ErrorAction SilentlyContinue){
                    Remove-ItemProperty -Path `$RegKeyPath -Name `$Item -Force -ErrorAction Stop
                }ELSE{
                    Write-LogEntry "The registry key property `$(Join-Path -Path `$RegKeyPath -ChildPath `$Item) can't be deleted because it doesn't exist." -Severity 1
                }
            }
            catch [System.Exception] {
                Write-LogEntry "Failed to remove the registry key property `$(Join-Path -Path `$RegKeyPath -ChildPath `$Item). Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }

        RUNDLL32.EXE USER32.DLL, UpdatePerUserSystemParameters 1, True
    }





    function Restore-Wallpaper {
        param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [String]`$Type
        )

        Clear-Variable FilePath -ErrorAction SilentlyContinue

        if (`$Type -like "Desktop") {
            `$FilePath = (Join-Path -Path `$DesktopImagePath -ChildPath `$DesktopImageName)
            
            `$Check = Test-Path -Path `$FilePath

            if (`$Check) {
                Set-WallPaper -Type Desktop -FilePath (Join-Path -Path `$DesktopImagePath -ChildPath `$DefaultDesktopImageName)
                Unlock-WallpaperFile -File `$FilePath
            }else {
                Write-LogEntry -Value "Desktop wallpaper file '`$FilePath' does not exist." -Severity 2
                Write-LogEntry -Value "Desktop image will not be restored." -Severity 2
            }

        }elseif (`$Type -like "Lockscreen") {
            `$DefaultFilePath = (Join-Path -Path `$LockScreenImagePath -ChildPath `$DefaultLockScreenImageName)
            `$BackupFilePath = (Join-Path -Path `$LockScreenImagePath -ChildPath "img100_Default.jpg")
            
            `$Check = Test-Path `$BackupFilePath

            if(`$Check){
                Unlock-WallpaperFile -File `$DefaultFilePath
                Unlock-WallpaperFile -File `$BackupFilePath
                Rename-Item -Path `$DefaultFilePath -NewName `$LockScreenImageName -Force
                Rename-Item -Path `$BackupFilePath -NewName `$DefaultLockScreenImageName -Force
                Lock-WallpaperFile -File `$DefaultFilePath

                # Set Windows Spotlight
                `$RegProperties = @("RotatingLockScreenEnabled","RotatingLockScreenOverlayEnabled","ContentDeliveryAllowed","SubscribedContent-338388Enabled","SubscribedContent-338389Enabled")
                Foreach(`$Item in `$RegProperties){
                    Set-AllUsersRegistry -Action EDIT -RegPath "Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegPropertyName `$Item -RegPropertyValue 1 -IncludeDefaultProfile
                }

                `$FilePath = (Join-Path -Path `$LockScreenImagePath -ChildPath `$LockScreenImageName)
            }else {
                Write-LogEntry -Value "Backup lock screen wallpaper file '`$BackupFilePath' does not exist." -Severity 2
                Write-LogEntry -Value "Lock screen image will not be restored." -Severity 2
            }
        }

        if(`$Check){
            try {
                Write-LogEntry -Value "Removing wallpaper file: `$FilePath" -Severity 1
                Remove-Item -Path `$FilePath -Force -ErrorAction Stop
                Write-LogEntry -Value "Wallpaper file successfully removed!" -Severity 1
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to remove wallpaper image file '`$FilePath'. Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }
    }


#endregion



#=============================================================================================================================================================================
#=============================================================================================================================================================================

    ### Run functions ###

    IF(`$RestoreDefault){
        ### Restore Desktop
            
            # Remove desktop wallpaper file and potential forced wallpaper restriction 
            Unrestrict-Wallpaper -Type Desktop
            Restore-Wallpaper -Type Desktop

        ### Restore Lockscreen
            
            # Remove lock screen wallpaper file and potential forced wallpaper restriction
            Unrestrict-Wallpaper -Type Lockscreen
            Restore-Wallpaper -Type Lockscreen

    }ELSEIF(`$WallpaperType){
        
        IF((`$WallpaperType -like "ALL") -OR (`$WallpaperType -like "DesktopOnly")){
        ### Desktop Wallpaper
            
            # Creates new image in `$DesktopImagePath folder from embedded base64 code. 
            Create-Wallpaperfile -Type Desktop

            IF((`$Restrict -like "ALL") -OR (`$Restrict -like "DesktopOnly")){
            ### Restricted Desktop Wallpaper
                
                # Apply wallpaper restriction
                Restrict-Wallpaper -Type Desktop

            }ELSE{
            ### Unrestricted Desktop Wallpaper
                
                # Remove forced wallpaper restriction
                Unrestrict-Wallpaper -Type Desktop

                # Sets custom image as desktop wallpaper
                Set-Wallpaper -Type Desktop
            
            }
        }

        IF((`$WallpaperType -like "ALL") -OR (`$WallpaperType -like "LockscreenOnly")){
        ### LockScreen Wallpaper
            
            # Creates new image in `$LockScreenImagePath folder from embedded base64 code. 
            Create-Wallpaperfile -Type Lockscreen

            IF((`$Restrict -like "ALL") -OR (`$Restrict -like "LockscreenOnly")){
            ### Restricted Lockscreen Wallpaper
                
                # Apply wallpaper restriction
                Restrict-Wallpaper -Type Lockscreen

            }ELSE{
            ### Unrestricted Lockscreen Wallpaper
                
                # Remove forced wallpaper restriction
                Unrestrict-Wallpaper -Type Lockscreen

                # Sets custom image as lock screen wallpaper
                Set-Wallpaper -Type Lockscreen

            }
        }
    }
}
"@


New-Item -Path $ScriptPath -Name "$FileName.ps1" -ItemType File -Value $PSScript -Force