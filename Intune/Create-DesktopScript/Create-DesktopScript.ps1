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


<# Install required modules for script execution
$Modules = @("PS2EXE")
foreach ($Module in $Modules) {
    try {
        $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction Stop -Verbose:$false
        if ($CurrentModule -ne $null) {
            $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction Stop -Verbose:$false).Version
            if ($LatestModuleVersion -gt $CurrentModule.Version) {
                $UpdateModuleInvocation = Update-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    }
    catch [System.Exception] {
        try {
            # Install NuGet package provider
            $PackageProvider = Install-PackageProvider -Name NuGet -Force -ErrorAction Stop -Verbose:$false -Scope CurrentUser
        
            # Install current missing module
            Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false -Scope CurrentUser
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
            Break
        }
    }
}
#>



Function Browse-File {
    Param(
        [String]$Title = "Choose an image"
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    #$FileBrowser.filter = 'All files (*.png;*.jpg;*.jpeg;*.jpe;*.jfif)|*.png;*.jpg;*.jpeg;*.jpe;*.jfif|PNG file (*.PNG)|*.png|JPEG file (*.jpg;*.jpeg;*.jpe;*.jfif)|*.jpg;*.jpeg;*.jpe;*.jfif' 
    $FileBrowser.filter = 'JPEG file (*.jpg;*.jpeg;*.jpe;*.jfif)|*.jpg;*.jpeg;*.jpe;*.jfif' 
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

$encoding = [System.Text.Encoding]::ASCII

IF(($WallpaperType -like "ALL") -OR ($WallpaperType -like "DesktopOnly")){
    Write-Verbose "Choose a Desktop wallpaper image" -Verbose

    [String]$DesktopFile = Browse-File -Title "Choose a Desktop wallpaper image"
    If([string]::IsNullOrEmpty($DesktopFile)){
        Break
    }

    $DesktopContent = Get-Content -Path $DesktopFile -Encoding Byte
    $DesktopBase64 = [System.Convert]::ToBase64String($DesktopContent)
}


IF(($WallpaperType -like "ALL") -OR ($WallpaperType -like "LockscreenOnly")){
    Write-Verbose "Choose a Lockscreen wallpaper image" -Verbose

    [String]$LockscreenFile = Browse-File -Title "Choose a Lockscreen wallpaper image"
    If([string]::IsNullOrEmpty($LockscreenFile)){
        Break
    }

    $LockscreenContent = Get-Content -Path $LockscreenFile -Encoding Byte
    $LockscreenBase64 = [System.Convert]::ToBase64String($LockscreenContent)

}

$PSScript = @"
<#
.SYNOPSIS
    Replace the default img0.jpg desktop wallpaper image in Windows 10, by creating a new image embedded in this script.
    Replace the default img100.jpg lockscreen wallpaper image in Windows 10, by creating a new image embedded in this script.
    Option to force and restrict wallpaper on local device using 'PersonalizationCSP'.

.DESCRIPTION
    Backups and replaces the default Windows 10 wallpaper images by creating a new image that is embedded in this script.
    The new image has already been embedded in this script by another script. Option to force and restrict wallpaper on local device is available using registry key 'PersonalizationCSP'. 

.PARAMETER Scope
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
    
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    
    IF(!`$WallpaperType){
        Throw 'The parameter WallpaperType needs to be provided.'
        Exit 9999
    }

    # Install required modules for script execution
    `$Modules = @("NTFSSecurity")
    foreach (`$Module in `$Modules) {
        try {
            `$CurrentModule = Get-InstalledModule -Name `$Module -ErrorAction Stop -Verbose:`$false
            if (`$CurrentModule -ne `$null) {
                `$LatestModuleVersion = (Find-Module -Name `$Module -ErrorAction Stop -Verbose:`$false).Version
                if (`$LatestModuleVersion -gt `$CurrentModule.Version) {
                    `$UpdateModuleInvocation = Update-Module -Name `$Module -Force -ErrorAction Stop -Confirm:`$false -Verbose:`$false
                }
            }
        }
        catch [System.Exception] {
            try {
                # Install NuGet package provider
                `$PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:`$false
        
                # Install current missing module
                Install-Module -Name `$Module -Force -ErrorAction Stop -Confirm:`$false -Verbose:`$false
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while attempting to install `$(`$Module) module. Error message: `$(`$_.Exception.Message)"
            }
        }
    }

    # Determine the localized name of the principals required for the functionality of this script
    [String]`$LocalAdministratorsPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate( [System.Security.Principal.NTAccount]).Value
    [String]`$LocalUsersPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate( [System.Security.Principal.NTAccount]).Value
    [String]`$ApplicationPackagesPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-15-2-1').Translate( [System.Security.Principal.NTAccount]).Value -replace "^.*\\"
    [String]`$RestrictedApplicationPackagesPrincipal = ([System.Security.Principal.SecurityIdentifier]'S-1-15-2-2').Translate( [System.Security.Principal.NTAccount]).Value -replace "^.*\\"
    [String]`$LocalSystemPrincipal = "NT AUTHORITY\SYSTEM"
    [String]`$TrustedInstallerPrincipal = "NT SERVICE\TrustedInstaller"
    `$BackupFolderName = "DefaultBackup"
    
    `$DefaultWallpaperFolderPath = Join-Path -Path `$env:windir -ChildPath "Web\Wallpaper\Windows"
    `$DefaultThemeFolder = Join-Path -Path `$env:windir -ChildPath "Web\Wallpaper\Theme1"
    `$Default4KWallpaperFolderPath = Join-Path -Path `$env:windir -ChildPath "Web\4K\Wallpaper\Windows"
    `$DefaultLockScreenFolderPath = Join-Path -Path `$env:windir -ChildPath "Web\Screen"
    
    `$EmbeddedDesktopFileName = "img0.jpg"
    `$EmbeddedLockScreenFileName = "img100.jpg"
    `$DesktopBase64 = @'
$DesktopBase64
'@
    `$LockScreenBase64 = @'
$LockScreenBase64
'@
}

#=============================================================================================================================================================================
#=============================================================================================================================================================================

Process {
    
    #region Functions
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




    function Remove-WallpaperFile {
        param(
            [parameter(Mandatory = `$false, HelpMessage = "Full path to the image file to be removed.")]
            [ValidateNotNullOrEmpty()]
            [string]`$FileName = "*",

            [parameter(Mandatory = `$true, HelpMessage = "Destination directory for the image file.")]
            [ValidateNotNullOrEmpty()]
            [string]`$Destination
        )

        `$BackupFolder = Join-Path -Path `$Destination -ChildPath `$BackupFolderName
        `$FullFilePath = Join-Path -Path `$Destination -ChildPath `$FileName

        Write-LogEntry -Value "Starting process to remove wallpaper file: `$FullFilePath" -Severity 1

        Write-LogEntry -Value "Checking if default backup exists before proceeding image deletion." -Severity 1
        IF(Get-ChildItem `$BackupFolder -File -ErrorAction SilentlyContinue){
            `$ImageItems = Get-ChildItem -Path `$FullFilePath -File -ErrorAction SilentlyContinue
            Foreach (`$Item in `$ImageItems){
                try {
                    # Take ownership of the wallpaper file
                    Write-LogEntry -Value "Determining if ownership needs to be changed for file: `$(`$Item.FullName)" -Severity 1
                    `$CurrentOwner = Get-Item -Path `$Item.FullName | Get-NTFSOwner
                    if (`$CurrentOwner.Owner -notlike `$LocalAdministratorsPrincipal) {
                        Write-LogEntry -Value "Amending owner as '`$(`$LocalAdministratorsPrincipal)' temporarily for: `$(`$Item.FullName)" -Severity 1
                        Set-NTFSOwner -Path `$Item.FullName -Account `$LocalAdministratorsPrincipal -ErrorAction Stop
                    }

                    try {
                        # Grant local Administrators group and system full control
                        Write-LogEntry -Value "Granting '`$(`$LocalSystemPrincipal)' Full Control on: `$(`$Item.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$Item.FullName -Account `$LocalSystemPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$LocalAdministratorsPrincipal)' Full Control on: `$(`$Item.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$Item.FullName -Account `$LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop

                        try {
                            # Remove existing local default wallpaper file
                            Write-LogEntry -Value "Attempting to remove existing default wallpaper image file: `$(`$Item.FullName)" -Severity 1
                            Remove-Item -Path `$Item.FullName -Force -ErrorAction Stop
                            Write-LogEntry -Value "Wallpaper file successfully removed!" -Severity 1
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to remove wallpaper image file '`$(`$Item.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                        }                    
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to grant Administrators and local system with full control for wallpaper image file. Error message: `$(`$_.Exception.Message)" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to take ownership of '`$(`$Item.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }
        }ELSE{
        
            Write-LogEntry -Value "No backup found. Deletion aborted!" -Severity 3

        }
    }




    function Create-Wallpaperfile{
        param(
            [parameter(Mandatory = `$true, HelpMessage = "Name of the image file to be created.")]
            [ValidateNotNullOrEmpty()]
            [string]`$FileName,

            [parameter(Mandatory = `$true, HelpMessage = "Destination directory for the image file.")]
            [ValidateNotNullOrEmpty()]
            [string]`$Destination,

            [parameter(Mandatory = `$true, HelpMessage = "Base64 code for chosen wallpaper.")]
            [ValidateNotNullOrEmpty()]
            [string]`$Base64Code
        )
        
        `$BackupFolder = "`$Destination\`$BackupFolderName"
        `$WallpaperImageFilePath = Join-Path -Path `$Destination -ChildPath `$FileName

        Write-LogEntry -Value "Starting process to create wallpaper file from base64 code: `$WallpaperImageFilePath" -Severity 1

        Write-LogEntry -Value "Checking if backup folder exists before creating and replacing wallpaper image." -Severity 1
        IF(Get-ChildItem `$BackupFolder -File -ErrorAction SilentlyContinue){
        
            try {
                # Creates a default wallpaper content file from base64 code embedded in this script
                Write-LogEntry -Value "Creating content file from embedded Base64 code: `$(`$FileName)" -Severity 1
                `$Content = [System.Convert]::FromBase64String(`$Base64Code)
                Set-Content -Path `$WallpaperImageFilePath -Value `$Content -Encoding Byte -ErrorAction Stop

                try {
                    # Grant non-inherited permissions for wallpaper item
                    Write-LogEntry -Value "Granting '`$(`$LocalSystemPrincipal)' Read and Execute on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Add-NTFSAccess -Path `$WallpaperImageFilePath -Account `$LocalSystemPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                    Write-LogEntry -Value "Granting '`$(`$LocalAdministratorsPrincipal)' Read and Execute on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Add-NTFSAccess -Path `$WallpaperImageFilePath -Account `$LocalAdministratorsPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                    Write-LogEntry -Value "Granting '`$(`$LocalUsersPrincipal)' Read and Execute on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Add-NTFSAccess -Path `$WallpaperImageFilePath -Account `$LocalUsersPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                    Write-LogEntry -Value "Granting '`$(`$ApplicationPackagesPrincipal)' Read and Execute on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Add-NTFSAccess -Path `$WallpaperImageFilePath -Account `$ApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                    Write-LogEntry -Value "Granting '`$(`$RestrictedApplicationPackagesPrincipal)' Read and Execute on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Add-NTFSAccess -Path `$WallpaperImageFilePath -Account `$RestrictedApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                    Write-LogEntry -Value "Granting '`$(`$TrustedInstallerPrincipal)' Full Control on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Add-NTFSAccess -Path `$WallpaperImageFilePath -Account `$TrustedInstallerPrincipal -AccessRights "FullControl" -ErrorAction Stop
                    Write-LogEntry -Value "Disabling inheritance on: `$(`$WallpaperImageFilePath)" -Severity 1
                    Disable-NTFSAccessInheritance -Path `$WallpaperImageFilePath -RemoveInheritedAccessRules -ErrorAction Stop

                    try {
                        # Set owner to trusted installer for new wallpaper file
                        Write-LogEntry -Value "Setting ownership for '`$(`$TrustedInstallerPrincipal)' on wallpaper image file: `$(`$WallpaperImageFilePath)" -Severity 1
                        Set-NTFSOwner -Path `$WallpaperImageFilePath -Account `$TrustedInstallerPrincipal -ErrorAction Stop
                        Write-LogEntry -Value "Wallpaper file successfully created!" -Severity 1
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to set ownership for '`$(`$TrustedInstallerPrincipal)' on wallpaper image file: `$(`$WallpaperImageFilePath). Error message: `$(`$_.Exception.Message)" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to revert permissions for wallpaper image file. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to create image from embedded base code. Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }ELSE{
            
            Write-LogEntry -Value "No backup folder found, wallpaper image creation aborted!" -Severity 3
            
        }
    }
    





    function Backup-Wallpaperfile {
        param(
            [parameter(Mandatory = `$false, HelpMessage = "Name of the image file.")]
            [ValidateNotNullOrEmpty()]
            [string]`$FileName = "*",
            
            [parameter(Mandatory = `$true, HelpMessage = "Destination directory for the image file.")]
            [ValidateNotNullOrEmpty()]
            [string]`$Destination
        )
        
        `$DefaultBackupPath = Join-Path -Path `$Destination -ChildPath `$BackupFolderName
        `$FullFilePath = Join-Path -Path `$Destination -ChildPath `$FileName

        Write-LogEntry -Value "Starting process to backup default wallpaper file(s): `$FullFilePath" -Severity 1

        # Backup default wallpaper files
        Write-LogEntry -Value "Checking if backup folder for Windows default wallpapers exists: `$DefaultBackupPath" -Severity 1
        IF(!(Test-Path `$DefaultBackupPath)){
            Write-LogEntry -Value "Backup folder from default Windows wallpapers does not exist: `$DefaultBackupPath" -Severity 1
            Write-LogEntry -Value "Creating backups of current wallpaper(s) in a Backup folder: `$DefaultBackupPath" -Severity 1
            try{
                New-Item -Path `$DefaultBackupPath -ItemType Directory -Force -ErrorAction Stop
            
                Get-ChildItem `$FullFilePath -File | Foreach{
                    try{
                        Copy-Item `$_.FullName -Destination (Join-Path -Path `$DefaultBackupPath -ChildPath `$_.Name) -Force -ErrorAction Stop
                        Write-LogEntry -Value "Backup successfully completed!" -Severity 1
                    }catch [System.Exception] {
                        Write-LogEntry -Value "Failed to backup default windows wallpaper. '`$(`$_.FullName)' Error message: `$(`$_.Exception.Message)" -Severity 3
                    }
                }
            } catch [System.Exception] {
                Write-LogEntry -Value "Failed to create backup folder '`$(`$DefaultBackupPath)'. Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }ELSE{
            Write-LogEntry -Value "Windows default wallpaper backup already exists. Skipping backup." -Severity 1
        }
    }








    function Restore-DefaultWallpaperFile {
        param(
            [parameter(Mandatory = `$true, HelpMessage = "Destination directory for the main wallpaper location.")]
            [ValidateNotNullOrEmpty()]
            [string]`$Destination,

            [parameter(Mandatory = `$false, HelpMessage = "Deletes backup.")]
            [Switch]`$DeleteBackup
            )
        
        `$DefaultBackupPath = Join-Path -Path `$Destination -ChildPath `$BackupFolderName
        `$BackupWallpapers = Get-ChildItem `$DefaultBackupPath -File -ErrorAction SilentlyContinue
        `$CurrentWallpapers = Get-ChildItem `$Destination -File -ErrorAction SilentlyContinue
        
        Write-LogEntry -Value "Starting process of restoring default wallpaper from backup: `$DefaultBackupPath" -Severity 1
        
        IF(`$BackupWallpapers){
            Write-LogEntry -Value "Removing current wallpapers and restoring Windows default wallpapers from backup folder: `$(`$DefaultBackupPath)" -Severity 1
            Foreach(`$Item in `$CurrentWallpapers){
                try {
                        `$CurrentOwner = Get-Item -Path `$Item.FullName -ErrorAction Stop | Get-NTFSOwner -ErrorAction Stop
                        if (`$CurrentOwner.Owner -notlike `$LocalAdministratorsPrincipal) {
                            Write-LogEntry -Value "Amending owner as '`$(`$LocalAdministratorsPrincipal)' temporarily for: `$(`$Item.FullName)" -Severity 1
                            Set-NTFSOwner -Path `$Item.FullName -Account `$LocalAdministratorsPrincipal -ErrorAction Stop
                        }

                        try {
                            # Grant local Administrators group and system full control
                            Write-LogEntry -Value "Granting '`$(`$LocalSystemPrincipal)' Full Control on: `$(`$Item.FullName)" -Severity 1
                            Add-NTFSAccess -Path `$Item.FullName -Account `$LocalSystemPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                            Write-LogEntry -Value "Granting '`$(`$LocalAdministratorsPrincipal)' Full Control on: `$(`$Item.FullName)" -Severity 1
                            Add-NTFSAccess -Path `$Item.FullName -Account `$LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop

                            try {
                                # Renaming and moving existing local default wallpaper file
                                Write-LogEntry -Value "Attempting to remove existing wallpaper image file: `$(`$Item.FullName)" -Severity 1
                                Remove-Item -Path `$Item.FullName -Force -ErrorAction Stop
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to remove wallpaper image file '`$(`$Item.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                            }                    
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to grant Administrators and local system with full control for wallpaper image file. Error message: `$(`$_.Exception.Message)" -Severity 3
                        }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to take ownership of '`$(`$Item.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }

            Write-LogEntry -Value "Restoring Windows default wallpapers from backup folder: `$DefaultBackupPath" -Severity 1

            Foreach(`$Item in `$BackupWallpapers){
                try{
                    `$NewItem = Copy-Item -Path `$Item.FullName -Destination `$Destination -Force -PassThru -ErrorAction Stop

                    try{
                        # Grant non-inherited permissions for wallpaper item
                        Write-LogEntry -Value "Setting '`$(`$TrustedInstallerPrincipal)' as Owner on: `$(`$NewItem.FullName)" -Severity 1
                        Set-NTFSOwner -Path `$NewItem.FullName -Account `$TrustedInstallerPrincipal -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$LocalSystemPrincipal)' Read and Execute on: `$(`$NewItem.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$NewItem.FullName -Account `$LocalSystemPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$LocalAdministratorsPrincipal)' Read and Execute on: `$(`$NewItem.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$NewItem.FullName -Account `$LocalAdministratorsPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$LocalUsersPrincipal)' Read and Execute on: `$(`$NewItem.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$NewItem.FullName -Account `$LocalUsersPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$ApplicationPackagesPrincipal)' Read and Execute on: `$(`$NewItem.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$NewItem.FullName -Account `$ApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$RestrictedApplicationPackagesPrincipal)' Read and Execute on: `$(`$NewItem.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$NewItem.FullName -Account `$RestrictedApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                        Write-LogEntry -Value "Granting '`$(`$TrustedInstallerPrincipal)' Full Control on: `$(`$NewItem.FullName)" -Severity 1
                        Add-NTFSAccess -Path `$NewItem.FullName -Account `$TrustedInstallerPrincipal -AccessRights "FullControl" -ErrorAction Stop
                        Write-LogEntry -Value "Disabling inheritance on: `$(`$NewItem.FullName)" -Severity 1
                        Disable-NTFSAccessInheritance -Path `$NewItem.FullName -RemoveInheritedAccessRules -ErrorAction Stop

                        Write-LogEntry -Value "Backup successfully restored!" -Severity 1
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to set default permissions on wallpaper image file '`$(`$NewItem.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                    }
                }
                Catch [System.Exception] {
                    Write-LogEntry -Value "Failed to copy backup wallpaper image file to destination '`$(`$NewItem.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }

            IF(`$DeleteBackup){
                try{
                    Remove-Item -Path `$DefaultBackupPath -Recurse -Force -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to delete default backup '`$(`$NewItem.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }

        }ELSE{
            Write-LogEntry -Value "`$BackupFolderName backup folder was not found. Restore failed: `$DefaultBackupPath" -Severity 3
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






    function Update-Wallpaper{
        param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [String]`$Type
        )

        IF(`$Type -like "Desktop"){

            try{
                Write-LogEntry -Value "Starting process of updating desktop wallpaper cache" -Severity 1
                `$AllUsers = Get-ChildItem -Path C:\Users -Exclude Public -Directory -ErrorAction Stop
                `$FilePath = (Join-Path -Path `$DefaultWallpaperFolderPath -ChildPath `$EmbeddedDesktopFileName)
                Write-LogEntry -Value "Looping users to update cached image with new wallpaper: `$FilePath" -Severity 1
                Foreach(`$User in `$AllUsers.Name){
                    Write-LogEntry -Value "Processing user: `$User" -Severity 1
                    `$CacheFolder = "C:\Users\`$User\AppData\Roaming\Microsoft\Windows\Themes"
                    `$CachedImage = Get-ChildItem "`$CacheFolder\CachedFiles\CachedImage*" -File -Force -ErrorAction SilentlyContinue
            
                    IF(`$CachedImage.Count -eq 1){
                        try{
                            Copy-Item -Path `$FilePath -Destination "`$CacheFolder\CachedFiles\`$(`$CachedImage.Name)" -Force -ErrorAction Stop
                            Copy-Item -Path `$FilePath -Destination "`$CacheFolder\TranscodedWallpaper" -Force -ErrorAction Stop
                            Write-LogEntry -Value "Desktop Wallpaper cache update is successfully done!" -Severity 1
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to copy wallpaper image file to destination. Error message: `$(`$_.Exception.Message)" -Severity 3
                        }
                    }ELSEIF(`$CachedImage.Count -gt 1){
                        Write-LogEntry -Value "More than one cached image was found. Aborting and skipping to next user." -Severity 2
                    }ELSE{
                        Write-LogEntry -Value "No cached image was found. Aborting and skipping to next user." -Severity 2
                    }
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Unable to get any userprofiles. Aborting Wallpaper update." -Severity 3
            }
            # Remove registry values to remove cached desktop wallpaper
            `$RegProperties = @("TranscodedImageCache","TranscodedImageCache_000","TranscodedImageCount")
            Foreach(`$Item in `$RegProperties){
                Set-AllUsersRegistry -Action DELETE -RegPath "Control Panel\Desktop" -RegPropertyName `$Item
            }

        }ELSE{
            Write-LogEntry -Value "Starting process of updating lockscreen cache" -Severity 1
            `$LockPath = Join-Path -Path `$env:ProgramData -ChildPath "Microsoft\Windows"
            `$SubFolders = @("SystemData","S-1-5-18","ReadOnly")
            
            try{
                
                Foreach(`$Folder in `$SubFolders){
                    `$LockPath = Join-Path -Path `$LockPath -ChildPath `$Folder
                    Write-LogEntry -Value "Taking ownership and granting full control to Administrators: `$LockPath" -Severity 1
                    Set-NTFSOwner -Path `$LockPath -Account `$LocalAdministratorsPrincipal -ErrorAction Stop
                    Add-NTFSAccess -Path `$LockPath -Account `$LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                }

                try{
                    Write-LogEntry -Value "Fetching all 'LockScreen_*' folders: '`$LockPath'" -Severity 1
                    `$LockFolders = Get-ChildItem `$LockPath -Filter "LockScreen_*" -Directory -Force -ErrorAction Stop
                    
                    Foreach(`$Folder in `$LockFolders){
                        try{
                            Write-LogEntry -Value "Taking ownership and granting full control to Administrators: `$(`$Folder.FullName)" -Severity 1
                            Set-NTFSOwner -Path `$Folder.FullName -Account `$LocalAdministratorsPrincipal -ErrorAction Stop
                            Add-NTFSAccess -Path `$Folder.FullName -Account `$LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                            
                            Write-LogEntry -Value "Fetching all files in folder: `$(`$Folder.FullName)" -Severity 1
                            try{
                                Get-ChildItem `$Folder.FullName -ErrorAction Stop | Foreach{
                                    try{
                                        Write-LogEntry -Value "Taking ownership and granting full control to Administrators: `$(`$_.FullName)" -Severity 1
                                        Set-NTFSOwner -Path `$_.FullName -Account `$LocalAdministratorsPrincipal -ErrorAction Stop
                                        Add-NTFSAccess -Path `$_.FullName -Account `$LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                                     }
                                     catch [System.Exception] {
                                        Write-LogEntry -Value "Failed to take ownership and grant administrators full control to the files under '`$(`$Folder.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                                     }
                                }
                                try{
                                    Remove-Item `$Folder.FullName -Recurse -Force -ErrorAction Stop
                                    Write-LogEntry -Value "Successfully deleted lockscreen cache folder: `$(`$Folder.FullName)" -Severity 1
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "Failed to delete folder '`$(`$Folder.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to get all files in '`$(`$Folder.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to take ownership and grant administrators full control to '`$(`$Folder.FullName)'. Error message: `$(`$_.Exception.Message)" -Severity 3
                        }
                    }

                    Write-LogEntry -Value "Resetting permissions to folder path." -Severity 1

                    Try{
                        1..3 | foreach{
                            Write-LogEntry -Value "Clears all permissions, granting SYSTEM ownership and full controll to SYSTEM and TRUSTEDINSTALLER on This Folder Only: `$LockPath" -Severity 1
                            Clear-NTFSAccess -Path `$LockPath -DisableInheritance -ErrorAction Stop
                            Add-NTFSAccess -Path `$LockPath -Account `$LocalSystemPrincipal -AccessRights "FullControl" -AccessType "Allow" -AppliesTo "ThisFolderOnly" -ErrorAction Stop
                            Add-NTFSAccess -Path `$LockPath -Account `$TrustedInstallerPrincipal -AccessRights "FullControl" -AccessType "Allow" -AppliesTo "ThisFolderOnly" -ErrorAction Stop
                            Set-NTFSOwner -Path `$LockPath -Account `$LocalSystemPrincipal -ErrorAction Stop
                            `$LockPath = Split-Path -Path `$LockPath -Parent
                        }
                        Write-LogEntry -Value "All permissions where successfully reset on folder path" -Severity 1
                        Write-LogEntry -Value "Wallpaper cache update is done!" -Severity 1
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to reset ownership and permission on '`$(`$LockPath)'. Error message: `$(`$_.Exception.Message)" -Severity 2
                        Write-LogEntry -Value "Folder path will reset ownership and permission on next reboot." -Severity 1
                    }

                    IF(`$RestoreDefault){
                        `$RegValue = 1
                    }ELSEIF((`$WallpaperType -like "ALL") -OR (`$WallpaperType -like "LockscreenOnly")){
                        `$RegValue = 0
                    }
                    # Set registry values to update lockscreen wallpaper
                    `$RegProperties = @("RotatingLockScreenEnabled","RotatingLockScreenOverlayEnabled","ContentDeliveryAllowed","SubscribedContent-338388Enabled","SubscribedContent-338389Enabled")
                    Foreach(`$Item in `$RegProperties){
                        Set-AllUsersRegistry -Action EDIT -RegPath "Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegPropertyName `$Item -RegPropertyValue `$RegValue -IncludeDefaultProfile
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to get all lockscreen folders in '`$LockPath'. Error message: `$(`$_.Exception.Message)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to take ownership and grant administrators full control to '`$LockPath'. Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }
    }







    function Restrict-Wallpaper{
        Param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [ValidateNotNullOrEmpty()]
            [String]`$Type,
            
            [parameter(Mandatory = `$true, HelpMessage = "File path of the image.")]
            [ValidateNotNullOrEmpty()]
            [string]`$FilePath
        )

         Write-LogEntry -Value "Restricting `$Type wallpaper." -Severity 1

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

        `$StatusValue = "1"
        `$WallpaperImageValue = `$FilePath

        try {
            IF (!(Test-Path `$RegKeyPath)) {
                New-Item -Path `$RegKeyPath -Force -ErrorAction Stop | Out-Null
            }
                
            try {
                New-ItemProperty -Path `$RegKeyPath -Name `$WallpaperStatus -Value `$Statusvalue -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
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
    }




    function Unrestrict-Wallpaper{
        Param(
            [parameter(Mandatory = `$True, HelpMessage = "Choose wallpaper type.")]
            [ValidateSet("Desktop","Lockscreen")]
            [ValidateNotNullOrEmpty()]
            [String]`$Type
        )

        Write-LogEntry -Value "Unrestricting `$Type wallpaper." -Severity 1

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
                    Write-LogEntry "The registry key property `$(Join-Path -Path `$RegKeyPath -ChildPath `$Item) can't be deleted because it doesn't exist." -Severity 2
                }
            }
            catch [System.Exception] {
                Write-LogEntry "Failed to remove the registry key property `$(Join-Path -Path `$RegKeyPath -ChildPath `$Item). Error message: `$(`$_.Exception.Message)" -Severity 3
            }
        }

        RUNDLL32.EXE USER32.DLL, UpdatePerUserSystemParameters 1, True
    }

#endregion



#=============================================================================================================================================================================
#=============================================================================================================================================================================

    IF(`$RestoreDefault){
        ### Restore Desktop
            # Remove potential forced wallpaper restriction
            Unrestrict-Wallpaper -Type Desktop

            # Restore deafult Windows desktop wallpaper
            Restore-DefaultWallpaperFile -Destination `$DefaultWallpaperFolderPath -DeleteBackup
            Restore-DefaultWallpaperFile -Destination `$Default4KWallpaperFolderPath -DeleteBackup

            `$ThemeImagePath = (Join-Path -Path `$DefaultThemeFolder -ChildPath `$EmbeddedDesktopFileName)
            Remove-Item `$ThemeImagePath -Force -ErrorAction SilentlyContinue

            # Updates cached image
            Update-Wallpaper -Type Desktop


        ### Restore Lockscreen
            # Remove potential forced wallpaper restriction
            Unrestrict-Wallpaper -Type Lockscreen

            # Restore deafult Windows lockscreen wallpaper
            Restore-DefaultWallpaperFile -Destination `$DefaultLockScreenFolderPath -DeleteBackup

            # Updates cached image
            Update-Wallpaper -Type Lockscreen


    }ELSEIF(`$WallpaperType){

        IF((`$WallpaperType -like "ALL") -OR (`$WallpaperType -like "DesktopOnly")){
        ### Desktop Wallpaper
            # Backups default Windows wallpapers in 4K wallpapers folder and also removes them from original folder 
            Backup-Wallpaperfile -Destination `$Default4KWallpaperFolderPath
            IF(Get-ChildItem `$Default4KWallpaperFolderPath -File -ErrorAction SilentlyContinue){
            
                Remove-WallpaperFile -Destination `$Default4KWallpaperFolderPath
        
            }
        
            # Backups default Windows wallpapers in wallpaper folder and also removes them from original folder.
            Backup-Wallpaperfile -Destination `$DefaultWallpaperFolderPath

            # Copies a copy of Windows main original wallpaper to Windows original theme wallpapers
            `$BackupImagePath = (Join-Path -Path (Join-Path -Path `$DefaultWallpaperFolderPath -ChildPath `$BackupFolderName) -ChildPath `$EmbeddedDesktopFileName)
            `$ThemeImagePath = (Join-Path -Path `$DefaultThemeFolder -ChildPath `$EmbeddedDesktopFileName)
            IF(Get-Item `$BackupImagePath -ErrorAction SilentlyContinue){
                Copy-Item `$BackupImagePath `$ThemeImagePath -Force
                Remove-WallpaperFile -Destination `$DefaultWallpaperFolderPath
            }
        
            # Creates new image in default wallpaper folder from embedded base64 code. 
            Create-Wallpaperfile -FileName `$EmbeddedDesktopFileName -Destination `$DefaultWallpaperFolderPath -Base64Code `$DesktopBase64

            # Updates cached image for all users so the new image gets applied
            Update-Wallpaper -Type Desktop

            IF((`$Restrict -like "ALL") -OR (`$Restrict -like "DesktopOnly")){
            ### Restricted Desktop Wallpaper
                `$CurrentImagePath = (Join-Path -Path `$DefaultWallpaperFolderPath -ChildPath `$EmbeddedDesktopFileName)
                Restrict-Wallpaper -Type Desktop -FilePath `$CurrentImagePath
            }ELSE{
            ### Unrestricted Desktop Wallpaper
                # Remove forced wallpaper restriction
                Unrestrict-Wallpaper -Type Desktop 
            }
        }

        IF((`$WallpaperType -like "ALL") -OR (`$WallpaperType -like "LockscreenOnly")){
        ### LockScreen Wallpaper
            # Backups default Windows wallpapers in screen folder and also removes them from original folder
            Backup-Wallpaperfile -Destination `$DefaultLockScreenFolderPath
            IF(Get-ChildItem `$DefaultLockScreenFolderPath -File -ErrorAction SilentlyContinue){
                Remove-WallpaperFile -Destination `$DefaultLockScreenFolderPath
            }

            # Creates new image in default lockscreen folder from embedded base64 code. 
            Create-Wallpaperfile -Destination `$DefaultLockScreenFolderPath -FileName `$EmbeddedLockScreenFileName -Base64Code `$LockScreenBase64

            # Updates cached image for all users so the new image gets applied
            Update-Wallpaper -Type Lockscreen

            IF((`$Restrict -like "ALL") -OR (`$Restrict -like "LockscreenOnly")){
            ### Restricted Lockscreen Wallpaper
                Restrict-Wallpaper -Type Lockscreen -FilePath (Join-Path -Path `$DefaultLockScreenFolderPath -ChildPath `$EmbeddedLockScreenFileName)
            }ELSE{
            ### Unrestricted Lockscreen Wallpaper
                # Remove forced wallpaper restriction
                Unrestrict-Wallpaper -Type Lockscreen
            }
        }
    }
}
"@


<#
$TempItem = New-Item -Path $env:TEMP -Name "$FileName.ps1" -ItemType File -Value $PSScript -Force

Invoke-ps2exe -inputFile $TempItem.FullName -outputFile (Join-Path -Path $ScriptPath -ChildPath "$FileName.exe") -STA -noConsole -noOutput -noConfigFile -title $FileName -supportOS -requireAdmin | Out-Null

$TempItem | Remove-Item -Force
#>

New-Item -Path $ScriptPath -Name "$FileName.ps1" -ItemType File -Value $PSScript -Force