#Requires -version 4.0


Param(

    [Parameter(Mandatory = $false, HelpMessage = "Provide an optional computer name to set for to this device.")]
    [String]$AddToGroup,

    [Parameter(Mandatory = $false, HelpMessage = "Provide an optional UPN for a user to be pre-assigned as primary user for this device.")]
    [ValidateScript({(($_ -match '^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$'))})]
    [String]$AssignedUser,

    [Parameter(Mandatory = $false, HelpMessage = "Provide an optional computer name to set for to this device.")]
    [ValidateLength(1,15)]
    [String]$AssignedComputerName,

    [Parameter(Mandatory = $false, HelpMessage = "Provide an optional Autopilot GroupTag.")]
    [String]$GroupTag

)


# Self-elevate the script if required
###################################################################################################################
# Auto Elevation
IF (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    IF ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-ExecutionPolicy Bypass " + "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}
else {
    Write-Host "Script is successfully run as Administrator!" -ForegroundColor Yellow
}

###################################################################################################################



$Params = @{
    Online = $true
    Assign = $true
    GroupTag = $GroupTag
    AssignedUser = $AssignedUser
    AssignedComputerName = $AssignedComputerName
    AddToGroup = $AddToGroup
    ErrorAction = "Stop"
}



try {
    Write-Host "Downloading Autopilot import script..." -ForegroundColor Yellow
    Install-Script -Name Get-WindowsAutopilotInfo -Force -ErrorAction Stop

    try {
        Get-InstalledScript -Name Get-WindowsAutoPilotInfo -ErrorAction Stop | Out-Null
        Write-Host "Autopilot import script has successfully been installed!" -ForegroundColor Yellow

        try {
            Write-Host "Importing device to Autopilot..." -ForegroundColor Yellow
            Get-WindowsAutopilotInfo.ps1 @Params

            try {
                Start-Process "$env:windir\system32\sysprep\sysprep.exe" -ArgumentList "/generalize /shutdown /oobe" -ErrorAction Stop
            }
            catch {
                Write-Host "Failed to Sysprep device to OOBE.`nError message: $_" -ForegroundColor Red -BackgroundColor Black
                Pause
            }
        }
        catch [System.Exception] {
            Write-Host "Failed to import device to Autopilot.`nError message: $_" -ForegroundColor Red -BackgroundColor Black
            Pause
        }
    }
    catch [System.Exception] {
        Write-Host "Failed to find downloaded Autopilot import script.`nError message: $_" -ForegroundColor Red -BackgroundColor Black
        Pause
    }
}
catch [System.Exception] {
    Write-Host "Failed install Autopilot import script.`nError message: $_" -ForegroundColor Red -BackgroundColor Black
    Pause
}