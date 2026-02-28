<#
.SYNOPSIS

  ScriptName: Invoke-AADHybridLockOOBE.ps1

.DESCRIPTION

  The script is invoked via Active Setup as set by script Set-AADHybridLockOOBE.ps1 that

	•  creates the runspaces which the AADHybridLockOOBE.ps1 script will utilize to display the OOBE splash screen.
	•  keeps the AADHybridLockOOBE.ps1 script alive to continue display the OOBE splash screen till the Hybrid Join process gets completed.
	•  invokes forced restart upon getting the success event, thereby purging the runspaces created by this script as well as the AADHybridLockOOBE.ps1 script.
	•  sets Run-Once key for InitialToastNotification.ps1 to display the Initial Toast Popup

  This is to note that this is originally adapted from WaitForUserDeviceRegistration.ps1 by Steve Prentice available at https://github.com/steve-prentice/autopilot/blob/master/WaitForUserDeviceRegistration.ps1

.OUTPUT

.NOTES

  Version:        1.0
  Author:         Joymalya Basu Roy
  Creation Date:  28-06-2021

#>


# Get current Script run location

If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation } [string]$mypath = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent

# Functions

function Test-BitLocker {

  $allDisks = (Get-WmiObject Win32_Volume -Filter ("DriveType={0}" -f [int][System.IO.DriveType]::Fixed | where {$_.DriveLetter})).DriveLetter | where {$_}

  $BitLockerEnabled = $true
  foreach ($disk in $allDisks){

    $result = (New-Object -ComObject Shell.Application).NameSpace($disk).Self.ExtendedProperty('System.Volume.BitLockerProtection')
    if ($result -ne 1){
      $BitLockerEnabled = $false
    }
  }

  if ($BitLockerEnabled){
    return "OK"
  }else{
    return "Not OK"
  }

}

# Check if AADHybridLockOOBE has been run before, end script if it has
if (Get-Item -Path "$PSScriptRoot\AADHybridLockOOBE.tag" -Force){
  Exit
}

# Add delay of upto 9 minutes to offset initial Windows login delay

Start-Sleep -Seconds 540

# Create runspace and invoke AADHybridLockOOBE script

Add-Type -AssemblyName System.Windows.Forms
$Screens = [System.Windows.Forms.Screen]::AllScreens
$PSInstances = New-Object System.Collections.ArrayList
Foreach ($Screen in $screens) {
    $PowerShell = [Powershell]::Create()
    [void]$PowerShell.AddScript({Param($ScriptLocation, $DeviceName); powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$ScriptLocation\AADHybridLockOOBE.ps1" -DeviceName $DeviceName})
    [void]$PowerShell.AddArgument($PSScriptRoot)
    [void]$PowerShell.AddArgument($Screen.DeviceName)
    [void]$PSInstances.Add($PowerShell)
    [void]$PowerShell.BeginInvoke()
}

# Wait for runspace execution

Start-Sleep -Seconds 10

# Run script to continuously trigger device registration
Start-Process -FilePath "Powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -NoLogo -File `"$PSScriptRoot\WaitForUserDeviceRegistration.ps1`""

# Check every 90 seconds for a successfull Hybrid join event

do{
    Start-Sleep 90
    $AutomaticRegistration = ""
    $AutomaticRegistration = Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' | Where-Object {$_.Id -eq "306"}
}until($AutomaticRegistration.Id -eq "306")

# Check BitLocker Status

do{
  Start-Sleep -Seconds 10
  $BitLockerStatus = ""
  $BitLockerStatus = Test-BitLocker
}until($BitLockerStatus -eq "OK")

# Set RunOnce key for Initial popup

Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name '!Splash' -Value 'Powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoLogo -File "C:\ProgramData\AADHybridLockOOBE\InitialToastNotification.ps1"'

# Restart system to complete process

shutdown.exe /r /t 0 /f


