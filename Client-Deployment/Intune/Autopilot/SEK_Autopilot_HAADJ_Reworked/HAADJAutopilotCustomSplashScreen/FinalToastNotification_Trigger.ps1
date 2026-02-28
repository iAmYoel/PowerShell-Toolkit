<#
.SYNOPSIS
  ScriptName: FinalToastNotification_Trigger.ps1
.DESCRIPTION
  This script runs detection every 30 secs to check if the required apps from Intune are installed on the device.
  When the detection returns success, it triggers the FinalToastNotification.ps1 which was already sent to device as part of the AADHybridLockOOBE package.
.OUTPUT
   When all the required apps are detected on the device, the script tiggers FinalToastNotification.ps1 to give the toast notifcation popup to user stating device is ready for use.
.NOTES
  Version:        1.0
  Author:         Joymalya Basu Roy, Wojciech Maciejewski
  Creation Date:  28-06-2021
#>

# Reference sample
function Test-AppInstall {
  $AppInstall = 0

  #Company Portal
  $One = Get-AppxPackage -Name "Microsoft.CompanyPortal" -ErrorAction Ignore
  If($One -ne $null){
    $AppInstall++
  }

  #Check if all
  If ($AppInstall -ge 1){
    return "OK"
  } else{
    return "Not OK"
  }
}

function Test-WindowsLicense {
  # Check if license is a digital license
  $DigitalLicense = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | ? PartialProductKey).PartialProductKey -match "3V66T"
  # Check if active Windows edition is Enterprise
  $WindowsEdition = (Get-WmiObject Win32_OperatingSystem).OperatingSystemSKU
  if (($DigitalLicense) -and ($WindowsEdition -eq 4)){
    return "OK"
  } else {
    return "Not OK"
  }
}

function Test-BitLocker {
  # Get all fixed disks, excludes removable disks like USB drives
  $allDisks = (Get-WmiObject Win32_Volume -Filter ("DriveType={0}" -f [int][System.IO.DriveType]::Fixed | where {$_.DriveLetter})).DriveLetter | where {$_}

  # Loop all fixed disks and check bitlocker status. If BitLocker status is not 1 (Protected) set BitLockerEnabled variable to false
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


function Test-SEKCertificate {
  # Update GPO and automatically input 'N' if log off prompt appears
  echo N | gpupdate /force /target:Computer
  # Check aquired computer certificate from SEK domain used for WiFI and VPN
  $SEKCert = Get-ChildItem -Path Cert:\LocalMachine\My | where {($_.Issuer -like "CN=SEK Issuing CA 03, DC=SEK, DC=SE") -and ($_.Subject -like "CN=$($env:COMPUTERNAME).sek.se")}
  if ($SEKCert){
    return "OK"
  }else{
    return "Not OK"
  }
}

$i=0
do{
  $i++

  if (!$AppInstallStatus) {
    $AppInstallStatus = $null
    $AppInstallStatus = Test-AppInstall
  }

  if (!$WindowsLicenseStatus) {
    $WindowsLicenseStatus = $null
    $WindowsLicenseStatus = Test-WindowsLicense
  }

  if (!$BitLockerStatus) {
    $BitLockerStatus = $null
    $BitLockerStatus = Test-BitLocker
  }

  if (!$SEKCertStatus) {
    $SEKCertStatus = $null
    $SEKCertStatus = Test-SEKCertificate
  }

  if(($i -ge 30) -AND ($BitLockerStatus -eq "OK") -AND (!$Notified)){
    Start-Process "Powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -NoLogo -File `"C:\ProgramData\AADHybridLockOOBE\InitialToastNotification.ps1`" -Message `"Device setup has taken longer than 15 minutes. A manual reboot may be required for the setup to be completed.`""
    $Notified = $true
  }

  Start-Sleep -Seconds 30

} until (($AppInstallStatus -eq "OK") -and ($WindowsLicenseStatus -eq "OK") -and ($BitLockerStatus -eq "OK") -and ($SEKCertStatus -eq "OK"))

# Trigger Final Toast Notification script
C:\ProgramData\AADHybridLockOOBE\FinalToastNotification.ps1

# Create file for IME detection - Not needed when its not a seperate package in Intune.
#mkdir C:\ProgramData\FinalToastNotification

