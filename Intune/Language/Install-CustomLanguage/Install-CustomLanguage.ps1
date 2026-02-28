<#
.SYNOPSIS
    Install custom languages on Windows 11 22H2 and later.

.DESCRIPTION
    This script will install specified languages and set the correct region, keyboard and timezone on the computer and remove any other language.
    Created to be used during Autopilot ESP but can be user while in Windows also.
    Uses PowerShell commands only Supported on Windows 11 22H2 and later

.EXAMPLE
    .\Install-CustomLanguage.ps1

.NOTES
    Author(s)    : Yoel.Abraham@rts.se

    Version history:
    1.0.0 - (2023-09-26) RTS Customized
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, HelpMessage="The name of the company")]
    [String]$companyName,

    [Parameter(Mandatory=$False, HelpMessage="The language we want as new default UI language. Language tag can be found here: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows")]
    [ValidateSet("en-GB","sv-SE")]
    [String]$UILanguage = "en-GB",

    [Parameter(Mandatory=$False, HelpMessage="Input locale can differ from the UI language. A list of input locales can be found here: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs")]
    [String]$inputLocale = "sv-SE",

    [Parameter(Mandatory=$False, HelpMessage="Geographical ID we want to set. GeoID can be found here: https://learn.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations?redirectedfrom=MSDN")]
    [Int32]$geoId = "221",

    [Parameter(Mandatory=$False)]
    [String]$inputTip = "041D:0000041D",

    [Parameter(Mandatory=$False)]
    [String]$TimeZone = "W. Europe Standard Time"
)

# If running as a 32-bit process on an x64 system, re-launch as a 64-bit process
$argsString = ""
If ($ENV:PROCESSOR_ARCHITECTURE -eq "x86") {
    foreach($k in $MyInvocation.BoundParameters.keys)
    {
        switch($MyInvocation.BoundParameters[$k].GetType().Name)
        {
            "SwitchParameter" {if($MyInvocation.BoundParameters[$k].IsPresent) { $argsString += "-$k " } }
            "String"          { $argsString += "-$k `"$($MyInvocation.BoundParameters[$k])`" " }
            "Int32"           { $argsString += "-$k $($MyInvocation.BoundParameters[$k]) " }
            "Boolean"         { $argsString += "-$k `$$($MyInvocation.BoundParameters[$k]) " }
        }
    }
    Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$PSCommandPath`" $argsString" -Wait -NoNewWindow
    Break
}

# Start Transcript
Start-Transcript -Path "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\$($MyInvocation.MyCommand.Name).log" -Force | Out-Null

#Company name
"CompanyName = $companyName"
# The language we want as new default UI language. Language tag can be found here: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows
"UILanguage = $UILanguage"
# As In some countries the input locale might differ from the installed language pack language, we use a separate input local variable.
# A list of input locales can be found here: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs
"inputLocale = $inputLocale"
# Geographical ID we want to set. GeoID can be found here: https://learn.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations?redirectedfrom=MSDN
"geoId = $geoId"

#Install language pack and change the language of the OS on different places

#Install an additional language pack including FODs
"Installing languagepack"
$installedLanguage = (Get-InstalledLanguage).LanguageId
Install-Language $UILanguage -CopyToSettings
if ($installedLanguage -notmatch $inputLocale) {
    Install-Language $inputLocale
}

#Check status of the installed language pack
"Checking installed languagepack status"
$installedLanguage = (Get-InstalledLanguage).LanguageId

if (($installedLanguage -match $UILanguage) -and ($installedLanguage -match $inputLocale)){
	"Language $UILanguage installed"
	}
	else {
	"Failure! Language $UILanguage NOT installed"
    Exit 1
}

#Set System Preferred UI Language
"Set SystemPreferredUILanguage $UILanguage"
Set-SystemPreferredUILanguage $UILanguage

# Configure new language defaults under current user (system) after which it can be copied to system
#Set Win UI Language Override for regional changes
"Set WinUILanguageOverride $UILanguage"
Set-WinUILanguageOverride -Language $UILanguage

# Set Win User Language List, sets the current user language settings
"Set WinUserLanguageList"
$Lang = New-WinUserLanguageList $UILanguage
$Lang[0].InputMethodTips.Clear()
$Lang[0].InputMethodTips.Add($inputTip)
Set-WinUserLanguageList $Lang -Force

# Set Culture, sets the user culture for the current user account.
"Set culture $inputLocale"
Set-Culture -CultureInfo $inputLocale

# Set Win Home Location, sets the home location setting for the current user
"Set WinHomeLocation $geoId"
Set-WinHomeLocation -GeoId $geoId

# Copy User Internaltional Settings from current user to System, including Welcome screen and new user
"Copy UserInternationalSettingsToSystem"
Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True

# Set timezone
Set-TimeZone -Id $TimeZone

# Add registry key for Intune detection
"Add registry key for Intune detection to HKLM\Software\$companyName\LanguageSet"
New-Item -Path "HKLM:\Software\$companyName\CustomLanguage\v1.0" -Name "LanguageSet" -Force
New-ItemProperty -Path "HKLM:\Software\$companyName\CustomLanguage\v1.0\LanguageSet" -Name "UILanguage" -PropertyType String -Value $UILanguage -Force
New-ItemProperty -Path "HKLM:\Software\$companyName\CustomLanguage\v1.0\LanguageSet" -Name "InputLocale" -PropertyType String -Value $inputLocale -Force
New-ItemProperty -Path "HKLM:\Software\$companyName\CustomLanguage\v1.0\LanguageSet" -Name "GeoID" -PropertyType String -Value $geoId -Force
New-ItemProperty -Path "HKLM:\Software\$companyName\CustomLanguage\v1.0\LanguageSet" -Name "InputTip" -PropertyType String -Value $inputTip -Force
New-ItemProperty -Path "HKLM:\Software\$companyName\CustomLanguage\v1.0\LanguageSet" -Name "TimeZone" -PropertyType String -Value $TimeZone -Force

Exit 3010
Stop-Transcript
