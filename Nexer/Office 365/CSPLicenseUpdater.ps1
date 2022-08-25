<#
.SYNOPSIS
    Automatically makes sure that the number of CSP licenses purchased from Arrow match the number of licenses assigned in Office 365

.DESCRIPTION
    Checks the number of licenses assigned through group based licensing and direct assignment in Office 365
    and makes sure that the number of CSP licenses purchased are a match. Also a report only function to be able
    to export a report of Office 365 and CSP license info.

.PARAMETER ReportOnly
    Only outputs a report of licenses and does not change the number of purchased seats.

.EXAMPLE
    .\CSPLicenseUpdater.ps1

.NOTES
    FileName:           CSPLicenseUpdater.ps1
    Author:             Yoel Abraham
    Contributors:       Magnus Schöllin (API)
    Contact:            Yoel.Abraham@rts.se
    Created:            2021-12-20
    Modified:           2022-06-01

    Version history:
    1.0.0 - (2021-12-20) Script created
    2.0.0 - (2022-06-01) Modified to use Microsoft Graph with service principal instead of MsolService

#>

[CmdletBinding()]
Param(
    [Parameter(HelpMessage = "Only exports a report and does not change any seats.")]
    [Switch]$ReportOnly
)


#region functions

# Function for log
function Write-LogEntry {
    param (
        [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [parameter(HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Severity = "INFO",

        [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
        [string]$LogPath = (Join-Path -Path $LogFolderPath -ChildPath "CSPLicenseUpdater_$date.Log")
    )

    # Test log file location
    if(!(Test-Path $LogFolderPath -PathType Container)){
        Write-Warning "Log folder path provided is not valid: $LogFolderPath"
    }else {

        # Construct date and time stamp for log entry
        $Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

        # Construct final log entry
        $LogText = "$Time | $Severity | $Message"

        # Output Value as verbose
        Write-Verbose $Message

        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogPath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }
}




# Install/Import necessary modules
function Install-ScriptModules{
    Write-LogEntry -Message "Importing necessary modules..."
    $Modules = @("Microsoft.PowerShell.SecretManagement","Microsoft.Graph.Users", "Microsoft.Graph.Groups", "Microsoft.Graph.Identity.DirectoryManagement")
    foreach ($Module in $Modules) {
        Write-LogEntry -Message "Checking $Module`t"
        Clear-Variable CurrentModule -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Stop"

        try{
            Import-Module -Name $Module
            $CurrentModule = Get-Module -Name $Module

            IF(!$CurrentModule){
                try{
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name NuGet -Force -ErrorAction Stop -Verbose:$false -Scope CurrentUser

                    try {
                        # Install current missing module
                        Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Scope CurrentUser
                    }catch [System.Exception] {
                        Write-LogEntry -Severity ERROR -Message "An error occurred while attempting to install the module. Error message: $($_.Exception.Message)"
                        Write-LogEntry -Severity WARNING -Message "Breaking script"
                        Break
                    }

                }catch [System.Exception] {
                    Write-LogEntry -Severity ERROR -Message "An error occurred while attempting to install nuGet package provider. Error message: $($_.Exception.Message)"
                    Write-LogEntry -Severity WARNING -Message "Breaking script"
                    Break
                }
            }ELSE{
                Write-Verbose "Successfully loaded the '$Module' module"
            }
        }catch{
            Write-LogEntry -Severity ERROR -Message "An error occurred while attempting to getting and import module. Error message: $($_.Exception.Message)"
            Write-LogEntry -Severity WARNING -Message "Breaking script"
            Break
        }

        $ErrorActionPreference = "Continue"

    }
}







# Function for connecting to Arrow CSP API @ Magnus.Schollin@rts.se
function Connect-CSPAPI {
    [CmdletBinding()]
    Param()

    $Headers = @{
        "apikey" = $CSPAPIKey
    }

    $Connection = Invoke-RestMethod -Method GET -Uri "$CSPAPIURL/whoami" -Headers $Headers -ContentType "application/json"

    if ($Connection) {
        $Script:CSPHeader = $Headers
    }
    else {
        throw "Could not connect to Arrow API"
    }
}




# Function for fetching all CSP purchased licenses and seats @ Magnus.Schollin@rts.se
function Get-CSPLicenses {
    [CmdletBinding()]
    Param()
    Invoke-RestMethod -Method GET -Uri "$CSPAPIURL/customers/$CSPCustomerReference/licenses" -Headers $CSPHeader
}




# Function for updating the number of seats for a purchased license. @ Magnus.Schollin@rts.se
function Update-CSPLicense {
    [CmdletBinding()]
    param(
        [parameter(mandatory)]
        [string]$LicenseId,

        [parameter(mandatory)]
        [Int32]$Seats
    )

    $Body = '
    {
        "seats": ' + $Seats + '
    }'
    Invoke-RestMethod -Method PUT -Uri "$CSPAPIURL/licenses/$LicenseId/seats" -Body $Body -ContentType "application/json" -Headers $CSPHeader
}

#endregion


# Modules
Install-ScriptModules


#region Authenticate to Office 365

# Set variables for O365 account
$CSPSecretName = "CSP"
$MgSecretName = "Nexer"

$CSPSecret = Get-Secret -Name CSP
$SecureCspApiKey = Get-Secret -Name CSP
$MgSecret = Get-Secret $MgSecretname
$MgTenantId = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MgSecret.TenantId))         # TenantId from secure string to plain text
$MgAppId = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MgSecret.AppId))               # AppId from secure string to plain text
$MgThumbprint = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MgSecret.Thumbprint))     # Certificate thumbprint from secure string to plain text


# Connect to Microsoft Graph

Try{
    # The certificate needs to be installed on the server running this script.
    $MgCert = Get-ChildItem Cert:\LocalMachine\My\$MgThumbprint -ErrorAction Stop # Get certificate object

    Try{
        # Connect to Microsoft Graph using TenantId and AppId gathered from secret vault, and also certificate from local machine
        Connect-MgGraph -TenantId $MgTenantId -AppId $MgAppId -Certificate $MgCert -ErrorAction Stop
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while connecting to Microsoft Graph. Error message: $($_.Exception.Message)"
        Write-LogEntry -Severity WARNING -Message "Breaking script"
        Break
    }

}catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while getting local certificate for Microsoft Graph. Error message: $($_.Exception.Message)"
    Write-LogEntry -Severity WARNING -Message "Breaking script"
    Break
}

#endregion




#region Set variables

$Date = Get-Date -Format "yyyy-MM-dd_HHmm"

# Set variable for script path
$scriptPath = Split-Path -Parent ($MyInvocation.MyCommand.Path)

# Set variable for log folder
$LogFolderPath = Join-Path -Path $scriptPath -ChildPath "Logs"

# Set variables for report paths
$ReportsFolderPath = Join-Path -Path $scriptPath -ChildPath "Reports"
$CSPReportFolderPath = Join-Path -Path $ReportsFolderPath -ChildPath "CSPUpdateReports"
$ReportOnlyFolderPath = Join-Path -Path $ReportsFolderPath -ChildPath "ReportOnly"
$CSPReportFileName = "CSPUpdateReport_$($Date).csv"
$ReportOnlyFileName = "ReportOnly_$date.csv"
$CSPReportFilePath = Join-Path -Path $CSPReportFolderPath -ChildPath $CSPReportFileName
$ReportOnlyFilePath = Join-Path -Path $ReportOnlyFolderPath -ChildPath $ReportOnlyFileName

# Set variables for Office 365 license Name
$E3Name = "Microsoft 365 E3"
$F3Name = "Microsoft 365 F3"
$E1Name = "Office 365 E1"
$EMSName = "EMS E3"

<#
# Set variables for Office 365 license SkuPartNumbers
$E3SkuPartNumber = "SPE_E3"
$F3SkuPartNumber = "SPE_F1"
$E1SkuPartNumber = "STANDARDPACK"
$EMSSkuPartNumber = "EMS"
#>

# Set variables for Office 365 license SkuIds
$E3SkuId = "05e9a617-0261-4cee-bb44-138d3ef5d965"
$F3SkuId = "66b55226-6b4f-492c-910c-a3b7a3c9d993"
$E1SkuId = "18181a46-0d4e-45cd-891e-60aabd171b4e"
$EMSSkuId = "efccb6f7-5641-4e0e-bd10-b4976e1bf68e"

# Set variables for CSP Subscription Reference
$E3CSPLicenseId = "XSP4321766"
$F3CSPLicenseId = "XSP4843052"
$E1CSPLicenseId = "XSP4453716"
$EMSCSPLicenseId = "XSP4843060"

# Set variable for CSP tenant
$CSPAPIURL = "https://xsp.arrow.com/index.php/api"  # API URL
$CSPCustomerReference = "XSP811990"                 # Customer Reference
# Get API key from secret and decrypt to plain text
$CSPAPIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CSPSecret.ApiKey))

# Create an array of information for all the licenses
$AllLicenses = @()
$AllLicenses += [PSCustomObject]@{ "Name"=$E3Name   ; "SkuId"=$E3SkuId   ; "CSPLicenseId"=$E3CSPLicenseId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$F3Name   ; "SkuId"=$F3SkuId   ; "CSPLicenseId"=$F3CSPLicenseId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$E1Name   ; "SkuId"=$E1SkuId   ; "CSPLicenseId"=$E1CSPLicenseId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$EMSName  ; "SkuId"=$EMSSkuId  ; "CSPLicenseId"=$EMSCSPLicenseId }

#endregion




#region Create necessary folder for log and report exports and remove old logs and reports

$ErrorActionPreference = "Stop"
try {
    Write-Verbose "Verifying Logs and Reports folder."

    # Create log folder
    New-Item $LogFolderPath -ItemType Directory -Force | Out-Null

    # Create reports folders
    New-Item $ReportsFolderPath -ItemType Directory -Force | Out-Null
    New-Item $CSPReportFolderPath -ItemType Directory -Force | Out-Null
    New-Item $ReportOnlyFolderPath -ItemType Directory -Force | Out-Null
}
catch [System.Exception] {
    Throw "Failed to create log and report folders. Error message: $($_.Exception.Message)"
    Break
}

Write-Verbose "Successfully verified Logs and Reports folder."
$ErrorActionPreference = "Continue"

# Remove logs and reports older than 90 days
Get-ChildItem –Path $LogFolderPath| Where{($_.LastWriteTime -lt (Get-Date).AddDays(-90))} | Remove-Item -Force
Get-ChildItem –Path $CSPReportFolderPath | Where{($_.LastWriteTime -lt (Get-Date).AddDays(-90))} | Remove-Item -Force

#endregion







if ($ReportOnly) {
    Write-LogEntry -Severity WARNING -Message "ReportOnly MODE"
}






#region Get info from Office 365 and CSP

# Get all users, groups and licenses
Write-LogEntry -Message "Fetching Azure AD Users, Groups and Licenses from Microsoft Graph"

try {
    $ErrorActionPreference = "Stop"
    $AllUsers = Get-MgUser -All -Property Id,AssignedLicenses | where{$_.AssignedLicenses} | Select Id,AssignedLicenses                         # Get only users with a license
    $AllGroups = Get-MgGroup -All -Property Id,AssignedLicenses | where{$_.AssignedLicenses} | Select Id,AssignedLicenses           # Get only groups that assigns a license
    $AllAccountSkus = Get-MgSubscribedSku -Property SkuId,ConsumedUnits,PrePaidUnits |
        Select SkuId,
        ConsumedUnits,
        @{Name="AvailableUnits";Expression={[Int32]([Int32]($_.PrePaidUnits.Enabled) + [Int32]($_.PrePaidUnits.WarningUnits)) - [Int32]($_.ConsumedUnits)}},
        PrePaidUnits
    $ErrorActionPreference = "Continue"
}
catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "Failed to gather information from Microsoft Graph. Error message: $($_.Exception.Message)"
    Write-LogEntry -Severity WARNING -Message "Breaking script."
    Break
}

#endregion




#region Check license assignments in Office 365

# Verify that the manually provided SkuIds in variables above match with the SkuIds found in Office 365
Write-LogEntry -Message "Verifying SkuIds"
$AllLicenses | ForEach-Object {
    if ($AllAccountSkus.SkuId -notcontains $_.SkuId) {
        Write-LogEntry -Severity ERROR -Message "SkuId ($($_.SkuId)) provided was not found in Office 365. Please change the value in the script."
        $VerificationError = $true
    }
}

if ($VerificationError) {
    Write-LogEntry -Severity WARNING -Message "Breaking script."
    Break
}else {
    Write-LogEntry -Message "Successfully verified SkuIds"
}






# Create an empty array variable for all license assignment info to be added to
$O365Result = @()

# Loop every license from $AllLicenses array
Write-LogEntry -Message "Processing O365 information"
foreach ($License in $AllLicenses) {
    # Create an empty array variable for users to be added to
    $Users = @()

    # Add all users with the license assigned to $Users
    $Users += ($AllUsers | where{$_.AssignedLicenses.SkuId -contains $License.SkuId}).Id

    # Get all groups that assigns the license
    $Groups = $AllGroups | where{$_.AssignedLicenses.SkuId -contains $License.SkuId}

    # Loop every group and add all the group members to $Users
    foreach ($item in $Groups) {
        $Users += (Get-MgGroupMember -GroupId $item.Id -All).Id
    }

    # Total count of unique users in $Users that needs a license seat
    [Int32]$UsersCount = ($Users | select -Unique).count

    # Matched account sku
    $AccountSku = $AllAccountSkus | where{$_.SkuId -like $License.SkuId}

    # Total number of seats purchased for license
    [Int32]$LicenseCount = $AccountSku.PrePaidUnits.Enabled

    # Calculate difference between users that needs a license seat and active licenses
    [Int32]$DifCount = $UsersCount - $LicenseCount

    # Add to $O365Result array
    $row = [PSCustomObject]@{ "Name"=$License.Name ; "SkuId"=$License.SkuId ; "CSPLicenseId"=$License.CSPLicenseId ; "TotalUsers"=$UsersCount ; "PrePaidUnits"=$LicenseCount ; "ConsumedUnits"=$AccountSku.ConsumedUnits ; "Difference"=$DifCount }
    $O365Result += $row
    Write-LogEntry -Message ($row | Select Name,TotalUsers,PrePaidUnits,Difference)
}

#endregion






#region Change number of purchased seats in CSP

# Get all licenses from $O365Result where the difference does not equal zero
if ($ReportOnly) {
    $ProcessLicenses = $O365Result
}else {
    $ProcessLicenses = $O365Result | where{$_.Difference -ne 0}
}

# If there are licenses with att difference count, change purchased seats in CSP-portal
if ($ProcessLicenses) {
    if ($ReportOnly) {
        Write-LogEntry -Message "Gathering CSP info for report"
    }else {
        Write-LogEntry -Message "Difference exists. Licenses will begin to be processed i Arrow CSP-portal"
    }


    # Connect to Arrow  CSP-Portal through API
    try {
        Write-LogEntry -Message "Connecting to Arrow CSP-portal API"
        Connect-CSPAPI -ErrorAction Stop

        # Get all purchased licenses and seats
        try {
            Write-LogEntry -Message "Fetching all license information from CSP-portal through API"
            $AllPurchasedSeats = (Get-CSPLicenses -ErrorAction Stop).Data.Licenses

            # Loop every license from CSP-portal matched with the gathered licenses from Office 365
            if ($ReportOnly) {
                Write-LogEntry -Message "Gathering license seat changes info from CSP-portal for report"
            }else {
                Write-LogEntry -Message "Processing license seat changes in CSP-portal"
            }

            # Create an empty array variable for the end result info
            $ExportResult = @()

            # Loop every license with assignment difference count
            foreach ($License in $ProcessLicenses) {
                # Match Office 365 license from all the gathered purchased license from CSP.
                $CSPLicense = $AllPurchasedSeats | where{$_.license_id -eq $License.CSPLicenseId}

                # If no licenses are matched, send error and skip to next in loop
                if (!$CSPLicense) {
                    Write-LogEntry -Severity ERROR -Message "'$($License.CSPLicenseId)' was not matched with any CSP license."
                }else {
                    Write-LogEntry -Message "Processing $($CSPLicense.name)"

                    # Get number of purchased seats from CSP
                    [Int32]$PurchasedSeats = $CSPLicense.seats

                    # Send warning to log if license i not active and skip process.
                    if ($CSPLicense.state -notlike "active") {
                        Write-LogEntry -Severity WARNING -Message "The license is in a '$($CSPLicense.state)' state"
                    }else {
                        # Calculate new number of purchased seats
                        [Int32]$NewPurchasedSeats = $PurchasedSeats + $License.Difference

                        # If NewPurchasedSeats is zero, increase with one, number of seats can't be zero.
                        if ($NewPurchasedSeats -eq 0) {
                            Write-LogEntry -Message "New purchased seats number is zero. Increasing the number to one."
                            $NewPurchasedSeats++
                        }

                        if (!$ReportOnly) {
                            # Send the new purchased seat number to CSP through API as long as the new purchased seats number is not the same as the old purchased seat number.
                            if ($PurchasedSeats -ne $NewPurchasedSeats) {
                                try {
                                    Write-LogEntry -Message "Updating seat change from $PurchasedSeats to $NewPurchasedSeats"
                                    Update-CSPLicense -LicenseId $CSPLicense.license_id -Seats $NewPurchasedSeats -ErrorAction Stop
                                    Write-LogEntry -Message "Successfully updated seat change"
                                    $UpdateStatus = "SUCCESS"
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to update seat change. Error message: $($_.Exception.Message)"
                                    $UpdateStatus = "FAILED"
                                }

                            }else {
                                # The $NewPurchasedSeats and $PurchasedSeats variables are the same.
                                Write-LogEntry -Severity WARNING -Message "The seat number $PurchasedSeats has not changed. Skipping seat number update."
                                $UpdateStatus = "SKIP"
                            }
                        }
                    }
                }

                # Insert end result to variable for export
                if ($ReportOnly) {
                    $row = [PSCustomObject]@{ "Name"=$CSPLicense.name ; "O365SkuId"=$License.SkuId ; "O365TotalUsers"=$License.TotalUsers ; "O365PrePaidUnits"=$License.PrePaidUnits ; "O365ConsumedUnits"=$License.ConsumedUnits ; "CSPLicenseId"=$CSPLicense.license_id ; "CSPLicenseState"=$CSPLicense.state ; "CSPPurchasedSeats"=$PurchasedSeats ; "CSPNewPurchasedSeats"=$NewPurchasedSeats ; "SeatsDifference"=$License.Difference }
                }else {
                    $row = [PSCustomObject]@{ "Name"=$CSPLicense.name ; "LicenseId"=$CSPLicense.license_id ; "LicenseState"=$CSPLicense.state ; "PurchasedSeats"=$PurchasedSeats ; "NewPurchasedSeats"=$NewPurchasedSeats ; "SeatsDifference"=$License.Difference ; "UpdateStatus"=$UpdateStatus }
                }
                $ExportResult += $row
            }

            # Exporting CSP Update result to csv
            Write-LogEntry -Message "Exporting result."
            if ($ReportOnly) {
                $ExportResult | Export-Csv -Path $ReportOnlyFilePath -Encoding UTF8 -Delimiter ";" -NoTypeInformation -Force
            }else {
                $ExportResult | Export-Csv -Path $CSPReportFilePath -Encoding UTF8 -Delimiter ";" -NoTypeInformation -Force
            }


        }
        catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to get license information from CSP-portal through API. Error message: $($_.Exception.Message)"
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "Failed to connect to API. Error message: $($_.Exception.Message)"
    }

}else {
    Write-LogEntry -Message "All license seats are a match."
}

Write-LogEntry -Message "Ending script."