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

    Version history:
    1.0.0 - (2021-12-20) Script created
    2.0.0 - (2022-09-15) Modified to use Microsoft Graph with service principal instead of MsolService and also added alerts

#>

[CmdletBinding()]
Param(
    [Parameter(HelpMessage = "Only exports a report and does not change any seats.")]
    [Switch]$ReportOnly
)



#region Set variables

$Date = Get-Date -Format "yyyy-MM-dd"

# Set variable for script path
if($PSScriptRoot){
    $scriptPath = $PSScriptRoot
}else{
    $scriptPath = "C:\RTSCloud\Script\CustomerSpecific\Sigma\CSPLicenseUpdater" # Used for testing when running script manually
}

# Set variable for log folder
$LogFolderPath  = Join-Path -Path $scriptPath -ChildPath "Logs"
$LogFilePath    = Join-Path -Path $LogFolderPath -ChildPath "CSPLicenseUpdater_$date.Log"

# Set variables for report paths
$ReportsFolderPath = Join-Path -Path $scriptPath -ChildPath "Reports"
$CSPReportFolderPath = Join-Path -Path $ReportsFolderPath -ChildPath "CSPUpdateReports"
$ReportOnlyFolderPath = Join-Path -Path $ReportsFolderPath -ChildPath "ReportOnly"
$CSPReportFileName = "CSPUpdateReport_$($Date).csv"
$ReportOnlyFileName = "ReportOnly_$date.csv"
$CSPReportFilePath = Join-Path -Path $CSPReportFolderPath -ChildPath $CSPReportFileName
$ReportOnlyFilePath = Join-Path -Path $ReportOnlyFolderPath -ChildPath $ReportOnlyFileName

# Alert variables
$CustomerFriendlyName   = "Sigma"
[int32]$AlertThreshold  = 20                            # Alert threshold for license purchase
$MailFrom               = "$CustomerFriendlyName-CSPLicenseUpdater@rts.se"
$MailTo                 = "support@rts.se"
$MailServer             = "smtprelay.rts.se"

# Set variables for Azure Service Principal
$CSPSecretName = "CSP"
$MgSecretName = "Sigma-CSPLicenseUpdater"

$CSPApiKey          = Get-Secret -Name $CSPSecretName -AsPlainText
$MgSecret           = Get-Secret $MgSecretname -AsPlainText
$MgTenantId         = $MgSecret.TenantId                            # TenantId from secure string to plain text
$MgAppId            = $MgSecret.AppId                               # AppId from secure string to plain text
$MgThumbprint       = $MgSecret.Thumbprint                          # Certificate thumbprint from secure string to plain text

# Set variables for Azure license Name
$E3Name = "Microsoft 365 E3"
$F3Name = "Microsoft 365 F3"
$E1Name = "Office 365 E1"
$EMSName = "EMS E3"

# Set variables for Azure license SkuIds
$E3SkuId  = "05e9a617-0261-4cee-bb44-138d3ef5d965"
$F3SkuId  = "66b55226-6b4f-492c-910c-a3b7a3c9d993"
$E1SkuId  = "18181a46-0d4e-45cd-891e-60aabd171b4e"
$EMSSkuId = "efccb6f7-5641-4e0e-bd10-b4976e1bf68e"

# Set variables for CSP Subscription Reference
$E3CSPLicenseId  = "XSP4289258"
$F3CSPLicenseId  = "XSP4289250"
$E1CSPLicenseId  = "XSP4289262"
$EMSCSPLicenseId = "XSP4289278"

# Set variable for CSP tenant
$CSPAPIURL = "https://xsp.arrow.com/index.php/api"  # API URL
$CSPCustomerReference = "XSP800618"                 # Customer Reference
# Get API key from secret and decrypt to plain text
$CSPAPIKey = $CSPApiKey.ApiKey

# Create an array of information for all the licenses
$AllLicenses = @()
$AllLicenses += [PSCustomObject]@{ "Name"=$E3Name   ; "SkuId"=$E3SkuId   ; "CSPLicenseId"=$E3CSPLicenseId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$F3Name   ; "SkuId"=$F3SkuId   ; "CSPLicenseId"=$F3CSPLicenseId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$E1Name   ; "SkuId"=$E1SkuId   ; "CSPLicenseId"=$E1CSPLicenseId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$EMSName  ; "SkuId"=$EMSSkuId  ; "CSPLicenseId"=$EMSCSPLicenseId }

#endregion





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
        [string]$FilePath = $LogFilePath
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
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }
}



# Function for sending alert email
function Send-Alert {
    param (
        [String]$SendFrom = $MailFrom,
        [String]$SendTo = $MailTo,
        [String]$Subject,
        [String]$Message
    )

    $EmailProps = @{
        From        = $SendFrom
        To          = $SendTo
        Subject     = $Subject
        Body        = $Message
        BodyAsHTML  = $true
        Encoding    = "UTF8"
        SmtpServer  = $MailServer
        Port        = 25
    }

    Send-MailMessage @EmailProps
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





Write-LogEntry "################ START ################"


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
    $AlertType = "Folder Creation"
        if ((Get-Content $LogFilePath) -match $AlertType) {
            Throw "Sending $AlertType error mail alert."
            Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName-CSPLicenseUpdater - ALERT - $AlertType" -Message $_
        }
    Break
}

Write-Verbose "Successfully verified Logs and Reports folder."
$ErrorActionPreference = "Continue"

# Remove logs and reports older than 90 days
Get-ChildItem –Path $LogFolderPath| Where{($_.LastWriteTime -lt (Get-Date).AddDays(-90))} | Remove-Item -Force
Get-ChildItem –Path $CSPReportFolderPath | Where{($_.LastWriteTime -lt (Get-Date).AddDays(-90))} | Remove-Item -Force

#endregion




#region Authenticate to Azure




# Connect to Microsoft Graph

#Install-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement -Force

Try{
    # The certificate needs to be installed on the server running this script.
    $MgCert = Get-ChildItem Cert:\LocalMachine\My\$MgThumbprint -ErrorAction Stop # Get certificate object

    Try{
        # Connect to Microsoft Graph using TenantId and AppId gathered from secret vault, and also certificate from local machine
        Connect-MgGraph -TenantId $MgTenantId -AppId $MgAppId -Certificate $MgCert -ErrorAction Stop
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while connecting to Microsoft Graph. Error message: $($_.Exception.Message)"
        $AlertType = "MgGraph Authentication"
        if ((Get-Content $LogFilePath) -match $AlertType) {
            Write-LogEntry -Severity INFO -Message "Sending $AlertType error mail alert."
            Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName-CSPLicenseUpdater - ALERT - $AlertType" -Message $_
        }
        Write-LogEntry -Severity WARNING -Message "Breaking script"
        Write-LogEntry "################ END ################"
        Break
    }

}catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while getting local certificate for Microsoft Graph. Error message: $($_.Exception.Message)"
    $AlertType = "Get Certificate"
        if ((Get-Content $LogFilePath) -match $AlertType) {
            Write-LogEntry -Severity INFO -Message "Sending $AlertType error mail alert."
            Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName - $AlertType" -Message $_
        }
    Write-LogEntry -Severity WARNING -Message "Breaking script"
    Write-LogEntry "################ END ################"
    Break
}

#endregion





if ($ReportOnly) {
    Write-LogEntry -Severity WARNING -Message "ReportOnly MODE"
}






#region Get info from Azure and CSP

# Get all users, groups and licenses
Write-LogEntry -Message "Fetching Azure AD Users, Groups and Licenses from Microsoft Graph"

try {
    $ErrorActionPreference = "Stop"
    $AllUsers       = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AssignedLicenses,LicenseAssignmentStates |
                        where{$_.AssignedLicenses} |
                        Select Id,DisplayName,UserPrincipalName,AssignedLicenses,LicenseAssignmentStates    # Get only users with a license

    $AllGroups      = Get-MgGroup -All -Property Id,DisplayName,AssignedLicenses |
                        where{$_.AssignedLicenses} |
                        Select Id,DisplayName,AssignedLicenses                                              # Get only groups that assigns a license

    $AllAccountSkus = Get-MgSubscribedSku -Property SkuId,ConsumedUnits,PrePaidUnits |
        Select SkuId,
        ConsumedUnits,
        @{Name="AvailableUnits";Expression={[Int32]([Int32]($_.PrePaidUnits.Enabled) + [Int32]($_.PrePaidUnits.WarningUnits)) - [Int32]($_.ConsumedUnits)}},
        PrePaidUnits
    $ErrorActionPreference = "Continue"
}
catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "Failed to gather user information from Microsoft Graph. Error message: $($_.Exception.Message)"
    $AlertType = "Get User and License info from Microsoft Graph"
        if ((Get-Content $LogFilePath) -match $AlertType) {
            Write-LogEntry -Severity INFO -Message "Sending $AlertType error mail alert."
            Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName-CSPLicenseUpdater - ALERT - $AlertType" -Message $_
        }
    Write-LogEntry -Message "Breaking script."
    Write-LogEntry "################ END ################"
    Break
}

#endregion




#region Check license assignments in Azure

# Verify that the manually provided SkuIds in variables above match with the SkuIds found in Azure
Write-LogEntry -Message "Verifying SkuIds"
$AllLicenses | ForEach-Object {
    if ($AllAccountSkus.SkuId -notcontains $_.SkuId) {
        Write-LogEntry -Severity ERROR -Message "SkuId ($($_.SkuId)) provided was not found in Azure. Please change the value in the script."
        $VerificationError = $true
    }
}

if ($VerificationError) {
    $AlertType = "SkuId Verification"
        if ((Get-Content $LogFilePath) -match $AlertType) {
            Write-LogEntry -Severity INFO -Message "Sending $AlertType error mail alert."
            Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName-CSPLicenseUpdater - ALERT - $AlertType" -Message $_
        }
    Write-LogEntry -Message "Breaking script."
    Write-LogEntry "################ END ################"
    Break
}else {
    Write-LogEntry -Message "Successfully verified SkuIds"
}






#region Assignment state

# License error translation hash table
$LicenseErrorHash = @{}
$LicenseErrorHash["None"] = "None"
$LicenseErrorHash["CountViolation"] = "Not enough licenses"
$LicenseErrorHash["MutuallyExclusiveViolation"] = "Conflicting service plans"
$LicenseErrorHash["DependencyViolation"] = "Other products depend on this license"
$LicenseErrorHash["ProhibitedInUsageLocationViolation"] = "Usage location isn't allowed"
$LicenseErrorHash["UniquenessViolation"] = "UniquenessViolation"
$LicenseErrorHash["Other"] = "Other"


# User list with all user license assignments and license active/error state
$AssignmentStateList = foreach ($user in $AllUsers) {   # Loop every user
    # Loop every license assignment state for the user
    foreach ($assignment in $user.LicenseAssignmentStates) {

        # Match license from license list
        $assignedLicense = ($AllLicenses | ? SkuId -like $assignment.SkuId)

        # Skip license assignment state if license is not found
        if (!$assignedLicense) { continue } # This is a zombie license that is not showing in Azure AD purchased SKUs.

        # Translate Error value to readable error message
        $assignmentError = $LicenseErrorHash[$assignment.Error]

        # Translate assignment group id to Display Name
        if ($assignment.AssignedByGroup) {
            # License is assigned through a group
            $assignmentType = "Group"
            $assignmentGroup = ($AllGroups | ? Id -like $assignment.AssignedByGroup).DisplayName
        }
        else {
            # Direct License Assignment
            $assignmentType = "Direct"
            $assignmentGroup = $null
        }

        # Create Custom object with all values
        [PSCustomObject]@{
            UserPrincipalName       = $user.UserPrincipalName
            Name                    = $user.DisplayName
            LicenseSkuId            = $assignment.SkuId
            LicenseName             = $assignedLicense.Name
            AssignmentType          = $assignmentType
            AssignmentGroup         = $assignmentGroup
            AssignmentState         = $assignment.State
            AssignmentError         = $assignmentError
            AssignmentLastUpdated   = $assignment.LastUpdatedDateTime
        }
    }
}

#endregion







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

            # Loop every license from CSP-portal matched with the gathered licenses from Azure
            if ($ReportOnly) {
                Write-LogEntry -Message "Gathering license seat changes info from CSP-portal for report"
            }else {
                Write-LogEntry -Message "Processing license seat changes in CSP-portal"
            }

            # Create an empty array variable for the end result info
            $ExportResult = @()

            # Loop every license with assignment difference count
            foreach ($License in $ProcessLicenses) {
                # Match Azure license from all the gathered purchased license from CSP.
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

                                    # Email alert for big license change
                                    if (($License.Difference -ge 20) -OR ($License.Difference -le -20)) {
                                        Write-LogEntry -Severity WARNING -Message "License change is above threshold, sending email alert."
                                        $AlertType = "Big license change"
                                        Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName-CSPLicenseUpdater - ALERT - $AlertType" -Message "$($License.Difference) $($License.Name) seats was bought for $CustomerFriendlyName tenant."
                                    }
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
    Write-LogEntry -Message "Checking license allocation..."

    #region License overallocation alert
    # List with all license that are overallocated
    $LicenseAllocationList = @()

    # Loop every license
    foreach ($License in $AllLicenses) {

        $Alert = $true

        # Matched account sku
        $AccountSku = $AllAccountSkus | where{$_.SkuId -like $License.SkuId}

        # Get total count of license seats in tenant
        [Int32]$TotalLicenseCount = $AccountSku.PrePaidUnits.Enabled

        # Get count of errors for the license
        [Int32]$LicenseErrorCount = ($AssignmentStateList | where{ ($_.LicenseSkuId -like $AccountSku.SkuId) -AND ($_.AssignmentState -like "Error")}).Count

        # Add count of used licenses with count of errors to get true count
        [Int32]$TrueLicenseCount = [Int32]$AccountSku.ConsumedUnits + [Int32]$LicenseErrorCount

        # Calculate difference between total count of license and true license count
        $LicenseDifCount = $TotalLicenseCount - $TrueLicenseCount

        if ($LicenseDifCount -gt 0) {
            Write-LogEntry -Severity WARNING -Message "$($License.Name) is overallocated with $LicenseDifCount seats."
            $AllocationCount = "+$LicenseDifCount"
        }elseif ($LicenseDifCount -lt 0) {
            Write-LogEntry -Severity WARNING -Message "$($License.Name) is underallocated with $LicenseDifCount seats."
            $AllocationCount = "-$LicenseDifCount"
        }else{
            # Allocation is correct
            $Alert = $false
        }

        if($Alert){
            $row = [PSCustomObject]@{ "Name"=$License.Name ; "SkuId"=$License.SkuId ; "TotalLicenseCount"=$TotalLicenseCount ; "TrueAssignmentCount"=$TrueLicenseCount ; "ErrorAssignmentCount"=$LicenseErrorCount ; "Allocation"=$AllocationCount }
            $LicenseAllocationList += $row
        }
    }

    # If a license allocation is incorrect, alert send alert email
    if ($LicenseAllocationList) {
        # Create custom mail body as html
        $MailBody = "
<h2><strong>License allocation alert!</strong></h2>

<p>
There is a discrepency between the amount licenses purschased from arrow, which is calculated by this script, and the amount of users that have the license assigned, including error assignment.
</p>

$(foreach($item in $LicenseAllocationList){
    "<p>"
    "Name:                  $($item.Name)<br />"
    "SkuId:                 $($item.SkuId)<br />"
    "TotalLicenseCount:     $($item.TotalLicenseCount)<br />"
    "TrueAssignmentCount:   $($item.TrueAssignmentCount)<br />"
    "ErrorAssignmentCount:  $($item.ErrorAssignmentCount)<br />"
    "Allocation:            $($item.Allocation)"
    "</p>"
})

<p>
TotalLicenseCount       - Amount of all users calculated by script who needs a license and is also the amount of licenses automatically purchased from Arrow. <br />
TrueAssignmentCount     - Amount of users that are assigned to this license, including error assignments. <br />
ErrorAssignmentCount    - Amount of error assignment of the license.
Allocation              - Difference between TotalLicenseCount and TrueAssignmentCount.
</p>

<p>
Regards,<br />
$CustomerFriendlyName CSPLicenseUpdater script<br />
$env:USERDOMAIN\$env:COMPUTERNAME
</p>
"

        $AlertType = "License allocation"
        if ((Get-Content $LogFilePath) -match $AlertType) {
            Send-Alert -SendTo "Yoel.Abraham@rts.se" -Subject "$CustomerFriendlyName-CSPLicenseUpdater - ALERT - $AlertType" -Message $MailBody
        }else {
        Write-LogEntry -Message "All license allocations are correct."
        }
    #endregion

    }
}

#endregion

Write-LogEntry "################ END ################"