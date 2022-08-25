<#
.SYNOPSIS
    Generates a report of licenses in tenant and sends report as email to provided recipient

.DESCRIPTION
    Checks the number of licenses assigned through group based licensing and direct assignment in Office 365
    and compares it with the amount of licenses bought.

.EXAMPLE
    .\LicenseAlert.ps1

.NOTES
    FileName:           LicenseAlert.ps1
    Author:             Yoel Abraham
    Contributors:       Magnus Schöllin (API)
    Contact:            Yoel.Abraham@rts.se
    Created:            2022-06-10

    Version history:
    1.0.0 - (2021-12-20) Script created

#>

#region functions


# Install/Import necessary modules
function Install-ScriptModules{
    $Modules = @("Microsoft.Graph.Users", "Microsoft.Graph.Users.Actions", "Microsoft.Graph.Groups", "Microsoft.Graph.Identity.DirectoryManagement")
    foreach ($Module in $Modules) {
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
                        Break
                    }

                }catch [System.Exception] {
                    Break
                }
            }ELSE{
            }
        }catch{
            Break
        }

        $ErrorActionPreference = "Continue"

    }
}



# Function for sending email with Microsoft Graph
function Send-GraphEmail {

    [cmdletbinding()]
    Param(
        [String]$From,
        [String[]]$Recipient = @(),
        [String]$Message
    )

    <#
        Function for sending email with send-mgusermail
        Ref:

        https://mikecrowley.us/2021/10/27/sending-email-with-send-mgusermail-microsoft-graph-powershell
        https://docs.microsoft.com/en-us/graph/api/user-sendmail
        https://docs.microsoft.com/en-us/powershell/module/microsoft.graph.users.actions/send-mgusermail

    #>

    #region 1: Setup

    $emailSender  = $From

    $emailSubject = "License consumption alert! | " + (Get-Date -UFormat %e%b%Y)

    [array]$toRecipients = foreach ($address in $Recipient) {
                                @{
                                    emailAddress = @{address = $address}
                                }
                            }

    #endregion 1


    #region 2: Run

    $emailBody  = @{
        ContentType = 'html'
        Content = $Message
    }

    $body += @{subject      = $emailSubject}
    $body += @{toRecipients = $toRecipients}
    $body += @{body         = $emailBody}

    $bodyParameter += @{'message'         = $body}
    $bodyParameter += @{'saveToSentItems' = $false}

    Send-MgUserMail -UserId $emailSender -BodyParameter $bodyParameter

}


#endregion


# Modules
Install-ScriptModules


#region Authenticate to Office 365

# Connect to Microsoft Graph
Connect-AzAccount -Identity
$graphAccessToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/" | Select-Object -ExpandProperty Token
Connect-MgGraph -AccessToken $graphAccessToken



#endregion




#region Set variables

$Date = Get-Date -Format "yyyy-MM-dd_HHmm"

# Set variables for Office 365 license Name
$E1Name = "Office 365 E1"
$E3Name = "Office 365 E3"
$E5Name = "Office 365 E5"
$EMSName = "EMS E3"
$E5SecName = "Microsoft 365 E5 Security"
$PBIProName = "Power BI Pro"



# Set variables for Office 365 license SkuIds
$E1SkuId = "18181a46-0d4e-45cd-891e-60aabd171b4e"
$E3SkuId = "6fd2c87f-b296-42f0-b197-1e91e994b900"
$E5SkuId = "c7df2760-2c81-4ef7-b578-5b5392b571df"
$EMSSkuId = "efccb6f7-5641-4e0e-bd10-b4976e1bf68e"
$E5SecSkuId = "26124093-3d78-432b-b5dc-48bf992543d5"
$PBIProSkuId = "f8a1db68-be16-40ed-86d5-cb42ce701560"

# Create an array of information for all the licenses
$AllLicenses = @()
$AllLicenses += [PSCustomObject]@{ "Name"=$E1Name   ; "SkuId"=$E1SkuId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$E3Name   ; "SkuId"=$E3SkuId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$E5Name   ; "SkuId"=$E5SkuId  }
$AllLicenses += [PSCustomObject]@{ "Name"=$EMSName  ; "SkuId"=$EMSSkuId }
$AllLicenses += [PSCustomObject]@{ "Name"=$E5SecName  ; "SkuId"=$E5SecSkuId }
$AllLicenses += [PSCustomObject]@{ "Name"=$PBIProName  ; "SkuId"=$PBIProSkuId }

#endregion



#region Get info from Office 365 and CSP

# Get all users, groups and licenses


$AllUsers = Get-MgUser -All -Property Id,AssignedLicenses | where{$_.AssignedLicenses} | Select Id,AssignedLicenses                         # Get only users with a license
$AllGroups = Get-MgGroup -All -Property Id,AssignedLicenses | where{$_.AssignedLicenses} | Select Id,AssignedLicenses           # Get only groups that assigns a license
$AllAccountSkus = Get-MgSubscribedSku -Property SkuId,ConsumedUnits,PrePaidUnits |
    Select SkuId,
    ConsumedUnits,
    @{Name="AvailableUnits";Expression={[Int32]([Int32]($_.PrePaidUnits.Enabled) + [Int32]($_.PrePaidUnits.WarningUnits)) - [Int32]($_.ConsumedUnits)}},
    PrePaidUnits


#endregion


#region Check license assignments in Office 365

# Verify that the manually provided SkuIds in variables above match with the SkuIds found in Office 365
$AllLicenses | ForEach-Object {
    if ($AllAccountSkus.SkuId -notcontains $_.SkuId) {
        $_.SkuId
        Write-Output "Provided SkuId is not found in tenant."
        Break
    }
}






# Create an empty array variable for all license assignment info to be added to
$O365Result = @()

# Loop every license from $AllLicenses array
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
    [Int32]$DifCount = $LicenseCount - $UsersCount

    # Add to $O365Result array
    $row = [PSCustomObject]@{ "Name"=$License.Name ; "TotalAssignedUsers"=$UsersCount ; "TotalLicenseCount"=$LicenseCount ; "ConsumedLicenses"=$AccountSku.ConsumedUnits ; "TotalAvailableLicenseCount"=$AccountSku.AvailableUnits ; "TotalDifference"=$DifCount }
    $O365Result += $row
}


$EmailMessage = @"
<html>
<style>
table, th, td {
  border:1px solid black;
}
</style>
<body>

<h2>License Consumption Alert</h2>
<p>Hej,</p>
<p>Här kommer en rapport för Office 365 licenser i er prodtenant.</p>

<table style="width:100%">
  <tr>
    <th>Name</th>
    <th>Total Assigned Users</th>
    <th>Total License Count</th>
    <th>Consumed Licenses</th>
    <th>Total Available License Count</th>
    <th>Total Difference</th>
  </tr>
$(  $O365Result | foreach{
@"
    <tr>
        <td>$($_.Name)</td>
        <td>$($_.TotalAssignedUsers)</td>
        <td>$($_.TotalLicenseCount)</td>
        <td>$($_.ConsumedLicenses)</td>
        <td>$($_.TotalAvailableLicenseCount)</td>
        <td>$(if($_.TotalDifference -gt 0){"+$($_.TotalDifference)"}else{$_.TotalDifference})</td>
    </tr>
"@
    }
)
</table>

<p>Mvh,<br />
Azure Automation
</p>
</body>
</html>
"@

foreach ($item in $O365Result){
    switch ($item.Name){
        "Office 365 E1"                 {
                                            if($item.TotalAvailableLicenseCount -le 2){
                                                $SendMail = $true
                                            }
                                        }
        "Office 365 E3"                 {
                                            if($item.TotalAvailableLicenseCount -le 3){
                                                $SendMail = $true
                                            }
                                        }
        "Office 365 E5"                 {
                                            if($item.TotalAvailableLicenseCount -le 1){
                                                $SendMail = $true
                                            }
                                        }
        "EMS E3"                        {
                                            if($item.TotalAvailableLicenseCount -le 3){
                                                $SendMail = $true
                                            }
                                        }
        "Microsoft 365 E5 Security"     {
                                            if($item.TotalAvailableLicenseCount -le 3){
                                                $SendMail = $true
                                            }
                                        }
        "Power BI Pro"                  {
                                            if($item.TotalAvailableLicenseCount -le 2){
                                                $SendMail = $true
                                            }
                                        }
    }
}

if ($SendMail){
    Send-GraphEmail -From "IT-Sakerhet@fastighetsbyran.se" -Recipient @("admin.manda.tolliner@fbmoln.onmicrosoft.com") -Message $EmailMessage
}
