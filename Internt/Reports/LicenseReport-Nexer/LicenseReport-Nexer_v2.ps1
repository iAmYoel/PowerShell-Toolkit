function Get-LicenseExclusion {
    param(
        $LicenseSku,
        $Group
    )
    $Exclusion = @()
    $Members = Get-ADGroupMember $Group -Server $ADServer -Credential $svcCRED | Get-ADUser -Server $ADServer -Credential $svcCRED
    foreach ($Member in $Members) {
        $Exclusion += [pscustomobject]@{
            userprincipalName = ($Member.UserPrincipalName).Replace("@ad.nexergroup.com","@nexeronline.onmicrosoft.com")
            License = "$LicenseSku"
        }
    }
    return $Exclusion
}


function Consolidate-MonthlyReports {
    Param(

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [String]$ReportsPath

    )

    # Get date from leaf folder name in string
    $DateString = Get-Date (Split-Path $ReportsPath -Leaf) -Format yyyy-MM

    # If folder name is not parseable as date, throw error and break script
    if (!$DateString) {
        throw "Could not parse date from folder name."
        Break
    }

    # Import all monthly reports
    $AllLists = @()
    Get-ChildItem $ReportsPath\*.xlsx -Exclude *_Final.xlsx | foreach {
        $AllLists += Import-Excel -Path $_.FullName
    }

    # Check if any row from any list have an empty objectid value
    $AllLists | foreach{
            if(!$_.objectId){$trigger=$true}
        }

    if ($trigger){ # If a row with an empty objectid value exists, sort unique on UserPrincipalName
        # Selec unique value for Username and License columns
        $FinalResult = $AllLists | Sort Username,License,LicenseID -Unique | Select Name,Username,Company,CostCenter,License,LicenseID,LicensePartNumber,ReportMonth,LockedLicensePrice,LicensePrice
    }else{ # else sort unique on objectId
        # Selec unique value for objectId and License columns
        $FinalResult = $AllLists | Sort ObjectId,License,LicenseID -Unique | Select ObjectId,Name,Username,Company,CostCenter,License,LicenseID,LicensePartNumber,ReportMonth,LockedLicensePrice,LicensePrice
    }

    # Export final consolidated monthly report to excel file
    $FinalResult | Export-Excel -Path "$ReportsPath\LicenseReport_${DateString}_Final.xlsx" -TableName Table1 -TableStyle Medium7 -FreezeTopRow

    #SEND EVERYTHING TO DATALAGRET!
    $password = Get-Secret -Vault DWH -Name licensreportwriter
    $SQLCredentials = New-Object System.Management.Automation.PsCredential("licensreportwriter",$password)

    $DateTime = Get-Date

    if($trigger){ # If a row with an empty objectid value exists, upload all rows to SQL without objectid
        # Loop all rows and upload to SQL
        foreach ($LicenseRow in $FinalResult){
            $LicenseRow = "'$($LicenseRow.Name)', '$($LicenseRow.Username)', '$($LicenseRow.CostCenter)', '$($LicenseRow.Company)', '$($LicenseRow.License)', '$($LicenseRow.LicenseId)', '$($DateTime)', '$($LicenseRow.ReportMonth)', '$($LicenseRow.LockedLicensePrice)','$($LicenseRow.LicensePrice)','$($AzSvcPrincipalSecretInfo.Metadata.TenantId)'"
            INSERT-SQL -Table "[DWH].[DBO].[LicenseReport]" -Headers "Name, Username, DepartmentNumber, Company, License, LicenseID, ReportRowGenerated, ReportMonth, LockedLicensePrice, LicensePrice, AzureTenantID" -Values $LicenseRow -Credentials $SQLCredentials -LogToFile $LogToFile
        }
    }else{ # else upload all rows to SQL with objectid
        # Loop all rows and upload to SQL
        foreach ($LicenseRow in $FinalResult){
            $LicenseRow = "'$($License.ObjectID)', '$($LicenseRow.Name)', '$($LicenseRow.Username)', '$($LicenseRow.CostCenter)', '$($LicenseRow.Company)', '$($LicenseRow.License)', '$($LicenseRow.LicenseId)', '$($DateTime)', '$($LicenseRow.ReportMonth)', '$($LicenseRow.LockedLicensePrice)','$($LicenseRow.LicensePrice)','$($AzSvcPrincipalSecretInfo.Metadata.TenantId)'"
            INSERT-SQL -Table "[DWH].[DBO].[LicenseReport]" -Headers "ObjectID, Name, Username, DepartmentNumber, Company, License, LicenseID, ReportRowGenerated, ReportMonth, LockedLicensePrice, LicensePrice, AzureTenantID" -Values $LicenseRow -Credentials $SQLCredentials -LogToFile $LogToFile
        }
    }
}

### SETUP START ###
### SETUP START ###

#LOCATIONS
#$ScriptPath = $PSScriptRoot
$ScriptPath = "C:\RTSCloud\Script\Reports\LicenseReport-Nexer"

#LOGGING
$LogToFile = $true

#Load all modules
$Modules = (Get-ChildItem -Path "C:\RTSCloud\Script\Modules").Name
foreach ($Module in $Modules){ . "C:\RTSCloud\Script\Modules\$Module" }

#AD Authentication
$ADServer = "10.224.128.10"
$Username   = 'NEXERGROUP\svc-adreader'
$Password   = Get-Secret -Name $Username -Vault Nexer
$svcCRED = New-Object -Type PSCredential($Username,$Password)

### SETUP END ###
### SETUP END ###

#get all Microsoft licenses
$licenseCsvURL = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
$licenseList = @{}
(Invoke-WebRequest -Uri $licenseCsvURL -UseBasicParsing).ToString() | ConvertFrom-Csv | ForEach-Object {
    $licenseList[$_.GUID] = @{
        "SkuPartNumber" = $_.String_Id
        "DisplayName" = $_.Product_Display_Name
    }
}

#Date when script was run
$RunDate = $(Get-Date -Format "yyyy-MM-dd")

#Get Month
$ReportMonth = (Get-Date -format "yyyy-MM")

#Retrieve price for license
$LicensePrices = Import-Excel -path "$ScriptPath\LicensePrices.xlsx"

#Connect to Azure API Application
$AzSvcPrincipalSecret = Get-Secret LicenseReportScript -Vault Nexer -AsPlainText
$AzSvcPrincipalSecretInfo = Get-SecretInfo LicenseReportScript -Vault Nexer
#Connect-GraphAPI -AzureTenantID "02b6749b-5ce0-4853-bd5c-a05f9bd9dd3a" -ApplicationID "18bb8fa9-0cf2-4b7b-b12b-d72b9190cf25" -t -LogToFile $LogToFile
Connect-MgGraph -TenantId $AzSvcPrincipalSecretInfo.Metadata.TenantId -AppId $AzSvcPrincipalSecretInfo.Metadata.AppId -Certificate (Get-ChildItem Cert:\LocalMachine\My\$AzSvcPrincipalSecret)

#Get all Azure users and AD users (AD users for departmentnumber
$AllAzureUsers = Get-MgUser -All -Property id,displayName,userPrincipalName,companyName,department,state,assignedLicenses | where{$_.AssignedLicenses}
$AllADUsers = Get-ADUser -Filter * -properties departmentNumber -Server $ADServer -Credential $svcCRED | select userprincipalName,SamAccountName,@{l='DepartmentNumber';e={$_.DepartmentNumber[0]}}

#User with License Exclusionlist
$ExclusionList = [pscustomobject]@()
$ExclusionList += Get-LicenseExclusion -LicenseSku DESKLESSPACK -Group SG_Office365-F3_EA
$ExclusionList += Get-LicenseExclusion -LicenseSku ENTERPRISEPACK -Group SG_Office365-E3_EA

<#
#Group of users that has a license that has "Locked" price.
$LockedLicenseMembers = @()
$LockedLicenseMembers += Get-LicenseExclusion -Group "SG_Microsoft365-E3_CSP-Locked" -LicenseSku SPE_E3
$LockedLicenseMembers += Get-LicenseExclusion -Group "SG_Microsoft365-F3_CSP-Locked" -LicenseSku SPE_F1
#>

#ExcludeLicenses
$ExcludeLicenses = Import-Excel -Path "$ScriptPath\ExcludeLicenses.xlsx"

#Build the report object
$LicenseReportObject = [pscustomobject]@()
foreach ($User in $AllAzureUsers){

    #Get the ADUser object from the list (to get departmentnumber 'CostCenter')
    $ADUser = $AllADUsers.Where({$_.userprincipalname -eq $User.userprincipalname})

    #Get Exclusion if exists from list
    $ExclusionObject = $ExclusionList | ? {$_.userPrincipalName -eq $User.userPrincipalName}

    #Loop through every license found on user.
    foreach ($License in $User.assignedLicenses.skuId){

        #Make sure that the license row being generated is not within the license exclusionlist
        if ($License -notin $ExcludeLicenses.SkuId) {

            #Get license price
            $OurLicensePrice = $LicensePrices.Where({$_.SkuId -eq "$License"}).LicensePrice

            #Get the license object from the User license SKUID
            $LicenseObject = $licenseList["$License"]

            #Get licenses in LockedLicense list and if found this price should be locked.
            $LockedLicense = $LockedLicenseMembers.Where({$LicenseObject.SkuPartNumber -in $_.License}).Where({$_.userPrincipalName -eq $ADUser.UserPrincipalName})

            #Initial license price
            $LicensePrice = 0
            if ($OurLicensePrice -ne $null) { #If we have a price then set our price
                $LicensePrice = $OurLicensePrice
            }

            #If user in LockedlicenseMember list then set lockedlicenseprice to True and license has the same skuid
            if ($LockedLicense){
                $LockedLicensePrice = $true
                if ($LicenseObject.SkuPartNumber -eq 'SPE_E3'){
                    $LicensePrice = 0
                }
                if ($LicenseObject.SkuPartNumber -eq 'SPE_F1'){
                    $LicensePrice = 0
                }
            }
            else {
                $LockedLicensePrice = $false
            }

            #Exclusion if the exclusion is not found or if the license that is found in the exclusion is another one
            if ($LicenseObject.SkuPartNumber -notin $ExclusionObject.License -OR $ExclusionObject -eq $null){

                #Create one row in license report
                $LicenseReportObject += [pscustomobject]@{
                    ObjectId = $User.Id
                    Name = $User.displayName -replace("'","")
                    Username = $User.userPrincipalName -replace("'","")
                    Company = $User.companyName
                    CostCenter = $ADUser.DepartmentNumber
                    License = $LicenseObject.DisplayName
                    LicensePartNumber = $LicenseObject.SkuPartNumber
                    LicenseId = $License
                    ReportMonth = $ReportMonth
                    ReportRowGenerated = $RunDate
                    LockedLicensePrice = $LockedLicensePrice
                    LicensePrice = $LicensePrice
                }
            }
        }
    }
}


#Export Excel file to Reports folder
$ThisDate = Get-Date -Format "yyyy-MM"
$ReportsFolder = Join-Path -Path $ScriptPath -ChildPath Reports
$ExportPath = Join-Path -Path $ReportsFolder -ChildPath $ThisDate
if(!(Test-Path $ExportPath -PathType Container)){New-Item -Path $ExportPath -ItemType Directory -Force}

$LicenseReportObject | Export-Excel -Path "$ExportPath\LicenseReport$(Get-Date -Format "yyyyMMdd_HHmm").xlsx" -TableName Table1 -TableStyle Medium7 -FreezeTopRow


#Consolidate monthly reports
$LastMonthDate = Get-Date (Get-Date).AddMonths(-1) -Format yyyy-MM
$LastMonthPath = Join-Path -Path $ReportsFolder -ChildPath $LastMonthDate

if(!(Test-Path -Path "$LastMonthPath\*_Final.xlsx")){
    Consolidate-MonthlyReports -ReportsPath $LastMonthPath
}