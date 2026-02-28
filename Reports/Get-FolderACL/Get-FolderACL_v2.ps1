
<#PSScriptInfo

.VERSION 2.0

.GUID 635618b3-acdd-4d62-89a6-b1ea201589ac

.AUTHOR Yoel Abraham - yoel.abraham@visolit.se

.COMPANYNAME Visolit Region Mitt AB

.COPYRIGHT

.TAGS NTFS Permission ACL Report

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


#>

<#

.DESCRIPTION
 General script for creating a report of all the NTFS permissions on a folder structure.
All you need is Admin privileges to run this script.

You have the following options,
to provide with a search path for the target of the report, (Mandatory)
to choose save format for export: ALL, CSV or XLSX
to choose a save path for export,
to skip the error logging,
to show duration of the script.

The save path for the export will default to script location with a default name if no path is provided.
An error log is created as default if there are any errors, and exported to the export path.

#>

#Requires -RunAsAdministrator

[Cmdletbinding()]
Param(

    [Parameter(Mandatory = $true, HelpMessage = 'Path to search ACL in.')]
    # Fixa UNC validation
    [String]$Path,

    [Parameter(Mandatory = $false, HelpMessage = 'SamAccountName of identites to only include')]
    [String[]]$Identities = @(),

    [Parameter(Mandatory = $false, HelpMessage = 'Search recursively in folder structure.')]
    [Switch]$Recurse,

    [Parameter(Mandatory = $false, HelpMessage = 'Save format for export file.')]
    [Validateset('CSV','XLSX','ALL')]$ExportFormat = "ALL",

    [Parameter(Mandatory = $false, HelpMessage = 'Save path for export file.')]
    [String]$ExportPath = (Split-Path -Parent $MyInvocation.MyCommand.Definition),

    [Parameter(Mandatory = $false, HelpMessage = "Add this parameter if you don't want an error log to be processed.")]
    [Switch]$NoErrorLog,

    [Parameter(Mandatory = $false, HelpMessage = "Add this parameter if you want to show time elapsed.")]
    [Switch]$ShowDuration

)


New-Variable -Name FolderPath -Value @() -Option AllScope -Force
New-Variable -Name ErrorList -Option AllScope -Force

# Set variable for current date and time
$Date = Get-Date -Format yyyy-MM-dd_HHmm

function Install-ScriptModules{
    param(
        [parameter(Mandatory=$true)]
        [string[]]$Modules = @()
    )

    foreach ($Module in $Modules) {
        Clear-Variable CurrentModule -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Stop"
        try{
            Import-Module -Name $Module -Force -ErrorAction SilentlyContinue
            $CurrentModule = Get-Module -Name $Module -ErrorAction SilentlyContinue
            IF(!$CurrentModule){
                try{
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false -ErrorVariable +ErrorList
                    try {
                        # Install current missing module
                        Install-Module -Name $Module -Force -ErrorVariable +ErrorList -Confirm:$false

                        # Import installed module
                        Import-Module -Name $Module -Force -ErrorVariable +ErrorList -ErrorAction SilentlyContinue
                        # Get imported module
                        $CurrentModule = Get-Module -Name $Module -ErrorAction SilentlyContinue
                        IF(!$CurrentModule){
                            # Log module install failed
                            Write-Host "Failed to get module after installation." -F Yellow -B Black
                            Break
                        }
                    }catch [System.Exception] {
                        Write-Host "Failed to install module." -F Yellow -B Black
                        Break
                    }
                }catch [System.Exception] {
                    Write-Host "Failed to install NuGet Package Provider." -F Yellow -B Black
                    Break
                }
            }ELSE{
                # Log module import success
            }
        }catch{
            Break
        }
        $ErrorActionPreference = "Continue"
    }
}



function Get-TooLongPath {
    param(
        [String]$ErrorPath,

        [String]$Drive
    )

    $parentPath = Split-Path -Path $errorPath -Parent
    $drivePath = $ErrorPath -replace "^[A-Za-z]\:","\\localhost\$($ErrorPath[0])$"

    do {
        if ($drivePath.Length -gt 256) {
            $childLeaf = "$(Split-Path -Path $drivePath -Leaf)\" + $childLeaf
            $drivePath = Split-Path -Path $drivePath -Parent
        }
    } until ($drivePath.Length -le 256)

    (net use ${drive}: "$drivePath") | Out-Null
    $childPath = Join-Path -Path $parentPath -ChildPath (Get-Item -Path "${drive}:\$childLeaf" -Force -ErrorAction SilentlyContinue -ErrorVariable +Errorlist).Name

    if ($FolderPath -notcontains $childPath) {
        $FolderPath += $childPath
    }

    if ($Recurse) {
        Get-ChildItem -Directory -Path "${drive}:\$childLeaf" -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +ErrorList | foreach {
            $childPath = Join-Path -Path $errorPath -ChildPath ($_.FullName -replace "$drive\:\\")
            if ($FolderPath -notcontains $childPath) {
                $FolderPath += $childPath
            }
        }
    }

    (net use ${drive}: /DELETE) | Out-Null

}




function Get-TooLongACL {
    param(
        [String]$ErrorPath,

        [String]$Drive
    )

    $drivePath = $ErrorPath -replace "^[A-Za-z]\:","\\localhost\$($ErrorPath[0])$"
    do {
        if ($drivePath.Length -gt 256) {
            $childLeaf = "$(Split-Path -Path $drivePath -Leaf)\" + $childLeaf
            $drivePath = Split-Path -Path $drivePath -Parent
        }
    } until ($drivePath.Length -le 256)
    (net use $($drive): "$drivePath") | Out-Null
    $returnACL += @(Get-ACL -Path "$($drive):\$childLeaf" -ErrorAction SilentlyContinue -ErrorVariable +Errorlist)
    Get-ChildItem -Path "$($drive):\$childLeaf" -Recurse -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable +Errorlist | foreach {
        $returnACL += Get-ACL -Path $_.FullName -ErrorAction SilentlyContinue -ErrorVariable +Errorlist
    }
    (net use $($drive): /DELETE) | Out-Null

    return $returnACL
}



function Free-DriveLetter {
    $drivelist = (Get-PSDrive -PSProvider filesystem).Name
    foreach ($drvletter in "DEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()) {
        if ($drivelist -notcontains $drvletter) {
            return $drvletter
        }
    }
}


#region format check

IF($ExportFormat -notlike "CSV"){

    Install-ScriptModules -Modules ImportExcel

}


#endregion

#region Path check


# Check SearchPath
IF (!(Test-Path $Path -PathType Container)){

    Throw 'Search path could not be found!'
    Break

}

if ([System.Uri]$Path.IsUnc) {
    $PathType = "UNC"
} else {
    $PathType = "LOCAL"
}

if ($PathType -eq "UNC") {
    $pathLetter = Free-DriveLetter
    (net use ${pathLetter}: $Path) | Out-Null
    $realPath = "${pathLetter}:\"
} else {
    $realPath = $Path
}




# Check export path
IF (($ExportPath -notlike "*.csv") -AND ($ExportPath -notlike "*.xlsx")){

    IF(!(Test-Path -Path $ExportPath -PathType Container)){

        Throw 'Export path could not be found!'
        Break

    }ELSE{

        Write-Verbose "Export Path found!"

    }

    $CSVExportPath = Join-Path -Path $ExportPath -ChildPath "FolderACL_$Date.csv"
    $XLSXExportPath = Join-Path -Path $ExportPath -ChildPath "FolderACL_$Date.xlsx"

}ELSE{

    IF(!(Test-Path (Split-Path -Parent $ExportPath) -PathType Container )){

        Throw 'Export folder path not found.'
        Break

    }ELSE{

        Write-Verbose "Export Path found!"

        $CSVExportPath = $ExportPath -replace ".xlsx$",".csv"
        $XLSXExportPath = $ExportPath -replace ".csv$",".xlsx"

    }
}

#endregion


#region Access mask

# Set access mask for permissions.
$AccessMask = [ordered]@{
  [uint32]'0x80000000' = 'GenericRead'
  [uint32]'0x40000000' = 'GenericWrite'
  [uint32]'0x20000000' = 'GenericExecute'
  [uint32]'0x10000000' = 'GenericAll'
  [uint32]'0x02000000' = 'MaximumAllowed'
  [uint32]'0x01000000' = 'AccessSystemSecurity'
  [uint32]'0x00100000' = 'Synchronize'
  [uint32]'0x00080000' = 'WriteOwner'
  [uint32]'0x00040000' = 'WriteDAC'
  [uint32]'0x00020000' = 'ReadControl'
  [uint32]'0x00010000' = 'Delete'
  [uint32]'0x00000100' = 'WriteAttributes'
  [uint32]'0x00000080' = 'ReadAttributes'
  [uint32]'0x00000040' = 'DeleteChild'
  [uint32]'0x00000020' = 'Execute/Traverse'
  [uint32]'0x00000010' = 'WriteExtendedAttributes'
  [uint32]'0x00000008' = 'ReadExtendedAttributes'
  [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
  [uint32]'0x00000002' = 'WriteData/AddFile'
  [uint32]'0x00000001' = 'ReadData/ListDirectory'
}

#endregion


#region Propagation rules

# Set Propagation rules
$PropagationRules = @(

    New-Object psobject -Property @{Message="This folder only";Flags="None","None"};
    New-Object psobject -Property @{Message="This folder and files";Flags="ObjectInherit","None"};
    New-Object psobject -Property @{Message="This folder and child file only";Flags="ObjectInherit","NoPropagateInherit"};
    New-Object psobject -Property @{Message="Files only";Flags="ObjectInherit","InheritOnly"};
    New-Object psobject -Property @{Message="Child file only";Flags="ObjectInherit","InheritOnly","NoPropagateInherit"};
    New-Object psobject -Property @{Message="This folder and subfolders";Flags="ContainerInherit","None"};
    New-Object psobject -Property @{Message="This folder and child folder only";Flags="ContainerInherit","NoPropagateInherit"};
    New-Object psobject -Property @{Message="Subfolders only";Flags="ContainerInherit","InheritOnly"};
    New-Object psobject -Property @{Message="Child folder only";Flags="ContainerInherit","InheritOnly","NoPropagateInherit"};
    New-Object psobject -Property @{Message="This folder, subfolder and files";Flags="ContainerInherit","ObjectInherit","None"};
    New-Object psobject -Property @{Message="This folder, child folder and child file only";Flags="ContainerInherit","ObjectInherit","NoPropagateInherit"};
    New-Object psobject -Property @{Message="Subfolders and files only";Flags="ContainerInherit","ObjectInherit","InheritOnly"};
    New-Object psobject -Property @{Message="Child folder and child file only";Flags="ContainerInherit","ObjectInherit","NoPropagateInherit","InheritOnly"}

)


# Create function for checking propagation.
Function Get-ACLPropagation{

    Param(

        $ACLAccessObject,

        $PropagationRules

    )

    Clear-Variable Flags -ErrorAction SilentlyContinue
    $Flags = $ACLAccessObject.InheritanceFlags -Split ", "
    $Flags += $ACLAccessObject.PropagationFlags -split ", "

    Foreach($Propagation in $PropagationRules){

        Clear-Variable AppliedToCheck -ErrorAction SilentlyContinue
        $AppliedToCheck = @(Compare-Object -ReferenceObject $Flags -DifferenceObject $Propagation.Flags -Verbose).Length -eq 0

        IF($AppliedToCheck){

            $Propagation.Message

        }
    }
}


#endregion



#region Get ACL

# Set variable for csv export.
$Report = @()
$ErrorLog = @()



# Set variable for amount of steps.
IF($NoErrorLog){

    $AllSteps = 3

}ELSE{

    $AllSteps = 4

}




# Start clock for time elapsed
IF($ShowDuration){

    $ElapsedTime = [system.diagnostics.stopwatch]::StartNew()

}






# Get all folders in path.
$tempFolderPathFile = "$PSScriptRoot\Temp_FolderList_"
if (!($tempFolderList = Get-Item $tempFolderPathFile*.csv | sort CreationTime | select -Last 1)){
    Write-Output "Fetching all folders..."
    $i=0

    # Get permissions from target folder
    $ParentFolderPath = Get-Item -Path $realPath -Force -ErrorAction SilentlyContinue -ErrorVariable TempErrorlist
    $timespan = New-TimeSpan -Seconds 1
    $startTime = [system.diagnostics.stopwatch]::StartNew()
    IF($Recurse){

        # Get permissions from child folders
        Get-ChildItem -Directory -Path $realPath -Recurse -Force -OutVariable ChildFoldersPath -ErrorAction SilentlyContinue -ErrorVariable +TempErrorList | ForEach-Object{

            #region Progress bar
            if (($startTime.Elapsed -ge $timespan) -or ($i -eq 0)) {
                IF($ShowDuration){

                    # Create variable for time elapsed
                    $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

                    # Create arguments for write-progress with time elapsed.
                    $Progress = @{
                        Id = 1
                        Activity = "Step 1 of $($AllSteps): Fetching folders."
                        CurrentOperation = $WriteTime
                        Status = "Processed $i folders."
                    }

                }ELSE{

                    # Create arguments for write-progress without time elapsed.
                    $Progress = @{
                        Id = 1
                        Activity = "Step 1 of $($AllSteps): Fetching folders."
                        Status = "Processed $i folders."
                    }

                }

                Write-Progress @Progress
                $startTime.Restart()
            }
            $i++
            #endregion
        }
    }ELSE{

        # Get permissions from child folders
        Get-ChildItem -Directory -Path $realPath -Force -OutVariable ChildFoldersPath -ErrorAction SilentlyContinue -ErrorVariable +TempErrorList | ForEach-Object{

            #region Progress bar
            if (($startTime.Elapsed -ge $timespan) -or ($i -eq 0)) {
                IF($ShowDuration){

                    # Create variable for time elapsed
                    $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

                    # Create arguments for write-progress with time elapsed.
                    $Progress = @{
                        Id = 1
                        Activity = "Step 1 of $($AllSteps): Fetching folders."
                        CurrentOperation = $WriteTime
                        Status = "Processed $i folders."
                    }

                }ELSE{

                    # Create arguments for write-progress without time elapsed.
                    $Progress = @{
                        Id = 1
                        Activity = "Step 1 of $($AllSteps): Fetching folders."
                        Status = "Processed $i folders."
                    }

                }

                Write-Progress @Progress
                $startTime.Restart()
            }
            $i++
            #endregion
        }

    }


    Write-Progress @Progress -Completed

    # Creating an array to add both target folder and child folders into same variable for processing

    $FolderPath += $ParentFolderPath
    $FolderPath += $ChildFoldersPath

    $FolderPath = $FolderPath.FullName



    Write-Output "Folders fetched!"



    # Error handling
    Write-Output "Handling errors..."
    $driveletter = Free-DriveLetter
    $i = 0
    $tot = ($TempErrorList | where {$_.CategoryInfo.Reason -eq "DirectoryNotFoundException"}).count
    $startTime.Restart()
    foreach ($item in ($TempErrorList | where {$_.CategoryInfo.Reason -eq "DirectoryNotFoundException"})){
        $i++
        if (($startTime.Elapsed -ge $timespan) -or ($i -eq 1)) {
            $percent = ($i / $tot * 100)
            $status = "{0:N0}" -f $percent

            IF($ShowDuration){

                # Create variable for time elapsed
                $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

                # Create arguments for write-progress with time elapsed.
                $Progress = @{
                    Id = 2
                    Activity = "Step 2 of $($AllSteps): Handling errors."
                    CurrentOperation = $WriteTime
                    Status = "Processing path $i of $tot : $status% Completed"
                    PercentComplete = $percent
                }

            }ELSE{

                # Create arguments for write-progress without time elapsed.
                $Progress = @{
                    Id = 2
                    Activity = "Step 2 of $($AllSteps): Handling errors."
                    Status = "Processing path $i of $tot : $status% Completed"
                    PercentComplete = ($i / $tot * 100)
                }

            }

            Write-Progress @Progress
            $startTime.Restart()
        }

        if ($item.CategoryInfo.TargetName.length -gt 256) {
            Get-TooLongPath -ErrorPath $item.CategoryInfo.TargetName -Drive $driveletter
        } else {
            $ErrorList += $item
        }
    }
    Write-Progress @Progress -Completed

    Write-Output "$($ErrorList.Count) errors remain. See error log when the script is done."

    Write-Output "Errors handled!"

    $FolderPath = $FolderPath | sort -Unique
    $FolderPath | Out-File -FilePath "$tempFolderPathFile$Date.txt" -Encoding UTF8 -Force

} else {
    try {
        $FolderPath = Get-Content -Path $tempFolderList.FullName -Encoding UTF8 -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to get content from existing folder list."
        break
    }
}

# Set progress bar variables
$i=0
$tempPermListFile = "$PSScriptRoot\FolderACL_Temp_${Date}_"
if ($tempPermLists = Get-Item $tempPermListFile*.csv -Force) {
    foreach ($file in $tempPermLists) {
        try {
            $Report = Import-Csv -Delimiter ";" -Path $file.FullName -Encoding UTF8 -ErrorAction Stop
            $i = $i + $report.count
        }
        catch {
            Write-Warning "Failed to import existing temp report csv."
        }
    }
}
$Report = @()
$ExportCap = 20000
$AddToCap = $ExportCap
$tot = $FolderPath.count
$startTime.Restart()

Write-Output "Processing folders..."

# Start processing every folder
Foreach ($Folder in ($FolderPath | select -Skip $i)) {

    $i++

    if ($Report -contains $folder) {
        Continue
    }

    #region Progress bar

    # Set up progress bar
    if (($startTime.Elapsed -ge $timespan) -or ($i -eq 1)) {
        $percent = ($i / $tot * 100)
        $status = "{0:N0}" -f $percent

        IF($ShowDuration){

            # Create variable for time elapsed
            $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

            # Create arguments for write-progress with time elapsed.
            $Progress = @{
                Id = 2
                Activity = "Step 3 of $($AllSteps): Exporting folder permissions."
                CurrentOperation = $WriteTime
                Status = "Processing folder $i of $tot : $status% Completed"
                PercentComplete = $percent
            }

        }ELSE{

            # Create arguments for write-progress without time elapsed.
            $Progress = @{
                Id = 2
                Activity = "Step 3 of $($AllSteps): Exporting folder permissions."
                Status = "Processing folder $i of $tot : $status% Completed"
                PercentComplete = ($i / $tot * 100)
            }

        }

        Write-Progress @Progress
        $startTime.Restart()
    }
    #endregion


    Write-Verbose "Processing $($Folder)"

    # Clear variables
    Clear-Variable -Name ACL,AccessRights,FolderInheritance,AccessAppliedTo,Properties -ErrorAction SilentlyContinue

    # Get acl for folder.
    try {
        $ACL = Get-Acl -Path $Folder -ErrorVariable TempErrorList -ErrorAction Stop
    }
    catch {
        if ($Folder.Length -gt 256) {
            $ACL = Get-TooLongACL -ErrorPath $Folder -Drive $driveletter
        } else {
            $ErrorList += $TempErrorList
        }
    }


    # Start processing every acl for folder.
    foreach ($AC in $ACL) {
        foreach ($Access in $AC.Access){
            Clear-Variable -Name matched -ErrorAction SilentlyContinue

            # If identity filter is provided
            if ($Identities) {
                $Identities | foreach {
                    if ($access.IdentityReference.Value -match $_) {
                        $matched = $true
                    }
                }
                if (!$matched) {
                    Continue
                }
            }

            # If user access is masked with numbers.
            IF ($Access.FileSystemRights -match '\d+'){

                # Translate permission using the access mask and set variable for translated permissions.
                $AccessRights = (($AccessMask.Keys | Where-Object { $Access.FileSystemRights.value__ -band $_ } | ForEach-Object { $AccessMask[$_] } | Out-String).Trim()) -replace "`n",", "

            }ELSE {

                # Set variable for permissions.
                $AccessRights = $Access.FileSystemRights

            }

            # Get folder inheritance setting
            IF ($AC.AreAccessRulesProtected){

                $FolderInheritance = "Disabled"

            }ELSE{

                $FolderInheritance = "Enabled"

            }

            # Use created function to get propagation.
            $AccessAppliedTo = Get-ACLPropagation -ACLAccessObject $Access -PropagationRules $PropagationRules

            #
            IF ($AccessRights){
                # Skriv om att appenda til len fil istället
                # Create hash table and add values.
                $Properties = [ordered]@{'FolderName'=$($AC.Path | Convert-Path);'Identity'=$Access.IdentityReference;'Permissions'=$AccessRights;'Type'=$Access.AccessControlType;'AppliesTo'=$AccessAppliedTo;'PermissionInherited'=$Access.IsInherited;'FolderInheritance'=$FolderInheritance}

                # Add hash table to csv array.
                $Report += New-Object -TypeName PSObject -Property $Properties

            }
        }
    }

    if ($i -ge $ExportCap) {
        try {
            $Report | Export-Csv -Path "$tempPermListFile$i.csv" -Encoding UTF8 -Delimiter ";" -NoTypeInformation -Force -ErrorAction Stop
            (Get-Item -Path $tempPermListFile).Attributes += [System.IO.FileAttributes]::Hidden
            $Report = @()
        }
        catch {
            <#Do this if a terminating exception happens#>
        }
        $ExportCap = $ExportCap + $AddToCap
    }
}
$startTime.Stop()
#endregion

$finalReport = @()
$csvParts = Get-Item -Path $tempPermListFile*.csv -Force
foreach ($csv in $csvParts) {
    try {
        $finalReport += Import-Csv -Delimiter ";" -Path $item.FullName -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Output "Failed to import all csv parts for final report."
    }
}

if (!$finalReport) {
    $finalReport = $Report
}



# Export result to csv.
IF($ExportFormat -notlike "XLSX"){

    $finalReport | Export-Csv -Path $CSVExportPath -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
    Write-Verbose "CSV export path: $CSVExportPath"

}


#Export result to xslx.
IF($ExportFormat -notlike "CSV"){

    $finalReport | Export-Excel -Path $XLSXExportPath -WorksheetName "Report" -AutoSize -FreezeTopRow -BoldTopRow -TableName Report -ErrorVariable +ErrorList -ErrorAction Stop
    Write-Verbose "XLSX export path: $XLSXExportPath"

}


Write-Output "Export done!"


#region Error handling

# If NoErrorLog parameter is used
IF($NoErrorLog){

    Write-Output "Export successfully completed!"

    IF($ShowDuration){

        # Create variable for time elapsed
        $WriteTime = ([string]::Format("{0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))
        Write-Output "Script duration: $WriteTime"

        # Stop clock for time elapsed
        $ElapsedTime.stop()

    }
}ELSE{

    Write-Verbose "Checking errors..."

    # Set progress bar variables
    $i=0
    $tot = $ErrorList.count

    # Process every error
    Foreach ($ErrorItem in $ErrorList){

        # Set up progress bar
	    $i++
	    $status = "{0:N0}" -f ($i / $tot * 100)

        # If ShowDuration parameter is used
        IF($ShowDuration){

            # Create variable for time elapsed
            $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

        }

	    Write-Progress -Activity "Step 4 of $($AllSteps): Exporting errors." -CurrentOperation $WriteTime -Status "Processing error $i of $tot : $status% Completed" -PercentComplete ($i / $tot * 100)

        # Create hash table and add values.
        $ErrorProperties = [ordered]@{'Command'=$ErrorItem.CategoryInfo.Activity;'FolderName'=$ErrorItem.CategoryInfo.TargetName;'Category'=$ErrorItem.CategoryInfo.Category;'Reason'=$ErrorItem.CategoryInfo.Reason;'Message'=$ErrorItem.Exception.Message}

        # Add hash table to csv array.
        $ErrorLog += New-Object -TypeName PSObject -Property $ErrorProperties
    }

    # If ErrorLog parameter is used
    if ($ErrorLog){

        # Export Error list to csv.
        Write-Output "Export completed with errors! Exporting error log to csv."

        IF ($ExportFormat -notlike "XLSX"){

            $CSVErrorExportPath = $CSVExportPath -replace '.csv','_ErrorLog.csv'
            $ErrorLog | Export-Csv -Path $CSVErrorExportPath -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
            Write-Verbose "CSV Error export path: $CSVErrorExportPath"

        }

        IF ($ExportFormat -notlike "CSV"){

            $XLSXErrorExportPath = $XLSXExportPath -replace '.xlsx','_ErrorLog.xlsx'
            $ErrorLog | Export-Excel -Path $XLSXErrorExportPath -WorksheetName "ErrorLog" -AutoSize -FreezeTopRow -BoldTopRow -TableName ErrorLog
            Write-Verbose "XLSX Error export path: $XLSXErrorExportPath"

        }


        # If ShowDuration parameter is used
        IF($ShowDuration){

            # Create variable for time elapsed
            $WriteTime = ([string]::Format("{0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))
            Write-Output "Script duration: $WriteTime"

            # Stop clock for time elapsed
            $ElapsedTime.stop()

        }

    }ELSE{

        Write-Output "Export successfully completed with no errors!"

        # If ShowDuration parameter is used
        IF($ShowDuration){

            # Create variable for time elapsed
            $WriteTime = ([string]::Format("{0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))
            Write-Output "Script duration: $WriteTime"

            # Stop clock for time elapsed
            $ElapsedTime.stop()

        }
    }
}

$tempFolderPathFile | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
$tempFolderList | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
$csvParts | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
(net use ${pathLetter}: /DELETE) | Out-Null

#endregion