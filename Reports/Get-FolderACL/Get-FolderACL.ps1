
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

    [Parameter(Mandatory, HelpMessage = 'Path to search ACL in.')]
    [String]$Path,

    [Switch]$Recurse,

    [Parameter(HelpMessage = 'Save format for export file.')]
    [Validateset('CSV','XLSX','ALL')]$ExportFormat = "ALL",

    [Parameter(HelpMessage = 'Save path for export file.')]
    [String]$ExportPath = (Split-Path -Parent $MyInvocation.MyCommand.Definition),

    [Parameter(HelpMessage = "Add this parameter if you don't want an error log to be processed.")]
    [Switch]$NoErrorLog,

    [Parameter(HelpMessage = "Add this parameter if you want to show time elapsed.")]
    [Switch]$ShowDuration

)


# Set variable for current date and time
$Date = Get-Date -Format yyyy-MM-dd_HHmm

#region format check

IF($ExportFormat -notlike "CSV"){

    # Check if ImportExcel module is imported, install module if it's not found.
    IF (!(Get-Module ImportExcel)){          
  
        Try{
            
            Write-Verbose "Installing module for xlsx export..." -Verbose
            Install-Module ImportExcel -Force -ErrorVariable +ErrorList -ErrorAction Stop -Verbose
            Import-Module ImportExcel -ErrorVariable +ErrorList -ErrorAction Stop -Verbose

        }Catch{
            
            Write-Host $_ -ForegroundColor Red -BackgroundColor Black
            Write-Warning "Failed to install module!"
            
            # If export format is ALL, continue script anyway with exportformat as CSV
            IF($ExportFormat -like "ALL"){
            
                Write-Verbose "Only exporting to csv"
                $ExportFormat = "CSV"
            
            }ELSE{
                
                Write-Verbose "Try this script again with another format."
                Pause
                Break

            }
        }
    }
}


#endregion

#region Path check


# Check SearchPath
IF (!(Test-Path $Path -PathType Container)){

    Throw 'Search path could not be found!'
    Break

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

    $AllSteps = 2

}ELSE{

    $AllSteps = 3

}




# Start clock for time elapsed
IF($ShowDuration){

    $ElapsedTime = [system.diagnostics.stopwatch]::StartNew()

}






# Get all folders in path.
Write-Output "Fetching all folders..."
$i=0

# Get permissions from target folder
$ParentFolderPath = Get-Item -Path $Path -Force -ErrorVariable Errorlist

IF($Recurse){

    # Get permissions from child folders
    Get-ChildItem -Directory -Path $Path -Recurse -Force -OutVariable ChildFoldersPath -ErrorVariable +ErrorList | ForEach-Object{
    
        #region Progress bar
        IF($ShowDuration){
        
            # Create variable for time elapsed
            $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

            # Create arguments for write-progress with time elapsed.
            $Progress = @{
                Activity = "Step 1 of $($AllSteps): Fetching folders."
                CurrentOperation = $WriteTime
                Status = "Processed $i folders."
            }

        }ELSE{
    
            # Create arguments for write-progress without time elapsed.
            $Progress = @{
                Activity = "Step 1 of $($AllSteps): Fetching folders."
                Status = "Processed $i folders."
            }    
    
        }

        Write-Progress @Progress 
        $i++
        #endregion
    }
}ELSE{

    # Get permissions from child folders
    Get-ChildItem -Directory -Path $Path -Force -OutVariable ChildFoldersPath -ErrorVariable +ErrorList | ForEach-Object{
    
        #region Progress bar
        IF($ShowDuration){
        
            # Create variable for time elapsed
            $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

            # Create arguments for write-progress with time elapsed.
            $Progress = @{
                Activity = "Step 1 of $($AllSteps): Fetching folders."
                CurrentOperation = $WriteTime
                Status = "Processed $i folders."
            }

        }ELSE{
    
            # Create arguments for write-progress without time elapsed.
            $Progress = @{
                Activity = "Step 1 of $($AllSteps): Fetching folders."
                Status = "Processed $i folders."
            }    
    
        }

        Write-Progress @Progress 
        $i++
        #endregion
    }

}

# Creating an array to add both target folder and child folders into same variable for processing
$FolderPath = @()
$FolderPath += $ParentFolderPath
$FolderPath += $ChildFoldersPath

Write-Output "Folders fetched!"




# Set progress bar variables
$i=0
$tot = $FolderPath.count

Write-Output "Processing folders..."

# Start processing every folder
Foreach ($Folder in $FolderPath) {
    
    #region Progress bar

    # Set up progress bar
	$i++
	$status = "{0:N0}" -f ($i / $tot * 100)
    
    IF($ShowDuration){
        
        # Create variable for time elapsed
        $WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))

        # Create arguments for write-progress with time elapsed.
        $Progress = @{
            Activity = "Step 2 of $($AllSteps): Exporting folder permissions."
            CurrentOperation = $WriteTime
            Status = "Processing folder $i of $tot : $status% Completed"
            PercentComplete = ($i / $tot * 100)
        }

    }ELSE{
        
        # Create arguments for write-progress without time elapsed.
        $Progress = @{
            Activity = "Step 2 of $($AllSteps): Exporting folder permissions."
            Status = "Processing folder $i of $tot : $status% Completed"
            PercentComplete = ($i / $tot * 100)
        }    
    
    }

    Write-Progress @Progress 
    #endregion


    Write-Verbose "Processing $($Folder.FullName)"
    
    # Clear variables
    Clear-Variable -Name ACL,AccessRights,FolderInheritance,AccessAppliedTo,Properties -ErrorAction SilentlyContinue

    # Get acl for folder.
    $ACL = Get-Acl -Path $Folder.FullName -ErrorVariable +ErrorList

    # Start processing every acl for folder.
    foreach ($Access in $ACL.Access){
        
        # If user access is masked with numbers.
        IF ($Access.FileSystemRights -match '\d+'){
                
            # Translate permission using the access mask and set variable for translated permissions.
            $AccessRights = (($AccessMask.Keys | Where-Object { $Access.FileSystemRights.value__ -band $_ } | ForEach-Object { $AccessMask[$_] } | Out-String).Trim()) -replace "`n",", "
            
        }ELSE {
            
            # Set variable for permissions.
            $AccessRights = $Access.FileSystemRights
            
        }

        # Get folder inheritance setting
        IF ($ACL.AreAccessRulesProtected){

            $FolderInheritance = "Disabled"

        }ELSE{
        
            $FolderInheritance = "Enabled"
        
        }
        
        # Use created function to get propagation.
        $AccessAppliedTo = Get-ACLPropagation -ACLAccessObject $Access -PropagationRules $PropagationRules

        # 
        IF ($AccessRights){

            # Create hash table and add values.
            $Properties = [ordered]@{'Folder Name'=$Folder.FullName;'User/Group'=$Access.IdentityReference;'Permissions'=$AccessRights;'Type'=$Access.AccessControlType;'Applies to'=$AccessAppliedTo;'Permission Inherited'=$Access.IsInherited;'Folder inheritance'=$FolderInheritance}

            # Add hash table to csv array.
            $Report += New-Object -TypeName PSObject -Property $Properties

        }
    }
}

#endregion







# Export result to csv.
IF($ExportFormat -notlike "XLSX"){

    $Report | Export-Csv -Path $CSVExportPath -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
    Write-Verbose "CSV export path: $CSVExportPath"

}


#Export result to xslx.
IF($ExportFormat -notlike "CSV"){
    
    $Report | Export-Excel -Path $XLSXExportPath -WorksheetName "Report" -AutoSize -FreezeTopRow -BoldTopRow -TableName Report -ErrorVariable +ErrorList -ErrorAction Stop
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

	    Write-Progress -Activity "Step 3 of $($AllSteps): Exporting errors." -CurrentOperation $WriteTime -Status "Processing error $i of $tot : $status% Completed" -PercentComplete ($i / $tot * 100)

        # Create hash table and add values.
        $ErrorProperties = [ordered]@{'Command'=$ErrorItem.CategoryInfo.Activity;'Folder Name'=$ErrorItem.CategoryInfo.TargetName;'Category'=$ErrorItem.CategoryInfo.Category;'Reason'=$ErrorItem.CategoryInfo.Reason;'Message'=$ErrorItem.Exception.Message}
    
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

#endregion