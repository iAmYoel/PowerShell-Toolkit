#Requires -RunAsAdministrator



# Get all disks with no partitions and is not systemdisk.
Write-Verbose "Getting disk info..."
$Disk = Get-Disk | Where {($_.NumberOfPartitions -eq 0) -AND ($_.IsSystem -eq $false)} | Sort Size -Verbose




""



Write-Verbose "Processing SQLTempDB (T:)."

## T: - (SQLTempDB)

# Checks if disk is larger than 2TB. If so, make it a GPT, otherwise make it a MBR. 
IF ($Disk[0].Size -ge 2TB){
    
    Write-Verbose "Configuring to GPT."
    $PartitionStyle = "GPT"
    
}ELSE{

    Write-Verbose "Configuring to MBR."
    $PartitionStyle = "MBR"

}



# Sets the disk online.
Write-Verbose "Setting disk online..."
Set-Disk -InputObject $Disk[0] -IsOffline $false -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Initialize disk and set partition style.
Write-Verbose "Initializing disk..."
Initialize-Disk -InputObject $Disk[0] -PartitionStyle $PartitionStyle -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Creates a new partition using the whole disk, and creates filesystem on partition.
Write-Verbose "Creating new partition and filesystem..."
New-Partition $Disk[0].Number -UseMaximumSize -Verbose | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel TempDB -Confirm:$false -Verbose | Out-Null

#  Sets driveletter.
Write-Verbose "Setting driveletter to partition..."
Get-Partition -DiskNumber $Disk[0].DiskNumber | Set-Partition -NewDriveLetter T -Verbose | Out-Null

Write-Verbose "SQLTempDB Done!"

""





Write-Verbose "Processing SQLSys (S:)."

## S: - (SQLSys)

# Checks if disk is larger than 2TB. If so, make it a GPT, otherwise make it a MBR. 
IF ($Disk[1].Size -ge (2TB)){

    Write-Verbose "Configuring to GPT."
    $PartitionStyle = "GPT"
    
}ELSE{

    Write-Verbose "Configuring to MBR."
    $PartitionStyle = "MBR"

}


# Sets the disk online.
Write-Verbose "Setting disk online..."
Set-Disk -InputObject $Disk[1] -IsOffline $false -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Initialize disk and set partition style.
Write-Verbose "Initializing disk..."
Initialize-Disk -InputObject $Disk[1] -PartitionStyle $PartitionStyle -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Creates a new partition using the whole disk, and creates filesystem on partition.
Write-Verbose "Creating new partition and filesystem..."
New-Partition $Disk[1].Number -UseMaximumSize -Verbose | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel SysDB -Confirm:$false -Verbose | Out-Null

#  Sets driveletter.
Write-Verbose "Setting driveletter to partition..."
Get-Partition -DiskNumber $Disk[1].DiskNumber | Set-Partition -NewDriveLetter S -Verbose | Out-Null

Write-Verbose "SQLSys Done!"



""



Write-Verbose "Processing SQLData (E:)."

## E: - (SQLData)

# Checks if disk is larger than 2TB. If so, make it a GPT, otherwise make it a MBR. 
IF ($Disk[2].Size -ge (2TB)){

    Write-Verbose "Configuring to GPT."
    $PartitionStyle = "GPT"
    
}ELSE{

    Write-Verbose "Configuring to MBR."
    $PartitionStyle = "MBR"

}


# Sets the disk online.
Write-Verbose "Setting disk online..."
Set-Disk -InputObject $Disk[2] -IsOffline $false -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Initialize disk and set partition style.
Write-Verbose "Initializing disk..."
Initialize-Disk -InputObject $Disk[2] -PartitionStyle $PartitionStyle -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Creates a new partition using the whole disk, and creates filesystem on partition.
Write-Verbose "Creating new partition and filesystem..."
New-Partition $Disk[2].Number -UseMaximumSize -Verbose | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel DataDB -Confirm:$false -Verbose | Out-Null

# Sets driveletter
Write-Verbose "Setting driveletter to partition..."
Get-Partition -DiskNumber $Disk[2].DiskNumber | Set-Partition -NewDriveLetter E -Verbose | Out-Null

Write-Verbose "SQLData Done!"




""




Write-Verbose "Processing SQLT-Log (L:)."

## L: - (SQLT-log)

# Checks if disk is larger than 2TB. If so, make it a GPT, otherwise make it a MBR. 
IF ($Disk[3].Size -ge (2TB)){

    Write-Verbose "Configuring to GPT."
    $PartitionStyle = "GPT"
    
}ELSE{

    Write-Verbose "Configuring to MBR."
    $PartitionStyle = "MBR"

}


# Sets the disk online.
Write-Verbose "Setting disk online..."
Set-Disk -InputObject $Disk[3] -IsOffline $false -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Initialize disk and set partition style.
Write-Verbose "Initializing disk..."
Initialize-Disk -InputObject $Disk[3] -PartitionStyle $PartitionStyle -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Creates a new partition using the whole disk, and creates filesystem on partition.
Write-Verbose "Creating new partition and filesystem..."
New-Partition $Disk[3].Number -UseMaximumSize -Verbose | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel LogDB -Confirm:$false -Verbose | Out-Null

# Sets driveletter
Write-Verbose "Setting driveletter to partition..."
Get-Partition -DiskNumber $Disk[3].DiskNumber | Set-Partition -NewDriveLetter L -Verbose | Out-Null

Write-Verbose "SQLT-Log Done!"




""




Write-Verbose "Processing SQLBackup (F:)."

## F: - (SQLBackup)

# Checks if disk is larger than 2TB. If so, make it a GPT, otherwise make it a MBR. 
IF ($Disk[4].Size -ge (2TB)){

    Write-Verbose "Configuring to GPT."
    $PartitionStyle = "GPT"
    
}ELSE{

    Write-Verbose "Configuring to MBR."
    $PartitionStyle = "MBR"

}


# Sets the disk online.
Write-Verbose "Setting disk online..."
Set-Disk -InputObject $Disk[4] -IsOffline $false -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Initialize disk and set partition style.
Write-Verbose "Initializing disk..."
Initialize-Disk -InputObject $Disk[4] -PartitionStyle $PartitionStyle -Verbose | Out-Null

Start-Sleep -Seconds 2 -Verbose

# Creates a new partition using the whole disk, and creates filesystem on partition.
Write-Verbose "Creating new partition and filesystem..."
New-Partition $Disk[4].Number -UseMaximumSize -Verbose | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel BackupDB -Confirm:$false -Verbose | Out-Null

# Sets driveletter
Write-Verbose "Setting driveletter to partition..."
Get-Partition -DiskNumber $Disk[4].DiskNumber | Set-Partition -NewDriveLetter F -Verbose | Out-Null

Write-Verbose "SQLBackup Done!"




""



Write-Output "All done!"
