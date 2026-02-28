# Force administrator
#Requires -RunAsAdministrator

# Parameters

[Cmdletbinding(DefaultParameterSetName = 'Dynamic')]

Param(

    [Parameter(Mandatory, HelpMessage = 'Name of the virtual machine')]
    [String]$VMName,

    [Parameter(Mandatory, HelpMessage = 'Where to save the virtual machine files.')]
    [ValidateScript({

        IF (!(Test-Path $_)){

            throw "The virtual machine path provided doesn't exist."
        
        }
        $true
    
    })]
    [String]$VMPath,

    [Parameter(Mandatory, HelpMessage = 'How many vCPU cores the virtual machine will have.')]
    [ValidateRange(1,32)]
    [Int]$vCpuCores,




    [Parameter(Mandatory, HelpMessage = 'Virtual machine Startup Memory in MB.')]
    [ValidateScript({

        IF($_ % 2){

            throw 'Supply an even number!'
            
        }
        $true
    })]
    [ValidateRange(32,256000)]
    [Int64]$StartupMemory,



    [Parameter(Mandatory, ParameterSetName='Dynamic', HelpMessage = 'Minimum Memory in MB.')]
    [ValidateScript({

        IF($_ % 2){

            throw 'Supply an even number!'
            
        }
        $true
    })]
    [ValidateRange(32,256000)]
    [Int64]$MinimumMemory,



    [Parameter(Mandatory, ParameterSetName='Dynamic', HelpMessage = 'Maximum Memory in MB.')]
    [ValidateScript({

        IF($_ % 2){

            throw 'Supply an even number!'
            
        }
        $true
    })]
    [ValidateRange(32,256000)]
    [Int64]$MaximumMemory,



    [Parameter(Mandatory, HelpMessage = 'Size of main system disk in GB.')]
    [ValidateRange(30,200)]
    [Int64]$SystemDiskSize,



    [Parameter(ParameterSetName='Static')]
    [Switch]$StaticMemory,


    [Parameter(HelpMessage = 'Name of the virtual switch to connect the virtual machine to.')]
    $VMSwitch,


    [Parameter(HelpMessage = 'Add this parameter to log script.')]
    [Switch]$Log

)


    # vSwitch

# If no vSwitch is provided as parameter
IF (!$VMSwitch){

    # Get all vSwitches on server
    $CheckvSwitch = Get-VMSwitch

    # If vSwitches are found, lets user choose vSwitch
    IF($CheckvSwitch){
        
        $VirtualSwitch = $CheckvSwitch | Out-GridView -Title "Choose vSwitch" -PassThru

    }ELSE{ # If no vSwitches are found, continues and skipping network adapter configuration on VM.
    
        Write-Warning "No vSwitch was found on server, no network adapter will be configured."
    
    }
}ELSE{ # If a vSwitch is provided as parameter
    
    # Get the vSwitch provided
    $VirtualSwitch = Get-VMSwitch $VMSwitch

    # If the vSwitch is found, verbose confirmation message
    IF($VirtualSwitch){
    
        Write-Verbose "VM will be connected to $VirtualSwitch"
    
    }ELSE{ # If the vSwitch is not found, break script.

        Write-Warning "No vSwitch with the name '$VMSwitch' was found. Breaking script..."
        Break

    }
}




# Clear error variable
$error.clear()




# Save a log file if the parameter is provided.
IF($Log){
    
    $Date = Get-Date -Format yyyy-mm-dd_HHmm
    Start-Transcript -Path "$env:temp\Log_$Date.txt"

}  

        
# Calculates Startup memory MB to Bytes
[Int64]$StartupMemory = $StartupMemory*1MB



# Calculates System disk size GB to Bytes
[Int64]$SystemDiskSize = $SystemDiskSize*1GB


# Creates VM
New-VM -Name $VMName -BootDevice VHD -MemoryStartupBytes $StartupMemory -Path $VMPath -Generation 2 -Verbose | Out-Null

# If vSwitch is chosen, connects VM network adapter to chosen vSwitch.
IF($VirtualSwitch){

    Connect-VMNetworkAdapter -VMName $VMName -Name $((Get-VMNetworkAdapter -VMName $VMName)[0].Name) -SwitchName $($VirtualSwitch).Name -Verbose

}

# Creates variable for VHD path.
$VHDPath = "$((Get-VM -Name $VMName).ConfigurationLocation)\Virtual Hard Disks"

# Creates system disk vhd on the VM.
New-VHD -Path "$VHDPath\$VMName.vhdx" -Dynamic -SizeBytes 12GB -Verbose | Out-Null
Add-VMHardDiskDrive -VMName $VMName -Path "$VHDPath\$VMName.vhdx" -ControllerType SCSI -ControllerNumber 0 -Verbose


# Configures VM Memory.
IF ($StaticMemory){
    
    # If StaticMemory parameter is provided, only configure vCPU cores.
    Set-VM -Name $VMName -ProcessorCount $vCpuCores -StaticMemory -Verbose

}ELSE{

    [Int64]$MinimumMemory = $MinimumMemory*1MB
    [Int64]$MaximumMemory = $MaximumMemory*1MB

    # If StaticMemory parameter is not provided, configure vCPU, minimum memory and maximum memory.
    Set-VM -Name $VMName -ProcessorCount $vCpuCores -DynamicMemory -MemoryMinimumBytes $MinimumMemory -MemoryMaximumBytes $MaximumMemory -Verbose

}




# Create 3 SCSI Controllers on the VM
Add-VMScsiController -VMName $VMName -Verbose
Add-VMScsiController -VMName $VMName -Verbose
Add-VMScsiController -VMName $VMName -Verbose



# Creates all the SQL VHDs in different controllers.
New-VHD -Path "$VHDPath\$($VMName)_SQLData.vhdx" -Dynamic -SizeBytes 12GB -Verbose | Out-Null
Add-VMHardDiskDrive -VMName $VMName -Path "$VHDPath\$($VMName)_E_SQLData.vhdx" -ControllerType SCSI -ControllerNumber 1 -Verbose

New-VHD -Path "$VHDPath\$($VMName)_SQLBackup.vhdx" -Dynamic -SizeBytes 14GB -Verbose | Out-Null
Add-VMHardDiskDrive -VMName $VMName -Path "$VHDPath\$($VMName)_F_SQLBackup.vhdx" -ControllerType SCSI -ControllerNumber 0 -Verbose

New-VHD -Path "$VHDPath\$($VMName)_SQLT-Log.vhdx" -Dynamic -SizeBytes 13GB -Verbose | Out-Null
Add-VMHardDiskDrive -VMName $VMName -Path "$VHDPath\$($VMName)_L_SQLT-Log.vhdx" -ControllerType SCSI -ControllerNumber 2 -Verbose

New-VHD -Path "$VHDPath\$($VMName)_SQLSys.vhdx" -Dynamic -SizeBytes 11GB -Verbose | Out-Null
Add-VMHardDiskDrive -VMName $VMName -Path "$VHDPath\$($VMName)_S_SQLSys.vhdx" -ControllerType SCSI -ControllerNumber 0 -Verbose

New-VHD -Path "$VHDPath\$($VMName)_SQLTempDB.vhdx" -Dynamic -SizeBytes 10GB -Verbose | Out-Null
Add-VMHardDiskDrive -VMName $VMName -Path "$VHDPath\$($VMName)_T_SQLTempDB.vhdx" -ControllerType SCSI -ControllerNumber 3 -Verbose