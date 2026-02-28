$vmName = "avd-img"
$rgName = "RG-Yoel-Abraham"
$location = "westeurope"
$imageName = "3.0.0"
$GalleryName = "AVDGallery01"
$DefinitionName = "avd-definition01"

Write-Host "`t Invokimg VM Command for Sysprep..." -ForegroundColor Yellow
if ((Invoke-AzVMRunCommand -ResourceGroupName $rgName -VMName $vmName -CommandId 'RunPowerShellScript' -ScriptString 'Start-Process "C:\Windows\System32\Sysprep\sysprep.exe" -ArgumentList "/oobe /generalize /shutdown" -Wait').Status -notmatch 'Succeeded') {
    Write-Warning "An error occurred when sending PS Commands to VM"
    Exit 1
}


Write-Host "`t Waiting for VM stop..." -ForegroundColor Yellow
while ($true){
    if(!($status = ((Get-AzVM -ResourceGroupName $rgName -Name $vmName -Status).Statuses | where {$_.Code -match '^PowerState/'}).Code -replace 'PowerState/')) {
        Write-Warning "Failed to get VM PowerState"
        Exit 2
    }

    if ($status -eq 'stopped'){
        if ((Stop-AzVM -ResourceGroupName $rgName -Name $vmName -Force).Status -notmatch 'Succeeded'){
            Write-Warning "An error occurred while Stopping VM (deallocate)"
            Exit 3
        }

        if(!($status = ((Get-AzVM -ResourceGroupName $rgName -Name $vmName -Status).Statuses | where {$_.Code -match '^PowerState/'}).Code -replace 'PowerState/')) {
            Write-Warning "Failed to get VM PowerState"
            Exit 2
        }
    }

    if ($status -eq 'deallocated'){
        Break
    }else {
        Start-Sleep 5
    }
}

Write-Host "`t Generalizing VM..." -ForegroundColor Yellow
if ((Set-AzVm -ResourceGroupName $rgName -Name $vmName -Generalized).Status -notmatch 'Succeeded'){
    Write-Warning "An error occurrred when to generalizing VM"
    Exit 4
}

if(!($vm = Get-AzVM -Name $vmName -ResourceGroupName $rgName)){
    Write-Warning "Failed to get VM object"
    Exit 5
}

Write-Host "`t Capturing VM..." -ForegroundColor Yellow
if ((New-AzGalleryImageVersion -ResourceGroupName RG-Yoel-Abraham -GalleryName $GalleryName -GalleryImageDefinitionName $DefinitionName -Name $imageName -Location $location -SourceImageId $vm.Id -ErrorAction Stop).ProvisioningState -notmatch 'Succeeded'){
    Write-Warning "Failed to create image version"
    Exit 6
}

$nics = Get-AzNetworkInterface -ResourceGroupName $rgName | where {$_.Id -eq $vm.NetworkProfile.NetworkInterfaces.id}

Write-Host "`t Deleting VM..." -ForegroundColor Yellow
if (($vm | Remove-AzVM -ForceDeletion $true -Force).Status -notmatch 'Succeeded'){
    Write-Warning "Failed to delete VM"
    Exit 7
}

foreach ($pip in ($nics.IpConfigurations.PublicIpAddress)) {
    $Pips += @(Get-AzPublicIpAddress -ResourceGroupName $rgName | where {$_.Name -eq $pip.Name})
}

$disks = @(
    Get-AzDisk -ResourceGroupName $rgName | where {$_.Id -eq $vm.StorageProfile.OsDisk.ManagedDisk.Id} -ErrorAction SilentlyContinue)

foreach ($disk in ($vm.StorageProfile.DataDisks)) {
    $disks += @(Get-AzDisk -ResourceGroupName $rgName | where {$_.Name -eq $disk.Name})
}

$nics = Get-AzNetworkInterface -ResourceGroupName $rgName | where{$_.Id -eq $vm.NetworkProfile.NetworkInterfaces.id}


$disks | foreach {
    Write-Host "`t Deleting disk resource '$($_.Name)'..." -ForegroundColor Yellow
    if ((Remove-AzDisk -ResourceGroupName $_.ResourceGroupName -DiskName $_.Name -Force).Status -notmatch 'Succeeded'){
        Write-Warning "Failed to delete VM Disk '$($_.Name)'"
        Exit 8
    }
}

$nics | foreach {
    Write-Host "`t Deleting Network Interface resource '$($_.Name)'..." -ForegroundColor Yellow
    if ((Remove-AzNetworkInterface -ResourceGroupName $_.ResourceGroupName -Name $_.Name -Force).Status -notmatch 'Succeeded'){
        Write-Warning "Failed to delete VM NIC '$($_.Name)'"
        Exit 8
    }
}

$Pips | foreach {
    Write-Host "`t Deleting Public IP resource '$($_.Name)'..." -ForegroundColor Yellow
    if ((Remove-AzPublicIpAddress -ResourceGroupName $_.ResourceGroupName -Name $_.Name -Force).Status -notmatch 'Succeeded'){
        Write-Warning "Failed to delete VM Public IP Address '$($_.Name)'"
        Exit 9
    }
}

