$logPath = "C:\ProgramData\Kaseya\Log\Stop-SQLServices.log"

function Write-LogEntry {
    param (
        [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [parameter(Mandatory = $false, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Severity = "INFO",

        [parameter(Mandatory = $false, HelpMessage = "File path of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath = $logPath,

        [parameter(Mandatory = $false, HelpMessage = "Outputs value to console")]
        [switch]$PrintOutput
    )

    # Construct time stamp for log entry
    $Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

    # Construct final log entry
     $LogText = "$Time | $Severity | $Message | Context: $Context"

    # Output Value as verbose
    Write-Verbose $Message

    # Add value to log file
    Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FilePath -Force -ErrorAction Stop
}


$continueReboot = "true"
New-Item -Path $logPath -ItemType File -Force

try {
    $services = Get-Service | Where-Object { $_.Name -like 'MSSQL$*' -or $_.Name -eq 'MSSQLSERVER' -or $_.DisplayName -like 'SQL Server (*)' -or $_.DisplayName -eq 'SQL Server' } -ErrorAction Stop

    Write-LogEntry -Message "Found SQL services: $($services.Name -join ", ")"

    foreach ($svc in $services) {
        Write-LogEntry -Message "Stopping '$($svc.Name)'..."

        $allDependentServices = @()
        $allDependentServices += $svc

        if ($svc.DependentServices) {
            $checkService = $svc
            do{
                $allDependentServices += $checkService.DependentServices
                if ($checkService.DependentServices) {
                    $checkService = $checkService.DependentServices
                } else {
                    $breakLoop = $true
                }
            } until ($breakLoop)
            Write-LogEntry -Message "Found dependency services: $($allDependentServices.Name -join ", ")"
        }

        foreach ($item in ($allDependentServices | sort -Descending)) {
            try {
                Stop-Service $item -ErrorAction Stop

                Start-Sleep -Seconds 3
                $i = 0
                do {
                    $newStatus = $item | Get-Service
                    if (($newStatus.Status) -AND ($newStatus.Status -ne "StopPending")) {
                        $checkDone = $true
                    } else {
                        Start-Sleep -Seconds 3
                        $i++
                    }
                } until ($checkDone -or ($i -eq 100))

                $newStatus = $item | Get-Service
                if($newStatus.Status -ne "Stopped"){
                    Write-LogEntry -Severity WARNING -Message "'$($item.Name)' was not stopped."
                    $continueReboot = "false"
                } else {
                    Write-LogEntry -Message "'$($item.Name)' was successfully stopped."
                }
            }
            catch {
                Write-LogEntry -Severity ERROR -Message "Failed to stop service '$($item.Name)'. Error message: $($_.Exception)"
                $continueReboot = "false"
                Break
            }
        }
    }
}
catch {
    Write-LogEntry -Severity ERROR -Message "Failed to get SQL-services. Error message: $($_.Exception)"
    $continueReboot = "false"
}

if ($continueReboot -eq "true") {
    Write-LogEntry -Message "Server will continue with post-patch reboot sequence."
} else {
    Write-LogEntry -Severity WARNING -Message "Server will NOT continue with post-patch reboot sequence. Server not be restarted."
}

Write-Output $continueReboot