#region VARIABLES
$LogFolderPath = "C:\Windows\Logs\AdobeRUM"
$LogFilePath = Join-Path -Path $LogFolderPath -ChildPath "Adobe_RemoteUpdateManager_$(Get-Date -Format yyyy-MM).log"
$exePath = "${env:ProgramFiles(x86)}\Common Files\Adobe\OOBE_Enterprise\RemoteUpdateManager\RemoteUpdateManager.exe"
$exeLogPath = "$env:TEMP\RemoteUpdateManager.log"
$exeArgList = @(
            "--action=install"
        )
#endregion


#region FUNCTIONS
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
    if(!(Test-Path $LogFolderPath)){
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
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FilePath -Force -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }
}
#endregion

#region PROCESS
New-Item -Path $LogFolderPath -ItemType Directory -Force | Out-Null
Write-LogEntry -Message "######## START SCRIPT ########"

if (Get-Item $exePath -Force) {
    Write-LogEntry -Message "Found path: $exePath"
    $ErrorActionPreference = "Stop"
    try {
        $CheckUpdates = (Start-Process -FilePath $exePath -ArgumentList $exeArgList -PassThru -Wait)

        try {
            Move-Item -Path $exeLogPath -Destination "$LogFolderPath\$((Split-Path -Path $exeLogPath -Leaf) -replace "(.*)[.](.*)", "`$1_$(Get-Date -Format yyyy-MM-dd).`$2")" -Force
        }
        catch {
            Write-LogEntry -Severity ERROR -Message "Failed to move RemoteUpdateManager.log from '$env:TEMP\RemoteUpdateManager.log' to log path. Error Message: $($_.Exception.Message)"
        }

        if($CheckUpdates.ExitCode -eq 0){
            Write-LogEntry -Message "Successfully Updated Adobe Apps"
            Write-LogEntry -Message "######## END SCRIPT ########"
            exit 0
        }
        if($CheckUpdates.ExitCode -eq 1){
            Write-LogEntry -Severity ERROR -Message "Generic error"
            Write-LogEntry -Message "######## END SCRIPT ########"
            exit 1
        }
        if($CheckUpdates.ExitCode -eq 2){
            Write-LogEntry -Severity ERROR -Message "One or more updates could not be installed"
            Write-LogEntry -Message "######## END SCRIPT ########"
            exit 2
        }
    }
    catch {
        Write-LogEntry -Severity ERROR -Message "An error occurred. Error message: $($_.Exception.Message)"
        Write-LogEntry -Message "######## END SCRIPT ########"
        exit 3
    }
    $ErrorActionPreference = "Continue"
} else {
    Write-LogEntry -Severity ERROR -Message "Could not find path: $cmdPath"
    Write-LogEntry -Message "######## END SCRIPT ########"
    exit 4
}
#endregion
