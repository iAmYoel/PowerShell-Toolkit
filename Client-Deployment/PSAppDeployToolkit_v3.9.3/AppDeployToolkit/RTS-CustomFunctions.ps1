##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region FunctionListings

#region Function Get-LogonStatus
Function Get-LogonStatus {
    try {
        $user = $null
        $user = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Username -ErrorAction Stop
        if (!($user)) {
            return "System"
        } #Not logged on
    }
    catch {
        return "System"
    } #Not logged on

    try {
        if ((Get-Process logonui -ErrorAction Stop) -and ($user)) {
            return "User"
        } #Workstation locked
    }
    catch {
        if ($user) {
            return "User"
        }
    } #Computer In Use
}
#endregion

#region Function Get-LastChildProcess
Function Get-WMILastChildProcess {
    param (
        [int]$ParentProcessId
    )

    $NewChild = Get-WmiObject Win32_Process -Filter "ProcessId = $ParentProcessId" -ErrorAction SilentlyContinue
    $LastChild = $NewChild
    do{
        if ($NewChild = Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = $($NewChild.ProcessId)" -ErrorAction SilentlyContinue){
            $LastChild = $NewChild
        }else {
            Break
        }
    }while($true)

    return $LastChild

}
#endregion

#region Function WaitFor-ChildProcesses
Function WaitFor-ChildProcesses {
    param (
        [int]$ParentProcessId
    )

    do {
        # Get the child processes of the parent process
        if($childProcesses = Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = $ParentProcessId" -ErrorAction SilentlyContinue){
            foreach ($childProcess in $childProcesses) {
                do{
                    if ($LastChildProcess = Get-WMILastChildProcess -ParentProcessId $childProcess.ProcessId){
                        #WaitFor-ChildProcesses -ParentProcessId $childProcess.ProcessId
                        $childProcessObject = Get-Process -Id $LastChildProcess.ProcessId -ErrorAction SilentlyContinue
                        if ($childProcessObject -ne $null) {
                            $childProcessObject.WaitForExit()
                        }
                    }else {
                        Break
                    }
                }while($true)
            }

            # Sleep for a short duration before checking again
            Start-Sleep -Seconds 1
        }elseif ($mainProcess = Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue){
            Start-Sleep -Seconds 1
        }else{
            Break
        }
    } while ($true)
}
#endregion

#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================