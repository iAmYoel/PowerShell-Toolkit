function Check-ADServerStatus{

    $ADServers = Get-ADComputer -Filter "OperatingSystem -like 'Windows Server*'" -Properties Enabled,OperatingSystem | where{$_.Enabled} | Sort Name

    $result = @()

    Foreach($item in $ADServers){
        Clear-Variable props,DNS -ErrorAction SilentlyContinue
        Write-Host "$($item.name) : " -ForegroundColor Yellow -NoNewline
        try{
            $DNS = Resolve-DnsName $item.Name -Type A -ErrorAction Stop

            IF($DNS){
                Try{
                    Invoke-Command -ComputerName $item.Name -ScriptBlock {} -ErrorAction Stop
                    Write-Host "SUCCESS" -ForegroundColor Green
                    $props = [Ordered]@{"Hostname"=$item.Name;"IP4Address"=$DNS.IP4Address;"OperatingSystem"=$item.OperatingSystem;"NameResolution"=$(IF($DNS){"SUCCESS"}ELSE{"FAILED"});"PingSucceeded"=(Test-Connection $item.Name -Count 1 -Quiet);"PSRemoting"="SUCCESS";"Reason"=""}
                }Catch [System.Exception]{
                    Write-Host "FAILED PSRemoting" -ForegroundColor Red
                    $props = [Ordered]@{"Hostname"=$item.Name;"IP4Address"=$DNS.IP4Address;"OperatingSystem"=$item.OperatingSystem;"NameResolution"=$(IF($DNS){"SUCCESS"}ELSE{"FAILED"});"PingSucceeded"=(Test-Connection $item.Name -Count 1 -Quiet);"PSRemoting"="FAILED";"Reason"=$_.Exception.Message}
                }
            }ELSE{
                Write-Host "FAILED NameResolution" -ForegroundColor Red
                $props = [Ordered]@{"Hostname"=$item.Name;"IP4Address"="";"OperatingSystem"=$item.OperatingSystem;"NameResolution"="FAILED";"PingSucceeded"="False";"PSRemoting"="FAILED";"Reason"=$_.Exception.Message}

            }
        }Catch [System.Exception]{
            Write-Host "FAILED NameResolution" -ForegroundColor Red
            $props = [Ordered]@{"Hostname"=$item.Name;"IP4Address"="";"OperatingSystem"=$item.OperatingSystem;"NameResolution"="FAILED";"PingSucceeded"="False";"PSRemoting"="FAILED";"Reason"=$_.Exception.Message}

        }

        New-Object -TypeName PSObject -Property $props
    }
}