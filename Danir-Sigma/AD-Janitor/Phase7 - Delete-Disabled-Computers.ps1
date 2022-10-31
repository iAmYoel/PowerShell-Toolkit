
Import-Module ActiveDirectory

$ou = 'OU=Disabled Computers,OU=SigmaGroup-Other,DC=sigma,DC=local'

function get-computers
{
    Get-ADComputer -SearchBase $ou -Filter * -Properties Name, LastLogonDate, distinguishedName, Description, ManagedBy, Enabled | 
    Select-Object Name, LastLogonDate, distinguishedName, Description, ManagedBy, Enabled | sort LastLogonDate |
    Where {$_.LastLogonDate -le (Get-Date).AddDays(-180) -and $_.Enabled -eq $false}
}

function export-computers
{
    #start-sleep -s 2
    $date = Get-Date -Format 'yyyy/MM/dd'
    $Comps | Export-csv -Path C:\PowerShell\Ad-Janitor\Logs\Phase7\$date-deleted-computers.csv -NoTypeInformation -Delimiter ";" -Encoding Default
}

function delete-computer
{
    Get-ADComputer $Comp.distinguishedName |  Remove-ADObject -Recursive -confirm:$false
}




$Comps = get-computers
export-computers

foreach($Comp in $Comps)
{
    #Write-Host $Comp.distinguishedName
    #Read-Host "OK?"
    delete-computer
}

