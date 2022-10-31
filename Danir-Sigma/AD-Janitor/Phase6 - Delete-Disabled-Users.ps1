
Import-Module ActiveDirectory

$ou = 'OU=Disabled Users,OU=SigmaGroup-Other,DC=sigma,DC=local'

function get-users
{
    Get-ADUser -SearchBase $ou -Filter * -Properties samAccountName, DisplayName, whenChanged, Enabled | 
    Select samAccountName, DisplayName, whenChanged, Enabled | sort whenChanged |
    Where {$_.Enabled -eq $false -and $_.whenChanged -le (Get-Date).AddDays(-180)}
}

function export-users
{
    #start-sleep -s 2
    $date = Get-Date -Format 'yyyy/MM/dd'
    $users | Export-csv -Path C:\PowerShell\Ad-Janitor\Logs\Phase6\$date-deleted-users.csv -NoTypeInformation -Delimiter ";" -Encoding Default
}

function delete-user
{
    $DistName = Get-ADUser -identity $user.SamAccountName | Select -ExpandProperty DistinguishedName
    #Write-Host $DistName
    Remove-ADObject $DistName -Recursive -confirm:$false
}




$users = get-users
export-users

foreach($user in $users)
{
    #Write-Host $user
    #Read-Host "OK?"
    delete-user
}


