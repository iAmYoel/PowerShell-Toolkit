if($PSScriptRoot){
    $scriptPath = $PSScriptRoot
}else{
    $scriptPath = "C:\PowerShell\Ad-Janitor"
}


$ous = "OU=Nexer Group Companies,DC=ad,DC=nexergroup,DC=com", "OU=External Users,OU=Nexer Group,DC=ad,DC=nexergroup,DC=com"


function get-expired-users-14days #Hämtar expired användare från 14 dagar eller mer tillbaka
{
    Get-ADUser -SearchBase $ou -Filter {(Enabled -eq $True) -and (AccountExpires -ne "0") -and (AccountExpires -ne "9223372036854775807")} -Properties DisplayName, SamAccountName, description, Company, Department, DistinguishedName, Manager, Created, LastLogonDate, Enabled, AccountExpirationDate |
    Select-Object DisplayName, SamAccountName, description, Company, Department, DistinguishedName, @{N='Manager';E={(Get-ADUser $_.Manager).sAMAccountName}}, Created, LastLogonDate, Enabled, AccountExpirationDate |
    Where-Object {($_.AccountExpirationDate -lt (Get-Date).AddDays(-14)) -and ($_.AccountExpirationDate -gt $Null)}
}

function get-disabled-users-14days #Hämtar inaktiverade användare som inte loggat in på 14dagar
{
    Get-ADUser -SearchBase $ou -Filter {(Enabled -eq $false)} -Properties DisplayName, SamAccountName, description, Company, Department, DistinguishedName, Manager, Created, LastLogonDate, Enabled, AccountExpirationDate |
    Select-Object DisplayName, SamAccountName, description, Company, Department, DistinguishedName, @{N='Manager';E={(Get-ADUser $_.Manager).sAMAccountName}}, Created, LastLogonDate, Enabled, AccountExpirationDate |
    Where-Object { ($_.LastLogonDate -lt (Get-Date).AddDays(-14)) }
}



function export-expired-users-14days #Exporterar en lista med expired användare från 14 dagar eller mer tillbaka
{
    start-sleep -s 2

    $dates = Get-Date -Format 'yyyy/MM/dd/ss'
    $date = Get-Date -Format 'yyyy/MM/dd'

    $users | Export-csv -Path "$scriptPath\Logs\Phase3\$date\_logs-expired-users-$dates.csv" -NoTypeInformation -Delimiter ";" -Encoding Default
}

function export-disabled-users-14days #Exporterar en lista med inaktiverade användare
{
    start-sleep -s 2

    $dates = Get-Date -Format 'yyyy/MM/dd/ss'
    $date = Get-Date -Format 'yyyy/MM/dd'

    $users | Export-csv -Path "$scriptPath\Logs\Phase3\$date\_logs-disabled-users-$dates.csv" -NoTypeInformation -Delimiter ";" -Encoding Default
}



function log-memberof-expired-users-14days
{
    $alias = $user.SamAccountName
    $date = Get-Date -Format 'yyyy/MM/dd'

    Get-ADPrincipalGroupMembership $alias | select name | Sort-Object name | Out-File "$scriptPath\Logs\Phase3\$date\$alias-Group-expired-users-14days.csv" -Encoding UTF8
}

function log-memberof-disabled-users-14days
{
    $alias = $user.SamAccountName
    $date = Get-Date -Format 'yyyy/MM/dd'

    Get-ADPrincipalGroupMembership $alias | select name | Sort-Object name | Out-File "$scriptPath\Logs\Phase3\$date\$alias-Group-disabled-users.csv" -Encoding UTF8
}



function create-folder
{
    $date = Get-Date -Format 'yyyy/MM/dd'
    New-Item "$scriptPath\Logs\Phase3\$date" -ItemType Directory
}

function disable-ad-user
{
    Disable-ADAccount -Identity $user.SamAccountName
}

function move-user-to-disabled-ou
{
    Move-ADObject -Identity $user.distinguishedname -TargetPath 'OU=Disabled Users,OU=NexerGroup-Other,DC=ad,DC=nexergroup,DC=com'
}

function delete-memberof
{
    $alias = $user.SamAccountName
    $Groups = Get-ADPrincipalGroupMembership $alias
    Remove-ADPrincipalGroupMembership -Identity $User -MemberOf $Groups
}

function clear-description
{
    Set-ADUser $user.SamAccountName -Clear Description
}


create-folder

foreach($ou in $ous) #Går igenom expired-users-14days
{
    $users = get-expired-users-14days
    export-expired-users-14days

    foreach($user in $users)
    {
        log-memberof-expired-users-14days
        delete-memberof
        clear-description
        disable-ad-user
        move-user-to-disabled-ou
    }
}

foreach($ou in $ous) #Går igenom disabled-users-14days
{
    $users = get-disabled-users-14days
    export-disabled-users-14days

    foreach($user in $users)
    {
        log-memberof-disabled-users-14days
        delete-memberof
        clear-description
        move-user-to-disabled-ou
    }
}
