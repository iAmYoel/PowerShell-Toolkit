
$ous = "OU=SigmaGroup,DC=sigma,DC=local", "OU=Users,OU=External,OU=SigmaGroup-Other,DC=sigma,DC=local"


function get-expired-users-14days #Hämtar expired användare från 14 dagar eller mer tillbaka
{
    Get-ADUser -SearchBase $ou -Filter * -Properties DisplayName, SamAccountName, description, Company, Department, DistinguishedName, Manager, Created, LastLogonDate, Enabled, AccountExpirationDate | 
    Select-Object DisplayName, SamAccountName, description, Company, Department, DistinguishedName, @{N='Manager';E={(Get-ADUser $_.Manager).sAMAccountName}}, Created, LastLogonDate, Enabled, AccountExpirationDate | 
    Where-Object {($_.AccountExpirationDate -lt (Get-Date).AddDays(-14)) -and ($_.AccountExpirationDate -gt $Null) -and 
    ($_.distinguishedname -notmatch 'OU=Common All') -and ($_.distinguishedname -notmatch'OU=Shared mailboxes') -and ($_.distinguishedname -notmatch 'OU=Service Accounts')}
}

function get-disabled-users-14days #Hämtar inaktiverade användare som inte loggat in på 14dagar
{
    Get-ADUser -SearchBase $ou -Filter * -Properties DisplayName, SamAccountName, description, Company, Department, DistinguishedName, Manager, Created, LastLogonDate, Enabled, AccountExpirationDate | 
    Select-Object DisplayName, SamAccountName, description, Company, Department, DistinguishedName, @{N='Manager';E={(Get-ADUser $_.Manager).sAMAccountName}}, Created, LastLogonDate, Enabled, AccountExpirationDate | 
    Where-Object {($_.Enabled -like "false") -and ($_.LastLogonDate -lt (Get-Date).AddDays(-14)) -and 
    ($_.distinguishedname -notmatch 'OU=Common All') -and ($_.distinguishedname -notmatch'OU=Shared mailboxes') -and ($_.distinguishedname -notmatch 'OU=Service Accounts')}
}



function export-expired-users-14days #Exporterar en lista med expired användare från 14 dagar eller mer tillbaka
{
    start-sleep -s 2
    
    $dates = Get-Date -Format 'yyyy/MM/dd/ss'
    $date = Get-Date -Format 'yyyy/MM/dd'

    $users | Export-csv -Path C:\PowerShell\Ad-Janitor\Logs\Phase3\$date\_logs-expired-users-$dates.csv -NoTypeInformation -Delimiter ";" -Encoding Default
}

function export-disabled-users-14days #Exporterar en lista med inaktiverade användare
{
    start-sleep -s 2
    
    $dates = Get-Date -Format 'yyyy/MM/dd/ss'
    $date = Get-Date -Format 'yyyy/MM/dd'

    $users | Export-csv -Path C:\PowerShell\Ad-Janitor\Logs\Phase3\$date\_logs-disabled-users-$dates.csv -NoTypeInformation -Delimiter ";" -Encoding Default
}



function log-memberof-expired-users-14days
{
    $alias = $user.SamAccountName
    $date = Get-Date -Format 'yyyy/MM/dd'

    Get-ADPrincipalGroupMembership $alias | select name | Sort-Object name | Out-File C:\PowerShell\Ad-Janitor\Logs\Phase3\$date\$alias-Group-expired-users--14days.csv -Encoding UTF8
}

function log-memberof-disabled-users-14days
{
    $alias = $user.SamAccountName
    $date = Get-Date -Format 'yyyy/MM/dd'

    Get-ADPrincipalGroupMembership $alias | select name | Sort-Object name | Out-File C:\PowerShell\Ad-Janitor\Logs\Phase3\$date\$alias-Group-disabled-users.csv -Encoding UTF8
}



function create-folder
{
    $date = Get-Date -Format 'yyyy/MM/dd'
    new-item C:\PowerShell\Ad-Janitor\Logs\Phase3\$date\ -itemtype directory
}

function disable-ad-user
{
    Disable-ADAccount -Identity $user.SamAccountName
}

function move-user-to-disabled-ou
{
    Move-ADObject -Identity $user.distinguishedname -TargetPath 'OU=Disabled Users,OU=SigmaGroup-Other,DC=sigma,DC=local'
}

function delete-memberof
{
    $alias = $user.SamAccountName
    $Groups = Get-ADPrincipalGroupMembership $alias
    ForEach($Group in $Groups)
    {
        Get-ADGroup -Identity $Group | Remove-ADGroupMember -Members $alias -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function clear-description
{
    Set-ADUser $user.SamAccountName -Clear Description
}

<#
function generate-maximo-excel-expired-users-14days
{
    $users = get-expired-users-14days

if(!$users)
{}
else
{
    #Exports the info to an excel. Uses custom headers.
    $date = Get-Date -Format 'yyyy/MM/dd'
    #$users | Export-XLSX -Path "C:\PowerShell\Ad-Janitor\Logs\Phase3\inactive-users-$date.xlsx" -AutoFit -Header DisplayName, SamAccountName, mail, mobile, title, Company, Department, StreetAddress, Office, DistinguishedName, Created
    $users | Export-XLSX -Path "C:\PowerShell\Ad-Janitor\Logs\Phase3\inactive-users-$date.xlsx" -AutoFit -Header DisplayName, SamAccountName, description, Company, Department, DistinguishedName, Created, LastLogonDate, Enabled, AccountExpirationDate
    $excel = New-Excel -Path "C:\PowerShell\Ad-Janitor\Logs\Phase3\inactive-users-$date.xlsx"
    $FilledCells = Search-CellValue -Excel $excel -FilterScript {$_ -like '*'} -WorkSheetName	($excel | Get-Worksheet)
    foreach ($Cell in $FilledCells)
    {
    if (($Cell.Column -ne '1') -and ($Cell.Row -ne '1'))
    {    
        Format-Cell -WorkSheet ($excel | Get-Worksheet) -StartRow $Cell.Row -StartColumn $Cell.Column -EndRow $Cell.Row -EndColumn $Cell.Column #-Color ForestGreen -Font Arial
    }
    }  
  
    Save-Excel -Excel $excel


#Variables to the send-mailmessage function.
$From = 'support@sigma.se'
$To = 'support@sigma.se'
$Attachments = "C:\PowerShell\Ad-Janitor\Logs\Phase3\inactive-users-$date.xlsx"
$SMTPServer = "mailrelay.sigma.local"
$Subject = "Avslut av Maximo konto $date"
$Body = @"
Hej!
Bifogat i detta mail så finns en excelfil. Den innehåller konton som har avslutats.
Vänligen inaktivera Maximokonto.
Rutin finns på Wiki:
RUTIN-LÄNK

Tack!

"@

Send-MailMessage -Attachments $Attachments -Body $Body -From $From -To $To -SmtpServer $SMTPServer -Subject $Subject -Encoding Default
Send-MailMessage -Attachments $Attachments -Body $Body -From $From -To "christian.spector@sigma.se" -SmtpServer $SMTPServer -Subject $Subject -Encoding Default

}

#>

<# RUN #>

create-folder

foreach($ou in $ous) #Går igenom expired-users-14days
{
    $users = get-expired-users-14days
    export-expired-users-14days
    #generate-maximo-excel-expired-users-14days

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
    #generate-maximo-excel

    foreach($user in $users)
    {
        log-memberof-disabled-users-14days
        delete-memberof
        clear-description
        move-user-to-disabled-ou
    }
}
