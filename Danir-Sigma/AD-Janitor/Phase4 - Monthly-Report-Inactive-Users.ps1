#Imports the PSExcel module
Import-Module "\\ss0233\SITM-SITS\Operations\Win group\PowerShell\Modules\PSExcel-master\PSExcel\PSExcel.psm1"

<# Choose which OU the script will search in #>
$ous = "OU=SigmaGroup,DC=sigma,DC=local", "OU=Users,OU=External,OU=SigmaGroup-Other,DC=sigma,DC=local"

<# Function library #>

function get-aduser-not-logged-in-90days #Hämtar användare som inte loggat in på 90 dagar
{
    Get-ADUser -SearchBase $ou -Filter * -Properties DisplayName, LastLogonDate, DistinguishedName, SamAccountName, description, Company, Department, Created | 
    Select-Object DisplayName, LastLogonDate, distinguishedname, samaccountname, description, Company, Department, Created | 
    Where-Object {($_.LastLogonDate -le (Get-Date).AddDays(-90)) -and ($_.LastLogonDate -gt $Null) -and ($_.distinguishedname -notmatch 'OU=Common All') -and 
    ($_.distinguishedname -notmatch 'OU=Service Accounts') -and ($_.distinguishedname -notmatch 'OU=Shared mailboxes')}
}

function get-adusers-never-logged-on-90days #Hämtar användare som funnits i 90 dagar men aldrig loggat in
{
    Get-ADUser -SearchBase $ou -Filter * -Properties DisplayName, LastLogonDate, DistinguishedName, SamAccountName, description, Company, Department, Created | 
    Select-Object DisplayName, LastLogonDate, distinguishedname, samaccountname, description, Company, Department, Created | 
    Where-Object {($_.Created -le (Get-Date).AddDays(-90)) -and ($_.LastLogonDate -eq $Null) -and ($_.distinguishedname -notmatch 'OU=Common All') -and 
    ($_.distinguishedname -notmatch 'OU=Service Accounts') -and ($_.distinguishedname -notmatch 'OU=Shared mailboxes')}
}


function create-folder
{
    $date = Get-Date -Format 'yyyy/MM/dd'
    new-item C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\ -itemtype directory
}

function export-users #Exporterar en lista med alla användare
{
    start-sleep -s 2
    
    $date = Get-Date -Format 'yyyy/MM/dd'
    $dates = Get-Date -Format 'yyyy/MM/dd/ss'

    $users | Export-csv -Path C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\users-$dates.csv -NoTypeInformation -Delimiter ";" -Encoding Default
}

function get-email-to-manager
{
    try
    {Get-ADUser $user.samaccountname -Properties Manager | %{(Get-AdUser $_.Manager -Properties EmailAddress).EmailAddress} -ErrorAction SilentlyContinue}
    catch
    {}
}

function mail-to-manager
{
    
    $SMTPServer = "smtprelay.net.sigma.se"
    $SMTPPort = 25
    $Encoding = [System.Text.Encoding]::UTF8
    
    $From = "support@nexergroup.com"
    $To = $managerepost
    $subject = "AD-Janitor Monthly User Report"
        
    $emailtext = "Hi,`n
This is an automated report on users in Sigma AD that
you are manager for. These users have not logged in to
the AD / Domain for 90 days or more.

It also includes users that have the 'safety' word 'Absentia'
added to there account. Absentia meaning user account is
excluded from automatically be reported as inactive due to
long-term vacancy, sick leave, parental leave, etc.


Please report users that should not be active.
Thanks.

Best Regards
RTS Support

Email: support@rts.se
Phone from Sweden: 020- 510 520
Phone from abroad +46 (0)10- 102 50 50   
Nexer phone switchboard: 020-1800 1800
    "

    Send-MailMessage -From $From -To $To -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue

    if (!$To)
    {
        Send-MailMessage -From $From -To "christian.spector@nexergroup.com" -Subject "AD-Janitor - Phase 4: $($user.SamAccountName) Missing Manager" -Body "$($user.SamAccountName) Missing Manager" -BodyAsHTML -Encoding Default -SmtpServer $Smtp
    }

    $date = Get-Date -Format 'yyyy/MM/dd'
    $LoggedInfo = @"

    User               = $($user.displayname)
    UserName           = $($user.SamAccountName)
    Mail sent to       = $To
"@
    Add-Content -Encoding Default -Value $LoggedInfo -Path C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\$date-mail-log.log



if ($To) {Clear-Variable To}

}

function mail-to-superuser
{

<# HR4Sigma Super Users #>

$scon_su    = "sofie.barck.abrahamsson@sigmaconnectivity.se" # Sigma Connectivity AB
$sconeng_su = "sofie.barck.abrahamsson@sigmaconnectivity.se" # Sigma Connectivity Engineering AB
$sciv_su    = "maria.nordstromeriksson@sigma.se"             # Sigma Civil AB
$see_su     = "richard.kahl@sigma.se"                        # Sigma Embedded Engineering AB
$sem_su     = "magnus.liljeqvist@sigma.se"                   # Sigma Energy & Marine AB
$sien_su    = "oscar.berggren@sigma.se"                      # Sigma Industry East North AB
$siso_su    = "dick.stenebo@sigma.se"                        # Sigma Industry South AB
$sisol_su   = "dick.stenebo@sigma.se"                        # Sigma Industry Solutions AB
$siwe_su    = "magnus.liljeqvist@sigma.se"                   # Sigma Industry West AB
$sit_su     = "veronica.johannesen@nexergroup.com"           # Sigma IT AB
$sittech_su = "fredrik.sandin@nexergroup.com"                # Sigma IT Tech AB
$srec_su    = "fredrik.sandin@nexergroup.com"                # Sigma Recruit AB
$syt_su     = "fredrik.sandin@nexergroup.com"                # Sigma Young Talent AB

if($user.Company -like "Sigma Connectivity AB")
{
    $To = $scon_su
}
if($user.Company -like "Sigma Connectivity Engineering AB")
{
    $To = $sconeng_su
}
if($user.Company -like "Sigma Civil AB")
{
    $To = $sciv_su
}
if($user.Company -like "Sigma Embedded Engineering AB")
{
    $To = $see_su
}
if($user.Company -like "Sigma Energy & Marine AB")
{
    $To = $sem_su
}
if($user.Company -like "Sigma Industry East North AB")
{
    $To = $sien_su
}
if($user.Company -like "Sigma Industry South AB")
{
    $To = $siso_su
}
if($user.Company -like "Sigma Industry Solutions AB")
{
    $To = $sisol_su
}
if($user.Company -like "Sigma Industry West AB")
{
    $To = $siwe_su
}
if($user.Company -like "Sigma IT AB")
{
    $To = $sit_su
}
if($user.Company -like "Sigma IT Tech AB")
{
    $To = $sittech_su
}
if($user.Company -like "Sigma Recruit AB")
{
    $To = $srec_su
}
if($user.Company -like "Sigma Young Talent AB")
{
    $To = $syt_su
}

<# SMTP Settings #>
    
$SMTPServer = "smtprelay.net.sigma.se"
$SMTPPort = 25
$Username = ""
$Encoding = [System.Text.Encoding]::UTF8
    
$From = "support@nexergroup.com"
$subject = "AD-Janitor Monthly User Report"
        
$emailtext = "Hi,`n
You're the HR4Sigma super user for Company: $($user.company).
This is an automated report on users in Sigma AD that
have not logged in to the AD / Domain for 90 days or more.

Please report users that should not be active.
Thanks.

Best Regards
RTS Support

Email: support@rts.se
Phone from Sweden: 020- 510 520
Phone from abroad +46 (0)10- 102 50 50   
Nexer phone switchboard: 020-1800 1800
"

Send-MailMessage -From $From -To $To -Subject $subject -Body $emailtext -BodyAsHTML -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue
Send-MailMessage -From $From -To "christian.spector@nexergroup.com" -Subject $subject -Body $emailtext -BodyAsHTML -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue

if ($To) {Clear-Variable To}

}


<# SMTP Settings #>
    
$SMTPServer = "smtprelay.net.sigma.se"
$SMTPPort = 25
$Encoding = [System.Text.Encoding]::UTF8
    
$From = "support@nexergroup.com"
$subject = "AD-Janitor Monthly User Report"
        
$emailtext = @"
Hi,

This is an automated report on users in Sigma AD that
you are manager for. These users have not logged in to
the AD / Domain for 90 days or more.

This is just for your information, no account will be
inactivated, but if you see some account that
should not be active, please report back.

Thanks.

Best Regards
RTS Support

Email: support@rts.se
Phone from Sweden: 020- 510 520
Phone from abroad +46 (0)10- 102 50 50   
Nexer phone switchboard: 020-1800 1800
"@

$date = Get-Date -Format 'yyyy/MM/dd'

<# Tar ut rapport på användare som inte loggat in eller varit skapade i 90 dagar och inte loggat in #>

create-folder

foreach($ou in $ous)
{
$users = get-aduser-not-logged-in-90days
export-users

    if(!$users)
    {}
    foreach($user in $users)
    {
        $UserManager = get-email-to-manager
        $UserManager | Out-File "C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\managers.log" -Append

        $user | Export-XLSX -Path "C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\Monthly-report-$UserManager.xlsx" -AutoFit -Append -Header DisplayName, LastLogonDate, DistinguishedName, SamAccountName, description, Company, Department, Created
        $excel = New-Excel -Path "C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\Monthly-report-$UserManager.xlsx"
        $FilledCells = Search-CellValue -Excel $excel -FilterScript {$_ -like '*'} -WorkSheetName ($excel | Get-Worksheet)
        foreach ($Cell in $FilledCells)
        {
            if (($Cell.Column -ne '1') -and ($Cell.Row -ne '1'))
            {    
                Format-Cell -WorkSheet ($excel | Get-Worksheet) -StartRow $Cell.Row -StartColumn $Cell.Column -EndRow $Cell.Row -EndColumn $Cell.Column #-Color ForestGreen -Font Arial
            }
        }
        Save-Excel -Excel $excel
    }
}


# Send mail to Manager with attachment
$UManagers = Get-Content -Path "C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\managers.log" | sort -Unique
foreach($UManager in $UManagers)
{
    $Attachment = "C:\PowerShell\Ad-Janitor\Logs\Phase4\$date\Monthly-report-$UManager.xlsx"
    Send-MailMessage -From $From -To $UManager -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -Attachments $Attachment -ErrorAction SilentlyContinue
}

