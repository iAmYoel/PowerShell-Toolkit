<#
Phase 1

Loggar i C:\PowerShell\Ad-Janitor\Logs\Phase1\
Loggar när Phase1 startar. Loggar när Phase1 avslutar.
Kollar efter konton som har fått ett "expire date" som är 10 dagar framåt.
Skickar mail till den personens manager att kontot kommer gå ut.
#>

$ErrorActionPreference = “SilentlyContinue”

$TimestampLog          = "C:\PowerShell\Ad-Janitor\Logs\Phase1\$(Get-Date -Format yyyy-MM-dd)_AD-Janitor_Timestamps.log"

Add-Content -Encoding Default "$((Get-Date).ToString("yyyy-MM-dd - HH:mm:ss")): Phase1 starting" -Path $TimestampLog

$Today           = (Get-Date).Day
$SearchBaseSites = "OU=SigmaGroup,DC=Sigma,DC=Local"

$EmailSupport    = "support@sigma.se"
$PhoneSupport    = "020-510 520"


Import-Module ActiveDirectory

$From            = "support@nexergroup.com"
$Smtp            = "mailrelay.sigma.local"
$SupportUser     = "christian.spector@nexergroup.com"

$AdUsers = Get-ADUser -Filter {(Enabled -eq $True) -and (AccountExpires -ne "0") -and (AccountExpires -ne "9223372036854775807")} -SearchBase $SearchBaseSites -Properties Mail,Manager | ? {($_.DistinguishedName -notlike '*OU=Quarantine*')}
ForEach ($AdUser in $AdUsers)
{
if (([DateTime]::FromFileTime((Get-ADUser -Identity $AdUser.SamAccountName -Properties AccountExpires).AccountExpires) -le ((Get-Date).AddDays(10))) -and ([DateTime]::FromFileTime((Get-ADUser -Identity $AdUser.SamAccountName -Properties AccountExpires).AccountExpires) -ge ((Get-Date))))
{
$AdUserAccountExpireTime = Get-Date(([DateTime]::FromFileTime((Get-ADUser -Identity $AdUser.SamAccountName -Properties AccountExpires).AccountExpires))) -Format 'yyyy-MM-dd HH:mm'
$TimeCountDown           = New-TimeSpan $(Get-Date) $([DateTime]::FromFileTime((Get-ADUser -Identity $AdUser.SamAccountName -Properties AccountExpires).AccountExpires))

if ($AdUser.Manager -like "CN=*")
{
    $AdUserManager = Get-ADUser $AdUser.Manager -Properties Mail,DisplayName
    $ManagerInfo3  = "$($AdUserManager.DisplayName) `n"

    if ($($AdUserManager.Mail) -ne $Null)
    {
    $ManagerInfo5  = "$($AdUserManager.Mail) `n"
    }
    else
    {
    $ManagerInfo5  = "(No Manager emailaddress available)"
    Send-MailMessage -From $From -To $SupportUser -Subject "ERROR: AD-Janitor Phase 1. No manager email $($AdUser.SamAccountName)" -Body $ManagerInfo5 -BodyAsHTML -Encoding Default -SmtpServer $Smtp
    }
}

else
{
$ManagerInfo2 = "No manager information is available in Active Directory `n"
Send-MailMessage -From $From -To $SupportUser -Subject "ERROR: AD-Janitor Phase 1. No manager info $($AdUser.SamAccountName)" -Body $ManagerInfo2 -BodyAsHTML -Encoding Default -SmtpServer $Smtp

}

if ($AdUser.Manager -like "CN=*")
{
$MailMessageToManager = @"
<pre>Hi $($AdUserManager.GivenName)

You are recieving this email because you are the manager of $($AdUser.Name) with user account $($AdUser.SamAccountName)
That user account will expire in $($TimeCountDown.Days) days and $($TimeCountDown.Hours) hours. ($AdUserAccountExpireTime)
If the account needs to be extended, please send an email to support@nexergroup.com

Kind Regards
Nexer Support
($EmailSupport) ($PhoneSupport)

</pre>
"@

Send-MailMessage -From $From -To ($AdUserManager.Mail) -Subject "INFO: Your employee $($AdUser.Name) ($($AdUser.SamAccountName)) user account is about to expire" -Body $MailMessageToManager -BodyAsHTML -Encoding Default -SmtpServer $Smtp

}
    $LoggedInfo = @"

    User               = $($AdUser.Name)
    UserName           = $($AdUser.SamAccountName)
    Manager            = $ManagerInfo3
    Manager username   = $($AdUserManager.SamAccountName)
    Expiry Date        = $AdUserAccountExpireTime
    Time to Expiration = $($TimeCountDown.Days) Days and $($TimeCountDown.Hours) Hours
    Mail sent to       = $($AdUserManager.Mail)

"@
    Add-Content -Encoding Default -Value $LoggedInfo -Path $TimestampLog 

}

if ($AdUserAccountExpireTime) {Clear-Variable AdUserAccountExpireTime}
if ($TimeCountDown) {Clear-Variable TimeCountDown}
if ($AdUserManager) {Clear-Variable AdUserManager}
if ($ManagerInfo2) {Clear-Variable ManagerInfo2}
if ($ManagerInfo3) {Clear-Variable ManagerInfo3}
if ($ManagerInfo4) {Clear-Variable ManagerInfo4}
if ($ManagerInfo5) {Clear-Variable ManagerInfo5}
if ($MailMessageToManager) {Clear-Variable MailMessageToManager}

}


Add-Content -Encoding Default "$((Get-Date).ToString("yyyy-MM-dd - HH:mm:ss")): Phase1 finished" -Path $TimestampLog