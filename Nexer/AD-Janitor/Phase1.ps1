<#
Phase 1

Loggar i C:\PowerShell\Ad-Janitor\Logs\Phase1\
Loggar när Phase1 startar. Loggar när Phase1 avslutar.
Kollar efter konton som har fått ett "expire date" som är 10 dagar framåt.
Skickar mail till den personens manager att kontot kommer gå ut.
#>

$ErrorActionPreference = "SilentlyContinue"

$Date = (Get-Date)

if($PSScriptRoot){
    $scriptPath = $PSScriptRoot
}else{
    $scriptPath = "C:\PowerShell\Ad-Janitor"
}


$TimestampLog          = "$scriptPath\Logs\Phase1\$($Date.ToString("yyyy-MM-dd"))_AD-Janitor_Timestamps.log"

Add-Content -Encoding Default "$((Get-Date).ToString("yyyy-MM-dd - HH:mm:ss")): Phase1 starting" -Path $TimestampLog

$Today           = $Date.Day
$SearchBaseSites = "OU=Nexer Group Companies,DC=ad,DC=nexergroup,DC=com"

$EmailSupport    = "support@rts.se"
$PhoneSupport    = "020-510 520"


Import-Module ActiveDirectory

$From            = "support@nexergroup.com"
$Smtp            = "smtprelay.net.nexergroup.com"
#$SupportUser     = "christian.spector@nexergroup.com"

$AdUsers = Get-ADUser -Filter {(Enabled -eq $True) -and (AccountExpires -ne "0") -and (AccountExpires -ne "9223372036854775807")} -SearchBase $SearchBaseSites -Properties AccountExpirationDate,Mail,Manager | ? {($_.DistinguishedName -notlike '*OU=Quarantine*')}

ForEach ($AdUser in $AdUsers){
    $Date = (Get-Date)

    if (($AdUser.AccountExpirationDate -le $Date.AddDays(10)) -and ($AdUser.AccountExpirationDate -ge $Date)){
        $AdUserAccountExpireTime = $AdUser.AccountExpirationDate.ToString('yyyy-MM-dd HH:mm')
        $TimeCountDown           = New-TimeSpan $Date $AdUser.AccountExpirationDate

    if ($AdUser.Manager -like "CN=*"){
        $AdUserManager = Get-ADUser $AdUser.Manager -Properties Mail,DisplayName
        $ManagerInfo3  = "$($AdUserManager.DisplayName) `n"

        $MailMessageToManager = @"
        <pre>Hi $($AdUserManager.GivenName)

        You are recieving this email because you are the manager of $($AdUser.Name) with user account $($AdUser.SamAccountName)
        That user account will expire in $($TimeCountDown.Days) days and $($TimeCountDown.Hours) hours. ($AdUserAccountExpireTime)
        If the account needs to be extended, please send an email to support@rts.se

        Kind Regards,
        RTS Support
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

    Clear-Variable AdUserAccountExpireTime,TimeCountDown,AdUserManager,ManagerInfo2,ManagerInfo3,ManagerInfo4,ManagerInfo5,MailMessageToManager -ErrorAction SilentlyContinue

}


Add-Content -Encoding Default "$((Get-Date).ToString("yyyy-MM-dd - HH:mm:ss")): Phase1 finished" -Path $TimestampLog