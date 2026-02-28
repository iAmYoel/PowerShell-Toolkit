
# Parameters

param
(
    [string]$alias            = "",             #0 - Anställnings ID (unique import ID)
    [string]$fornamn          = "",             #2 - Firstname
    [string]$efternamn        = "",             #3 - Lastname
    [string]$userphone        = "",             #1003 - Mobiltelefon
    [string]$jobtitle         = "",             #1140 - Title
    [string]$usermanager      = "",             #9 - Chef
    [string]$company          = "",             #1002 - Företag
    [string]$department       = "",             #1135 - Department
    [string]$departmentnumber = "",             #1070 - Kostnadsställe/Sektion
    [string[]]$dggroup        = @("N/A"),       #Finns inte med
    [string]$sggroup          = "N/A",          #Finns inte med
    [string[]]$sgcivilgroup   = @("N/A"),       #Finns inte med
    [string]$street           = "",             #1259 - Kontorsadress
    [string]$city             = "",             #14 - Arbetsplatsort
    #[string]$zipcode          = "",             #Finns inte med
    [string]$country          = "Sverige",      #24 - Land
    [string]$o365             = "",             #Finns inte med
    [string]$companyid        = "",             #attr 6
    [string]$expire           = ""              #38 - Slutdatum
)

# Root CatalystOne Integration folder
$RootFolder = (Get-Item $PSScriptRoot).Parent.FullName

# Functions

function check-user
{
    $user = $(try {Get-ADUser $alias} catch {$null})
    if ($user -ne $null)
    {
        "$date - $alias exist. Change.`r`n" | Out-File $loginfo -Append
        . $PSScriptRoot\ChangeUser-HR4Sigma.ps1 -alias $alias -fornamn $fornamn -efternamn $efternamn -userphone $userphone -jobtitle $jobtitle -usermanager $usermanager -company $company -department $department -departmentnumber $departmentnumber -dggroup $dggroup -sggroup $sggroup -sgcivilgroup $sgcivilgroup -street $street -city $city -country $countryprefix -o365 $o365 -expire $expire -companyid $companyid
    }
    else
    {
        "$date - $alias doesn't exist. Create.`r`n" | Out-File $loginfo -Append
        . $PSScriptRoot\NewUser-HR4Sigma.ps1 -alias $alias -fornamn $fornamn -efternamn $efternamn -userphone $userphone -jobtitle $jobtitle -usermanager $usermanager -company $company -department $department -departmentnumber $departmentnumber -dggroup $dggroup -sggroup $sggroup -sgcivilgroup $sgcivilgroup -street $street -city $city -country $countryprefix -o365 $o365 -expire $expire -companyid $companyid
    }
}
    
function check-values
{
    if ([string]::IsNullOrWhiteSpace($alias))
    {
        "$date - Alias Empty" | Out-File $logerror -Append
        Break
    }
    if ([string]::IsNullOrWhiteSpace($fornamn))
    {
        "$date - Förnamn Empty. Alias:$alias" | Out-File $logerror -Append
        Break
    }
    if ([string]::IsNullOrWhiteSpace($efternamn))
    {
        "$date - Efternamn Empty. Alias:$alias" | Out-File $logerror -Append
        Break
    }
    if ([string]::IsNullOrWhiteSpace($userphone))
    {
        "$date - Userphone Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($jobtitle))
    {
        "$date - Jobtitle Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($usermanager))
    {
        "$date - Usermanager Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($company))
    {
        "$date - Company Empty. Alias:$alias" | Out-File $logerror -Append
        Break
    }
    if ([string]::IsNullOrWhiteSpace($department))
    {
        "$date - Department Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($street))
    {
        "$date - Street Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($city))
    {
        "$date - City Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($country))
    {
        "$date - Land Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($o365))
    {
        "$date - Office365 Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($expire))
    {
        "$date - Expire Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($cinodeactive))
    {
        "$date - Expire Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($companyid))
    {
        "$date - Expire Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($cunumber))
    {
        "$date - Expire Empty. Alias:$alias" | Out-File $loginfo -Append
    }
    if ([string]::IsNullOrWhiteSpace($cuname))
    {
        "$date - Expire Empty. Alias:$alias" | Out-File $loginfo -Append
    }
}

function load-modules
{

    #Active Directory
    try
    {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch
    {
        Write-Error "ERROR! Kan inte ladda ActiveDirectory Modul"
        "$date - ERROR! Kan inte ladda ActiveDirectory Modul" | Out-File $logerror -Append
        $emailtext = "ERROR! Kan inte ladda ActiveDirectory Modul - $date"
        Send-MailMessage -From $From -To $To -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding
        Break
    }

    #SQL
    Push-Location
    Import-Module sqlps -DisableNameChecking -ErrorAction SilentlyContinue -ErrorVariable SQLError
    if ($SQLError)
    {
        Write-Warning "Kan inte ladda SQL Modul, fortsätter..."
        "$date - WARNING! Kan inte ladda SQL Modul" | Out-File $logerror -Append
        $emailtext = "WARNING! Kan inte ladda SQL Modul - $date"
        Send-MailMessage -From $From -To $To -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding
    }
    Pop-Location

    #cls
}

function convert-country($country)
{
    if($country -eq "Sverige" -or $country -eq "Sweden")
    {
        $countryprefix = "SE"
    }
    return $countryprefix
}

function unload-modules
{
    Get-PSSession | Remove-PSSession
}

$date = Get-Date -Format "yyyy-MM-dd HH:mm"
$logdate = Get-Date -Format "yyyyMMdd"
$logerror = "$RootFolder\log\step1-error-HR4Sigma_$logdate.log"
$loginfo = "$RootFolder\log\step1-info-HR4Sigma_$logdate.log"

#Mail Settings
$SMTPServer = "smtprelay.net.sigma.se"
$SMTPPort = 25
$Username = ""
$Encoding = [System.Text.Encoding]::UTF8
$subject = "HR4Sigma ERROR!"
$From = "support@sigma.se"
$To = "monitor-sd@sigma.se"

# RUN
    
load-modules
check-values
$countryprefix = convert-country $country
check-user
unload-modules
