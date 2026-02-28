
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
    [string]$street           = "",             #1259 - Kontorsadress
    [string]$city             = "",             #14 - Arbetsplatsort
    [string]$countryprefix    = "SE",           #24 - Land
    [string]$o365             = "",             #Finns inte med
    [string]$cinodeactive     = "",             #attr 5
    [string]$companyid        = "",             #attr 6
    [string]$cunumber         = "",             #attr 7
    [string]$cuname           = "",             #attr 8
    [string]$expire           = ""              #38 - Slutdatum
)

############################################################################

# Root CatalystOne Integration folder
$RootFolder = (Get-Item $PSScriptRoot).Parent.FullName

# Import Librarys

. "$RootFolder\library\Company-CatalystOne.ps1"

# Loading Modules

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
        Break
    }

    #SQL
    <# SQL Module behövs ej då SQLCMD.EXE används istället
    Push-Location
    Import-Module SqlServer -DisableNameChecking -ErrorAction SilentlyContinue -ErrorVariable SQLError
    if ($SQLError)
    {
        Write-Warning "Kan inte ladda SQL Modul, fortsätter..."
        "$date - WARNING! Kan inte ladda SQL Modul" | Out-File $logerror -Append
    }
    Pop-Location
    #>
    #cls
    }

    function unload-modules
    {
        Get-PSSession | Remove-PSSession
    }

# Load functions
    # Not longer used when the customer stopped using licenses via EA and only uses licenses via CSP.
    function Check-EALicense {
        param (
            [Parameter(Mandatory)]
            [ValidateSet("E3","F3")]
            [String]$License
        )


        switch ($License) {
            'E3' { [int32]$MaxUsers = 1472 }
            'F3' { [int32]$MaxUsers = 525 }
        }

        $EAGroupName = "SG_Office365-${License}_EA"
        $CSPGroupName = "SG_Microsoft365-${License}_CSP"

        $EAGroupMembersCount = (Get-ADGroupMember -Identity $EAGroupName -Recursive).Count

        if ($EAGroupMembersCount -lt $MaxUsers) {
            $ReturnGroup = $EAGroupName
        }else {
            $ReturnGroup = $CSPGroupName
        }

        Return $ReturnGroup
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
    }


    function create-account-ad
    {
        $CNnameCheck = Get-ADUser -Filter "cn -like '$namn'"
        if (!$CNnameCheck) {$CNName = $namn}
        else
        {
            "$date - CNName $namn exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName/CN Path
            $AddNumber = 1
	        Do
            {
                $AddNumber++
                $CNName = $namn + $AddNumber
                $NewCNNameCheck = Get-ADUser -Filter "cn -like '$CNName'"
            } Until(!$NewCNNameCheck)
            "$date - New CNName $CNName" | Out-File $loginfo -Append
        }

        $UPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@$domain" #$AddNumber kan innehalla siffra men kan vara tomt, därför är denna UPN alltid korrekt.
        #$MailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till New-ADUser -EmailAddress och Set-ADUser -ProxyAddresses

        $UPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue
        If ($UPNCheck)
        {
            "$date - UPN $UPN exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName/CN Path
            $AddNumber = 1
	        Do
	        {
		        $AddNumber++
                $CNName = $namn + $AddNumber
                $UPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@$domain"
                #$MailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till New-ADUser -EmailAddress och Set-ADUser -ProxyAddresses

                $NewCNNameCheck = Get-ADUser -Filter "cn -like '$CNName'"
		        $NewUPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue
	        } Until(!$NewCNNameCheck -and !$NewMailboxCheck)

            "$date - New CNName $CNName, New UPN $UPN" | Out-File $loginfo -Append

        }

        New-ADUser -Name $CNName -GivenName $fornamn -Surname $efternamn -DisplayName $namn -SamAccountName $alias -UserPrincipalName $UPN -Path $OU -AccountPassword $pw -EmailAddress $UPN -Enabled:$true

    }

    function create-px
    {
        if($database -eq "" -or $database -eq $null)
        {}
        else
        {
            #$varArray = "v18 = $alias", "v19 = $alias";
            $v18 = $alias
            $v19 = $alias

            # SQLCMD.EXE används istället för Invoke-Sqlcmd för att integrationen körs i 32-bit powershell, som ej är kompatibelt med Invoke-Sqlcmd.
            #Invoke-Sqlcmd -ServerInstance "NEXER-PXSQL01.ad.nexergroup.com" -Query "CREATE LOGIN [`$(v18)] WITH PASSWORD = '`$(v19)', CHECK_POLICY = OFF" -Variable $varArray
            SQLCMD.EXE -S "NEXER-PXSQL01.ad.nexergroup.com" -Q "CREATE LOGIN [$v18] WITH PASSWORD = '$v19', CHECK_POLICY = OFF"
        }
    }


    function Generate-Password
    {
        function Get-RandomCharacters($length, $characters) {
        $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
        $private:ofs=""
        return [String]$characters[$random]
        }

        $password = Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
        $password += Get-RandomCharacters -length 4 -characters 'abcdefghiklmnoprstuvwxyz'
        $password += Get-RandomCharacters -length 2 -characters '1234567890'
        $password += Get-RandomCharacters -length 1 -characters '!?#%'
        return $password
    }

    function Get-Email($användarnamn)
    {
        $epost = (Get-ADUser $användarnamn -Properties mail).mail

        return $epost
    }

    function Get-UserManagerName
    {
        $umname = Get-ADUser $usermanager -Properties displayname | Select displayname

        return $umname
    }

    function Get-PhoneNumber-Manager
    {
        try
        {
            $phone = Get-AdUser -Identity $usermanager -Properties mobile -ErrorAction Stop | Select -expand mobile
        }
        catch
        {
            Write-Error "
Chef saknas för andvändare: $alias.
Inget SMS med lösenord kan skickats till chef.
"
"1. Chef saknas för: $alias." | Out-File $logsmserror -Append
        }
        try
        {
            if ($phone.StartsWith("0") -or ($phone.StartsWith("+")))
            {
            $phone = $phone -replace '^0','+46'
            $phone = $phone -replace '\s',''
            $phone = $phone -replace '-',''
            $phone = $phone -replace '\(',''
            $phone = $phone -replace '\)',''
            }

            return $phone
        }
        catch
        {
            Write-Error "
Mobilnummer kunde inte hittas då chef saknas för andvändare: $alias.
Inget SMS med lösenord har skickats till chef.
"
"2. Mobilnummer saknas på chef för andvändare: $alias.
Inget SMS har skickats till chef eller användare." | Out-File $logsmserror -Append
        }
    }

    function Get-PhoneNumber-User
    {
        try
        {
            $phone = Get-AdUser -Identity $alias -Properties mobile -ErrorAction Stop | Select -expand mobile
        }
        catch
        {
            Write-Error "
Kunde inte hitta användare: $alias.
Inget SMS med lösenord har skickats till användaren.
"
"1. Kan inte hitta användare: $alias." | Out-File $logsmserror -Append
            Return
        }
        try
        {
            if ($phone.StartsWith("0") -or ($phone.StartsWith("+")))
            {
            $phone = $phone -replace '^0','+46'
            $phone = $phone -replace '\s',''
            $phone = $phone -replace '-',''
            $phone = $phone -replace '\(',''
            $phone = $phone -replace '\)',''
            }

            return $phone
        }
        catch
        {
            Write-Error "
Mobilnummer kunde inte hittas för andvändare: $alias.
Inget SMS med lösenord har skickats till användaren.
"
"2. Mobilnummer saknas för andvändare: $alias.
Inget SMS har skickats till användaren." | Out-File $logsmserror -Append
        }
    }


    function log
    {

        $UserObject = Get-ADUser -Identity $alias -Properties mail
        $usermail = $UserObject.mail
        $userupn = $UserObject.UserPrincipalName
"Processing started (on " + $date + "):
--------------------------------------------
:::PARAMS:::

ALIAS: $alias
FÖRNAMN: $fornamn
EFTERNAMN: $efternamn
EMAIL: $usermail
UPN: $userupn
MOBILE: $userphone
TITEL: $jobtitle
CHEF: $usermanager
COMPANY: $company
DEPARTMENT: $department
DEPARTMENT NR: $departmentnumber
DG GRUPP: $dggroup
SG GRUPP: $sggroup
CITY: $city
O365: $o365
EXPIRE DATE: $expire

:::AUTOFIX:::

NAMN: $namn
DATE: $date
CLEAN FIRSTNAM: $cleanedFirstName
CLEAN LASTNAME: $cleanedLastName

ADD GROUPS: $($AddGroups -join ", ")

:::ARRAY FIX:::

PATH: $OU
DATABASE: $database
"+ "`r`n" | Out-File $log -append
"`r" | Out-File $loginfo -append
    }


    function mail #tidigare funktion
    {

    $SMTPServer = "smtprelay.net.nexergroup.com"
    $SMTPPort = 25
    $Username = ""
    $Encoding = [System.Text.Encoding]::UTF8

    $From = "support@nexergroup.com"
    $To = Get-Email $usermanager
    $subject = "$namn's account is now created"
    $usermail = Get-Email $alias
    $usermanagername = Get-UserManagerName $usermanager

    $emailtext = "
    Hi, $namn's account is now created

    Username: NEXERGROUP\$alias
    $(
        "Password: "
        if ($company -eq "Nexer Tech Talent AB") {
            "Sent to users phone"
        }else{
            "Sent to manager $($usermanagername.displayname)"
        }
    )
    Email: $usermail
    Mobile: $userphone
    Title: $jobtitle
    Company: $company
    Department: $department
    Department number: $departmentnumber
    DL: $dggroup
    SG: $sggroup
    Work place: $city
    Office 365 License: $o365
    Account expire date: $expire

    PX: $alias
    PX-password: $alias

    Best Regards
    Nexer Support

    Email: support@rts.se
    Phone: +46 (0)10-643 945 00
    Nexer phone switchboard: 020-550 550
    "

    Send-MailMessage -From $From -To $To -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding

    }


    # function for formatting special characters to normal and removing spaces from string
    function Format-LatinCharacters {
        param(
            [Parameter(ValueFromPipeline)]
            [string]$String
        )
        $NewString = $String -replace "ð","d"
        [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($NewString)) -replace "\s"

    }

    function return-info
    {
        $UserObject = Get-ADUser -Identity $alias -Properties mail
        $usermail = $UserObject.mail
        $userupn = $UserObject.UserPrincipalName

        Write-Output "Användarnamn;$alias UserMail;$usermail UPN;$userupn"
    }


    function set-account-expire
    {
        if ($expire -eq "")
        {
            Set-ADAccountExpiration -Identity $alias -DateTime $null
        }
        else
        {
            $newexpire = [datetime]::parseexact($expire, 'yyyy-MM-dd', $null).AddDays(1).ToString('yyyy-MM-dd')
            Set-ADAccountExpiration -Identity $alias -DateTime $newexpire
        }
    }

    function set-account-info
    {
        $props = @{
        identity       = $alias
        givenName      = if($fornamn         ){$fornamn         }else{$null}
        surname        = if($efternamn       ){$efternamn       }else{$null}
        description    = if($description     ){$description     }else{$null}
        mobile         = if($userphone       ){$userphone       }else{$null}
        OfficePhone    = if($userphone       ){$userphone       }else{$null}
        Office         = if($city            ){$city            }else{$null}
        streetAddress  = if($street          ){$street          }else{$null}
        city           = if($city            ){$city            }else{$null}
        country        = if($countryprefix   ){$countryprefix   }else{$null}
        title          = if($jobtitle        ){$jobtitle        }else{$null}
        department     = if($department      ){$department      }else{$null}
        company        = if($company         ){$company         }else{$null}
        manager        = if($usermanager     ){$usermanager     }else{$null}
        employeeNumber = if($departmentnumber){$departmentnumber}else{$null}
        }

        if($cinodeactive -eq "")
        {set-aduser @props}
        else
        {set-aduser @props -Add @{extensionAttribute5 = "$cinodeactive"}}

        if($companyid -eq "")
        {set-aduser @props}
        else
        {set-aduser @props -Add @{extensionAttribute6 = "$companyid"}}

        if($cunumber -eq "")
        {set-aduser @props}
        else
        {set-aduser @props -Add @{extensionAttribute7 = "$cunumber"}}

        if($cuname -eq "")
        {set-aduser @props}
        else
        {set-aduser @props -Add @{extensionAttribute8 = "$cuname"}}

        if($departmentnumber -eq "")
        {set-aduser @props}
        else
        {set-aduser @props -Add @{departmentNumber = "$departmentnumber"}}
    }

    function set-account-memberof
    {
        # Create variables where all group memberships to be added and to be removed are gathered and defined
        $AddGroups = @()
        $RemoveGroups = @()

        # Switch to match which company the user belongs to and adds the correct group to $AddGroups
        $AddGroups += switch ($company) {
            "Nexer AB"                              { "Nexer SWE Office $city" }
            "Nexer Asset Management Oy"             { "Asset Management FIN Office $city" }
            "Nexer Cybersecurity AB"                { "Cybersecurity SWE Office $city" }
            "Nexer Digital Ltd"                     { "Digital GBR Office $city" }
            "Nexer Enterprise Applications AB"      { "Enterprise Applications SWE Office $city" }
            "Nexer Enterprise Applications Inc"     { "Enterprise Applications USA Office $city" }      # New company
            "Nexer Enterprise Applications Ltd"     { "Enterprise Applications GBR Office $city" }
            "Nexer Enterprise Applications Prv Ltd" { "Enterprise Applications IND Office $city" }
            "Nexer Infrastructure AB"               { "Infrastructure SWE Office $city" }
            "Nexer Insight AB"                      { "Insight SWE Office $city" }
            "Nexer Insight Inc"                     { "Insight SWE Office $city" }
            "Nexer Insight Ltd"                     { "Insight GBR Office $city" }
            "Nexer Insight Sp. z o.o."              { "Insight POL Office $city" }
            "Nexer Prv Ltd"                         { "Nexer IND Office $city" }
            "Nexer Recruit AB"                      { "Recruit SWE Office $city" }
            "Nexer Sp. z o.o."                      { "ITC Office $city" }                              # No existing active user found with this company name, is this an old company that can be deleted?
            "Sigma IT Polska Sp. z o.o."            { "ITC Office $city" }
            "Nexer Tech Talent AB"                  { "Tech Talent SWE Office $city" }
            "Nexer Data Management AB"              { "Data Management SWE Office $city" }
            "Nexer Unified Commerce AB"             { "Unified Commerce SWE $city" }
            Default                                 { "Office $city All" }
        }

        # SG Groups
        foreach ($item in $sggroup)
        {
            if ($item -notlike "N/A") {
                $AddGroups += $item
            }
        }

        # DG Groups
        foreach ($item in $dggroup)
        {
            if ($item -notlike "N/A") {
                $AddGroups += $item
            }
        }


        # Office365
        # If license value passed from CatalystOne
        if($o365)
        {
            # Checks the $O365 value that has been passed from CatalystOne. Sets the correct Security group depending on the value.
            $o365group = switch ($o365) {
                "E1"            { "SG_Office365-E1_CSP" }
                "F1"            { "SG_Microsoft365-F3_CSP" }
                "F3"            { "SG_Microsoft365-F3_CSP" }
                "E3"            { "SG_Microsoft365-E3_CSP" }
                "Ingen licens"  {}
                "Underkonsult"  {}
                "UK"            {}
            }

            # Gather all current 365 group memberships to be removed
            $OldO365Groups = Get-ADPrincipalGroupMembership $alias | Where {$_.Name -match "^SG(_Temp_|_)(Microsoft|Office)365-(F|E)(1|3)(_Nexer-|_)(CSP|EA)$"}
            IF($OldO365Groups)
            {
                # Adds the found 365 groups to $RemoveGroups to be removed from membership
                $RemoveGroups += $OldO365Groups

            }

            # Checks if $o365group variable has been assigned a group name
            if ($o365group) {
                # Add group name to $AddGroups to be added to membership
                $AddGroups += $o365group
            }
        }



        # Removes all group membership gathered in $RemoveGroups
        foreach ($item in $RemoveGroups)
        {
            Get-ADGroup -Identity $item | Remove-ADGroupMember -Members $alias -Confirm:$false
        }

        # Adds all group membership gathered in $AddGroups
        foreach ($item in $AddGroups)
        {
            Get-ADGroup -Identity $item | Add-ADGroupMember -Members $alias
        }

    }





    function sms-and-mail
    {

        $SMTPServer = "smtprelay.net.nexergroup.com"
        $SMTPPort = 25
        $SMSSubject = " "
        $MailSubject = "$namn's account is now created"
        $Encoding = [System.Text.Encoding]::UTF8
        $SMSFrom = "support@sigma.se"
        $MailFrom = "support@nexergroup.com"

        # SMS
        if ($company -eq "Nexer Tech Talent AB"){
            $nr = Get-PhoneNumber-User
            $SMSPhrase = "your account"
        }else{
            $nr = Get-PhoneNumber-Manager
            $SMSPhrase = "user: `n$namn`nPassword"
        }

        if($nr){
            $Recipient = $nr + "@qlnk.se"
            $SMStext =
            "Hi!`nHere's the password for ${SMSPhrase}: $pwd
            `nBR`nNexer Support"

            Send-MailMessage -From $SMSFrom -To $Recipient -Subject $SMSSubject -Body $SMStext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue
        }
        else{
            $nonr = "No Number"
        }

    # Mail

    $To = Get-Email $usermanager
    $usermail = Get-Email $alias
    $usermanagername = Get-UserManagerName

    $emailtext = "
    Hi, $namn's account is now created

    Username: NEXERGROUP\$alias
    $(
        "Password: "

        if($nonr){

            if ($company -eq "Nexer Tech Talent AB") {
                $stringphrase = "Phone number"
            }else{
                $stringphrase = "Manager or phone number"
            }

            "$stringphrase missing, no password has been sent!"

        }else{

            if ($company -eq "Nexer Tech Talent AB") {
                $stringphrase = "phone"
            }else{
                $stringphrase = "manager $($usermanagername.displayname)"
            }

            "Sent to $stringphrase"

        }
    )
    Email: $usermail
    Mobile: $userphone
    Title: $jobtitle
    Company: $company
    Department: $department
    Department number: $departmentnumber
    DL: $dggroup
    SG: $sggroup
    Work place: $city
    Office 365 License: $o365
    Account expire date: $expire

    PX: $alias
    PX-password: $alias

    Best Regards
    Nexer Support

    Email: support@rts.se
    Phone: +46 (0)10-643 945 00
    Nexer phone switchboard: 020-550 550
    "

    Send-MailMessage -From $MailFrom -To $To -Subject $MailSubject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding

    }

    function sms-with-password  # Not used
    {
    $SMTPServer = "smtprelay.net.nexergroup.com"
    $SMTPPort = 25
    $From = "support@sigma.se"
    $SMSSubject = " "
    $Encoding = [System.Text.Encoding]::UTF8

    if ($company -eq "Nexer Tech Talent AB"){
        $nr = Get-PhoneNumber-User $alias

        if($nr){
            $Recipient = $nr + "@qlnk.se"
            $smstext =
            "Hi!`nHere's the password for your account: $pwd
            `nBR`nNexer Support"

            Send-MailMessage -From $From -To $Recipient -Subject $SMSSubject -Body $smstext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue
            }
        else{}
        }
    else {
        $nr = Get-PhoneNumber-Manager $usermanager

        if($nr){
            $Recipient = $nr + "@qlnk.se"
            $smstext =
            "Hi!`nHere's the password for user: `n$namn`nPassword: $pwd
            `nBR`nNexer Support"

            Send-MailMessage -From $From -To $Recipient -Subject $SMSSubject -Body $smstext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue
            }
        else{}
        }
    }

############################################################################

# Load modules

load-modules

# Autofix

$date = get-date -format "yyyy-MM-dd HH:mm"
$logdate = Get-Date -Format "yyyyMMdd"
$log= "$RootFolder\log\new-user-CatalystOne_$logdate.log"
$logerror = "$RootFolder\log\new-user-error-CatalystOne_$logdate.log"
$loginfo = "$RootFolder\log\new-user-info-CatalystOne_$logdate.log"
$logsmserror = "$RootFolder\log\sms-error-CatalystOne_$logdate.log"
#$description = "CatalystOne, $usermanager, $date"
$description = "CatalystOne"
$namn = "$fornamn $efternamn" #Behövs för mail functionen
$pwd = Generate-Password
$pw = ConvertTo-SecureString -string $pwd -asPlainText -Force
$cleanedFirstName = Format-LatinCharacters $fornamn  #Behövs för UPN
$cleanedLastName = Format-LatinCharacters $efternamn #Behövs för UPN

# Array Fixes

$OU = $ListOfCompanys["select"][$company]["OU"]
$database = $ListOfCompanys["select"][$company]["Database"]
$Domain = $ListOfCompanys["select"][$Company]["Domain"]
    if($department -eq "ITC Bool")
    {$Domain = "bool.se"}

# Run

check-values

create-account-ad

Start-Sleep -Seconds 10 # För att den ska få tid att skapa upp konto innan info sätts

set-account-info

set-account-memberof

set-account-expire

create-px

Start-Sleep -Seconds 10 # För att den ska få tid att plocka upp rätt E-post

#mail
#sms-with-password
sms-and-mail
return-info
log

unload-modules
