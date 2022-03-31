
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
    [string]$countryprefix    = "SE",           #24 - Land
    [string]$o365             = "",             #Finns inte med
    [string]$cinodeactive     = "",             #attr 5
    [string]$companyid        = "",             #attr 6
    [string]$cunumber         = "",             #attr 7
    [string]$cuname           = "",             #attr 8
    [string]$expire           = ""              #38 - Slutdatum
)

############################################################################

# Import Librarys

. "C:\hr4sigma\library\Company-HR4Sigma.ps1"

# Loading Modules
    
    function load-modules
    {
    #Active Directory
    try
    {
        Import-Module activedirectory -ErrorAction Stop
    }
    catch
    {
        Write-Error "ERROR! Kan inte ladda ActiveDirectory Modul"
        "$date - ERROR! Kan inte ladda ActiveDirectory Modul" | Out-File $logerror -Append
        Break
    }

    #SQL
    Push-Location
    Import-Module sqlps -DisableNameChecking -ErrorAction SilentlyContinue -ErrorVariable SQLError
    if ($SQLError)
    {
        Write-Warning "Kan inte ladda SQL Modul, fortsätter..."
        "$date - WARNING! Kan inte ladda SQL Modul" | Out-File $logerror -Append
    }
    Pop-Location

    #cls
    }

    function unload-modules
    {
        Get-PSSession | Remove-PSSession
    }

# Load functions

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
        
        $EAGroupName = "SG_Office365-${License}_Nexer-EA"
        $CSPGroupName = "SG_Microsoft365-${License}_Nexer-CSP"

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
        $CNnameCheck = Get-ADUser -Filter * -Properties cn | Where-Object {$_.cn -eq $namn}
        if (!$CNnameCheck) {$CNName = $namn}
        else
        {
            "$date - CNName $namn exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName/CN Path	
            $AddNumber = 1
	        Do
            {
                $AddNumber++
                $CNName = $namn + $AddNumber
                $NewCNNameCheck = Get-ADUser -Filter * -Properties cn | Where-Object {$_.cn -eq $CNName}
            } Until(!$NewCNNameCheck)
            "$date - New CNName $CNName" | Out-File $loginfo -Append
        }

        $UPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@sigma.se" #$AddNumber kan innehalla siffra men kan vara tomt, därför är denna UPN alltid korrekt.
        $MailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till New-ADUser -EmailAddress och Set-ADUser -ProxyAddresses

        $UPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue
        If ($UPNCheck)
        {
            "$date - UPN $UPN exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName/CN Path
            $AddNumber = 1
	        Do
	        {
		        $AddNumber++
                $CNName = $namn + $AddNumber
                $UPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@sigma.se"
                $MailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till New-ADUser -EmailAddress och Set-ADUser -ProxyAddresses
        
                $NewCNNameCheck = Get-ADUser -Filter * -Properties cn | Where-Object {$_.cn -eq $CNName}
		        $NewUPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue
	        } Until(!$NewCNNameCheck -and !$NewMailboxCheck)
    		
            "$date - New CNName $CNName, New UPN $UPN" | Out-File $loginfo -Append

        }

        New-ADUser -Name $CNName -GivenName $fornamn -Surname $efternamn -DisplayName $namn -SamAccountName $alias -UserPrincipalName $UPN -Path $OU -AccountPassword $pw -EmailAddress "$MailAddress@$Domain" -Enabled:$true

        Set-ADUser -Identity $alias -add @{ProxyAddresses="SMTP:$MailAddress@$Domain"}

    }

    function create-px
    {
        if($database -eq "" -or $database -eq $null)
        {}
        else
        {
            $varArray = "v18 = $alias", "v19 = $alias";
            Invoke-Sqlcmd -ServerInstance "SS0305.sigma.local" -Query "CREATE LOGIN [`$(v18)] WITH PASSWORD = '`$(v19)', CHECK_POLICY = OFF" -Variable $varArray
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
            $phone = Get-AdUser -Identity $usermanager -Properties mobile | Select -expand mobile -ErrorAction SilentlyContinue
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
            $phone = Get-AdUser -Identity $alias -Properties mobile | Select -expand mobile -ErrorAction SilentlyContinue
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
Civil Systemgrupp: $sgcivilgroup
CITY: $city
O365: $o365
EXPIRE DATE: $expire

:::AUTOFIX:::

NAMN: $namn
DATE: $date
CLEAN FIRSTNAM: $cleanedFirstName
CLEAN LASTNAME: $cleanedLastName

:::ARRAY FIX:::

PATH: $OU
DATABASE: $database
"+ "`r`n" | Out-File $log -append
"`r" | Out-File $loginfo -append
    }


    function mail #tidigare funktion
    {
    
    $SMTPServer = "smtprelay.net.sigma.se"
    $SMTPPort = 25
    $Username = ""
    $Encoding = [System.Text.Encoding]::UTF8
    
    $From = "support@nexergroup.com"
    $To = Get-Email $usermanager
    $subject = "$namn's account is now created"
    $usermail = Get-Email $alias
    $usermanagername = Get-UserManagerName $usermanager
        
    if($company -eq "Sigma Civil AB")
    {$emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Sent to manager $($usermanagername.displayname)
    Email: $usermail
    Mobile: $userphone
    Title: $jobtitle
    Company: $company
    Department: $department
    Department number: $departmentnumber
    DL: $dggroup
    SG: $sggroup
    Systemgrupp: $sgcivilgroup
    Work place: $city
    Office 365 License: $o365
    Account expire date: $expire

    PX: $alias
    PX-password: $alias

    Best Regards
    Nexer Support

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    elseif($company -eq "Nexer Tech Talent AB")
    {$emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Sent to users phone
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

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    else
    {$emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Sent to manager $($usermanagername.displayname)
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

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }

    Send-MailMessage -From $From -To $To -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding
    Send-MailMessage -From $From -To "christian.spector@nexergroup.com" -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding

    }


    function remove-special-letters($WordToBeCleaned)
    {
           
        $tmp_swename = $WordToBeCleaned.replace("ä","a")
        $tmp_swename = $tmp_swename.replace("ö","o")
        $tmp_swename = $tmp_swename.replace("Ä","A")
        $tmp_swename = $tmp_swename.replace("Ö","O")
        $tmp_swename = $tmp_swename.replace("Ø","O")
        $tmp_swename = $tmp_swename.replace("Å","A")
        $tmp_swename = $tmp_swename.replace("Ž","Z")
        $tmp_swename = $tmp_swename.replace(" ","")
        $tmp_swename = $tmp_swename.replace("´","")
        $tmp_swename = $tmp_swename.replace("æ","ae")
        $tmp_swename = $tmp_swename.replace("á","a")
        $tmp_swename = $tmp_swename.replace("à","a")
        $tmp_swename = $tmp_swename.replace("ą","a")
        $tmp_swename = $tmp_swename.replace("é","e")
        $tmp_swename = $tmp_swename.replace("è","e")
        $tmp_swename = $tmp_swename.replace("ë","e")
        $tmp_swename = $tmp_swename.replace("ł","l")
        $tmp_swename = $tmp_swename.replace("ń","n")
        $tmp_swename = $tmp_swename.replace("ó","o")
        $tmp_swename = $tmp_swename.replace("ò","o")
        $tmp_swename = $tmp_swename.replace("ø","o")
        $tmp_swename = $tmp_swename.replace("í","i")
        $tmp_swename = $tmp_swename.replace("ì","i")
        $tmp_swename = $tmp_swename.replace("ç","c")
        $tmp_swename = $tmp_swename.replace("ü","u")
        $tmp_swename = $tmp_swename.replace("ñ","n")
        $ettnamn = $tmp_swename.replace("å","a")
        return $ettnamn
       
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
        #postalCode     = if($zipcode         ){$zipcode         }else{$null}
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
        $AddGroups = @()
        $AddGroups += switch ($company) {
            "Danir AB"                              { "Danir Office $city" }
            "Nexer AB"                              { "ITC Office $city" }
           #"Nexer Asset Management AS"             {}
            "Nexer Asset Management Oy"             { "ITC Finland Office $city" }
            "Nexer Cybersecurity AB"                { "Cybersecurity Office $city" }
            "Sigma Cybersecurity AB"                { "Cybersecurity Office $city" }
            "Nexer Digital Ltd"                     { "ITC UK Office $city" }
            "Nexer Enterprise Applications AB"      { "Dynamics Office $city" }
            "Nexer Enterprise Applications Inc"     { "Enterprise Applications Inc Office $city" }
            "Nexer Enterprise Applications Ltd"     { "Enterprise Applications Ltd Office $city" }
            "Nexer Enterprise Applications Prv Ltd" { "ITC India Enterprise Applications Office $city" }
            "Nexer Infrastructure AB"               { "IT Tech Office $city" }
            "Nexer Insight AB"                      { "IoT AI Office $city" }
            "Nexer Insight Inc"                     { "ITC Office $city" }
            "Nexer Insight Ltd"                     { "ITC Insight Ltd Office $city" }
            "Nexer Insight Sp. z o.o."              { "ITC Insight Poland Office $city" }
            "Nexer IT Services AB"                  { "NITS Office $city" }
            "Nexer Prv Ltd"                         { "ITC Office $city" }
            "Nexer Recruit AB"                      { "Recruit Office $city" }
            "Nexer Sp. z o.o."                      { "ITC Office $city" }
            "Sigma IT Polska Sp. z o.o."            { "ITC Office $city" }
            "Nexer Tech Talent AB"                  { "Young Talent Office $city" }
            "Sigma Civil AB"                        {
                                                        if($city -like "Stockholm")
                                                            { "Civil Office Stockholm Liljeholmen" }
                                                        else
                                                            { "Civil Office $city" }

                                                        foreach ($cg in $sgcivilgroup)
                                                        {
                                                            Get-ADUser -Identity $alias | Add-ADPrincipalGroupMembership -memberof $cg
                                                        }
                                                    }
            "Sigma Connectivity AB"                 { @("og-ConnectivityAll","Connectivity SWE Office $city") }
            "Sigma Connectivity ApS"                {
                                                        if($city -like "Köpenhamn")
                                                            { @("og-ConnectivityAll","Connectivity DK Office Copenhagen") }
                                                        else
                                                            { @("og-ConnectivityAll","Connectivity DK Office $city") }
                                                    }
            "Sigma Connectivity Inc."               { @("og-ConnectivityAll","Connectivity INC Office $city") }
            "Sigma Connectivity Sp. z o.o."         { @("og-ConnectivityAll","Connectivity PL Office $city") }
            "Sigma Connectivity Engineering AB"     { @("og-ConnectivityAll","SC Engineering Office $city") }
            "Sigma Embedded Engineering AB"         { "Embedded Engineering Office $city" }
            "Sigma Energy & Marine AB"              { "Energy Marine Office $city" }
            "Sigma Energy & Marine AS"              { "Energy Marine AS Office $city" }
            "Sigma Industry East North AB"          { "Industry East North Office $city" }
            "Sigma Industry Evolution AB"           { "Industry Evolution Office $city" }
           #"Sigma Industry Inc."                   { "SII Office $city" }
            "Sigma Industry Solutions AB"           { "Industry Solutions Office $city" }
            "Sigma Industry South AB"               { "Industry South Office $city" }
            "Sigma Industry West AB"                { "Industry West Office $city" }
            "Sigma Quality & Compliance AB"         {
                                                        if($city -like "Göteborg")
                                                            { "QC Office Gothenburg" }
                                                        else
                                                            { "QC Office $city" }
                                                    }
            "Sigma Quality & Compliance ApS"        {
                                                        if($city -like "Göteborg")
                                                            { "QC Office Gothenburg" }
                                                        else
                                                            { "QC Office $city" }
                                                    }
            "aptio group Sweden AB"                 {
                                                        if($city -eq "Göteborg")
                                                            { "QC Office Gothenburg" }
                                                        else
                                                            { "QC Office $city" }
                                                    }
            "aptio group Denmark ApS"               {
                                                        if($city -eq "Göteborg")
                                                            { "QC Office Gothenburg" }
                                                        else
                                                            { "QC Office $city" }
                                                    }
           #"Sigma Software LLC"                    {}
            Default                                 { "Office $city All" }
        }
        
        # SG Groups
        if($sggroup -notlike "N/A")
        {
            $AddGroups += $sggroup
        }

        # DG Groups
        if($dggroup -notlike "N/A")
        {
            foreach ($g in $dggroup)
            {
                $AddGroups += $dggroup
            }
        }
        
        # Office365
        # If license value passed from HR4Sigma
        if($o365)
        {
            # Match Nexer companies, Sigma IT Polska is a Nexer company that hasn't been able to legally change the name.
            IF(($company -like "Nexer*") -OR ($company -like "Sigma IT Polska Sp. z o.o."))
            {
                # Checks the $O365 value that has been passed from HR4Sigma. Sets the correct Security group depending on the value.
                $o365group = switch ($o365) {
                    "E1"            { "SG_Office365-E1_Nexer-CSP" }
                    "F1"            { Check-EALicense -License "F3" }
                    "F3"            { Check-EALicense -License "F3" }
                    "E3"            { Check-EALicense -License "E3" }
                    "Ingen licens"  {}
                    "Underkonsult"  {}
                    "UK"            {}
                }
            }

            # Match Danir, Sigma, A Society and Aptio companies
            elseif (($company -like "Danir*") -OR ($company -like "Sigma*") -OR ($company -like "A Society*") -OR ($company -like "Aptio*")) 
            {
                # Checks the $O365 value that has been passed from HR4Sigma. Sets the correct Security group depending on the value.
                $o365group = switch ($o365) {
                    "E1"            { "SG_Office365-E1_Sigma-CSP" }
                    "F1"            { "SG_Microsoft365-F3_Sigma-CSP" }
                    "F3"            { "SG_Microsoft365-F3_Sigma-CSP" }
                    "E3"            { "SG_Microsoft365-E3_Sigma-CSP" }
                    "Ingen licens"  {}
                    "Underkonsult"  {}
                    "UK"            {}
                }
            }

            # Checks if $o365group variable has been assigned a group name
            if ($o365group) {
                # Add group name to $AddGroups to be added to membership
                $AddGroups += $o365group
            }
        }


        # Adds all group membership gathered in $AddGroups
        foreach ($item in $AddGroups)
        {
            Get-ADGroup -Identity $item | Add-ADGroupMember -Members $alias
        }
    
    }




    
    function sms-and-mail
    {
    
    $SMTPServer = "smtprelay.net.sigma.se"
    $SMTPPort = 25
    $SMSSubject = " "
    $MailSubject = "$namn's account is now created"
    $Encoding = [System.Text.Encoding]::UTF8
    $SMSFrom = "support@sigma.se"
    $MailFrom = "support@nexergroup.com"

    # SMS
    if ($company -eq "Nexer Tech Talent AB"){
        $nr = Get-PhoneNumber-User

        if($nr){
            $Recipient = $nr + "@qlnk.se"
            $SMStext =
            "Hi!`nHere's the password for your account: $pwd
            `nBR`nNexer Support"

            Send-MailMessage -From $SMSFrom -To $Recipient -Subject $SMSSubject -Body $SMStext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue
            }
        else{
            $nonr = "No Number"
            }
        }
    else{
        $nr = Get-PhoneNumber-Manager
        
        if($nr){
            $Recipient = $nr + "@qlnk.se"
            $SMStext =
            "Hi!`nHere's the password for user: `n$namn`nPassword: $pwd
            `nBR`nNexer Support"

            Send-MailMessage -From $SMSFrom -To $Recipient -Subject $SMSSubject -Body $SMStext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding -ErrorAction SilentlyContinue
            }
        else{
            $nonr = "No Number"
            }
        }    

    # Mail

    $To = Get-Email $usermanager
    $usermail = Get-Email $alias
    $usermanagername = Get-UserManagerName
        
    if($company -eq "Sigma Civil AB" -and $nonr){
    $emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Manager or phone number missing, no password has been sent!
    Email: $usermail
    Mobile: $userphone
    Title: $jobtitle
    Company: $company
    Department: $department
    Department number: $departmentnumber
    DL: $dggroup
    SG: $sggroup
    Systemgrupp: $sgcivilgroup
    Work place: $city
    Office 365 License: $o365
    Account expire date: $expire

    PX: $alias
    PX-password: $alias

    Best Regards
    Nexer Support

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    elseif($company -eq "Sigma Civil AB"){
    $emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Sent to manager $($usermanagername.displayname)
    Email: $usermail
    Mobile: $userphone
    Title: $jobtitle
    Company: $company
    Department: $department
    Department number: $departmentnumber
    DL: $dggroup
    SG: $sggroup
    Systemgrupp: $sgcivilgroup
    Work place: $city
    Office 365 License: $o365
    Account expire date: $expire

    PX: $alias
    PX-password: $alias

    Best Regards
    Nexer Support

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    if($company -eq "Nexer Tech Talent AB" -and $nonr){
    $emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Phone number missing, no password has been sent!
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

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    elseif($company -eq "Nexer Tech Talent AB"){
    $emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Sent to phone
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

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    if($company -ne "Nexer Tech Talent AB" -and $company -ne "Sigma Civil AB" -and $nonr){
    $emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Manager or phone number missing, no password has been sent!
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

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    elseif($company -ne "Nexer Tech Talent AB" -and $company -ne "Sigma Civil AB"){
    $emailtext = "
    Hi, $namn's account is now created

    Username: SIGMA\$alias
    Password: Sent to manager $($usermanagername.displayname)
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

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }

    Send-MailMessage -From $MailFrom -To $To -Subject $MailSubject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding
    Send-MailMessage -From $MailFrom -To "christian.spector@nexergroup.com" -Subject $MailSubject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding

    }

    function sms-with-password #tidigare funktion
    {
    $SMTPServer = "smtprelay.net.sigma.se"
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
$log= "C:\hr4sigma\log\new_user_HR4Sigma$logdate.log"
$logerror = "C:\hr4sigma\log\new_user_error_HR4Sigma$logdate.log"
$loginfo = "C:\hr4sigma\log\new_user_info_HR4Sigma$logdate.log"
$logsmserror = "C:\hr4sigma\log\sms_error_HR4Sigma$logdate.log"
#$description = "HR4Sigma, $usermanager, $date"
$description = "HR4Sigma"
$namn = "$fornamn $efternamn" #Behövs för mail functionen
$pwd = Generate-Password
$pw = ConvertTo-SecureString -string $pwd -asPlainText -Force
$cleanedFirstName = remove-special-letters $fornamn  #Behövs för UPN
$cleanedLastName = remove-special-letters $efternamn #Behövs för UPN

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

if ($company -notlike "Nexer IT Services AB") {
    set-account-memberof
}

set-account-expire

create-px

Start-Sleep -Seconds 10 # För att den ska få tid att plocka upp rätt E-post
        
#mail
#sms-with-password
sms-and-mail
return-info
log

unload-modules
