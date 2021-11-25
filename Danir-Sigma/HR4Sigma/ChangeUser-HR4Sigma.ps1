
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

# Import Library

. "C:\hr4sigma\library\Company-HR4Sigma.ps1"

# Loading Modules
    
    function load-modules
    {
        #Exchange
        try
        {
            $exch=New-PSSession -ConnectionUri http://ss0251/powershell -ConfigurationName Microsoft.Exchange 
            Import-PSSession $exch -AllowClobber -DisableNameChecking -ErrorAction Stop
        }
        catch
        {
            Write-Error "ERROR! Kan inte ladda Exchange Modul"
            "$date - ERROR! Kan inte ladda Exchange Modul" | Out-File $logerror -Append
            Break
        }

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
            $AddGroup = $EAGroupName
        }else {
            $AddGroup = $CSPGroupName
        }
    
        Return $AddGroup
    }

    function unload-modules
    {
        Get-PSSession | Remove-PSSession
    }

# Load functions

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

    function create-px
    {
        if($database -eq "" -or $database -eq $null)
        {
            return
        }
        if($database -ne "")
        {
            $varArray = "v18 = $alias";
            $existingpx = Invoke-Sqlcmd -ServerInstance "SS0305.sigma.local" -Query "SELECT name FROM master.sys.sql_logins WHERE name LIKE '`$(v18)'" -Variable $varArray
            if($existingpx)
            {
                "$date - PX account already exists. Alias:$alias" | Out-File $loginfo -Append
                return $existingpx
            }
            else
            {
                $varArray = "v18 = $alias", "v19 = $alias";
                $existingpx =Invoke-Sqlcmd -ServerInstance "SS0305.sigma.local" -Query "CREATE LOGIN [`$(v18)] WITH PASSWORD = '`$(v19)', CHECK_POLICY = OFF" -Variable $varArray
                return $existingpx
            }
        }
    }


    function delete-old-groups
    {
        #Get-ADPrincipalGroupMembership $alias | select name | Where {($_.Name -like '*ITC*' -or $_.Name -like '*Civil*')} | Sort-Object name
        $member = Get-ADPrincipalGroupMembership $alias | 
        Where {
        (
        $_.Name -like '*A Society*' -or `
        $_.Name -like '*Danir*' -or `
        $_.Name -like '*Civil*' -or `
        $_.Name -like '*Connectivity*' -or `
        $_.Name -like '*SC Engineering*' -or `
        $_.Name -like '*Energy Marine*' -or `
        $_.Name -like '*Embedded Engineering*' -or `
        $_.Name -like '*Dynamics*' -or `
        $_.Name -like '*Industry*' -or `
        $_.Name -like '*ITC*' -or `
        $_.Name -like '*ITM Norway*' -or `
        $_.Name -like '*QC*' -or `
        $_.Name -like '*IT Tech*' -or `
        $_.Name -like '*Recruit*' -or `
        $_.Name -like '*Young Talent*' -or `
        $_.Name -like '*SSOY*' -or `
        $_.Name -like '*Office*' # Kommer radera t.ex. Office Lund All + Office365
        )}
        foreach ($group in $member)
        {
            #Write-Debug $group
            #Read-Host "OK?"
            Get-ADGroup $group | Remove-ADGroupMember -Members $alias -Confirm:$false
        }
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


    function log
    {
$usermail = Get-RemoteMailbox -Identity $alias | select -expand PrimarySmtpAddress
$userupn = Get-RemoteMailbox -Identity $alias | select -expand UserPrincipalName
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


    function mail
    {
    
    $SMTPServer = "smtprelay.net.sigma.se"
    $SMTPPort = 25
    $Username = ""
    $Encoding = [System.Text.Encoding]::UTF8
    
    $From = "support@nexergroup.com"
    $To = Get-Email $usermanager
    $subject = "$namn's account is now changed"
    $usermail = Get-Email $alias
    $usermanagername = Get-UserManagerName
    
    $px = create-px

    if($company -eq "Sigma Civil AB" -and $px -eq "" -or $px -eq $null)
    {$emailtext = "
    Hi, $namn's account is now changed

    Username: SIGMA\$alias
    Email: $($usermail.mail)
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
    Manager: $usermanager

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
    elseif($company -eq "Sigma Civil AB" -and $px -like "System.Data.DataRow")
    {$emailtext = "
    Hi, $namn's account is now changed

    Username: SIGMA\$alias
    Email: $($usermail.mail)
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
    Manager: $usermanager

    Best Regards
    Nexer Support

    Email: support@nexergroup.com
    Phone from Sweden: 020- 510 520
    Phone from abroad +46 (0)10- 102 50 50   
    Nexer phone switchboard: 020-550 550
    "
    }
    elseif($px -like "System.Data.DataRow")
    {$emailtext = "
    Hi, $namn's account is now changed

    Username: SIGMA\$alias
    Email: $($usermail.mail)
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
    Manager: $usermanager

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
    Hi, $namn's account is now changed

    Username: SIGMA\$alias
    Email: $($usermail.mail)
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
    Manager: $usermanager

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

    #Send-MailMessage -From $From -To $($To.mail) -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding
    #Send-MailMessage -From $From -To "christian.spector@nexergroup.com" -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding

    }

    function move-ad-user
    {
       Get-ADUser -Identity $alias | Move-ADObject -TargetPath $OU
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
        #$usermail = Get-RemoteMailbox -Identity $alias | select -expand PrimarySmtpAddress
        #$userupn = Get-RemoteMailbox -Identity $alias | select -expand UserPrincipalName

        $usermail = Get-ADUser -Identity $alias -Properties mail | select -expand mail
        $userupn = Get-ADUser -Identity $alias -Properties UserPrincipalName | select -expand UserPrincipalName

        Write-Output "Användarnamn;$alias UserMail;$usermail UPN;$userupn"
    }


    function set-account-expire
    {
        if($expire -eq "")
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
        #description    = if($description     ){$description     }else{$null}
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
        {set-aduser @props -Clear extensionAttribute5}
        else
        {set-aduser @props -Replace @{extensionAttribute5 = "$cinodeactive"}}

        if($companyid -eq "")
        {set-aduser @props -Clear extensionAttribute6}
        else
        {set-aduser @props -Replace @{extensionAttribute6 = "$companyid"}}

        if($cunumber -eq "")
        {set-aduser @props -Clear extensionAttribute7}
        else
        {set-aduser @props -Replace @{extensionAttribute7 = "$cunumber"}}

        if($cuname -eq "")
        {set-aduser @props -Clear extensionAttribute8}
        else
        {set-aduser @props -Replace @{extensionAttribute8 = "$cuname"}}

        if($departmentnumber -eq "")
        {set-aduser @props -Clear departmentNumber}
        else
        {set-aduser @props -Replace @{departmentNumber = "$departmentnumber"}}
    }

    function set-account-memberof
    {
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
            "Sigma Industry Solutions AB"            { "Industry Solutions Office $city" }
            "Sigma Industry South AB"                { "Industry South Office $city" }
            "Sigma Industry West AB"                 { "Industry West Office $city" }
            "Sigma Quality & Compliance AB"          {
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

        foreach ($item in $AddGroups)
        {
            Get-ADGroup -Identity $item | Add-ADGroupMember -Members $alias
        }

        # DG Groups
        if($dggroup -notlike "N/A")
        {
            foreach ($g in $dggroup)
            {
                Get-ADUser -Identity $alias | Add-ADPrincipalGroupMembership -memberof $g
            }
        }

        
        # Office365
        IF(($company -like "Nexer*") -OR ($company -like "Sigma IT Polska Sp. z o.o."))
        {
            $o365group = switch ($o365) {
                "E1"            { "SG_Office365-E1_Nexer-CSP" }
                "E3"            { Check-EALicense -License "E3" }
                "F3"            { Check-EALicense -License "F3" }
                "Ingen licens"  {}
                "Underkonsult"  {}
                "UK"            {}
            }
        }
        elseif (($company -like "Danir AB") -OR ($company -like "Sigma*")) 
        {
            $o365group = switch ($o365) {
                "E1"            { "SG_Office365-E1_Sigma-CSP" }
                "E3"            { "SG_Microsoft365-E3_Sigma-CSP" }
                "F3"            { "SG_Microsoft365-F3_Sigma-CSP" }
                "Ingen licens"  {}
                "Underkonsult"  {}
                "UK"            {}
            }
        }
        # If license value passed from HR4Sigma
        if($o365)
        {
            # Remove old license groups
            $o365member = Get-ADPrincipalGroupMembership $alias | Where {($_.Name -match "^SG_(Microsoft|Office)365-(F|E)\d_(Nexer|Sigma)-(CSP|EA)$") -OR ($_.Name -match "^SG\sOffice365\s(F|E)\d$")}
            IF($o365member)
            {
                foreach ($item in $o365member)
                {    
                    Get-ADGroup $item | Remove-ADGroupMember -Members $alias -Confirm:$false
                }
            }

            # Add new license groups (If assigned)
            if ($o365group) {
                Get-ADGroup $o365group | Add-ADGroupMember -Members $alias
            }
        }

        # No Group
        #if($dggroup -eq "No Group" -or $sggroup -eq "No Group" -or $sgcivilgroup -eq "No Group")
        #{
        #    Get-ADGroup -Identity "No Group" | Remove-ADGroupMember -Members $alias -Confirm:$false
        #}
    }

    function set-new-mailaddress
    {    
        $existinguser = Get-ADUser $alias
        if ($existinguser.GivenName -eq $fornamn -and $existinguser.Surname -eq $efternamn)
        {
            "$date - Ingen ändring på e-post $alias $fornamn $efternamn..." | Out-File $loginfo -Append
            Start-Sleep -s 2
            return
        }
        else
        {
            $fullName = $fornamn + " " + $efternamn
            $UPN = "$cleanedFirstName.$cleanedLastName@sigma.se"
        
            $Mailbox = Get-RemoteMailbox -Identity $UPN -ErrorAction SilentlyContinue
            If ($Mailbox)
            {
                "$date - Mailbox $Mailbox exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName
                Start-Sleep -s 2
                $AddNumber = 1
                Do
                {
                    $AddNumber++
                    $NewUPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@sigma.se"
                    $NewMailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till set-new-mailaddress
                    $NewMailbox = Get-RemoteMailbox -Identity $NewUPN -ErrorAction SilentlyContinue
                    #Write-Debug "Mailbox: $Mailbox"
                    #Write-Debug "UPN: $UPN"
                    #Write-Debug "NewMailbox: $NewUPN"
                    #Write-Debug "NewUPN: $NewUPN"
                    #Write-Debug "Domain: $Domain"
                    #Read-Host "OK?"
                } Until(!$NewMailbox)

                $newName = $fornamn + " " + $efternamn + $AddNumber
                Set-RemoteMailbox -Identity $alias -name $newName -displayname $fullName -PrimarySmtpAddress "$NewMailAddress@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $NewUPN
                Set-ADUser $alias -GivenName $fornamn -Surname $efternamn
            }
            else
            {
                Set-RemoteMailbox -Identity $alias -name $fullName -displayname $fullName -PrimarySmtpAddress "$cleanedFirstName.$cleanedLastName@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
                Set-ADUser $alias -GivenName $fornamn -Surname $efternamn
            }
        }
    }

    function set-new-name-and-cnname
    {    
        $existinguser = Get-ADUser $alias
        if ($existinguser.GivenName -eq $fornamn -and $existinguser.Surname -eq $efternamn)
        {}
        else
        {
            "$date - Ändring på namn $alias..." | Out-File $loginfo -Append
            $CNName = Get-ADUser -Filter * -Properties cn | Where-Object {$_.cn -eq $namn}
            if ($CNName)
            {
                "$date - Ändring på CNnamn $alias $namn..." | Out-File $loginfo -Append
                $AddNumber = 1
                Do
                {
                    $AddNumber++
                    $NewCNName = $namn + $AddNumber
                    $NewCNNameCheck = Get-ADUser -Filter * -Properties cn | Where-Object {$_.cn -eq $NewCNName}
                } Until(!$NewCNNameCheck)

                "$date - Nytt CNnamn $alias $namn till $NewCNName..." | Out-File $loginfo -Append
                Set-ADUser $alias -GivenName $fornamn -Surname $efternamn -DisplayName $namn -PassThru | Rename-ADObject -NewName $NewCNName
            }
            else
            {
                Set-ADUser $alias -GivenName $fornamn -Surname $efternamn -DisplayName $namn -PassThru | Rename-ADObject -NewName $namn
            }
        }
    }

############################################################################

#Load modules

load-modules

$date = get-date -format "yyyy-MM-dd HH:mm"
$logdate = Get-Date -Format "yyyyMMdd"
$log= "C:\hr4sigma\log\change_user_HR4Sigma$logdate.log"
$logerror = "C:\hr4sigma\log\change_user_error_HR4Sigma$logdate.log"
$loginfo = "C:\hr4sigma\log\change_user_info_HR4Sigma$logdate.log"
#$description = "HR4Sigma, $usermanager, $date"
$namn = "$fornamn $efternamn" #Behövs för mail & set-new-mailaddress funktionen
$cleanedFirstName = remove-special-letters $fornamn #Behövs för UPN
$cleanedLastName = remove-special-letters $efternamn #Behövs för UPN

# Array Fixes

$OU = $ListOfCompanys["select"][$company]["OU"]
$database = $ListOfCompanys["select"][$company]["Database"]
$Domain = $ListOfCompanys["select"][$Company]["Domain"]
    if($department -eq "ITC Bool")
    {$Domain = "bool.se"}

#Run

check-values
#set-new-mailaddress
set-account-memberof #Denna måste ligga före set-new-name-and-cnname annars fungerar inte Get-ADPrincipalGroupMembership
set-new-name-and-cnname

#Start-Sleep -Seconds 10 # För att den ska få tid att ändra konto innan info sätts

#delete-old-groups
set-account-info
set-account-expire
move-ad-user

#create-px # Funktion körs i funktionen "mail"

#Start-Sleep -Seconds 10 # För att den ska få tid att plocka upp rätt E-post

mail
return-info
log

unload-modules
