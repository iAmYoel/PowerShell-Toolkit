
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
    [string]$companyid        = "",             #attr 6
    [string]$expire           = ""              #38 - Slutdatum
)

############################################################################

# Root HR4Sigma Integration folder
$RootFolder = (Get-Item $PSScriptRoot).Parent.FullName

# Import Library

. "$RootFolder\library\Company-HR4Sigma.ps1"

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

        REMOVE GROUPS: $($RemoveGroups -join ", ")
        ADD GROUPS: $($AddGroups -join ", ")

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

        $From = "support@sigma.se"
        $To = Get-Email $usermanager
        $subject = "$namn's account is now changed"
        $usermail = Get-Email $alias
        $usermanagername = Get-UserManagerName

        $px = create-px

        $emailtext = "
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
        $(
            if(($company -eq "Sigma Civil AB") -OR ($company -eq "Sigma Civil Öst AB")){
                "Systemgrupp: $sgcivilgroup"
                "`n   " # New line and indentation before the "Work place" line
            }
            "Work place: $city"
        )
        Office 365 License: $o365
        Account expire date: $expire
        Manager: $usermanager
        $(
            if ($px -notlike "System.Data.DataRow") {
                "`n   " # New line and indentation
                "PX: $alias"
                "`n   " # New line and indentation
                "PX-password: $alias"
                "`n   " # New line and indentation
            }
        )
        Best Regards
        Sigma Support

        Email: support@rts.se
        Phone from Sweden: 020- 510 520
        Phone from abroad +46 (0)10- 102 50 50
        "

        #Send-MailMessage -From $From -To $($To.mail) -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding
        #Send-MailMessage -From $From -To "christian.spector@nexergroup.com" -Subject $subject -Body $emailtext -SmtpServer $SMTPServer -Port $SMTPPort -Encoding $Encoding

    }

    function move-ad-user
    {
       Get-ADUser -Identity $alias | Move-ADObject -TargetPath $OU
    }


    # function for formatting special characters to normal and removing spaces from string
    function Format-LatinCharacters {
        param(
            [Parameter(ValueFromPipeline)]
            [string]$String
        )

        [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String)) -replace "\s"

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

        if($companyid -eq "")
        {set-aduser @props -Clear extensionAttribute6}
        else
        {set-aduser @props -Replace @{extensionAttribute6 = "$companyid"}}

        if($departmentnumber -eq "")
        {set-aduser @props -Clear departmentNumber}
        else
        {set-aduser @props -Replace @{departmentNumber = "$departmentnumber"}}
    }

    function set-account-memberof
    {
        # Create variables where all group memberships to be added and to be removed are gathered and defined
        $AddGroups = @()
        $RemoveGroups = @()

        # Switch to match which company the user belongs to and adds the correct group to $AddGroups
        $AddGroups += switch ($company) {
            "Danir AB"                              { "Danir Office $city" }
            "Sigma Civil AB"                        {
                                                        if($city -like "Stockholm")
                                                            { "Civil Office Stockholm Liljeholmen" }
                                                        else
                                                            { "Civil Office $city" }

                                                        foreach ($cg in $sgcivilgroup)
                                                        {
                                                            if ($cg -notlike "N/A") {
                                                                $cg
                                                            }
                                                        }
                                                    }
            "Sigma Civil Öst AB"                    {
                                                        "Civil Öst Office $city"

                                                        foreach ($cg in $sgcivilgroup)
                                                        {
                                                            if ($cg -notlike "N/A") {
                                                                $cg
                                                            }
                                                        }
                                                    }
            "Sigma Connectivity AB"                 { @("og-ConnectivityAll","Connectivity SWE Office $city") }
            "Sigma Connectivity ApS"                {
                                                        if($city -like "Köpenhamn"){ @("og-ConnectivityAll","Connectivity DK Office Copenhagen") }
                                                        else{ @("og-ConnectivityAll","Connectivity DK Office $city") }
                                                    }
            "Sigma Connectivity Inc."               { @("og-ConnectivityAll","Connectivity INC Office $city") }
            "Sigma Connectivity Sp. z o.o."         { @("og-ConnectivityAll","Connectivity PL Office $city") }
            "Sigma Connectivity Engineering AB"     { @("og-ConnectivityAll","SC Engineering Office $city") }
            "Sigma Embedded Engineering AB"         { "Embedded Engineering Office $city" }
            "Sigma Energy & Marine AB"              { "Energy Marine Office $city" }
            "Sigma Energy & Marine AS"              { "Energy Marine AS Office $city" }
            "Sigma Industry East North AB"          { "Industry East North Office $city" }
            "Sigma Industry Evolution AB"           { "Industry Evolution Office $city" }
            "Sigma Industry Solutions AB"            { "Industry Solutions Office $city" }
            "Sigma Industry South AB"                { "Industry South Office $city" }
            "Sigma Industry West AB"                 { "Industry West Office $city" }
            "Sigma Quality & Compliance AB"          {
                                                        if($city -like "Göteborg"){ "QC Office Gothenburg" }
                                                        else{ "QC Office $city" }
                                                    }
            "Sigma Quality & Compliance ApS"        {
                                                        if($city -like "Göteborg"){ "QC Office Gothenburg" }
                                                        else{ "QC Office $city" }
                                                    }
            "aptio group Sweden AB"                 {
                                                        if($city -eq "Göteborg"){ "QC Office Gothenburg" }
                                                        else{ "QC Office $city" }
                                                    }
            "aptio group Denmark ApS"               {
                                                        if($city -eq "Göteborg"){ "QC Office Gothenburg" }
                                                        else{ "QC Office $city" }
                                                    }
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
        # If license value passed from HR4Sigma
        if($o365)
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

            # Gather all current 365 group memberships to be removed
            $OldO365Groups = Get-ADPrincipalGroupMembership $alias | Where {($_.Name -match "^SG_(Microsoft|Office)365-(F|E)(1|3)_Sigma-CSP$") -OR ($_.Name -match "^SG\sOffice365\s(F|E)(1|3)$")}
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

            $UPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue
            If ($UPNCheck)
            {
                "$date - UPN $UPNCheck exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName
                Start-Sleep -s 2
                $AddNumber = 1
                Do
                {
                    $AddNumber++
                    $NewUPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@sigma.se"
                    $NewMailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till set-new-mailaddress
                    $NewUPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue

                } Until(!$NewUPNCheck)

                $newName = $fornamn + " " + $efternamn + $AddNumber
                #Set-RemoteMailbox -Identity $alias -name $newName -displayname $fullName -PrimarySmtpAddress "$NewMailAddress@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $NewUPN
                Set-ADUser $alias -GivenName $fornamn -Surname $efternamn -Name $newName -DisplayName $fullName -UserPrincipalName $NewUPN

                $ProxyAddresses = (Get-ADUser $alias -Properties ProxyAddresses).ProxyAddresses | Foreach{
                    if($_ -cmatch "^SMTP:"){
                        "SMTP:$NewMailAddress@$Domain"
                    }else{
                        $_
                    }
                }

                Set-ADUser $alias -replace @{ProxyAddresses=$ProxyAddresses}

            }
            else
            {
                #Set-RemoteMailbox -Identity $alias -name $fullName -displayname $fullName -PrimarySmtpAddress "$cleanedFirstName.$cleanedLastName@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
                Set-ADUser $alias -GivenName $fornamn -Surname $efternamn -name $fullName -DisplayName $fullName -UserPrincipalName $UPN

                $ProxyAddresses = (Get-ADUser $alias -Properties ProxyAddresses).ProxyAddresses | Foreach{
                    if($_ -cmatch "^SMTP:"){
                        "SMTP:$cleanedFirstName.$cleanedLastName@$Domain"
                    }else{
                        $_
                    }
                }

                Set-ADUser $alias -replace @{ProxyAddresses=$ProxyAddresses}

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
                    $NewCNNameCheck = Get-ADUser -Filter "cn -like '$NewCNName'"
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
$log= "$RootFolder\log\change-user-HR4Sigma_$logdate.log"
$logerror = "$RootFolder\log\change-user-error-HR4Sigma_$logdate.log"
$loginfo = "$RootFolder\log\change-user-info-HR4Sigma_$logdate.log"
#$description = "HR4Sigma, $usermanager, $date"
$namn = "$fornamn $efternamn" #Behövs för mail & set-new-mailaddress funktionen
$cleanedFirstName = Format-LatinCharacters $fornamn #Behövs för UPN
$cleanedLastName = Format-LatinCharacters $efternamn #Behövs för UPN

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
