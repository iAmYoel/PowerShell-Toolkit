
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

# Import Library

. "$RootFolder\library\Company-CatalystOne.ps1"

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

        $EAGroupName = "SG_Temp_Office365-${License}_Nexer-EA"
        $CSPGroupName = "SG_Temp_Microsoft365-${License}_Nexer-CSP"

        $EAGroupMembersCount = (Get-ADGroupMember -Identity $EAGroupName -Recursive).Count

        if ($EAGroupMembersCount -lt $MaxUsers) {
            $ReturnGroup = $EAGroupName
        }else {
            $ReturnGroup = $CSPGroupName
        }

        Return $ReturnGroup
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
            #$varArray = "v18 = $alias";
            $v18 = $alias

            #$existingpx = Invoke-Sqlcmd -ServerInstance "NEXER-PXSQL01.ad.nexergroup.com" -Query "SELECT name FROM master.sys.sql_logins WHERE name LIKE '`$(v18)'" -Variable $varArray
            $existingpx = SQLCMD.EXE -S "NEXER-PXSQL01.ad.nexergroup.com" -Q "SELECT COUNT(name) FROM master.sys.sql_logins WHERE name = '$v18'"

            $existingpxcount = [int32]$existingpx[2].Trim()

            if($existingpxcount -gt 0)
            {
                "$date - PX account already exists. Alias:$alias" | Out-File $loginfo -Append
                return $existingpx
            }
            else
            {
                #$varArray = "v18 = $alias", "v19 = $alias";
                $v18 = $alias
                $v19 = $alias

                # SQLCMD.EXE används istället för Invoke-Sqlcmd för att integrationen körs i 32-bit powershell, som ej är kompatibelt med Invoke-Sqlcmd.
                #$existingpx = Invoke-Sqlcmd -ServerInstance "NEXER-PXSQL01.ad.nexergroup.com" -Query "CREATE LOGIN [`$(v18)] WITH PASSWORD = '`$(v19)', CHECK_POLICY = OFF" -Variable $varArray
                $existingpx = SQLCMD.EXE -S "NEXER-PXSQL01.ad.nexergroup.com" -Q "CREATE LOGIN [$v18] WITH PASSWORD = '$v19', CHECK_POLICY = OFF"
                return $existingpx
            }
        }
    }


    function delete-old-groups  # Not used
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
        $SMTPServer = "smtprelay.net.nexergroup.com"
        $SMTPPort = 25
        $Username = ""
        $Encoding = [System.Text.Encoding]::UTF8

        $From = "support@nexergroup.com"
        $To = Get-Email $usermanager
        $subject = "$namn's account is now changed"
        $usermail = Get-Email $alias
        $usermanagername = Get-UserManagerName

        $px = create-px

        $emailtext = "
        Hi, $namn's account is now changed

        Username: NEXERGROUP\$alias
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

        Email: support@rts.se
        Phone: +46 (0)10-643 945 00
        Nexer phone switchboard: 020-550 550
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
            "Nexer Enterprise Applications Inc"     { "Enterprise Applications Inc Office $city" }      # No existing active user found with this company name, is this an old company that can be deleted?
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
                "E1"            { "SG_Temp_Office365-E1_Nexer-CSP" }
                "F1"            { Check-EALicense -License "F3" }
                "F3"            { Check-EALicense -License "F3" }
                "E3"            { "SG_Temp_Microsoft365-E3_Nexer-CSP" } # Ändrat för migrering av Nexer. Ska egentligen vara Check-EALicense -License "E3"
                "Ingen licens"  {}
                "Underkonsult"  {}
                "UK"            {}
            }

            # Gather all current 365 group memberships to be removed
            $OldO365Groups = Get-ADPrincipalGroupMembership $alias | Where {$_.Name -match "^SG_(Microsoft|Temp_Microsoft|Office|Temp_Office)365-(F|E)(1|3)_Nexer-(CSP|EA)$"}
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

    function set-new-mailaddress    # Not used
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
            $UPN = "$cleanedFirstName.$cleanedLastName@$domain"

            $UPNCheck = Get-ADUser -Filter "UserPrincipalName -like '$UPN'" -ErrorAction SilentlyContinue
            If ($UPNCheck)
            {
                "$date - UPN $UPNCheck exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName
                Start-Sleep -s 2
                $AddNumber = 1
                Do
                {
                    $AddNumber++
                    $NewUPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@$domain"
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
$log= "$RootFolder\log\change-user-CatalystOne_$logdate.log"
$logerror = "$RootFolder\log\change-user-error-CatalystOne_$logdate.log"
$loginfo = "$RootFolder\log\change-user-info-CatalystOne_$logdate.log"
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
