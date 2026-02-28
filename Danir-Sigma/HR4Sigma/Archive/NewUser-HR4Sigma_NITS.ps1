
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

    function create-account-office365-activedirectory #tidigare funktion
    {
        $fullName = $fornamn + " " + $efternamn
        $UPN = "$cleanedFirstName.$cleanedLastName@sigma.se"
        
        # Check If Mailbox Exist
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
            New-RemoteMailbox -name $newName -FirstName $fornamn -LastName $efternamn -displayname $fullName -SamAccountName $alias -Alias $alias -OnPremisesOrganizationalUnit $OU -UserPrincipalName $NewUPN -ResetPasswordOnNextLogon $false -Password $pw
            
            #cls
            
            Set-RemoteMailbox -Identity $alias -PrimarySmtpAddress "$NewMailAddress@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $NewUPN
        }
        Else
        {
            New-RemoteMailbox -name $fullName -FirstName $fornamn -LastName $efternamn -displayname $fullName -SamAccountName $alias -Alias $alias -OnPremisesOrganizationalUnit $OU -UserPrincipalName $UPN -ResetPasswordOnNextLogon $false -Password $pw
        
            #cls

            Set-RemoteMailbox -Identity $alias -PrimarySmtpAddress "$cleanedFirstName.$cleanedLastName@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
        }
    }

    function create-account-ad-exchangeonline
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
        $MailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till Set-RemoteMailbox -PrimarySmtpAddress

        $Mailbox = Get-Recipient -Identity $UPN -ErrorAction SilentlyContinue
        If ($Mailbox)
        {
            "$date - UPN $UPN exists, checking next available..." | Out-File $loginfo -Append #Returnerar DisplayName/CN Path
            $AddNumber = 1
	        Do
	        {
		        $AddNumber++
                $CNName = $namn + $AddNumber
                $UPN = $cleanedFirstName + "." + $cleanedLastName + $AddNumber + "@sigma.se"
                #$NewMailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till Set-RemoteMailbox -PrimarySmtpAddress
                $MailAddress = $cleanedFirstName + "." + $cleanedLastName + $AddNumber # Denna används till Set-RemoteMailbox -PrimarySmtpAddress
        
                $NewCNNameCheck = Get-ADUser -Filter * -Properties cn | Where-Object {$_.cn -eq $CNName}
		        $NewMailboxCheck = Get-Recipient -Identity $UPN -ErrorAction SilentlyContinue
	        } Until(!$NewCNNameCheck -and !$NewMailboxCheck)
    		
            "$date - New CNName $CNName, New UPN $UPN" | Out-File $loginfo -Append

            New-RemoteMailbox -name $CNName -FirstName $fornamn -LastName $efternamn -displayname $namn -SamAccountName $alias -Alias $alias -OnPremisesOrganizationalUnit $OU -UserPrincipalName $UPN -ResetPasswordOnNextLogon $false -Password $pw
	
	        #Set-RemoteMailbox -Identity $alias -PrimarySmtpAddress "$NewMailAddress@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
            Set-RemoteMailbox -Identity $alias -PrimarySmtpAddress "$MailAddress@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
        }
        Else
        {
            New-RemoteMailbox -name $CNName -FirstName $fornamn -LastName $efternamn -displayname $namn -SamAccountName $alias -Alias $alias -OnPremisesOrganizationalUnit $OU -UserPrincipalName $UPN -ResetPasswordOnNextLogon $false -Password $pw
	
	        #Set-RemoteMailbox -Identity $alias -PrimarySmtpAddress "$cleanedFirstName.$cleanedLastName@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
            Set-RemoteMailbox -Identity $alias -PrimarySmtpAddress "$MailAddress@$Domain" -EmailAddressPolicyEnabled $false -UserPrincipalName $UPN
        }

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
        $usermail = Get-RemoteMailbox -Identity $alias | select -expand PrimarySmtpAddress
        $userupn = Get-RemoteMailbox -Identity $alias | select -expand UserPrincipalName

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
            if($company -eq "Danir AB")
            {
                Get-ADGroup -Identity "Danir Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer AB")
            {
                Get-ADGroup -Identity "ITC Office $city" | Add-ADGroupMember -Members $alias
            }

            #elseif($company -eq "Nexer Asset Management AS")
            #{}

            elseif($company -eq "Nexer Asset Management Oy")
            {
                Get-ADGroup -Identity "ITC Finland Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Cybersecurity AB")
            {
                Get-ADGroup -Identity "Cybersecurity Office $city" | Add-ADGroupMember -Members $alias
            }
            elseif($company -eq "Sigma Cybersecurity AB")
            {
                Get-ADGroup -Identity "Cybersecurity Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Digital Ltd")
            {
                Get-ADGroup -Identity "ITC UK Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Enterprise Applications AB")
            {
                Get-ADGroup -Identity "Dynamics Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Enterprise Applications Inc")
            {
                Get-ADGroup -Identity "Enterprise Applications Inc Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Enterprise Applications Ltd")
            {
                Get-ADGroup -Identity "Enterprise Applications Ltd Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Enterprise Applications Prv Ltd")
            {
                Get-ADGroup -Identity "ITC India Enterprise Applications Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Infrastructure AB")
            {
                Get-ADGroup -Identity "IT Tech Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Insight AB")
            {
                Get-ADGroup -Identity "IoT AI Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Insight Inc")
            {
                Get-ADGroup -Identity "ITC Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Insight Ltd")
            {
                Get-ADGroup -Identity "ITC Insight Ltd Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Insight Sp. z o.o.")
            {
                Get-ADGroup -Identity "ITC Insight Poland Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer IT Services AB")
            {
                Get-ADGroup -Identity "NITS Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Prv Ltd")
            {
                Get-ADGroup -Identity "ITC Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Recruit AB")
            {
                Get-ADGroup -Identity "Recruit Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Sp. z o.o.")
            {
                Get-ADGroup -Identity "ITC Office $city" | Add-ADGroupMember -Members $alias
            }
            elseif($company -eq "Sigma IT Polska Sp. z o.o.")
            {
                Get-ADGroup -Identity "ITC Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Nexer Tech Talent AB")
            {
                Get-ADGroup -Identity "Young Talent Office $city" | Add-ADGroupMember -Members $alias
            }


            elseif($company -eq "Sigma Civil AB")
            {
                if($city -eq "Stockholm")
                    {Get-ADGroup -Identity "Civil Office Stockholm Liljeholmen" | Add-ADGroupMember -Members $alias}
                else
                    {Get-ADGroup -Identity "Civil Office $city" | Add-ADGroupMember -Members $alias}
                
                foreach ($cg in $sgcivilgroup)
                {
                    Get-ADUser -Identity $alias | Add-ADPrincipalGroupMembership -memberof $cg
                }
            }

            elseif($company -eq "Sigma Connectivity AB")
            {
                Get-ADGroup -Identity "og-ConnectivityAll" | Add-ADGroupMember -Members $alias
                Get-ADGroup -Identity "Connectivity SWE Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Connectivity ApS")
            {
                Get-ADGroup -Identity "og-ConnectivityAll" | Add-ADGroupMember -Members $alias
                if($city -eq "Köpenhamn")
                    {Get-ADGroup -Identity "Connectivity DK Office Copenhagen" | Add-ADGroupMember -Members $alias}
                else
                    {Get-ADGroup -Identity "Connectivity DK Office $city" | Add-ADGroupMember -Members $alias}
            }

            elseif($company -eq "Sigma Connectivity Inc.")
            {
                Get-ADGroup -Identity "og-ConnectivityAll" | Add-ADGroupMember -Members $alias
                Get-ADGroup -Identity "Connectivity INC Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Connectivity Sp. z o.o.")
            {
                Get-ADGroup -Identity "og-ConnectivityAll" | Add-ADGroupMember -Members $alias
                Get-ADGroup -Identity "Connectivity PL Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Connectivity Engineering AB")
            {
                Get-ADGroup -Identity "og-ConnectivityAll" | Add-ADGroupMember -Members $alias
                Get-ADGroup -Identity "SC Engineering Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Embedded Engineering AB")
            {
                Get-ADGroup -Identity "Embedded Engineering Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Energy & Marine AB")
            {
                Get-ADGroup -Identity "Energy Marine Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Energy & Marine AS")
            {
                Get-ADGroup -Identity "Energy Marine AS Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Industry East North AB")
            {
                Get-ADGroup -Identity "Industry East North Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Industry Evolution AB")
            {
                Get-ADGroup -Identity "Industry Evolution Office $city" | Add-ADGroupMember -Members $alias
            }

            #elseif($company -eq "Sigma Industry Inc.")
            <#{
                Get-ADGroup -Identity "SII Office $city" | Add-ADGroupMember -Members $alias
            }#>

            elseif($company -eq "Sigma Industry Solutions AB")
            {
                Get-ADGroup -Identity "Industry Solutions Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Industry South AB")
            {
                Get-ADGroup -Identity "Industry South Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Industry West AB")
            {
                Get-ADGroup -Identity "Industry West Office $city" | Add-ADGroupMember -Members $alias
            }

            elseif($company -eq "Sigma Quality & Compliance AB" -or $company -eq "Sigma Quality & Compliance ApS")
            {
                if($city -eq "Göteborg")
                    {Get-ADGroup -Identity "QC Office Gothenburg" | Add-ADGroupMember -Members $alias}
                else
                    {Get-ADGroup -Identity "QC Office $city" | Add-ADGroupMember -Members $alias}
            }

            elseif($company -eq "aptio group Sweden AB" -or $company -eq "aptio group Denmark ApS")
            {
                if($city -eq "Göteborg")
                    {Get-ADGroup -Identity "QC Office Gothenburg" | Add-ADGroupMember -Members $alias}
                else
                    {Get-ADGroup -Identity "QC Office $city" | Add-ADGroupMember -Members $alias}
            }

            #elseif($company -eq "Sigma Software LLC")
            #{}

            else
            {
                Get-ADGroup -Identity "Office $city All" | Add-ADGroupMember -Members $alias        
            }

        # DG Groups
        if($dggroup -eq "N/A")
        {
            #return
        }
        else
        {
            foreach ($g in $dggroup)
            {
                Get-ADUser -Identity $alias | Add-ADPrincipalGroupMembership -memberof $g
            }
        }
        
        # SG Groups
        if($sggroup -eq "N/A")
        {
            #return
        }
        else
        {
            Get-ADGroup -Identity $sggroup | Add-ADGroupMember -Members $alias
        }
        
        # Office365
        if($o365 -eq "E1")
        {
            Get-ADGroup -Identity "SG Office365 E1" | Add-ADGroupMember -Members $alias
        }
        if($o365 -eq "E3")
        {
            Get-ADGroup -Identity "SG Office365 E3" | Add-ADGroupMember -Members $alias
        }
        if($o365 -eq "F1")
        {
            Get-ADGroup -Identity "SG Office365 F1" | Add-ADGroupMember -Members $alias
        }
        if($o365 -eq "Ingen licens" -or $o365 -eq "Underkonsult" -or $o365 -eq "" -or $o365 -eq $null)
        {
            #return
        }

        # No Group
        #if($dggroup -eq "No Group" -or $sggroup -eq "No Group" -or $sgcivilgroup -eq "No Group")
        #{
        #    Get-ADGroup -Identity "No Group" | Remove-ADGroupMember -Members $Alias -Confirm:$false
        #}
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
#create-account-office365-activedirectory
create-account-ad-exchangeonline

Start-Sleep -Seconds 10 # För att den ska få tid att skapa upp konto innan info sätts

set-account-info
if ($company -notlike "Nexer IT Services AB") { # NITS användare ska ej in i några grupper efter uppköpet av RTS. Förändrat 2021-12-02 @ Yoel Abraham
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
