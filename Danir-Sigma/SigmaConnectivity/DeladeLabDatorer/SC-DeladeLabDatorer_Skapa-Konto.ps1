[CmdletBinding()]
param()

$VerbosePreference = 'Continue'

#region functions

function Write-Menu {
    <#
    .SYNOPSIS
        Outputs a menu when given an array
    .DESCRIPTION
        Outputs menu and gives options to choose an item when given an array.
        You can choose which property to show in menu.
    .EXAMPLE
        PS C:\> Write-Menu (Get-ChildItem) -DisplayProperty BaseName
        Prints out all Items from Get-ChildItem in a numbered menu with the Items BaseName
    .INPUTS
        -ChoiceItems []
        -DisplayProperty <string>
    .OUTPUTS
        Numbered menu
    .NOTES
        
    #>
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline)][array]$Items,
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)][string]$Name
    )

    begin {
        #$currentState = 0
        $searchMenu = [ordered] @{ }
    }
    process { 
        $ChoiceItems += $Items
    }
    end {
        if (($Items | gm -Static).TypeName[0] -like "System.String") {
            
        }else {
            
            $htMenu = [ordered] @{ }
            for ($i = 1; $i -le $ChoiceItems.Count; $i++) {
                Write-Verbose "Adding $($ChoiceItems[$i - 1]) as choice $i"
                $htMenu.Add("$i", $ChoiceItems[$i - 1])
            }
            #$htMenu.Add("b", "Go back")
            $htMenu.Add("q", "Quit")

            if ($htMenu.Count -ge 9) {
                do {
                    [string]$answer = (Read-Host "This will print $($htMenu.Count-1) options`nDo you want to (s)earch, (l)ist or (q)uit?").ToLower()
                } while ($answer -notin "s", "l", "q")
                if ($answer -eq "s") {
                    $searchString = Read-Host -Prompt "Search for"
                    $searchResults = $htMenu.GetEnumerator() | Where-Object { $_.Value.Name -match $searchString }
                    for ($i = 1; $i -le $searchResults.Count; $i++) {
                        Write-Verbose "Adding $($searchResults[$i - 1]) as choice $i"
                        $searchMenu.Add("$i", $searchResults[$i - 1].Value)
                    }
                    $searchMenu.Add("q", "Quit")
                    foreach ($key in $searchMenu.Keys) {
                        if ($key -eq "q") {
                            Write-Host "'$key' for: $($searchMenu[$key])"
                        }
                        else {
                            Write-Host "'$key' for: $($searchMenu[$key].$Name)"
                        }
                    }

                    do {
                        [string]$choice = Read-Host "Choice"
                    } until ($choice -in $searchMenu.Keys)

                    if ($choice -eq "q") {
                        return
                    }
                    return $searchMenu[$choice]
                }
                if ($answer -eq "q") {
                    return
                }
            }

        }

        foreach ($key in $htMenu.Keys) {
            if ($key -eq "q") {
                Write-Host "'$key' for: $($htMenu[$key])"
            }
            else {
                if ($searchString -and $htMenu[$key].$Name -notlike "*$searchString*") {
                    #Write-Host "'$key' for: $($htMenu[$key].$Name)"
                }
                else {
                    Write-Host "'$key' for: $($htMenu[$key].$Name)"
                }
            }
        }

        do {
            [string]$choice = Read-Host "Choice"
        } until ($choice -in $htMenu.Keys)

        if ($choice -eq "q") {
            return
        }
        return $htMenu[$choice]
    }
}

#endregion




$scriptPath = Split-Path -Parent ($MyInvocation.MyCommand.Path)

# A list of pre-defined departments
$AllDepartments = @()
Foreach($item in @("Radio","Mobile","Audio")){
    $AllDepartments += [PSCustomObject]@{"Name"=$item}
}



# Prompt for values
Write-Host "Please choose a department for the shared lab user.`n"
$Department = (Write-Menu -Items $AllDepartments -Name Name).Name
$ComputerName = Read-Host -Prompt "Provide the lab Computer Name"
$PurchaserMail = Read-Host -Prompt "Provide the Email address of the Authorized Purchased"
$TicketNr = Read-Host -Prompt "Provide the ticket number from Topdesk"



# Set static variables
$RootOU = "OU=Shared Lab,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local"
$UserOU = "OU=Users,$RootOU"
$AdmUserOU = "OU=Admin Users,$RootOU"
$ComputerOU = "OU=Computers,$RootOU"
$GroupOU = "OU=Groups,$RootOU "
$ComputerDN = "CN=$ComputerName,$ComputerOU"



$UserPass = (ConvertTo-SecureString -AsPlainText "Hallon20!" -Force)
$AdmUserPass = (ConvertTo-SecureString -AsPlainText "Hallon20!" -Force)




# Get AD info
$ComputerObject = Get-ADComputer $ComputerName -Properties DistinguishedName
$PurchaserObject = Get-ADUser -Filter "EmailAddress -like '$PurchaserMail'"


# Check if computer exist in AD
if (!$ComputerObject) {
    Write-Warning "The lab Computer $ComputerName was not found in AD"
    Break
}else {
    Write-Output "The lab computer name $ComputerName has been verified"
}

if (!$PurchaserObject) {
    Write-Warning "The Authorized Purchaser $PurchasedMail does not exist"
    Break
}else {
    Write-Output "The authorized purchaser $PurchaserMail has been verified"
}


# Check username number and find an available number
[Int32]$i = 0
do{
    $i++
    $nr = '{0:00}' -f $i
    $UserName = "Labb-" + $Department + $nr
    $AdmUserName = "Adm-Labb-" + $Department + $nr
    
    $CheckUserName = Get-ADUser -Filter "SamAccountName -like '$UserName'"

    if(!$CheckUserName){

        $CheckAdmUserName = Get-ADUser -Filter "SamAccountName -like '$AdmUserName'"

        if(!$CheckAdmUserName){
            Write-Output "The Account name $UserName has been verified"
            $Valid = $true
        }else {
            Write-Warning "The username for admin account $AdmUserName is already in use."
            Write-Output "Adding number and trying again"
        }
    }else {
        Write-Warning "The username $UserName is already in use."
        Write-Output "Adding number and trying again"
    }

}Until($Valid)






# Set static variables
$SharePath = "\\<SERVER>\temp\$UserName" # Ej bestämt än
$LLGroupName = "SG-LL-$UserName" # LL stands for Local Logon
$LAGroupName = "SG-LA-$UserName" # LA stands for Local Admin
$GPOName = "C - SC Shared Lab $UserName"
$GPOComment = $TicketNr
$GPOGUID = "{BC4B4E04-1116-4ECA-B783-67E6EA287AB3}"
$GPOBackupPath = "$scriptPath\$GPOGUID"


# Get AD Info
$LLGroupObject = Get-ADGroup -Filter "Name -like '$LLGroupName'"
$LAGroupObject = Get-ADGroup -Filter "Name -like '$LAGroupName'"


# Verify Groups and Pruchaser
if($LLGroupObject){
    Write-Warning "The $LLGroupName group already exist"
    Break
} elseif ($LAGroupObject) {
    Write-Warning "The $LAGroupName group already exist"
    Break
} else {
    Write-Output "Groups has been successfully verified"
}





# Create new user
$NewUserObject = New-ADUser -Name $UserName -UserPrincipalName "$UserName@sigma.local" -SamAccountName $UserName -Description "Shared lab account for $ComputerName - $TicketNr" -Company "Sigma Connectivity" -Department $Department -Path $UserOU -AccountPassword $UserPass -Enabled $true -PassThru


# Create new admin user
$NewAdmUserObject = New-ADUser -Name $AdmUserName -UserPrincipalName "$AdmUserName@sigma.local" -SamAccountName $AdmUserName -Description "Shared lab Admin account for $ComputerName - $TicketNr" -Company "Sigma Connectivity" -Department $Department -Path $AdmUserOU -AccountPassword $AdmUserPass -Enabled $true -PassThru


# Move computer to correct OU
if ($ComputerObject.DistinguishedName -notlike $ComputerDN) {
    $ComputerObject | Move-ADObject -TargetPath $ComputerOU
}else {
    Write-Output "The computer is already in correct OU"
}


# Create new share folder
New-Item -Path $SharePath -ItemType Directory -Force

# Grant modify permission to new accounts - ska man ha med gruppen som modify eller kontot?
$acl = Get-Acl $SharePath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SIGMA\$UserName", "Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $SharePath


$acl = Get-Acl $SharePath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SIGMA\$AdmUserName", "Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $SharePath



# Create new AD Group
$NewLLGroupObject = New-ADGroup -Name $LLGroupName -Description "Shared Lab Group that grants Local Logon permission for the computer $ComputerName - $TicketNr" -GroupCategory Security -GroupScope Global -Path $GroupOU -PassThru
$NewLAGroupObject = New-ADGroup -Name $LAGroupName -Description "Shared Lab Group that grants Local Admin permission for the computer $ComputerName - $TicketNr" -GroupCategory Security -GroupScope Global -Path $GroupOU -PassThru

# Add user to group
$NewLLGroupObject | Add-ADGroupMember -Members $NewUserObject.SAMAccountName

# Set GPO Settings
$xml = [xml](Get-Content -Path "$GPOBackupPath\gpreport.xml")
$xml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment.Member.SID.childnodes.Item(1).value = $NewLLGroupObject.SID
$xml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment.Member.Name.childnodes.Item(1).value = "${env:USERDOMAIN}\$($NewLLGroupObject.Name)"
$xml.gpo.computer.ExtensionData.Extension.RestrictedGroups.ChildNodes.ChildNodes.ChildNodes.Item(7).Value = $NewLAGroupObject.SID
$xml.gpo.computer.ExtensionData.Extension.RestrictedGroups.ChildNodes.ChildNodes.ChildNodes.Item(8).Value = "${env:USERDOMAIN}\$($NewLAGroupObject.Name)"
$xml.Save("$GPOBackupPath\gpreport.xml")

$ConfFile = "$GPOBackupPath\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
$ConfText = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = Administrator,*S-1-5-21-2500833851-3511497465-3171418345-512,*S-1-5-21-2500833851-3511497465-3171418345-13156,*$($NewLAGroupObject.SID)
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*$($NewLLGroupObject.SID)
"@

Set-Content -Path $ConfFile -Value $ConfText -Force

# Import GPO
$NewGPOObject = Import-GPO -BackupId $GPOGUID -Path $scriptPath -TargetName $GPOName -CreateIfNeeded

# Set correct GPO Delegation  
Set-GPPermission -Name $GPOName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GPORead -Replace
Set-GPPermission -Name $GPOName -TargetName $ComputerName -TargetType Computer -PermissionLevel GPORead
Set-GPPermission -Name $GPOName -TargetName $ComputerName -TargetType Computer -PermissionLevel GPOApply

# Link GPO to OU
$NewGPOObject | New-GPLink -Target $ComputerOU -LinkEnabled Yes



<# # Parameters for sending mail to the Authorized Purchaser.
$MailProps=@{
    From        =   "Support@rts.se"
    To          =   $PurchaserObject.EmailAddress
    SmtpServer  =   "smtp.net.sigma.se"
    Encoding    =   "UTF8"
    Port        =   "25"
    Subject     =   ""
    Body        =   "Hej $($PurchaserObject.givenName),

Nu har det beställda kontot `"$UserName`" blivit skapat.

Med vänlig hälsning,
Real Time Services Cloud Support
"
}


# Parameters for sending mobile text message to the Authorized Purchaser with the account password.
$MobileNr = (((($PurchaserObject.mobile`
            -replace '^0','+46')`
            -replace '\s')`
            -replace '-')`
            -replace '\(')`
            -replace '\)'


$SMSProps = @{
    From        =   "Support@sigma.se"
    To          =   "$MobileNr@qlnk.se"
    SmtpServer  =   "smtp.net.sigma.se"
    Encoding    =   [System.Text.Encoding]::UTF8
    Port        =   "25"
    Subject     =   " "
    Body        =   "Hej $($PurchaserObject.givenName),

Nedan har du lösenordet till det nya labbkontot.

$UserPass

Med vänlig hälsning,
Real Time Services Cloud Support
"
}


# Skicka mail och SMS
Send-MailMessage @MailProps
Send-MailMessage @SMSProps #>