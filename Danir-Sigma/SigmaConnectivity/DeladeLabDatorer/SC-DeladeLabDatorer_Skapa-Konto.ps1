# A list of pre-defined departments
$AllDepartments = @("Radio","test")


# Prompt for values
$ComputerName = Read-Host -Prompt "Provide the lab Computer Name"
$PurchaserMail = Read-Host -Prompt "Provide the Email address of the Authorized Purchased"
$TicketNr = Read-Host -Prompt "Provide the ticket number from Topdesk"
$Department = $AllDepartments | Out-GridView -PassThru


# Set static variables
$RootOU = "OU=Shared Lab,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local"
$UserOU = "OU=Users,$RootOU"
$AdmUserOU = "OU=Admin Users,$RootOU"
$ComputerOU = "OU=Computers,$RootOU"
$GroupOU = "OU=Groups,$RootOU "
$SharePath = "\\<SERVER>\test\$UserName" # Ej bestämt än
$ComputerDN = "CN=$ComputerName,$ComputerOU"
$LLGroupName = "SG-LL-$UserName" # LL stands for Local Logon
$LAGroupName = "SG-LA-$UserName" # LA stands for Local Admin
$GPOName = "C - SC Shared Lab $UserName"
$GPOComment = "$TicketNr"

$UserPass = 
$AdmUserPass =


# Get AD info
$ComputerObject = Get-ADComputer $ComputerName -Properties DistinguishedName
$PurchaserObject = Get-ADUser -Filter "EmailAddress -like '$PurchaserMail'"
$LLGroupObject = Get-ADGroup $LLGroupName
$LAGroupObject = Get-ADGroup $LAGroupName


# Check if computer exist in AD
if (!$ComputerObject) {
    Write-Warning "The lab Computer $ComputerName was not found in AD"
    Break
}else {
    Write-Output "The lab computer name $ComputerName has been verified"
}


# Check username number and find an available number
[Int32]$i = 0
do{
    $i++
    $nr = '{0:00}' -f $i
    $UserName = "Labb-" + $Department + $nr
    $AdmUserName = "Adm-Labb-" + $Department + $nr
    
    if(!(Get-ADUser $UserName)){
        if(Get-ADUser $AdmUserName){
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


# Verify Groups and Pruchaser
if($LLGroupObject){
    Write-Warning "The $LLGroupName group already exist"
    Break
} elseif ($LAGroupObject) {
    Write-Warning "The $LAGroupName group already exist"
    Break
} elseif (!$PurchaserObject) {
    Write-Warning "The Authorized Purchaser $PurchasedMail does not exist"
    Break
} else {
    Write-Output "Input successfully verified"
}





# Create new user
$NewUserObject = New-ADUser -Name $UserName -UserPrincipalName "$UserName@sigma.local" -SamAccountName $UserName -Description "Shared lab account for $ComputerName - $TicketNr" -Company "Sigma Connectivity" -Path $UserOU -AccountPassword $UserPass -Enabled $true -PassThru


# Create new admin user
$NewAdmUserObject = New-ADUser -Name $AdmUserName -UserPrincipalName "$AdmUserName@sigma.local" -SamAccountName $AdmUserName -Description "Shared lab Admin account for $ComputerName - $TicketNr" -Company "Sigma Connectivity" -Path $AdmUserOU -AccountPassword $AdmUserPass -Enabled $true -PassThru


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
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SIGMA\$UserName","Modify","Allow")
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SIGMA\$AdmUserName","Modify","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $SharePath


# Create new AD Group
$NewLLGroupObject = New-ADGroup -Name $LLGroupName -Description "Shared Lab Group that grants Local Logon permission for the computer $ComputerName - $TicketNr" -GroupCategory Security -GroupScope Global -Path $GroupOU -PassThru
$NewLAGroupObject = New-ADGroup -Name $LAGroupName -Description "Shared Lab Group that grants Local Admin permission for the computer $ComputerName - $TicketNr" -GroupCategory Security -GroupScope Global -Path $GroupOU -PassThru

# Add user to group
$NewLLGroupObject | Add-ADGroupMember -Members $NewUserObject.SAMAccountName

# Create and link empty GPO to OU
New-GPO -Name $GPOName -Comment $GPOComment | New-GPLink -Target $ComputerOU -LinkEnabled Yes

# Set correct GPO Delegation  
Set-GPPermission -Name $GPOName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GPORead -Replace
Set-GPPermission -Name $GPOName -TargetName $ComputerName -TargetType Computer -PermissionLevel GPORead
Set-GPPermission -Name $GPOName -TargetName $ComputerName -TargetType Computer -PermissionLevel GPOApply


# GPO Settings to be set manually
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Allow log on locally
# $NewLLGroupObject, Administrators

# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Allow log on through Terminal Services
# $NewLLGroupObject, Administrators

# Computer Configuration > Policies > Windows Settings > Security Settings > Restricted Groups
# Group - Administrators
# Members - $NewLAGroupObject, SIGMA\la-AllServers, SIGMA\Domain Admins, Administrator
# Group - Users
# Members - SIGMA\Domain Users


# Parameters for sending mail to the Authorized Purchaser.
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
Send-MailMessage @SMSProps