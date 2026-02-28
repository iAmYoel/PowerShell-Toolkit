#+-----------------------------------------------------------------------------------+
#| = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = |
#|{>/-----------------------------------------------------------------------------\<}|
#|: |                           RDS Permission
#| :|
#|: |   Purpose:
#|: |  			Checks RDS permissions on all servers in current domain
#| :|			and exports the result to CSV files.
#|: |
#| :|                                Date: 2019-04-04
#|: | 					/^(o.o)^\    Version: 7
#| :|                                Author: Yoel Abraham
#|{>/-----------------------------------------------------------------------------\<}|
#| = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = : = |
#+-----------------------------------------------------------------------------------+
cls
Import-Module ActiveDirectory



# The segment below checks if powershell session is elevated, tries to elevate if not. Taken from https://blogs.msdn.microsoft.com/virtual_pc_guy/2010/09/23/a-self-elevating-powershell-script/
######################################################################################################
        # AUTO ELEVATION



# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
   }
else
   {
   # We are not running "as Administrator" - so relaunch as administrator
   
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
   
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
   
   # Exit from the current, unelevated, process
   exit
   }
 
# Run your code that needs to be elevated here
"";Write-Host "`t Powershell session was elevated successfully!" -ForegroundColor Green;""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")



######################################################################################################
        ### FUNCTION




# Function for browsing folder. https://code.adonline.id.au/folder-file-browser-dialogues-powershell/
function Find-Folders {
    [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $browse = New-Object System.Windows.Forms.FolderBrowserDialog
    $browse.RootFolder = [System.Environment+SpecialFolder]'MyComputer'
    $browse.ShowNewFolderButton = $true
    $browse.Description = "Select a directory"

    $loop = $true
    while($loop)
    {
        if ($browse.ShowDialog() -eq "OK")
        {
        $loop = $false
		
		#Insert your script here
		
        } else
        {
            $res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or use a default location?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
            if($res -eq "Cancel")
            {
                #Ends script
                return
            }
        }
    }
    $browse.SelectedPath
    $browse.Dispose()
}




# User get browse where to save csv files
"";Write-Host "Choose a folder to save CSV files in: " -ForegroundColor Yellow -NoNewline
$CSVPath = Find-Folders



# If no folder is chosen, csv will be saved in a default location.
IF([string]::IsNullOrWhiteSpace($CSVPath)){
    
    $CSVPath = "C:\Users\$env:USERNAME\Documents"
    "";"";Write-Host "No folder chosen." -ForegroundColor Yellow
    "";Write-Host "CSV will be saved in default location: " -ForegroundColor Yellow -NoNewline
    $CSVPath;""


}ELSE{
    $CSVPath;""

}





# Asks if user wants the csv file to have tree view style or table view style with server name in every row.
do {
    
    "";Write-Host "Do you want the csv to be in (t)ree view style or table view style with the server name written in (e)very row? [T\E]: " -ForegroundColor Yellow -NoNewline
    $TreeView = Read-Host



    # If 'T' is chosen.
    IF($TreeView -like "t"){
        
        # Set TreeView variable to true
        $TreeView = $true

    }



    # if 'E' is chosen.
    ELSEIF($TreeView -like "e"){
    
        # Set TreeView variable to false
        $TreeView = $false

    }



    # if neither of specifically 'T' or 'E' is inputted.
    Else{

    # Instruct user to answer correctly.
    "";Write-Host "Please answer with the letters 'T' or 'E'."
    
    }

}Until (($TreeView -eq $true) -or ($TreeView -eq $false))



######################################################################################################
        ### FUNCTION






# Get all Windows servers from AD.
$Servers = Get-ADComputer -Filter * -Properties * | where{$_.OperatingSystem -like "*Windows*Server*"} | select -Property name,OperatingSystem


# Function for getting the SID of the RDS users that are allowed to log into the server.
function Get-RDSPermission {

    # Create a temporary file to store user rights policies in
    $tmp = "$env:TEMP\TempUserRights.txt"

    # Savs all the settings in local security policy to a file.
    secedit /export /areas USER_RIGHTS /cfg $tmp | Out-Null

    # Get the content of the saved file into a variable.
    $Value = Get-Content $tmp | where {$_ -like "*SeRemoteInteractiveLogonRight*"}
    
    # Delete the temporary file containing user rights policies
    Remove-Item -Path $tmp -Force

    # Seperate and only get users.
    $Value = $Value -replace (".*\=\s", "")

    # If there are more than one user, split them into an array.
    if ($Value -like "*,*"){
        $Value = $Value.Split(",")
    }

    # Create array of final list of users.
    $NewValue = @()

    # Check if server is a DC
    $OSType = $null
    $DCCheck = $null
    $OSType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    IF ($OSType -like "2"){
        
        # If $OSType is 2, means that the machine is a Domain controller
        $DCCheck = $true

    }ELSE{
            
        # If $OSType is not 2, means that the machine is not a Domain controller. #3 means server. #1 means workstation.
        $DCCheck = $false
    }


    # Goes through every line in array, translates if line is SID, adds every line to the final list array $NewValue. 
    foreach ($ValueSID in $Value){
        # Resets a temp variable
        $TempValue = $null

        # If line has a "*" in it. Which in turn means that the line is a SID.
        IF ($ValueSID -match "\*"){
            
            # Remove the "*" character.
            $TempValue = $ValueSID -replace ("\*", "")

            # Translates the SID to account name. Put in temp variable
            $objSID = New-Object System.Security.Principal.SecurityIdentifier ($TempValue) 
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
            $TempValue = $objUser.Value

        }ELSE{   # If line doesn't have "*" in it. Means that the line has the name already translated.
            
            # Put the already translated name in temp variable.
            $TempValue = $ValueSID

            # Check if machine is DC.
            IF ($DCCheck -eq $true){

                # If machine is a DC, change line to "<DOMAIN>\<USER>
                $TempValue = "$env:USERDOMAIN\$TempValue"

            }ELSE{

                # If machine is NOT a DC, change line to "<SERVER>\<USER>
                $TempValue = "$env:COMPUTERNAME\$TempValue"

            }
        }

        # Add the line to the final list array $NewValue.
        $NewValue += $TempValue
    }

    # Outputs the final list of users with permission.
    $NewValue
}

######################################################################################################
        ### TABLE




# Resets table variable and create table for RDS Permissions
$table = $null
$table = New-Object System.Data.DataTable


# Create columns in table and define them as strings.
$table.Columns.Add("Server","String") | Out-Null
$table.Columns.Add("OS","String") | Out-Null
$table.Columns.Add("UserSAM","String") | Out-Null
$table.Columns.Add("UserDN","String") | Out-Null
$table.Columns.Add("Groups","String") | Out-Null
$table.Columns.Add("GroupMemberSAM","String") | Out-Null
$table.Columns.Add("GroupMemberDN","String") | Out-Null
$table.Columns.Add("SAMInGroupMember","String") | Out-Null
$table.Columns.Add("DNInGroupMember","String") | Out-Null

######################################################################################################
        ### CHECK SERVERS





"";"";"";"";Write-Host "`t Gathering permissions from all Windows Servers in domain..." -ForegroundColor Yellow


# Creating variable indicating first item in a array
$FirstItem = $true

$i = 0

# Check every server in AD for RDS permissions.
foreach ($Srv in $Servers){
    
    $i++

    # Check if server is not the first item in array.
    IF ($FirstItem -eq $false){
        
        # Adds empty lines between servers in table.
        $table.Rows.Add($table.NewRow())
        $table.Rows.Add($table.NewRow())
        $table.Rows.Add($table.NewRow())
    }

    # Changing value of variable to indicate first item is passed.
    $FirstItem = $false

    # Resets variables
    $RDS = $null
    $DCCheck = $null
    
    
    # Check for RDS permission and put SID into variable
    $RDS = Invoke-Command -ComputerName $Srv.Name -ScriptBlock ${Function:Get-RDSPermission} -ErrorAction SilentlyContinue


    # Check if server is a DC
    $DCCheck = Invoke-Command -ComputerName $Srv.Name -ScriptBlock {

        # Check if server is a DC
        $OSType = $null
        $DCCheck = $null
        $OSType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

        IF ($OSType -like "2"){
        
            # If $OSType is 2, means that the machine is a Domain controller
            $DCCheck = $true

        }ELSE{
            
            # If $OSType is not 2, means that the machine is not a Domain controller. #3 means server. #1 means workstation.
            $DCCheck = $false
        }

        $DCCheck

    } -ErrorAction SilentlyContinue
    


    # Puts (Domain Controller) as suffix for domain controllers.
    IF ($DCCheck -eq $true){
        
        # Output Server being checked and its operating system
        "";"";Write-Host "$i."
        Write-Host "Host: $($Srv.Name) (Domain Controller)"
        Write-Host "OS:   $($Srv.OperatingSystem)"

    }ELSE{

        "";"";Write-Host "$i."
        Write-Host "Host: $($Srv.Name)"
        Write-Host "OS:   $($Srv.OperatingSystem)"

    }



    # Reset row variable and create new row.
    $r = $null
    $r = $table.NewRow()
    
    # Insert name of server into the "Server" column and add row to table. Resets row variable afterwards.
    $r.Server = $Srv.Name
    $r.OS = $Srv.OperatingSystem
    $table.Rows.Add($r)
    $r = $null








######

############ Object check begins

######









    # Starts checking each object that have permission in Local Security Policies
    foreach ($ADObject in $RDS){
        

        # Not creating rows for null values
        IF ([string]::IsNullOrWhiteSpace($ADObject)){
        }ELSE{
            
            # Resets variables
            $LocalGroup = $null
            $ADGroup = $null

            # If the object is not a domain object, check in local objects.
            IF ($ADObject -notlike "$env:USERDOMAIN\*"){

                $LocalGroup = Invoke-Command -ComputerName $Srv.Name -ArgumentList $ADObject -ScriptBlock{ param($ADObject);Get-LocalGroup ($ADObject -replace (".*\\", "")) -ErrorAction SilentlyContinue }
            
            }

            # If server is not a DC and object is "Administrators" or "Remote Desktop Users", do not check in AD.
            IF (($DCCheck -eq $false) -and (($ADObject -like "*administrators") -or ($ADObject -like "*Remote Desktop Users"))){
            
                # Will not check group in domain if object is local administrator group or local Remote Desktop Users group.

            }ELSE {   # Checks in AD otherwise.

                # Uses a try and catch to prevent errors being outputted. Erroraction did not work for some reason.
                try{$ADGroup = Get-ADGroup ($ADObject -replace (".*\\", "")) -ErrorAction SilentlyContinue}Catch{}
            
            }





######

############ Local group

######





            # If a local group is found.
            IF ($LocalGroup){

                # Create a new row for the table
                $r = $table.NewRow()


                # If tree view is not chosen
                IF($TreeView -eq $false){

                    # Input servername in new row.
                    $r.Server = $Srv.Name

                }


                # Put object name in the Groups column.
                $r.Groups = "$ADObject - (Local Group)"
                
                # Add the row to the table. Resets row variable afterwards.
                $table.Rows.Add($r)
                $r = $null

                # Resets variable.
                $ObjectInLocalGroup = $null

                # Get local members in group and put into variable.
                $ObjectInLocalGroup = Invoke-Command -ComputerName $Srv.Name -ArgumentList $LocalGroup -ScriptBlock{ param($LocalGroup);Get-LocalGroupMember $LocalGroup -ErrorAction SilentlyContinue }

                # Resets variable.
                $ObjectInGroup = $null




                # Check every local group member 
                foreach ($ObjectInGroup in $ObjectInLocalGroup){
        
                    # Create a new row for the table
                    $r = $table.NewRow()


                    # If tree view is not chosen
                    IF($TreeView -eq $false){

                        # Input servername in new row.
                        $r.Server = $Srv.Name

                    }




                    # If the local group member is a group.
                    IF ($ObjectInGroup.ObjectClass -like "Group"){
                        




                        # If the local group member is a domain group
                        IF ($ObjectInGroup.PrincipalSource -like "ActiveDirectory"){
                            


                            # Put object name in the GroupMemberSAM column and add row. Resets row variable afterwards.
                            $r.GroupMemberSAM = "$($ObjectInGroup.Name) - (Domain Group)"
                            $table.Rows.Add($r)
                            $r = $null

                            # Reset variable.
                            $ObjectMembersInADGroup = $null

                            # Get domain group members from member object.
                            $ObjectMembersInADGroup = Get-ADGroupMember ($ObjectInGroup.name -replace (".*\\", "")) -ErrorAction SilentlyContinue
                            
                            # Resets variable
                            $ObjectMemberInADGroup = $null
                            
                            
                            
                            
                            # Check all domain group members from object
                            foreach ($ObjectMemberInADGroup in $ObjectMembersInADGroup){

                                # Add the row to the table
                                $r = $table.NewRow()

                                # If tree view is not chosen
                                IF($TreeView -eq $false){

                                    # Input servername in new row.
                                    $r.Server = $Srv.Name

                                }
                                

                                # If the domain group member object is a group
                                IF ($ObjectMemberInADGroup.ObjectClass -like "group"){
                                
                                # Put the group name in SAMInGroupMember column.
                                $r.SAMInGroupMember = "$env:USERDOMAIN\$($ObjectMemberInADGroup.SamAccountName) - (Domain Group)"
                                
                                }
                                
                                # If the domain group member object is a user
                                IF ($ObjectMemberInADGroup.ObjectClass -like "user"){

                                # Put the user name in SAMInGroupMember column.
                                $r.SAMInGroupMember = "$env:USERDOMAIN\$($ObjectMemberInADGroup.SamAccountName) - (Domain User)"
                                
                                }

                                # Add row to the table. Resets row variable afterwards.
                                $table.Rows.Add($r)
                                $r = $null

                            }
                        }







                        # If the local group member is another local group.
                        IF ($ObjectInGroup.PrincipalSource -like "Local"){

                            # Put object name in the GroupMemberSAM column and add row. Resets row variable afterwards.
                            $r.GroupMemberSAM = "$($ObjectInGroup.Name) - (Local Group)"
                            $table.Rows.Add($r)
                            $r = $null
                            
                            # Resets variable
                            $ObjectMembersInLocalGroup = $null
                            
                            # Get local group members from object. 
                            $ObjectMembersInLocalGroup = Invoke-Command -ComputerName $Srv.Name -ArgumentList $ObjectInGroup -ScriptBlock{ param($ObjectInGroup);Get-LocalGroupMember ($ObjectInGroup.name -replace (".*\\", "")) -ErrorAction SilentlyContinue }

                            # Resets variable.
                            $ObjectMemberInLocalGroup = $null






                            # Check all local group members from object.
                            foreach ($ObjectMemberInLocalGroup in $ObjectMembersInLocalGroup){
                                    
                                # Create a new row for the table
                                $r = $table.NewRow()


                                # If tree view is not chosen
                                IF($TreeView -eq $false){

                                    # Input servername in new row.
                                    $r.Server = $Srv.Name

                                }


                                # Resets variable.
                                $ObjectMemberInLocalGroup2 = $null

                                # Get local user info.
                                $ObjectMemberInLocalGroup2 = Invoke-Command -ComputerName $Srv.Name -ArgumentList $ObjectMemberInLocalGroup -ScriptBlock{ param($ObjectMemberInLocalGroup);Get-LocalUser ($ObjectMemberInLocalGroup.name -replace (".*\\", "")) -ErrorAction SilentlyContinue }




                                # If user is found.
                                IF ($ObjectMemberInLocalGroup2){
                                    
                                    # Put the user name in the SAMInGroupMember and DNGroupMember columns.
                                    $r.SAMInGroupMember = "$($Srv.Name)\$($ObjectMemberInLocalGroup2.Name) - (Local User)"
                                    $r.DNInGroupMember = "$($ObjectMemberInLocalGroup2.FullName)"




                                }ELSE{   # If no user is found.
                                    
                                    # Check user in active directory.
                                    $ObjectMemberInLocalGroup2 = Get-ADUser ($ObjectMemberInLocalGroup.name -replace (".*\\", ""))

                                    # Put the found user in active directory name in the SAMInGroupMember and DNInGroupMember columns.
                                    $r.SAMInGroupMember = "$env:USERDOMAIN\$($ObjectMemberInLocalGroup2.SamAccountName) - (Domain User)"
                                    $r.DNInGroupMember = "$($ObjectMemberInLocalGroup2.Name)"

                                }
                                


                                # Adds row to the table. Resets row variable afterwards.
                                $table.Rows.Add($r)
                                $r = $null
                            }
                        }
                    
                    
                    
                    
                    
                    


                    }ELSE{   # If the local group member is a user.
                        
                        
                        # If the user is a local user.
                        IF ($ObjectInGroup.Name -like "$($Srv.Name)\*"){
                            
                            # Put the user name in the GroupMemberSAM column.
                            $r.GroupMemberSAM = "$($ObjectInGroup.Name) - (Local User)"

                            # Resets variable.
                            $ObjectInGroupName = $null

                            # Gets local user information.
                            $ObjectInGroupName = Invoke-Command -ComputerName $Srv.Name -ArgumentList $ObjectInGroup -ScriptBlock{ param($ObjectInGroup);Get-LocalUser ($ObjectInGroup.Name -replace (".*\\", "")) }

                            # Puts users name in the GroupMemberDN column.
                            $r.GroupMemberDN = "$($ObjectInGroupName.FullName)"

                        }




                        # If the user is a domain user.
                        IF ($ObjectInGroup.Name -like "$env:USERDOMAIN\*"){
                            
                            # Puts the users name in the GroupMemberSAM column.
                            $r.GroupMemberSAM = "$($ObjectInGroup.Name) - (Domain User)"

                            # Resets variable
                            $ObjectInGroupName = $null

                            # Get domain user information.
                            $ObjectInGroupName = Get-ADUser ($ObjectInGroup.Name -replace (".*\\", ""))
                            
                            # Puts users name in the GroupMemberDN column.
                            $r.GroupMemberDN = "$($ObjectInGroupName.Name)"

                        }



                        # Adds row to the table. Resets row variable afterwards.
                        $table.Rows.Add($r)
                        $r = $null



                    }
                }
            }

            









######

############ AD Group

######










            # If AD group is found.
            IF ($ADGroup){

                # Create a new row for the table
                $r = $table.NewRow()


                # If tree view is not chosen
                IF($TreeView -eq $false){

                    # Input servername in new row.
                    $r.Server = $Srv.Name

                }


                # If SID is a group, add the group to the row under the column "Groups" and add group to AllGroups array created earlier.
                $r.Groups = "$env:USERDOMAIN\$($ADGroup.Name) - (Domain Group)"
                
                # Add the row to the table. Resets row variable afterwards.
                $table.Rows.Add($r)
                $r = $null

                # Resets variable.
                $ObjectInDomainGroup = $null

                # Get members in group
                $ObjectInDomainGroup = Get-ADGroupMember $ADGroup -ErrorAction SilentlyContinue

                # Resets variable.
                $ObjectInGroup = $null






                # Check every member from group.
                foreach ($ObjectInGroup in $ObjectInDomainGroup){
        
                    # Creates a new row to the table.
                    $r = $table.NewRow()


                    # If tree view is not chosen
                    IF($TreeView -eq $false){

                        # Input servername in new row.
                        $r.Server = $Srv.Name

                    }





                    # If group member is a group.
                    IF ($ObjectInGroup.ObjectClass -like "group"){
                        
                        # Puts group name in GroupMemberSAM column. Adds row to the table. Resets row variable afterwards.
                        $r.GroupMemberSAM = "$env:USERDOMAIN\$($ObjectInGroup.SamAccountName) - (Domain Group)"
                        $table.Rows.Add($r)
                        $r = $null

                        # Resets variable.
                        $ObjectMembersInADGroup = $null

                        # Gets group member from member object.
                        $ObjectMembersInADGroup = Get-ADGroupMember $ObjectInGroup.SamAccountName -ErrorAction SilentlyContinue
                        
                        # Resets variable.
                        $ObjectMemberInADGroup = $null
                        






                        # Check every group member from group object.
                        foreach ($ObjectMemberInADGroup in $ObjectMembersInADGroup){
                                    
                            # Add the row to the table
                            $r = $table.NewRow()


                            # If tree view is not chosen
                            IF($TreeView -eq $false){

                                # Input servername in new row.
                                $r.Server = $Srv.Name

                            }




                            IF ($ObjectMembersInADGroup.objectClass -like "user"){
                                
                                $r.SAMInGroupMember = "$env:USERDOMAIN\$($ObjectMemberInADGroup.SamAccountName) - (Domain User)"
                                $r.DNInGroupMember = "$($ObjectMemberInADGroup.Name)"

                            }ELSE{   # If the member object is a group
                                
                                # Puts the group name in the SAMInGroupMember column.
                                $r.SAMInGroupMember = "$env:USERDOMAIN\$($ObjectMemberInADGroup.SamAccountName) - (Domain Group)"

                            }



                            # Adds row to the table. Resets row variable afterwards.
                            $table.Rows.Add($r)
                            $r = $null



                        }
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    }ELSE{   # if group member is a user.
                        
                        # Puts the users name in the GroupMemberSAM and GroupMemberDN columns.
                        $r.GroupMemberSAM = "$env:USERDOMAIN\$($ObjectInGroup.SamAccountName) - (Domain User)"
                        $r.GroupMemberDN = "$($ObjectInGroup.Name)"


                        # Adds row to the table. Resets row variable afterwards.
                        $table.Rows.Add($r)
                        $r = $null



                        
                    }
                }
            }








######

############ Neither local group or AD group was found, treats as User.

######







            # If RDS Access object is neither a local group or AD group, treat as user.
            IF (([string]::IsNullOrWhiteSpace($LocalGroup)) -and ([string]::IsNullOrWhiteSpace($ADGroup))){

                # Create a new row for the table
                $r = $table.NewRow()


                # If tree view is not chosen
                IF($TreeView -eq $false){

                    # Input servername in new row.
                    $r.Server = $Srv.Name

                }




                # If the user is a local user
                IF ($ADObject -like "$($Srv.Name)\*"){
                    
                    # Resets variable
                    $ObjectUserName = $null

                    # Gets local user information.
                    $ObjectUserName = Invoke-Command -ComputerName $Srv.Name -ArgumentList $ADObject -ScriptBlock{ param($ADObject);Get-LocalUser ($ADObject -replace (".*\\", "")) }


                    # Puts user name in the UserDN and UserSAM columns.
                    $r.UserDN = $ObjectUserName.FullName
                    $r.UserSAM = "$env:COMPUTERNAME\$($ObjectUserName.Name)"

                }




                # ElseIf user is a domain user.
                ELSEIF ($ADObject -like "$env:USERDOMAIN\*"){

                    # Resets variable
                    $ObjectUserName = $null

                    # Gets AD user information. 
                    $ObjectUserName = Get-ADUser ($ADObject -replace (".*\\", ""))
                    

                    # Puts user name in the UserDN and UserSAM columns.
                    $r.UserDN = $ObjectUserName.Name
                    $r.UserSAM = "$env:USERDOMAIN\$($ObjectUserName.SamAccountName)"

                }





                # Add the row to the table. Resets row variable afterwards.
                $table.Rows.Add($r)
                $r = $null

            }
        }
    }
}


######################################################################################################
        ### CSV EXPORT


"";"";"";Write-Host "`t Done gathering permissions from $($Servers.Count) servers!" -ForegroundColor Yellow


# Name of CSV files.
$RDSFile = "RDS_Permissions"
$GroupFile = "Group_Members"


# Export table to a csv file.
$table | Export-Csv -Path "$CSVPath\$RDSFile.csv" -NoTypeInformation -Encoding UTF8 -Force
Set-Content -Path "$CSVPath\$RDSFile.csv" -Value ((Get-Content "$CSVPath\$RDSFile.csv") -replace ("\,", ";")) -Force


"";Write-Host "`t Result exported to file!" -ForegroundColor Yellow;""
Pause