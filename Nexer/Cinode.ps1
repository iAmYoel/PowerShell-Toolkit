<#


    Cinode script
    checks AD for extensionattributes containing specific CU names and comparing them against groups in Azure AD. 
    Creates unique new groups and assigns them to the app Cinode.

    The script runs with a certificate called CinodePwshAutomation (password in passwordstate)


    cert installed on SS0281 Cert:\localmachine\my (exportable)
    c:\Scripts\Cinode\CinodePwshAutomation.pfx

    Created by: 
        Frederik Zita
        Robert Amartinesei

    2021-06-11


#>
#Extensionattribute 8 = Från hr4sigma som är CU-namnet
#CU namnet skall skapa dynamiska grupper i AzureAD



#$logpath = "$env:userprofile\desktop\logfile.txt"
$logpath = "C:\Scripts\Cinode\logfile.txt"
$maillog = @()
#region helperfunction

    Function Write-Log {
    
        param (
            [validateset('Information','Error','Warning')]
            $entrytype,

            $message

            

        )

            if ($entrytype -like "Error") {
                $ErrorExist = $true
            }

            $logfile = $logpath
            "$(get-date -Format 'yyy-MM-dd HH:mm:ss') | $entrytype | $message" | Out-File $logfile -Encoding utf8 -Append
    
    }


#endregion

#region Variables

#mail settings for mailing log
$smtpserver = "smtprelay.net.sigma.se"
$mailfrom = "Cinode <noreply@nexergroup.com>"
$mailto = "rtsc.monitor-sd@rts.se"
$Subject = "NEXER - Cinode Integration - Error Log for Dynamic Cinode Groups"
$maillog += "Contact: Martin Lundgren - martin.lundgren@rts.se"

#Cinode Enterprise application
$EnterpriseApp = "Cinode"
$EnterpriseAppRole = "User"


$Allusers = Get-ADUser -filter 'enabled -eq $true' -SearchBase "OU=SigmaGroup,DC=sigma,DC=local" -Properties extensionattribute5, extensionattribute8, extensionattribute6, extensionattribute7
$CUProperty = "Extensionattribute8"


$EmptyCU = $UniqueCU | Where-Object -FilterScript {$_.name -eq ""} #saves a variable with empty CU's. Otherwise not used
$UniqueCU = $Allusers | where{$_.extensionattribute5 -eq "YES"} | Group-Object -Property $CUProperty #Gets all unique values from $CuProperty


$AADGroupPrefix = "CU " #prefix for AzureAD Groups created from AD

Write-Log -entrytype Information -message "Starting Script...."
$maillog += "Starting Script...."

#endregion 

#region Connect AzureAD

#    Connect-AzureAD -Credential $AADCreds
Connect-AzureAD -TenantId "f82b0fb7-0101-410d-8e87-0efa7c1d3978" -ApplicationId "f0c4232f-536f-4e90-80e2-18c5309f5e36" -CertificateThumbprint "317FC7A50CDBFF513A5FB13B8A2C48904806D54F"

#endregion

#region Compare Groups to CU's

    #Getting all dynamic groups
    $AADDynamicGroups = Get-AzureADMSGroup -All $true | Where-Object -FilterScript {($_.grouptypes -eq 'DynamicMembership') -and ($_.DisplayName -match '^CU ')}

    #Compare to find groups only in AD and only in Azure AD
    $compareGroupNames = Compare-Object -ReferenceObject $UniqueCU.name.trim() -DifferenceObject ($AADDynamicGroups.displayname -replace '^CU\s') -IncludeEqual #| Where-Object -FilterScript {$_.sideindicator -eq '='}
    $CUOnlyinAD = ($compareGroupNames | Where-Object -FilterScript {$_.sideindicator -eq '<=' -and $_.inputobject -gt ""} | sort inputobject)
    $CUOnlyinAzureAD = ($compareGroupNames | Where-Object {$_.sideindicator -eq '=>'} | sort inputobject)
    
    #if $CUOnlyinAzureAD contains items then loop through and remove the groups from Azure AD
    if ($CUOnlyinAzureAD) {
    
        foreach ($item in $CUOnlyinAzureAD) {
            
            Clear-Variable ItemObject,GroupMembership -ErrorAction SilentlyContinue

            $ItemObject = $AADDynamicGroups | where{$_.DisplayName -like "CU $($item.inputobject)"}

            IF(($ItemObject | measure).Count -gt 1){
                Write-Log -entrytype Error -message "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. More than one group was found with the same name."
                $maillog += "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. More than one group was found with the same name."
            }ELSEIF(($ItemObject | measure).Count -lt 1){
                Write-Log -entrytype Error -message "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. Could not find object from Azure AD group list."
                $maillog += "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. Could not find object from Azure AD group list."
            }ELSE{
                Try{  
                    $GroupMembership = Get-AzureADGroupMember -ObjectId $ItemObject.Id -ErrorAction Stop

                    IF(($GroupMembership | measure).Count -lt 1){
                        Try{
                            Remove-AzureADMSGroup -Id $ItemObject.Id -ErrorAction Stop

                            Write-Log -entrytype Information -message "`"$($item.inputobject)`" -- Automatically removed from Azure AD. The group has no user assignment."
                            $maillog += "`"$($item.inputobject)`" -- Automatically removed from Azure AD. The group has no user assignment."
                        }Catch [System.Exception]{
                            Write-Log -entrytype Information -message "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. An error occurred while trying to remove group. Error message: $($_.Exception.Message)"
                            $maillog += "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. An error occurred while trying to remove group. Error message: $($_.Exception.Message)"
                        }
                    }ELSE{
                        Write-Log -entrytype Error -message "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. Group still have members."
                        $maillog += "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. Group still have members."
                    }
                }Catch{
                    Write-Log -entrytype Error -message "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. Could not get group membership for verification. Error message: $($_.Exception.Message)"
                    $maillog += "`"$($item.inputobject)`" -- Attempt to remove group from Azure AD failed. Could not get group membership for verification. Error message: $($_.Exception.Message)"
                }
            }
        }
    }


    #if $CUOnlyinAD contains items then loop through and do stuff
    if ($CUOnlyinAD) {

        Write-Log -entrytype Information -message "Found $(($CUOnlyinAD | Measure-Object).Count) number of group in AD not existing in AAD"
        $maillog += "Found $(($CUOnlyinAD | Measure-Object).Count) number of group in AD not existing in AAD"

        #Looping through each unique group in $CUOnlyinAD
        foreach ($Group in $CUOnlyinAD.inputobject) {

            ################################
            $AzureADGroupName = $AADGroupPrefix + $Group
            
            #Try catch block to capture any errors upon creating group in Azure AD and log it

            #Get first user from each group (extensionattribute8) to store extensionattributes for the membershiprule
            $extAttributes = $UniqueCU[$UniqueCU.Name.IndexOf($Group)].Group[0] | Select-Object ExtensionAttribute*

            $MembershipRule = "(user.extensionAttribute5 -EQ ""$($extAttributes.extensionAttribute5)"" -and user.extensionAttribute8 -EQ ""$($extAttributes.extensionAttribute8)"")"
            #user.extensionAttribute6 -EQ ""443""

            Write-Log -entrytype Information -message "this is the rule: $MembershipRule"
            $maillog += "this is the rule: $MembershipRule"

            try {
                $ErrorActionPreference = "stop"

                
                #actually trying to create group
                $NewAzureADMSGroup = New-AzureADMSGroup -DisplayName "$AzureADGroupName" `
                                                -Description "Dynamic Group for Cinode" `
                                                -MailEnabled $False `
                                                -MailNickName "$($AzureADGroupName -replace '\s')" `
                                                -SecurityEnabled $True `
                                                -GroupTypes "DynamicMembership" `
                                                -MembershipRule $MembershipRule `
                                                -MembershipRuleProcessingState "On" `
                                                -Verbose

                Write-Host -ForegroundColor Green -BackgroundColor black -Object "Created Group `"$group`" in AzureAD with newname $AzureADGroupName"

                write-log -entrytype Information -message "Created Group `"$group`" in AzureAD with newname $AzureADGroupName"
                $maillog += "Created Group `"$group`" in AzureAD with newname $AzureADGroupName"
                
                $ErrorActionPreference = "Continue"
                

            }catch {
                
                $myerror = $error[0] #just another placeholder for the most recent error
                Write-Log -entrytype Error -message "Could not create `"$group`" in AzureAD with newname $AzureADGroupName | $($myerror.exception.message)"
                $maillog += "Could not create `"$group`" in AzureAD with newname $AzureADGroupName | $($myerror.exception.message)"

                Continue #continue loop

            }


            $ADMSgroup = $null #reset before next admsgroup loop
            $starttime = (get-date)
            do {
                
            $ADMSgroup = Get-AzureADGroup -ObjectId $NewAzureADMSGroup.Id -ErrorAction SilentlyContinue
            sleep 30
            write-host -ForegroundColor green -BackgroundColor Black -Object "Still trying... seconds passed: $(((get-date)-$starttime).Totalseconds)"
                
            }until (($ADMSgroup -gt $null) -or ((get-date) -gt $starttime.AddMinutes(3)))

            if ($ADMSgroup) {

                #Trying to add user assigment for newly created group in Enterprise applications
                Try {
                    $ErrorActionPreference = "stop"
                    #Start-Sleep -Seconds 30 #Allow group to replicate in AzureAD before assigning permissions
                    # Assign the values to the variables
                    $groupname = $NewAzureADMSGroup.id
                    $app_name = $EnterpriseApp
                    $app_role_name = $EnterpriseAppRole

                    # Get the user to assign, and the service principal for the app to assign to
                
                    $sp = Get-AzureADServicePrincipal -Filter "displayName eq '$app_name'"
                    $appRole = $sp.AppRoles | Where-Object { $_.DisplayName -eq $app_role_name }

                    # Assign the user to the app role
                    New-AzureADGroupAppRoleAssignment -ObjectId $ADMSgroup.ObjectId -PrincipalId $ADMSgroup.ObjectId -ResourceId $sp.ObjectId -Id $appRole.Id

                    $ErrorActionPreference = "Continue"

                    #break
                }Catch {
                    Write-Log -entrytype Error -message $error[0].exception.message
                    $maillog += $error[0].exception.message
                }

            }else {
                Write-Log -entrytype Error -message "Could not find group: $AzureADGroupName - id: $($NewAzureADMSGroup.id)"
                $maillog += "Could not find group: $AzureADGroupName - id: $($NewAzureADMSGroup.id)"
            }





            ################################

        }

    }else {
        Write-Log -entrytype Information -message "There are no unique groups from AD"
        $maillog += "There are no unique groups from AD"
    }



    Write-Log -entrytype Information -message "End script"
    $maillog += "End script"

    if ($ErrorExist) {
        Send-MailMessage -SmtpServer $smtpserver -From $mailfrom -to $mailto -Subject $Subject -Body $($maillog | out-string) -Encoding utf8
    }

#endregion
