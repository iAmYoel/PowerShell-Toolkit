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
            Write-Host "Ok, quit"
            Pause
            Exit 1
        }
        return $htMenu[$choice]
    }
}


Function Test-Question {
    Param
    (
        [Parameter(Mandatory = $false)]$Hash,
        [Parameter(Mandatory = $True)][String]$String
    )
    BEGIN {
        Clear-Host
        foreach ($i in $Hash.keys) {
            Write-Output "$i : $($Hash.$i)"
        }
    }

    PROCESS {
        while ($true) {
            if ($Var -eq "Q") {
                break
            }
            elseif ($Var -eq "D") {
                break
            }
            else {
                $Var = (Read-Host "`n $String - (Q)uit or (D)eploy").ToUpper()
            }
        }
    }
    END {
        if ($Var -eq "Q") {
            Write-Host "Ok, quit"
            Pause
            Exit 2
        }
    }
}


function Get-EmptyName {
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline)][string]$Question
    )
    while (!($answer)) {
        $answer = Read-Host -Prompt $Question
    }
    return $answer
}


function Get-Question {
    [CmdletBinding()]
    param (
        #[parameter(Mandatory = $true)][string]$Input,
        [parameter(Mandatory = $false)][string]$Answer1 = 'Y',
        [parameter(Mandatory = $false)][String]$Answer2 = 'N',
        [parameter(Mandatory = $true)][String]$Question
    )
    begin {}
    process {
        while (($Test -ne $Answer1) -and ($Test -ne $Answer2)) {
            $Test = (Read-Host -Prompt $Question).ToUpper()
        }
    }
    end {
        if($Test -eq 'Y'){
            $Test = $true
        }elseif($Test -eq 'N'){
            $Test = $false
        }
        return $Test
    }
}


function Connect-Azure {

    try {
        $Session = Connect-AzAccount -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to connect to Azure: $($_.exception)" -ForegroundColor Red -BackgroundColor Black
        Exit 3
    }


    if ($Session){

        Write-Host "`nCurrent context:" -ForegroundColor Yellow
        #Get-AzContext | select Account,@{n='SubscriptionName';e={$_.Subscription.Name}},@{n='SubscriptionId';e={$_.Subscription.Id}},Tenant | fl
        $Context = $Session.Context | select account,@{n='subscriptionName';e={$_.Subscription.Name}},@{n='subscriptionId';e={$_.Subscription.Id}},tenant
        $Context | fl

        $ChangeContext = Get-Question -Question "Change subscription? [Y/N]"

        if ($ChangeContext){
            Write-Host "Choose a new subscription:"
            $NewSub = Write-Menu -Items (Get-AzSubscription) -Name Name

            try{
                Write-Host "`nNew context:" -ForegroundColor Yellow
                $Context = Set-AzContext -SubscriptionObject $NewSub -Force -ErrorAction Stop | select account,@{n='subscriptionName';e={$_.Subscription.Name}},@{n='subscriptionId';e={$_.Subscription.Id}},tenant
                $Context | fl
            }catch{
                Write-Host "Failed to set Azure context: $($_.exception)" -ForegroundColor Red -BackgroundColor Black
                Exit 5
            }
        }

        $Context.psobject.properties | Foreach { $ContextHash[$_.Name] = $_.Value }

    }else{
        Exit 6
    }
}


function Check-Permission {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)][string[]]$Roles
    )

    $Permissions = Get-AzRoleAssignment -SignInName $Session.Context.Account -ResourceGroupName $mainHash.resourceGroup

    foreach ($i in $Roles){
        if ($i -in $Permissions.RoleDefinitionName){
            $Check = $true
        }
    }

    if (!$Check){
        Write-Warning "You may not have the necessary permissions to deploy resource in this resource group."
        Write-Host "Current roles assigned: $($Permissions.RoleDefinitionName -join ', ')"
        Pause
    }

}

#endregion functions

#region set variables
New-Variable -Name Context -Option AllScope
New-Variable -Name ContextHash -Option AllScope
$ContextHash    = @{}
$mainHash       = @{}
$deployHash     = @{}
#$nsgHash        = @{}
#endregion

#region connect to Azure and set context

Write-Host "`t Connecting to Azure... `n" -ForegroundColor Yellow

Connect-Azure

Write-Host "Please choose a resource group from subscription: "
$mainHash.resourceGroup     = (Write-Menu -Items (Get-AzResourceGroup) -Name ResourceGroupName).ResourceGroupName
Check-Permission -Roles 'Owner', 'Contributor'
Clear-Host

#endregion

#region input
Write-Host "`t Set deploy parameters... `n" -ForegroundColor Yellow

$deployHash.vnetName          = Get-EmptyName -Question "Please enter a resource name for the new virtual network"
$deployHash.vnetPrefixAddress = Get-EmptyName -Question "Please enter an IP address prefix for the new virtual network (i.e 10.0.0.0/16)"
$deployHash.snetName          = Get-EmptyName -Question "Please enter a name for the new subnet"
$deployHash.snetPrefixAddress = Get-EmptyName -Question "Please enter an IP address prefix for the new subnet (i.e 10.0.10.0/24)"
$deployHash.deployNSG         = Get-Question -Question "Create and connect an new Network Security Group to subnet? [Y/N]"
if ($deployHash.deployNSG -eq "Y"){ $deployHash.nsgName = Get-EmptyName -Question "Please enter a name for the new Network Security Group" }


$AllHash = @($ContextHash,$mainHash,$deployHash)

Test-Question -Hash $AllHash -String "`nIs this Correct?"

#endregion

#region Deploy
Write-Host "`n`t Deploying... `n" -ForegroundColor Yellow
<#
if ($mainHash.DeployNSG -eq "Y"){
    $nsgDeployment = New-AzResourceGroupDeployment -Name "Biecp-NetworkSecurityGroup-Deployment-$(Get-Date -Format yyyyMMddHHmm)" -ResourceGroupName $mainHash.resourceGroup -Mode Incremental -TemplateFile $scriptpath\..\Bicep\nsg.bicep -TemplateParameterObject $nsgHash

    if ($nsgDeployment.ProvisioningState -notmatch "Succeeded"){
        Throw "An error occurred while deploying the Network Security Group. Breaking script."
        Pause
        Exit 7
    }
}
 #>
$Deployment = New-AzResourceGroupDeployment -Name "Bicep-VirtualNetwork-Deployment-$(Get-Date -Format yyyyMMddHHmm)" -ResourceGroupName $mainHash.resourceGroup -Mode Incremental -TemplateFile $PSScriptRoot\..\Bicep\Main.bicep -TemplateParameterObject $deployHash

if($Deployment.ProvisioningState -notmatch "Succeeded"){
    Throw "An error occurred while deploying the Virtual network and subnet."
    Pause
    Exit 7
}
#endregion