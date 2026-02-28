
#region Set variables
$tenantId = "f09b3a23-ec35-4146-916f-9aa0e395023e"
$NamePrefix = "Azure.Intune.Cli.App."

$AppList = @(
    [PSCustomObject][Ordered]@{
        "FullName"    = "7-Zip"
        "GroupName"   = "7-Zip"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "ACBS"
        "GroupName"   = "ACBS"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Adaptive Server Enterprise PC Client"
        "GroupName"   = "Adaptive.Server.Enterprise.PC.Client"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Adobe Acrobat Reader DC"
        "GroupName"   = "Adobe.Acrobat.Reader.DC"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Adobe Creative Cloud Desktop Application"
        "GroupName"   = "Adobe.Creative.Cloud"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Amazon Corretto 21"
        "GroupName"   = "Amazon.Corretto.21"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Amazon Corretto OpenJRE Java"
        "GroupName"   = "Amazon.Corretto.OpenJRE.Java"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Anaconda 3"
        "GroupName"   = "Anaconda.3"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Apache Maven"
        "GroupName"   = "Apache.Maven"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Atlassian Companion"
        "GroupName"   = "Atlassian.Companion"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Azure Storage Explorer"
        "GroupName"   = "Azure.Storage.Explorer"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Beyond Compare 4"
        "GroupName"   = "Beyond.Compare.4"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Bloomberg"
        "GroupName"   = "Bloomberg"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Cisco AnyConnect"
        "GroupName"   = "Cisco.AnyConnect"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Cisco AnyConnect Umbrella"
        "GroupName"   = "Cisco.AnyConnect.Umbrella"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Contentworker Adobe Plug-ins"
        "GroupName"   = "Contentworker.Adobe.Plugins"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Contentworker Office Add-Ins"
        "GroupName"   = "Contentworker.Office.AddIns"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Contentworker Office Outlook Add-Ins"
        "GroupName"   = "Contentworker.Office.Outlook.AddIns"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "CREW"
        "GroupName"   = "CREW"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "CtrlPrint Transfer Manager"
        "GroupName"   = "CtrlPrint.Transfer.Manager"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "DAX Studio"
        "GroupName"   = "DAX.Studio"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "DBeaver"
        "GroupName"   = "DBeaver"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "EasyWay (Euroclear) WebClient"
        "GroupName"   = "EasyWay.Euroclear.WebClient"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Eikon"
        "GroupName"   = "Eikon"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Eikon Messenger"
        "GroupName"   = "Eikon.Messenger"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Enterprise Architect 15"
        "GroupName"   = "Enterprise.Architect.15"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Everything"
        "GroupName"   = "Everything"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "FileZilla Client"
        "GroupName"   = "FileZilla.Client"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Git"
        "GroupName"   = "Git"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Git Extensions"
        "GroupName"   = "Git.Extensions"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "GNU Octave"
        "GroupName"   = "GNU.Octave"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Google Chrome"
        "GroupName"   = "Google.Chrome"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Graphviz"
        "GroupName"   = "Graphviz"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "grepWin"
        "GroupName"   = "grepWin"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Handelsbanken BankID CardReader"
        "GroupName"   = "Handelsbanken.BankID.CardReader"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "harmon.ie"
        "GroupName"   = "harmon.ie"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Jabra Xpress"
        "GroupName"   = "Jabra.Xpress"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Java 8 Update 202"
        "GroupName"   = "Java.8.Update.202"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "LogExpert"
        "GroupName"   = "LogExpert"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Management Servers"
        "GroupName"   = "Management.Servers"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Meld"
        "GroupName"   = "Meld"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Analysis Services OLE DB Provider"
        "GroupName"   = "Microsoft.Analysis.Services.OLE.DB.Provider"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Analysis Services Projects 2022 - VS 2022 Extension"
        "GroupName"   = "Microsoft.Analysis.Services.Projects.2022"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Hyper-V"
        "GroupName"   = "Microsoft.HyperV"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft IIS"
        "GroupName"   = "Microsoft.IIS"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft ODBC Driver 17 for SQL Server"
        "GroupName"   = "Microsoft.ODBC.Driver.17.for.SQL.Server"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Power BI Desktop RS (January 2023)"
        "GroupName"   = "Microsoft.Power.BI.Desktop.RS.January.2023"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Power BI Desktop RS (May 2023)"
        "GroupName"   = "Microsoft.Power.BI.Desktop.RS.May.2023"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft PowerShell 7"
        "GroupName"   = "Microsoft.PowerShell.7"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Remote Server Administration Tools (RSAT)"
        "GroupName"   = "RSAT"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Reporting Services Projects 2022 - VS 2022 Extension"
        "GroupName"   = "Microsoft.Reporting.Services.Projects.2022"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft SCOM Console"
        "GroupName"   = "Microsoft.SCOM.Console"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft SQL Server 2019 MDS Add-in for Excel"
        "GroupName"   = "Microsoft.SQL.Server.2019.MDS.Add-in"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft SQL Server Data Tools 2017"
        "GroupName"   = "Microsoft.SQL.Server.Data.Tools.2017"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft SQL Server Management Studio"
        "GroupName"   = "Microsoft.SQL.Server.Management.Studio"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Microsoft Visual Studio Code"
        "GroupName"   = "Microsoft.Visual.Studio.Code"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "MiKTeX"
        "GroupName"   = "MiKTeX"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "MobaXterm Personal"
        "GroupName"   = "MobaXterm.Personal"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "MobaXterm Professional"
        "GroupName"   = "MobaXterm.Professional"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Murex MX3 Client"
        "GroupName"   = "Murex.MX3.Client"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Murex MX3 Datamasking"
        "GroupName"   = "Murex.MX3.Datamasking"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Murex MX3 Testing Tool Onyx"
        "GroupName"   = "Murex.MX3.Testing.Tool.Onyx"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Notepad++"
        "GroupName"   = "Notepad++"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Oracle DevTools ODAC for Visual Studio 2017"
        "GroupName"   = "Oracle.DevTools.ODAC.for.Visual.Studio.2017"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Oracle SQL Developer"
        "GroupName"   = "Oracle.SQL.Developer"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Password Expire - Check"
        "GroupName"   = "Password.Expire.Check"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Periodisk Inrapportering"
        "GroupName"   = "Periodisk.Inrapportering"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "PingPlotter 5"
        "GroupName"   = "PingPlotter.5"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Postman"
        "GroupName"   = "Postman"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Pricka Bokslut PreProd"
        "GroupName"   = "Pricka.Bokslut.PreProd"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Pricka Bokslut Prod"
        "GroupName"   = "Pricka.Bokslut.Prod"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Pricka Bokslut Test"
        "GroupName"   = "Pricka.Bokslut.Test"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "PuTTY"
        "GroupName"   = "PuTTY"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Python 3.7"
        "GroupName"   = "Python"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Python 3.11"
        "GroupName"   = "Python"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "R for Windows"
        "GroupName"   = "R.for.Windows"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "R Studio"
        "GroupName"   = "R.Studio"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "RasPhone"
        "GroupName"   = "RasPhone"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Remote Desktop Connection Manager"
        "GroupName"   = "Remote.Desktop.Connection.Manager"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "S&P Capital IQ Pro Office"
        "GroupName"   = "SP.Capital.IQ.Pro.Office"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SafeNet Minidriver"
        "GroupName"   = "SafeNet Minidriver"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SEK Always On"
        "GroupName"   = "SEK.Always.On"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SEK Fonts"
        "GroupName"   = "SEK.Fonts"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SEK Teams Backgrounds"
        "GroupName"   = "SEK.Teams.Backgrounds"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SoapUI"
        "GroupName"   = "SoapUI"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SourceGear DiffMerge"
        "GroupName"   = "SourceGear.DiffMerge"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Splunk Universal Forwarder"
        "GroupName"   = "Splunk.Universal.Forwarder"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Spotlight on Oracle"
        "GroupName"   = "Spotlight.on.Oracle"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SQL Prompt"
        "GroupName"   = "SQL.Prompt"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "SQL Search"
        "GroupName"   = "SQL Search"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Swift Alliance User"
        "GroupName"   = "Swift.Alliance.User"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Swift Token Client"
        "GroupName"   = "Swift.Token.Client"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Sysinternals Sysmon"
        "GroupName"   = "Sysinternals.Sysmon"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Tabular Editor 3"
        "GroupName"   = "Tabular.Editor.3"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Telavox Desktop"
        "GroupName"   = "Telavox.Desktop"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Telavox Operator"
        "GroupName"   = "Telavox.Operator"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "TeXstudio"
        "GroupName"   = "TeXstudio"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Toad for Oracle"
        "GroupName"   = "Toad.for.Oracle"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "TortoiseGit"
        "GroupName"   = "TortoiseGit"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Visma Control 11"
        "GroupName"   = "Visma.Control.11"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Visma DCE Administrator"
        "GroupName"   = "Visma.DCE.Administrator"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Visual Studio 17 Professional"
        "GroupName"   = "Visual.Studio.17.Pro"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Visual Studio 19 Professional"
        "GroupName"   = "Visual.Studio.19.Pro"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "wc3270 Emulator for VPC"
        "GroupName"   = "wc3270.Emulator.for.VPC"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "WinMerge"
        "GroupName"   = "WinMerge"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "WinSCP"
        "GroupName"   = "WinSCP"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "Wireshark"
        "GroupName"   = "Wireshark"
    },
    [PSCustomObject][Ordered]@{
        "FullName"    = "XMind 8"
        "GroupName"   = "XMind.8"
    }
)

#endregion


#############################################################################################################################################################
#           DO NOT CHANGE BELOW
#region Run script

$DescPrefix = "Members will get the"

$Suffix = @(
    [PSCustomObject][Ordered]@{
        "Name"         =   "Required"
        "Description"   =   "Intune app automatically installed."
    },
    [PSCustomObject][Ordered]@{
        "Name"         =   "Available"
        "Description"   =   "Intune app available in Company Portal."
    },
    [PSCustomObject][Ordered]@{
        "Name"         =   "Uninstall"
        "Description"   =   "Intune app uninstalled."
    }
)

if ($PSScriptRoot){
    $scriptPath = $PSScriptRoot
}else{
    $scriptPath = "C:\Users\yoeabr\OneDrive - RTS\Powershell\GitHub\Client-Deployment\Intune\Create-IntuneAppGroups\"
}

Import-Module -Name "$scriptPath\IntuneWin32App" -Force
Import-Module -Name AzureAD -Force

Connect-AzureAD -TenantId $tenantId
Connect-MSIntuneGraph -TenantID $tenantId -Interactive


$AllApps = Get-IntuneWin32App

$SelectedApps = $AllApps | Select displayName,displayVersion,id,createdDateTime | Out-GridView -Title "Choose app(s) to create groups for" -OutputMode Multiple

foreach ($app in ($AppList | where {$_.FullName -like "Microsoft Analysis Services Projects 2022*"})) {
    $MatchedIntuneApps = $AllApps | ? displayName -like $app.FullName
    foreach ($MatchedApp in $MatchedIntuneApps){
        $Assignments = (Get-IntuneWin32AppAssignment -ID $MatchedApp.id)

        foreach ($item in $Suffix) {
            $GroupFullName = "${NamePrefix}$($app.GroupName)_$($item.Name)"
            $GroupDesc = "$DescPrefix `"$($app.FullName)`" $($item.Description)"

            if (($Assignments.intent -match $item.Name) -AND (($Assignments | ? intent -like $item.Name).target.'@odata.type' -match "graph\.groupAssignmentTarget")){
                if ($item.Name -like "Uninstall") {
                    if (($Assignments | where {$_.target.'@odata.type' -match "graph\.exclusionGroupAssignmentTarget"}).intent -match "Required") {
                        "$($item.Name) is assigned for '$($app.FullName)'"
                    }else{
                        "$($item.Name) is not completely assigned for '$($app.FullName)'"
                        "Assigning uninstall group as excluded on required"
                        $GroupId = ($Assignments | where {$_.intent -like "Uninstall"}).target.groupId
                        Add-IntuneWin32AppAssignmentGroup -ID $MatchedApp.id -Exclude -Intent required -GroupID $GroupId
                    }
                }else{
                    "$($item.Name) is assigned for '$($app.FullName)'"
                }
            }else{
                "$($item.Name) is not assigned for '$($app.FullName)'"
                if (!(Get-AzureADGroup -SearchString $GroupFullName)){
                    $NewGroup = New-AzureADGroup -Description $GroupDesc -DisplayName $GroupFullName -SecurityEnabled $true -MailEnabled $false -MailNickName "NotSet"
                }

                Add-IntuneWin32AppAssignmentGroup -ID $MatchedApp.id -Include -Intent $item.Name -GroupID $NewGroup.ObjectId

                if($item.Name -like "Uninstall"){
                    Add-IntuneWin32AppAssignmentGroup -ID $MatchedApp.id -Exclude -Intent required -GroupID $NewGroup.ObjectId
                }
            }
        }
    }
}

#endregion