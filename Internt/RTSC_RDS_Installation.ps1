<#
.DESCRIPTION
    This script will create a configured RTS Cloud standard Remote Desktop Server Farm 
.SYNOPSIS
    Created for Real Time Services Cloud AB for standardized deployment of Remote Desktop Server Farm
.EXAMPLE
    .\Install_RDSFarm.ps1 -ConnectionBroker CORP-RBG01 -RDSHosts "CORP-RDSH01,CORP-RDSH02" -WebAccessServer CORP-RBG01 -RDGatewayServer CORP-RBG01 -GatewayExternalFQDN access.corp.local -DesktopCollectionName "Corporation Name"
    
    Multiple RDSHosts can be defined as comma-separated string-values.
    ConnectionBroker, WebAccessServer, RDGatewayServer and LICServer are optional. If omitted, local machine will be used.
.NOTES

#>


# Original Author Julian Mooren | https://citrixguyblog.com
# Modified for Real Time Services Cloud AB by Yoel Abraham, 2022-02-01 

#Requires -version 4.0
#Requires -RunAsAdministrator

#Functions
#http://www.leeholmes.com/blog/2009/11/20/testing-for-powershell-remoting-test-psremoting/

[CmdletBinding()]
Param(
        
    [Parameter()]
    [string]$ConnectionBroker = $env:COMPUTERNAME,

    [Parameter()]
    [string]$DomainController = ($env:LOGONSERVER -replace "\\"),

    [Parameter(Mandatory=$True)]
    [string[]]$RDSHosts = @(),

    [Parameter(Mandatory=$True)]
    [string]$GatewayExternalFQDN,

    [Parameter()]
    [string]$DesktopCollectionName = $env:USERDOMAIN,

    [Parameter()]
    [string]$DomainName = $env:USERDNSDOMAIN,

    [Parameter()]
    [string]$WebAccessServer = $env:COMPUTERNAME,

    [Parameter()]
    [string]$RDGatewayServer = $env:COMPUTERNAME,

    [Parameter()]
    [string]$RDSAccessGroup = "SG_RDS_Users",

    [Parameter()]
    [string]$LICServer = $env:COMPUTERNAME,

    [Parameter()]
    [ValidateSet("PerUser","PerDevice")]
    [string]$LICMode = "PerUser",

    [Parameter()]
    [switch]$InstallRdsCAL,

    [Parameter(Mandatory=$True)]
    [string]$ProfileDiskUNCPath,

    [Parameter()]
    [string]$CertFilePath,

    [Parameter()]
    [String]$CertPassword,

    [Parameter()]
    [string]$LogPath = "$env:windir\temp\RTSC-RDS-Installation_$(Get-Date -Format yyyy-MM-dd_HHmm).log"

    )

$DeploymentName = "RTS Cloud Standard RDS Installation 2022"
$ElapsedTime = [system.diagnostics.stopwatch]::StartNew()
$ScriptPath = (Split-Path -Parent $MyInvocation.MyCommand.Definition)

##################################################################################################################
#region Functions

# Function for testing PS Remoting to remote server
function Test-PSRemoting {
    param(
        [Parameter(Mandatory = $true)]
        $ComputerName
    )
    try
    {
        $result = Invoke-Command -ComputerName $computername { 1 } -ErrorAction Stop
    }
    catch
    {
        Write-LogEntry -Severity ERROR -Message $_
        return $false
    }
   
    ## I've never seen this happen, but if you want to be
    ## thorough....
    if($result -ne 1)
    {
        return $false
    }
    return $true
} # end Test-PsRemoting


# Function for Logging
function Write-LogEntry {
    param (
        [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
    
        [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Severity,
    
        [parameter(Mandatory = $false, HelpMessage = "File path of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath = $LogPath,

        [parameter(Mandatory = $false, HelpMessage = "Outputs value to console")]
        [switch]$PrintOutput
    )

    # Construct time stamp for log entry
    $Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        
    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
    # Construct final log entry
     $LogText = "$Time | $Severity | $Message | Context: $Context"
        
    # Output Value as verbose
    IF($Severity -like "INFO"){
        IF($PrintOutput -and ($VerbosePreference -like "SilentlyContinue")){
            Write-Output $Message
        }ELSE{
            Write-Verbose $Message
        }
    }ELSEIF(($Severity -like "WARNING") -and ($PrintOutput)){
        Write-Warning $Message
    }ELSEIF(($Severity -like "ERROR") -and ($PrintOutput)){
        Write-Host $Message -ForegroundColor Red -BackgroundColor Black
    }

    # Add value to log file
    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogPath -Force -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}


Function Stop-Script{
    $ElapsedTime.stop()
    Write-LogEntry -Severity ERROR -PrintOutput -Message "Deployment cannot continue! Ending script"
    Write-Verbose "See the log for more information: $LogPath"
    Pause
}

#endregion




#####################################################################################################################################################
#region Pre-requisite check
Write-Host "`t === $DeploymentName ===" -ForegroundColor Yellow
Write-Host "`t`tPre-requisite check" -ForegroundColor Yellow


# Validate Log Path
Write-Host "  Validating log path..." -ForegroundColor Yellow
Write-Host $LogPath"`t" -NoNewline
Try {
    IF(!(Test-Path $LogPath -PathType Leaf)){
        New-Item -Path $LogPath -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    Write-Host "Success`n" -ForegroundColor Green
}Catch [System.Exception] {
    Write-Host "An error occurred while creating log file '$LogPath'" -ForegroundColor Red -BackgroundColor Black
    Write-Host $_ -ForegroundColor Red -BackgroundColor Black
    $ElapsedTime.stop()
    Pause
    Break
}





# Import AD and DNS modules from the domain controller
Write-Host "  Importing necessary modules..." -ForegroundColor Yellow
$Modules = @("ActiveDirectory","DnsServer","RemoteDesktop")
foreach ($Module in $Modules) {
    Write-Host "$Module`t" -NoNewline
    Clear-Variable CurrentModule -ErrorAction SilentlyContinue

    Import-Module -Name $Module
    $CurrentModule = Get-Module -Name $Module
        
    IF(!$CurrentModule){
        # Install current missing module
        IF((@("ActiveDirectory","DnsServer") -contains $Module) -AND ($env:COMPUTERNAME -notlike $DomainController)){
            Try{
                $ModuleSession = New-PSSession $DomainController -ErrorAction Stop
                Import-Module -Name $Module -PSSession $ModuleSession -Force -ErrorAction Stop
                Write-Host "Success" -ForegroundColor Green
            }Catch [System.Exception] {
                Write-LogEntry -Severity ERROR -PrintOutput -Message "An error occurred while attempting to import the $($Module) module from domain controller. Error message: $($_.Exception.Message)"
                Stop-Script
                Break
            }

            IF(!(Get-Module -Name $Module)){
                Write-LogEntry -Severity ERROR -PrintOutput -Message "Failed to find the '$($Module)' module!"
                Stop-Script
                Break
            }

        }ELSE{
            Write-LogEntry -Severity ERROR -PrintOutput -Message "Failed to find the '$($Module)' module!"
            Stop-Script
            Break
        }
    }ELSE{
        Write-LogEntry -Severity INFO -Message "Successfully loaded the '$Module' module"
        Write-Host "Success" -ForegroundColor Green
    }
}
Write-Host




# Prompt for RDS License CAL Count
IF($InstallRdsCAL){
    $ErrorActionPreference = "Stop"
    Try{
        [int32]$LicenseCount = Read-Host -Prompt "How many RDS License CALs needs to be installed? (Max amount of RDS Users)"
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "Incorrect input! Only digits allowed." -PrintOutput
        Stop-Script
        Break
    }
    $ErrorActionPreference = "Continue"
}
Write-Host



# Validate Profile Disk UNC Path
Write-Host "  Validating profile disk path..." -ForegroundColor Yellow
Write-Host $ProfileDiskUNCPath"`t" -NoNewline
IF(!(Test-Path $ProfileDiskUNCPath -PathType Container)){
    Write-LogEntry -Severity ERROR -Message "Profile disk UNC-path '$ProfileDiskUNCPath' is not valid." -PrintOutput
    Stop-Script
    Break
}ELSE{
    IF(([System.Uri]$ProfileDiskUNCPath).IsUnc){
        Write-LogEntry -Severity INFO -Message "Profile disk UNC-path '$ProfileDiskUNCPath' has been validated."
        Write-Host "Success`n" -ForegroundColor Green
        Try{
            New-Item -Path $ProfileDiskUNCPath -Name O365 -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to create the folder '$ProfileDiskUNCPath\O365'." -PrintOutput
        }
        Try{
            New-Item -Path $ProfileDiskUNCPath -Name Configuration -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to create the folder '$ProfileDiskUNCPath\Configuration'." -PrintOutput
        }
    }ELSE{
        Write-LogEntry -Severity ERROR -Message "Profile disk UNC-path '$ProfileDiskUNCPath' is not an UNC-path." -PrintOutput
        Stop-Script
        Break
    }
}




# Validate Certificate File Path
IF($CertFilePath){
    Write-Host "  Validating certificate path..." -ForegroundColor Yellow
    IF (Test-Path $CertFilePath -PathType Leaf) {
        Write-LogEntry -Severity INFO -Message "SSL Certificate was found."
        Write-Host "Success`n" -ForegroundColor Green
    }ELSE{
        Write-LogEntry -Severity ERROR -PrintOutput "Certificate file path '$CertFilePath' is not valid."
        Stop-Script
        break
    }
    if(!$CertPassword){
        Write-LogEntry -Severity ERROR -PrintOutput "Parameter CertPassword cannot be used without parameter CertFilePath."
        Stop-Script
        break
    }
}
if($CertPassword -and !($CertFilePath)){
    Write-LogEntry -Severity ERROR -PrintOutput "Parameter CertFilePath cannot be used without parameter CertPassword."
    Stop-Script
    break
}






# Get AD object for RD session host servers
Write-Host "  Validating servers..." -ForegroundColor Yellow
$ServerList = @()
$DefinedRDSH = @()    
$ADServerFailed = $false
Foreach($Server in $RDSHosts){
    Write-Host "RDSHost: $Server`t" -NoNewline
    $ADServer = Get-ADComputer -Filter "Name -like '$Server'"
    if(!$ADServer){
        Write-Host "Failed" -ForegroundColor Red
        $ADServerFailed = $true
        Write-LogEntry -Severity ERROR -Message "An error occurred while validating server '$Server'. Server not found in AD!"
    }
    else{
        Write-Host "Success" -ForegroundColor Green
        $DefinedRDSH += $ADServer
        $ServerList += $ADServer
        Write-LogEntry -Severity INFO -Message "Validated server '$Server'"
    }
}


# Get AD object for each role server
Write-Host "DomainController: $DomainController`t" -NoNewline
$DefinedDC = Get-ADComputer -Filter "Name -like '$DomainController'"
if(!$DefinedDC){
    Write-Host "Failed" -ForegroundColor Red
    $ADServerFailed = $true
    Write-LogEntry -Severity ERROR -Message "An error occurred while validating server '$DomainController'. Server not found in AD!"
}
else{Write-Host "Success" -ForegroundColor Green}

Write-Host "ConnectionBroker: $ConnectionBroker`t" -NoNewline
$DefinedCB = Get-ADComputer -Filter "Name -like '$ConnectionBroker'"
if(!$DefinedCB){
    Write-Host "Failed" -ForegroundColor Red
    $ADServerFailed = $true
    Write-LogEntry -Severity ERROR -Message "An error occurred while validating server '$ConnectionBroker'. Server not found in AD!"
}
else{Write-Host "Success" -ForegroundColor Green}

Write-Host "WebAccessServer: $WebAccessServer`t" -NoNewline
$DefinedWEB = Get-ADComputer -Filter "Name -like '$WebAccessServer'"
if(!$DefinedWEB){
    Write-Host "Failed" -ForegroundColor Red
    $ADServerFailed = $true
    Write-LogEntry -Severity ERROR -Message "An error occurred while validating server '$WebAccessServer'. Server not found in AD!"
}
else{Write-Host "Success" -ForegroundColor Green}

Write-Host "RDGatewayServer: $RDGatewayServer`t" -NoNewline
$DefinedGW = Get-ADComputer -Filter "Name -like '$RDGatewayServer'"
if(!$DefinedGW){
    Write-Host "Failed" -ForegroundColor Red
    $ADServerFailed = $true
    Write-LogEntry -Severity ERROR -Message "An error occurred while validating server '$RDGatewayServer'. Server not found in AD!"
}
else{Write-Host "Success" -ForegroundColor Green}

Write-Host "LICServer: $LICServer`t" -NoNewline
$DefinedLIC = Get-ADComputer -Filter "Name -like '$LICServer'"
if(!$DefinedLIC){
    Write-Host "Failed" -ForegroundColor Red
    $ADServerFailed = $true
    Write-LogEntry -Severity ERROR -Message "An error occurred while validating server '$LICServer'. Server not found in AD!"
}
else{Write-Host "Success" -ForegroundColor Green}
Write-Host

if($ADServerFailed){
    Write-LogEntry -Severity ERROR -PrintOutput -Message "An error occurred while validating servers!"
    Stop-Script
    Exit
}


# Add servers to all servers array
IF($DefinedDC.dNSHostName -notin $ServerList.dNSHostName){
    $ServerList += $DefinedDC
}
IF($DefinedCB.dNSHostName -notin $ServerList.dNSHostName){
    $ServerList += $DefinedCB
}
IF($DefinedWEB.dNSHostName -notin $ServerList.dNSHostName){
    $ServerList += $DefinedWEB
}
IF($DefinedGW.dNSHostName -notin $ServerList.dNSHostName){
    $ServerList += $DefinedGW
}
IF($DefinedLIC.dNSHostName -notin $ServerList.dNSHostName){
    $ServerList += $DefinedLIC
}


# Validate PSremoting to all servers
$statusok = $true
Write-Host "  Testing PSRemoting on servers..." -ForegroundColor Yellow
foreach($computer in $ServerList.DNSHostname){
    Write-Host "$computer`t" -NoNewline
    $status = Test-PsRemoting -computername $computer
    if($status){$foreground = 'Green'}else{$foreground = 'Red'}
    Write-Host $status -ForegroundColor $foreground
    if(!($status)){
        $statusok = $false;
    }
}
Write-Host
if($statusok){
    Write-LogEntry -Severity INFO -Message "PSRemoting is working on all Hosts."
}
else{
    Write-LogEntry -Severity ERROR -PrintOutput -Message "PSRemoting is not working on all Hosts." 
    Stop-Script
    break
}



# Check Share access to connection broker. Open SMB firewall rule if it is not reachable
Write-Host "  Verifying ProfileDisk SMB Firewall rule..." -ForegroundColor Yellow
Write-Host $DefinedCB.dNSHostName"`t" -NoNewline
IF(Test-Path "\\$($DefinedCB.dNSHostName)\c$"){
    Write-LogEntry -Severity INFO -Message "UNC Path to $($DefinedCB.dNSHostName) is reachable"
    Write-Host "Success" -ForegroundColor Green
}ELSE{
    Write-LogEntry -Severity WARNING -Message "UNC path to $($DefinedCB.dNSHostName) not reachable. Attempting to open firewall rules on server..." -PrintOutput
    Invoke-Command -ComputerName $DefinedCB.dNSHostName {
        Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Enable-NetFirewallRule
    }

    IF(Test-Path "\\$($DefinedCB.dNSHostName)\c$"){
        Write-LogEntry -Severity INFO -Message "UNC Path to $($DefinedCB.dNSHostName) is reachable"
        Write-Host "Success" -ForegroundColor Green
    }ELSE{
        Write-LogEntry -Severity ERROR -Message "UNC path to $($DefinedCB.dNSHostName) still not reachable!" -PrintOutput
        Write-Host "Failed" -ForegroundColor Red
        Stop-Script
        Break
    }
}
Write-Host




# Validate AD group, create if not exist
Write-Host "  Verifying RDSAccessGroup..." -ForegroundColor Yellow
IF(!(Get-ADGroup -Filter "Name -like '$RDSAccessGroup'")){
    Try{
        Write-LogEntry -Severity INFO -Message "AD group '$RDSAccessGroup' was not found. Creating AD group '$RDSAccessGroup'..." -PrintOutput
        $NewADGroup = New-ADGroup -Name $RDSAccessGroup -GroupCategory Security -GroupScope Global -PassThru -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "AD group '$RDSAccessGroup' has successfully been created." -PrintOutput
        ($NewADGroup | Get-ADGroup -Properties CanonicalName).CanonicalName
        Write-Host "RDSAccessGroup: "$RDSAccessGroup"`t" -NoNewline
        Write-Host "Success" -ForegroundColor Green
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while attempting to create the AD group '$RDSAccessGroup'. Error Message: $($_.Exception.Message)" -PrintOutput
        Write-Host "RDSAccessGroup: "$RDSAccessGroup"`t" -NoNewline
        Write-Host "Failed" -ForegroundColor Red
        Stop-Script
        Break
    }
}ELSE{
    Write-LogEntry -Severity INFO -Message "AD group '$RDSAccessGroup' has been found and validated."
    Write-Host "Success" -ForegroundColor Green
}


# Summarize configuration for log
Write-LogEntry -Severity INFO -Message "DomainController: $($DefinedDC.dNSHostName)"
Write-LogEntry -Severity INFO -Message "ConnectionBroker: $($DefinedCB.dNSHostName)"
Write-LogEntry -Severity INFO -Message "WebAccessServer: $($DefinedWEB.dNSHostName)"
Write-LogEntry -Severity INFO -Message "RDGatewayServer: $($DefinedGW.dNSHostName)"
$i=1
foreach($RDSH in $DefinedRDSH.dNSHostName){
    Write-LogEntry -Severity INFO -Message "RDSHost ${i}: $RDSH"
    $i++
}
Write-LogEntry -Severity INFO -Message "DomainName: $($env:USERDNSDOMAIN)"
Write-LogEntry -Severity INFO -Message "LICserver: $($DefinedLIC.dNSHostName)"
Write-LogEntry -Severity INFO -Message "LICmode: $LICmode"
Write-LogEntry -Severity INFO -Message "DesktopCollectionName: $DesktopCollectionName"
Write-LogEntry -Severity INFO -Message "ProfileDiskPath: $ProfileDiskUNCPath"
Write-LogEntry -Severity INFO -Message "RDSAccessGroup: $RDSAccessGroup"
Write-LogEntry -Severity INFO -Message "GatewayExternalFqdn: $GatewayExternalFQDN"
Write-LogEntry -Severity INFO -Message "CertPath: $CertFilePath"



# Final check user prompt
Write-Host "`n  Final Configuration" -ForegroundColor Yellow
Write-Host "=====================" -ForegroundColor Yellow
Write-Host "DomainController: $($DefinedDC.dNSHostName)" -ForegroundColor Yellow
Write-Host "ConnectionBroker: $($DefinedCB.dNSHostName)" -ForegroundColor Yellow
Write-Host "WebAccessServer: $($DefinedWEB.dNSHostName)" -ForegroundColor Yellow
Write-Host "RDGatewayServer: $($DefinedGW.dNSHostName)" -ForegroundColor Yellow
$i=1
foreach($RDSH in $DefinedRDSH.dNSHostName){
    Write-Host "RDSHost${i}: $RDSH" -ForegroundColor Yellow
    $i++
}
Write-Host "DomainName: $env:USERDNSDOMAIN" -ForegroundColor Yellow
Write-Host "LICserver: $($DefinedLIC.dNSHostName)" -ForegroundColor Yellow
Write-Host "LICmode: $LICmode" -ForegroundColor Yellow
Write-Host "DesktopCollectionName: $DesktopCollectionName" -ForegroundColor Yellow
Write-Host "ProfileDiskPath: $ProfileDiskUNCPath" -ForegroundColor Yellow
Write-Host "RDSAccessGroup: $RDSAccessGroup" -ForegroundColor Yellow
Write-Host "GatewayExternalFqdn: $GatewayExternalFQDN" -ForegroundColor Yellow
if($CertFilePath){Write-Host "CertPath: $CertFilePath" -ForegroundColor Yellow}
Write-Host
Write-Host "Please review configuration above!`n" -BackgroundColor Yellow -ForegroundColor Black
read-host "Press [Enter] to start installation"


#endregion




#####################################################################################################################################################
#region RDS Installation
Write-Host "`t`tInstallation `n" -ForegroundColor Yellow


##### MultiDeployment Configuration Parameters ##### 

# Create RDS deployment
Try{
    New-RDSessionDeployment -ConnectionBroker $DefinedCB.dNSHostName -WebAccessServer $DefinedWEB.dNSHostName -SessionHost $DefinedRDSH.dNSHostName -ErrorAction Stop
    Write-LogEntry -Severity INFO -Message "Successfully created a new RDS session deployment" -PrintOutput
}Catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while creating a new RDS session deployment. Error message: $($_.Exception.Message)" -PrintOutput
    Stop-Script
    Break
}


# Create Desktop Collection
Try{
    New-RDSessionCollection  -CollectionName $DesktopCollectionName -SessionHost $DefinedRDSH.dNSHostName -ConnectionBroker $DefinedCB.dNSHostName -ErrorAction Stop
    Write-LogEntry -Severity INFO -Message "Successfully created a new RDS Collection" -PrintOutput

}Catch [System.Exception] {
    $CheckRDSCollection = Get-RDSessionCollection -CollectionName $DesktopCollectionName
    IF($CheckRDSCollection){
        IF($CheckRDSCollection.Size -eq $DefinedRDSH.Count){
            Write-LogEntry -Severity INFO -Message "Successfully created a new RDS Collection" -PrintOutput
        }ELSE{
            Write-LogEntry -Severity WARNING -Message "Make sure that all the session hosts has been added to the RDS collection. Add the session hosts manually if needed." -PrintOutput
        }
    }ELSE{
        Write-LogEntry -Severity ERROR -Message "An error occurred while creating a new RDS collection. Error message: $($_.Exception.Message)" -PrintOutput
        Stop-Script
        Break
    }
}
# Set Access Group for RDS Collection
Try{
    Set-RDSessionCollectionConfiguration -CollectionName $DesktopCollectionName -UserGroup $RDSAccessGroup -ActiveSessionLimitMin 720 -DisconnectedSessionLimitMin 180 -IdleSessionLimitMin 180 -ConnectionBroker $DefinedCB.dNSHostName -ErrorAction Stop
    Write-LogEntry -Severity INFO -Message "Successfully configured access for the AD group $RDSAccessGroup" -PrintOutput
}Catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while assigning RDS collection access to AD group. Error message: $($_.Exception.Message)" -PrintOutput
}



#Install Gateway
Try{
    Add-WindowsFeature -Name RDS-Gateway -IncludeManagementTools -ComputerName $DefinedGW.dNSHostName -ErrorAction Stop | Out-Null
    Write-LogEntry -Severity INFO -Message "Successfully installed the RDS Gateway" -PrintOutput 


    #Join Gateway to Broker
    Try{
        Add-RDServer -Server $DefinedGW.dNSHostName -Role "RDS-GATEWAY" -ConnectionBroker $DefinedCB.dNSHostName -GatewayExternalFqdn $GatewayExternalFQDN -ErrorAction Stop | Out-Null
        Write-LogEntry -Severity INFO -Message "Successfully assigned RDS Gateway to Broker" -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while assigning the RDS Gateway to broker. Error message: $($_.Exception.Message)" -PrintOutput
    }


    # Redirect to RDWeb (IIS)
    IF($DefinedWEB.Name -like $env:COMPUTERNAME){
        Try{
            $siteName = "Default Web Site"
            Import-Module webAdministration
            Set-WebConfiguration system.webServer/httpRedirect "IIS:\sites\$siteName" -Value @{enabled="true";destination="/rdweb";exactDestination="false";httpResponseStatus="Found"} -ErrorAction Stop
            Write-LogEntry -Severity INFO -Message "Successfully configured RDWeb Redirect" -PrintOutput
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RDS Gateway. Error message: $($_.Exception.Message)" -PrintOutput
        }
    }ELSE{
        $WebResult = Invoke-Command -ComputerName $DefinedWEB.dNSHostName -ScriptBlock {
            Try{
                $siteName = "Default Web Site"
                Import-Module webAdministration
                Set-WebConfiguration system.webServer/httpRedirect "IIS:\sites\$siteName" -Value @{enabled="true";destination="/rdweb";exactDestination="false";httpResponseStatus="Found"} -ErrorAction Stop
                return $True
            }Catch [System.Exception] {
                return $_.Exception.Message
            }
        }Write-LogEntry -Severity INFO 

        IF($WebResult -eq $True){
            Write-LogEntry -Severity INFO -Message "Successfully configured RDWeb Redirect" -PrintOutput
        }ELSE{
            Write-LogEntry -Severity ERROR -Message "An error occurred while configuring RFWeb Redirect. Error message: $WebResult" -PrintOutput
        }
    }
    

    # Configure WebAccess (when RDBroker is available, no Gateway will be used)
    Try{
        Set-RDDeploymentGatewayConfiguration -GatewayMode Custom -GatewayExternalFqdn $GatewayExternalFqdn -LogonMethod Password -UseCachedCredentials $True -BypassLocal $True -ConnectionBroker $DefinedCB.dNSHostName -Force -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully configured Gateway Mapping" -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while configuring RDS Gateway mapping. Error message: $($_.Exception.Message)" -PrintOutput
    }


}Catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RDS Gateway. Error message: $($_.Exception.Message)" -PrintOutput
}







# Install RDS Licencing
Try{
    Add-RDServer -Server $DefinedLIC.dNSHostName -Role "RDS-LICENSING" -ConnectionBroker $DefinedCB.dNSHostName -ErrorAction Stop | Out-Null
    Write-LogEntry -Severity INFO -Message "Successfully installed the RDS License Server: $($DefinedLIC.dNSHostName)" -PrintOutput

    Try{
        Set-RDLicenseConfiguration -LicenseServer $DefinedLIC.dNSHostName -Mode $LICMode -ConnectionBroker $DefinedCB.dNSHostName -Force -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully configured RDS Licensing mode to: $LICMode" -PrintOutput
    }Catch [System.Exception] {
        $RDLicenseConfiguration = Get-RDLicenseConfiguration
        IF(($RDLicenseConfiguration.Mode -like $LICMode) -and ($RDLicenseConfiguration.LicenseServer -like $DefinedLIC.dNSHostName)){
            Write-LogEntry -Severity INFO -Message "Successfully configured RDS Licensing mode to: $LICMode" -PrintOutput
        }ELSE{
            Write-LogEntry -Severity ERROR -Message "An error occurred while configuring the RDS Licensing mode. Error message: $($_.Exception.Message)" -PrintOutput
        }
    }
    

    # Activate License Server
    $ErrorActionPreference = "Stop"
    Try{
        $licServerResult = @{}
        $licServerResult.LicenseServerActivated = $Null

        $wmiClass = ([wmiclass]"\\$($DefinedLIC.Name)\root\cimv2:Win32_TSLicenseServer")

        $wmiTSLicenseObject = Get-WmiObject Win32_TSLicenseServer -ComputerName $DefinedLIC.Name
        $wmiTSLicenseObject.FirstName="<FÖRNAMN>"
        $wmiTSLicenseObject.LastName="<EFTERNAMN>"
        $wmiTSLicenseObject.Company="<BOLAGSNAMN>"
        $wmiTSLicenseObject.CountryRegion="Sweden"
        $wmiTSLicenseObject.Put()

        $wmiClass.ActivateServerAutomatic() | Out-Null

        $licServerResult.LicenseServerActivated = $wmiClass.GetActivationStatus().ActivationStatus

        Add-ADGroupMember -Identity "Terminal Server License Servers" -Members $DefinedLIC.SamAccountName
        Invoke-Command $DefinedDC.Name -ScriptBlock {net localgroup "Terminal Server License Servers" /Add 'Network Service'} | Out-Null
        Restart-Service TermServLicensing -Force

        IF($licServerResult.LicenseServerActivated -ne 0){
            Write-LogEntry -Severity ERROR -Message "Failed to activate the RDS Licensing server." -PrintOutput
        }ELSE{
            Write-LogEntry -Severity INFO -Message "Successfully activated the RDS Licensing server." -PrintOutput
        }

        # Install RTS Cloud RDS SPLA License CALs
        IF($InstallRdsCAL){
            $wmiPack = ([wmiclass]"\\$($DefinedLIC.Name)\root\cimv2:Win32_TSLicenseKeyPack")
            [String]$agreementNumber = "1234567"
            $LicenseInstallResult = $wmiPack.InstallAgreementLicenseKeyPack(4, $agreementNumber, 6, 1, $LicenseCount)
            IF($LicenseInstallResult.ReturnValue -eq 0){
                Write-LogEntry -Severity INFO -Message "Successfully installed RTS Cloud RDS SPLA License CAL." -PrintOutput
            }ELSE{
                Write-LogEntry -Severity ERROR -Message "Failed to install RTS Cloud RDS SPLA License CAL." -PrintOutput
            }
        }

    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while activating the RDS Licensing server. Error message: $($_.Exception.Message)" -PrintOutput
    }
    $ErrorActionPreference = "Continue"
    

}Catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RDS Licensing server. Error message: $($_.Exception.Message)" -PrintOutput
}






# Set Certificates
IF($CertFilePath){
    
    $Password = ConvertTo-SecureString -String $CertPassword -AsPlainText -Force

    Try{
        Set-RDCertificate -Role RDPublishing -ImportPath $CertFilePath  -Password $Password -ConnectionBroker $DefinedCB.dNSHostName -Force -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully installed the RD Publishing certificate." -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RD Publishing certificate. Error message: $($_.Exception.Message)" -PrintOutput
    }

    Try{
        Set-RDCertificate -Role RDRedirector -ImportPath $CertFilePath -Password $Password -ConnectionBroker $DefinedCB.dNSHostName -Force -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully installed the RD Redirector certificate." -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RD Redirector certificate. Error message: $($_.Exception.Message)" -PrintOutput
    }

    Try{
        Set-RDCertificate -Role RDWebAccess -ImportPath $CertFilePath -Password $Password -ConnectionBroker $DefinedCB.dNSHostName -Force -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully installed the RD Web Access certificate." -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RD Web Access certificate. Error message: $($_.Exception.Message)" -PrintOutput
    }

    Try{
        Set-RDCertificate -Role RDGateway -ImportPath $CertFilePath  -Password $Password -ConnectionBroker $DefinedCB.dNSHostName -Force -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully installed the RD Gateway certificate." -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while installing the RD Gateway certificate. Error message: $($_.Exception.Message)" -PrintOutput
    }
}ELSE{
    Write-LogEntry -Severity INFO -Message "No certificate provided, skipping step." -PrintOutput
}






# Create RDS Broker DNS-Record
$IPBroker01 = ([System.Net.Dns]::GetHostAddresses($DefinedCB.dNSHostName)| Where{$_.addressfamily -eq 'InterNetwork'})[0].IPAddressToString

Try{
    Add-DnsServerPrimaryZone -ComputerName $DomainController -Name $GatewayExternalFqdn -ReplicationScope Domain -ErrorAction Stop
    Write-LogEntry -Severity INFO -Message "Successfully created a new DNS primary zone for $GatewayExternalFQDN" -PrintOutput

    Try{
        Add-DnsServerResourceRecordA -ComputerName $DomainController -Name "." -ZoneName $GatewayExternalFqdn -AllowUpdateAny -IPv4Address $IPBroker01 -ErrorAction Stop
        Write-LogEntry -Severity INFO -Message "Successfully created a RDS Broker DNS-record" -PrintOutput
    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "An error occurred while creating RDS Broker DNS-record. Error message: $($_.Exception.Message)" -PrintOutput
    }

}Catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while creating new DNS Primary Zone for $GatewayExternalFQDN. Error message: $($_.Exception.Message)" -PrintOutput
}





# Add servers to managed servers in Server Manager
$srvmgrproc = Get-Process ServerManager -ErrorAction SilentlyContinue
Try{
    if($srvmgrproc){
        $srvmgrproc | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    $servermanagerfile = Get-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\ServerManager\ServerList.xml" -ErrorAction Stop
    $xml = [xml](Get-Content $servermanagerfile -ErrorAction Stop)

    foreach($computer in $ServerList.dNSHostName){
        Clear-Variable newserver -ErrorAction SilentlyContinue
        if(!($xml.ServerList.ServerInfo.name -match $computer)){
            $newserver = @($xml.ServerList.ServerInfo)[0].clone()
            $newserver.name = $computer
            $newserver.lastUpdateTime = “0001-01-01T00:00:00” 
            $newserver.status = “2”
            $newserver.locale = “sv-SE”
            $xml.ServerList.AppendChild($newserver) | Out-Null # Osäker om denna medför problem
        }
    }
    $xml.Save($servermanagerfile.FullName)
}Catch [System.Exception] {
    Write-LogEntry -Severity ERROR -Message "An error occurred while adding servers in Server Manager. Error message: $($_.Exception.Message)" -PrintOutput
}



# Install FSLogix
$FSLogixPath = "$ScriptPath\FSLogix"
$LocalInstallPath = "C:\Windows\Temp\FSLogixAppsSetup.exe"

IF(Test-Path $InstallMedia -PathType Leaf){
    $ADIncludeGroups = @("FSLogix-ODFC-Include-List","FSLogix-Profile-Include-List")
    $ADExcludeGroups = @("FSLogix-ODFC-Exclude-List","FSLogix-Profile-Exclude-List")

    $OUPath = Get-ADOrganizationalUnit -Filter "Name -like 'ServiceGroups'"

    Foreach($Server in $DefinedRDSH){

        Clear-Variable InstallResult,RemoteInstallPath -ErrorAction SilentlyContinue
        $RemoteInstallPath = "\\$($Server.Name)\C$\Windows\Temp\FSLogixAppsSetup.exe"

        Try{
            Copy-Item "$FSLogixPath\FSLogixAppsSetup.exe" $RemoteInstallPath -Force -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 3
            IF(Test-Path $RemoteInstallPath -PathType Leaf){
                Write-LogEntry -Severity INFO -Message "Successfully copied FSLogix install media to $($Server.Name)" -PrintOutput

                $InstallResult = Invoke-Command -ComputerName $Server.dNSHostName -ArgumentList $LocalInstallPath -ScriptBlock {
                    Start-Process $($args[0]) -ArgumentList "/quiet /norestart" -Wait

                    IF(Get-Service frxsvc){
                        return $false
                    }ELSE{
                        return "FSLogix service was not found after installation. Installation failed."
                    }
                }
        
                IF($InstallResult){
                    Write-LogEntry -Severity ERROR -Message $InstallResult -PrintOutput
                }ELSE{
                    Write-LogEntry -Severity INFO -Message "Successfully installed FSLogix on $($Server.Name)" -PrintOutput
                    Remove-Item $RemoteInstallPath -Force

                    IF($OUPath){
                        
                        Foreach($group in $ADIncludeGroups){
                            $LocalGroupName = $($group -replace "-"," ")
                            $ADGroupName = "SG_${group}_$($Server.name -replace "\D")"
                            Try{
                                New-ADGroup -Name $ADGroupName -Description "Member of the local group '$LocalGroupName' on $($Server.Name)" -GroupScope Global -GroupCategory Security -Path $OUPath.DistinguishedName -ErrorAction Stop
                                Write-LogEntry -Severity INFO -Message "Successfully created the AD group '$ADGroupName'"
                                Try{
                                    Add-ADGroupMember -Identity $group -Members $RDSAccessGroup -ErrorAction Stop
                                    Write-LogEntry -Severity INFO -Message "Successfully added group members to the AD group '$ADGroupName'"
                                }Catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to add members to the AD group $ADGroupName. Error message: $($_.Exception.Message)" -PrintOutput
                                }
                                Try{    
                                    Invoke-Command -ComputerName $Server.dNSHostName -ErrorAction Stop  -ScriptBlock{
                                        Add-LocalGroupMember -Group $LocalGroupName -Member "$env:USERDOMAIN\$ADGroupName" -ErrorAction Stop
                                    }
                                    Write-LogEntry -Severity INFO -Message "Successfully added the AD group '$ADGroupName' in the localgroup on $($Server.Name)"
                                }Catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to add the AD group $ADGroupName to the local group of $($Server.Name). Error message: $($_.Exception.Message)" -PrintOutput
                                }
                            }Catch [System.Exception] {
                                Write-LogEntry -Severity ERROR -Message "Failed to create the AD group $ADGroupName. Error message: $($_.Exception.Message)" -PrintOutput
                            }
                        }


                        Foreach($group in $ADExcludeGroups){
                            $LocalGroupName = $($group -replace "-"," ")
                            $ADGroupName = "SG_${group}_$($Server.name -replace "\D")"
                            Try{
                                New-ADGroup -Name $ADGroupName -Description "Member of the local group '$LocalGroupName' on $($Server.Name)" -GroupScope Global -GroupCategory Security -Path $OUPath.DistinguishedName -ErrorAction Stop
                                Write-LogEntry -Severity INFO -Message "Successfully created the AD group '$ADGroupName'"
                                Try{    
                                    Invoke-Command -ComputerName $Server.dNSHostName -ErrorAction Stop  -ScriptBlock{
                                        Add-LocalGroupMember -Group $LocalGroupName -Member "$env:USERDOMAIN\$ADGroupName" -ErrorAction Stop
                                    }
                                    Write-LogEntry -Severity INFO -Message "Successfully added the AD group '$ADGroupName' in the localgroup on $($Server.Name)"
                                }Catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to add the AD group $ADGroupName to the local group of $($Server.Name). Error message: $($_.Exception.Message)" -PrintOutput
                                }
                            }Catch [System.Exception] {
                                Write-LogEntry -Severity ERROR -Message "Failed to create the AD group $ADGroupName. Error message: $($_.Exception.Message)" -PrintOutput
                            }
                        }


                    }ELSE{

                        Foreach($group in $ADIncludeGroups){
                            $LocalGroupName = $($group -replace "-"," ")
                            $ADGroupName = "SG_${group}_$($Server.name -replace "\D")"
                            Try{
                                New-ADGroup -Name $ADGroupName -Description "Member of the local group '$LocalGroupName' on $($Server.Name)" -GroupScope Global -GroupCategory Security -ErrorAction Stop
                                Write-LogEntry -Severity INFO -Message "Successfully created the AD group '$ADGroupName'"
                                Try{
                                    Add-ADGroupMember -Identity $group -Members $RDSAccessGroup -ErrorAction Stop
                                    Write-LogEntry -Severity INFO -Message "Successfully added group members to the AD group '$ADGroupName'"
                                }Catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to add members to the AD group $ADGroupName. Error message: $($_.Exception.Message)" -PrintOutput
                                }
                                Try{    
                                    Invoke-Command -ComputerName $Server.dNSHostName -ErrorAction Stop  -ScriptBlock{
                                        Add-LocalGroupMember -Group $LocalGroupName -Member "$env:USERDOMAIN\$ADGroupName" -ErrorAction Stop
                                    }
                                    Write-LogEntry -Severity INFO -Message "Successfully added the AD group '$ADGroupName' in the localgroup on $($Server.Name)"
                                }Catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to add the AD group $ADGroupName to the local group of $($Server.Name). Error message: $($_.Exception.Message)" -PrintOutput
                                }
                            }Catch [System.Exception] {
                                Write-LogEntry -Severity ERROR -Message "Failed to create the AD group $ADGroupName. Error message: $($_.Exception.Message)" -PrintOutput
                            }
                        }


                        Foreach($group in $ADExcludeGroups){
                            $LocalGroupName = $($group -replace "-"," ")
                            $ADGroupName = "SG_${group}_$($Server.name -replace "\D")"
                            Try{
                                New-ADGroup -Name $ADGroupName -Description "Member of the local group '$LocalGroupName' on $($Server.Name)" -GroupScope Global -GroupCategory Security -ErrorAction Stop
                                Write-LogEntry -Severity INFO -Message "Successfully created the AD group '$ADGroupName'"
                                Try{    
                                    Invoke-Command -ComputerName $Server.dNSHostName -ErrorAction Stop  -ScriptBlock{
                                        Add-LocalGroupMember -Group $LocalGroupName -Member "$env:USERDOMAIN\$ADGroupName" -ErrorAction Stop
                                    }
                                    Write-LogEntry -Severity INFO -Message "Successfully added group members to the AD group '$ADGroupName'"
                                }Catch [System.Exception] {
                                    Write-LogEntry -Severity ERROR -Message "Failed to add the AD group $ADGroupName to the local group of $($Server.Name). Error message: $($_.Exception.Message)" -PrintOutput
                                }
                            }Catch [System.Exception] {
                                Write-LogEntry -Severity ERROR -Message "Failed to create the AD group $ADGroupName. Error message: $($_.Exception.Message)" -PrintOutput
                            }
                        }
                    }
                }
            }ELSE{
                Write-LogEntry -Severity ERROR -Message "'$RemoteInstallPath' was not found after copy." -PrintOutput
                Write-LogEntry -Severity WARNING -Message "FSLogix will have to be installed manually on $($Server.Name)" -PrintOutput
            }
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to copy 'FSLogixAppsSetup.exe' from script path to '$RemoteInstallPath'. Error message: $($_.Exception.Message)" -PrintOutput
            Write-LogEntry -Severity WARNING -Message "FSLogix will have to be installed manually on $($Server.Name)" -PrintOutput
        }
    }






    # Install GPO
    $GPOPath = "$FSLogixPath\GPOBackup"
    $ADMXPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\PolicyDefinitions"
    $ADMLPath = "$ADMXPath\en-US"
    
    # Copy files from script path
    Try{
        New-Item -Path $ADMLPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        Try{
            Copy-Item -Path "$FSLogixPath\fslogix.admx" -Destination "$ADMXPath\fslogix.admx" -Force -ErrorAction Stop
            Write-LogEntry -Severity INFO -Message "Successfully copied fslogix.admx to '$ADMXPath'." -PrintOutput
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to copy fslogix.admx to '$ADMXPath'. Error message: $($_.Exception.Message)"
        }
        Try{
            Copy-Item -Path "$FSLogixPath\fslogix.adml" -Destination "$ADMLPath\fslogix.adml" -Force -ErrorAction Stop
            Write-LogEntry -Severity INFO -Message "Successfully copied fslogix.adml to '$ADMLPath'." -PrintOutput
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to copy fslogix.adml to '$ADMLPath'. Error message: $($_.Exception.Message)"
        }
        Try{
            Copy-Item -Path "$FSLogixPath\Redirections.xml" -Destination "$ProfileDiskUNCPath\Configuration\Redirections.xml" -Force -ErrorAction Stop
            Write-LogEntry -Severity INFO -Message "Successfully copied Redirections.xml to '$ProfileDiskUNCPath\Configuration'." -PrintOutput
        }Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to copy Redirections.xml to '$ProfileDiskUNCPath\Configuration'. Error message: $($_.Exception.Message)"
        }

    }Catch [System.Exception] {
        Write-LogEntry -Severity ERROR -Message "Failed to create '$ADMLPath'. Error message: $($_.Exception.Message)"
    }

    # Import GPO from script folder
    $DomainDN = (Get-ADDomain).DistinguishedName
    $GPOItem = Get-ChildItem $GPOPath -Directory
    $XMLFilePath = (Join-Path -Path $GPOItem.FullName -ChildPath gpreport.xml)
    $XMLData = [XML](Get-Content $XMLFilePath)
    $GPOName = $XMLData.GPO.Name
    $GPOCheck = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    IF($GPOCheck){
        Write-LogEntry -Severity INFO -Message "The FSLogix GPO '$GPOName' already exist. Skipping GPO configuration." -PrintOutput
    }ELSE{
        Try{
            # Import GPO
            $ImportedGPO = Import-GPO -BackupId $GPOItem.Name -TargetName $GPOName -Path $GPOPath -CreateIfNeeded -ErrorAction Stop
            Write-LogEntry -Severity INFO -Message "Successfully imported FSLogix GPO '$GPOName'." -PrintOutput
            
            # Change GPO settings
            Try{
                Set-GPRegistryValue -Name $GPOName -Key HKLM\SOFTWARE\FSLogix\Profiles -ValueName VHDLocations -Value $ProfileDiskUNCPath -Type String -ErrorAction Stop | Out-Null
                Write-LogEntry -Severity INFO -Message "Successfully edited FSLogix GPO profile VHD Location to '$ProfileDiskUNCPath'." -PrintOutput
                Start-Sleep -Seconds 2
            }
            Catch [System.Exception] {
                Write-LogEntry -Severity ERROR -Message "Failed to edit FSLogix GPO profile VHD Location to '$ProfileDiskUNCPath'. Error message: $($_.Exception.Message)"
                Write-LogEntry -Severity WARNING -Message "Make sure to manually edit GPO setting 'VHD Location' under 'Computer Configuration/Administrative Templates/FSLogix/Profile Containers'"
            }
            Try{
                Set-GPRegistryValue -Name $GPOName -Key HKLM\SOFTWARE\FSLogix\Profiles -ValueName RedirXMLSourceFolder -Value "$ProfileDiskUNCPath\Configuration" -Type String -ErrorAction Stop | Out-Null
                Write-LogEntry -Severity INFO -Message "Successfully edited FSLogix GPO profile RedirXMLSourceFolder to '$ProfileDiskUNCPath\Configuration'." -PrintOutput
                Start-Sleep -Seconds 2
            }
            Catch [System.Exception] {
                Write-LogEntry -Severity ERROR -Message "Failed to edit FSLogix GPO profile RedirXMLSourceFolder to '$ProfileDiskUNCPath\Configuration'. Error message: $($_.Exception.Message)"
                Write-LogEntry -Severity WARNING -Message "Make sure to manually edit GPO setting 'RedirXMLSourceFolder' under 'Computer Configuration/Administrative Templates/FSLogix/Profile Containers/Advanced'"
            }
            Try{
                Set-GPRegistryValue -Name $GPOName -Key HKLM\SOFTWARE\Policies\FSLogix\ODFC -ValueName VHDLocations -Value "$ProfileDiskUNCPath\O365" -Type String -ErrorAction Stop | Out-Null
                Write-LogEntry -Severity INFO -Message "Successfully edited FSLogix GPO Office 365 VHD Location to '$ProfileDiskUNCPath\O365'." -PrintOutput
                Start-Sleep -Seconds 2
            }
            Catch [System.Exception] {
                Write-LogEntry -Severity ERROR -Message "Failed to edit FSLogix GPO profile Office 365 VHD Location to '$ProfileDiskUNCPath\O365'. Error message: $($_.Exception.Message)"
                Write-LogEntry -Severity WARNING -Message "Make sure to manually edit GPO setting 'VHD Location' under 'Computer Configuration/Administrative Templates/FSLogix/Office 365 Containers'"
            }

            Write-LogEntry -Severity WARNING -Message "Make sure to manually control check the GPO settings and link it to the RDS servers OU." -PrintOutput

        }
        Catch [System.Exception] {
            Write-LogEntry -Severity ERROR -Message "Failed to import FSLogix GPO '$GPOName'. Error message: $($_.Exception.Message)"
            Write-LogEntry -Severity WARNING -Message "Make sure to manually create GPO for FSLogix settings." -PrintOutput
        }
    }
}ELSE{
    Write-LogEntry -Severity ERROR -Message "The share path '$InstallMedia' could not be validated"
    Write-LogEntry -Severity WARNING -Message "Make sure to manually install FSLogix on session hosts and create GPO for FSLogix settings." -PrintOutput
}
Write-Host



$WriteTime = ([string]::Format("Time Elapsed: {0:d2}:{1:d2}:{2:d2}", $elapsedTime.Elapsed.hours, $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds))
$ElapsedTime.stop()
Write-LogEntry -Severity INFO -Message "Script is done!" -PrintOutput
Write-LogEntry -Severity INFO -Message $WriteTime -PrintOutput
Write-Verbose "See the log for more information: $LogPath" -Verbose
Pause