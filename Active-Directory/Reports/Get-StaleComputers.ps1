Function Get-StaleComputers {
    <#
        .SYNOPSIS
        This Function searches Active Directory for stale computer objects.
         
        .DESCRIPTION
        This Function searches Active Directory for stale computer objects based on the NumberOfDays parameter. It checks both the LastLogonDate and PasswordLastSet attributes against NumberOfDays.
 
        .PARAMETER NumberOfDays
            The number of days old a computer object is to be considered stale.  Default is 120 days.
 
        .EXAMPLE
        Get-StaleComputers
 
        Returns Stale computers using the default values of 120 Days.
        Number Of Days: 120
 
        .EXAMPLE
        Get-StaleComputers -NumberOfDays 180
 
        Returns Stale computers using the value of 180 Days.
        Number Of Days: 180
 
    #>
 
    [CmdletBinding()]
    param(
        # # of days ago to purge
        [int] $NumberOfDays = 120
    )
 
    # Computer Variable Initializations
    Write-Verbose -Message "Initializing Variables."
    $DaysAgo = 0 - $NumberOfDays
    $AllADComputerObjects = $null
    Write-Verbose "Number Of Days: $NumberOfDays"
 
    # Computer Properties List
    Write-Verbose -Message "Set Property Variables."
    $ComputerPropsAll = $("Name","SamAccountName","Enabled","OperatingSystem","OperatingSystemServicePack","IPv4Address","LastLogonDate","PasswordLastSet","Modified","canonicalname","DistinguishedName","whenChanged","whenCreated")
    $ComputerPropsPlusCreator = $("Name","SamAccountName","Enabled","OperatingSystem","OperatingSystemServicePack","IPv4Address","LastLogonDate","PasswordLastSet","Modified","canonicalname","DistinguishedName","whenChanged","whenCreated",@{Name="CreatedBy";Expression={$(([ADSI]"LDAP://$($_.DistinguishedName)").psbase.ObjectSecurity.Owner)}})
 
    # Gather Computer Data from Active Directory and Analyze
    Write-Verbose -Message "Querying Active Directory for Computer Objects..." 
    $AllADComputerObjects = (Get-ADComputer -Filter "OperatingSystem -notlike '*Server*'" -Properties $ComputerPropsAll)
 
    Write-Verbose -Message "Searching Active Directory for Stale ($DaysAgo Days) Computers."
    $StaleDate = (Get-Date).AddDays($DaysAgo)
    ($AllADComputerObjects | ? {$_.PasswordLastSet -le $StaleDate -and $_.LastLogonDate -le $StaleDate}) | Select-Object $ComputerPropsPlusCreator
}