Function Get-StaleComputersReport {
    <#
        .SYNOPSIS
        This Function searches Active Directory for stale computer objects.
         
        .DESCRIPTION
        This Function searches Active Directory for stale computer objects based on the NumberOfDays parameter. It checks both the LastLogonDate and PasswordLastSet attributes against NumberOfDays.
 
        .PARAMETER NumberOfDays
            The number of days old a computer object is to be considered stale.  Default is 120 days.
 
        .PARAMETER ExportToCSV
            If specified location and CSV file to output the results. Default is the script directory location and a file named StaleComputers_yyyyMMss.csv.
 
        .EXAMPLE
        Get-StaleComputers
 
        Returns Stale computers using the default values of 120 Days and writes a csv file to the scripts execution location.
        Number Of Days: 120
        Export To CSV : C:\Scripts\StaleComputers_20200106.csv
 
        .EXAMPLE
        Get-StaleComputers -NumberOfDays 180
 
        Returns Stale computers using the value of 180 Days and writes a csv file to the scripts execution location.
        Number Of Days: 180
        Export To CSV : C:\Scripts\StaleComputers_20200106.csv
 
        .EXAMPLE
        Get-StaleComputers -NumberOfDays 180
 
        Returns Stale computers using the value of 180 Days and writes a csv file to the scripts execution location.
        Number Of Days: 180
        Export To CSV : C:\Scripts\StaleComputers_20200106.csv    
 
        .EXAMPLE
        Get-StaleComputers -NumberOfDays 180 -ExportToCSV c:\Reports\StaleComputers.csv
 
        Returns Stale computers using the value of 180 Days and writes a csv file to C:\Reports\StaleComputers.csv.
        Number Of Days: 180
        Export To CSV : c:\Reports\StaleComputers.csv
    #>
 
    [CmdletBinding()]
    param(
        # # of days ago to purge
        [int] $NumberOfDays = 120,
        # Specifies to export to the specified csv file
        [String] $ExportToCSV = $($PSScriptRoot + "\StaleComputers_" + $(Get-Date -Format yyyyMMdd) +".csv")
    )
 
    # Computer Variable Initializations
    Write-Verbose -Message "Initializing Variables."
    $DaysAgo = 0 - $NumberOfDays
    $AllADComputerObjects = $null
    Write-Output "Number Of Days: $NumberOfDays"
    Write-Output "Export To CSV : $ExportToCSV"
 
    # Computer Properties List
    Write-Verbose -Message "Set Property Variables."
    $ComputerPropsAll = $("Name","SamAccountName","Enabled","OperatingSystem","OperatingSystemServicePack","IPv4Address","LastLogonDate","PasswordLastSet","Modified","canonicalname","DistinguishedName","whenChanged","whenCreated")
    $ComputerPropsPlusCreator = $("Name","SamAccountName","Enabled","OperatingSystem","OperatingSystemServicePack","IPv4Address","LastLogonDate","PasswordLastSet","Modified","canonicalname","DistinguishedName","whenChanged","whenCreated",@{Name="CreatedBy";Expression={$(([ADSI]"LDAP://$($_.DistinguishedName)").psbase.ObjectSecurity.Owner)}})
 
    # Gather Computer Data from Active Directory and Analyze
    Write-Verbose -Message "Querying Active Directory for Computer Objects..." 
    $AllADComputerObjects = (Get-ADComputer -Filter "OperatingSystem -notlike '*Server*'" -Properties $ComputerPropsAll)
 
    Write-Verbose -Message "Searching Active Directory for Stale ($DaysAgo Days) Computers."
    $StaleDate = (Get-Date).AddDays($DaysAgo)
    $StaleComputers = ($AllADComputerObjects | ? {$_.PasswordLastSet -le $StaleDate -and $_.LastLogonDate -le $StaleDate}) | Select-Object $ComputerPropsPlusCreator
    If ($StaleComputers) {
        $StaleComputers | Export-Csv -Path $ExportToCSV -Encoding UTF8 -Delimiter ";" -NoTypeInformation -Force
        Write-Output "Stale Computers Found: $($StaleComputers.count)"
        Write-Output "Output was sent to $ExportToCSV"
    } Else {
        Write-Output "No Stale Computers Found."
    }
}