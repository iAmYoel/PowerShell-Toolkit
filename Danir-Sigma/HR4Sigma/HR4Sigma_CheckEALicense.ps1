function Check-EALicense {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("E3","F3")]
        [String]$License,

        [Parameter(Mandatory)]
        #[ValidateScript({($_ -match '@sigma.se$')})]
        [String]$SamAccountName
    )
    

    switch ($License) {
        'E3' { 
                $EAGroupName = "SG_Office365-E3_Nexer_EA"
                $CSPGroupName = "SG_Microsoft365-E3_Nexer_CSP"
                [int32]$MaxUsers = 1472
            }
        
        'F3' {
                $EAGroupName = "SG_Office365-F3_Nexer_EA"
                $CSPGroupName = "SG_Microsoft365-F3_Nexer_CSP"
                [int32]$MaxUsers = 525
            }
    }

    $EAGroupMembers = Get-ADGroupMembers -Identity $EAGroupName

    if ($EAGroupMembers.Count -lt $MaxUsers) {
        $AddGroup = $EAGroupName
    }else {
        $AddGroup = $CSPGroupName
    }

    Add-ADGroupMember -Identity $AddGroup -Members $SamAccountName
}