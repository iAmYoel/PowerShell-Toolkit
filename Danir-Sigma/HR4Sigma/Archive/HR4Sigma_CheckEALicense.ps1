function Check-EALicense {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("E3","F3")]
        [String]$License
    )
    

    switch ($License) {
        'E3' { [int32]$MaxUsers = 1472 }
        'F3' { [int32]$MaxUsers = 525 }
    }
    
    $EAGroupName = "SG_Office365-${License}_Nexer-EA"
    $CSPGroupName = "SG_Microsoft365-${License}_Nexer-CSP"

    $EAGroupMembersCount = (Get-ADGroupMember -Identity $EAGroupName -Recursive).Count

    if ($EAGroupMembersCount -lt $MaxUsers) {
        $AddGroup = $EAGroupName
    }else {
        $AddGroup = $CSPGroupName
    }

    Return $AddGroup
}