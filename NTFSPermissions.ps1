Function Set-NTOwner{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$Path,

        [Parameter(Mandatory=$True)]
        [String]$Principal
    )
    
    try {
        # Define the principal for owner
        $PrincipalObject = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $Principal -ErrorAction Stop

        try {
            # Get a list of folders and files
            $Item = Get-Item -Path $Path -Force -ErrorAction Stop

            try {
                # Get the ACL from the item
                $Acl = Get-Acl -Path $Item -ErrorAction Stop

                # Update the in-memory ACL
                $Acl.SetOwner($PrincipalObject)
                
                try {
                    # Set the updated ACL on the target item
                    Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop
                }
                catch [System.Exception] {
                    throw "Could not set ACL for path. Error Message: $($_)"
                }
            }
            catch [System.Exception] {
                throw "Could not get ACL from path. Error Message: $($_)"
            }
        }
        catch [System.Exception] {
            throw "Could not find path. Error Message: $($_)"
        }
    }
    catch [System.Exception] {
        throw "Could not validate principal. Error Message: $($_)"
    }
}

Function Add-NTAccess{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$Path,

        [Parameter(Mandatory=$True)]
        [String]$Principal,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Read","Write","ReadAndExecute","Modify","FullControl")]
        [String]$Access,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Allow","Deny")]
        [String]$AccessType = "Allow",

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "This folder only",
            "This folder, subfolder and files",
            "This folder and subfolders",
            "This folder and files",
            "Subfolders and files only",
            "Subfolders only",
            "Files only",
            "This folder, child folder and child file only",
            "This folder and child folder only",
            "This folder and child file only",
            "Child folder and child file only",
            "Child folder only",
            "Child file only"
        )]
        [String]$Propagation = "This folder, subfolder and files"

    )

    $PropagationRules = @(

        New-Object psobject -Property @{Message="This folder only";Inheritance="None";Propagation="None"};
        New-Object psobject -Property @{Message="This folder and files";Inheritance="ObjectInherit";Propagation="None"};
        New-Object psobject -Property @{Message="This folder and child file only";Inheritance="ObjectInherit";Propagation="NoPropagateInherit"};
        New-Object psobject -Property @{Message="Files only";Inheritance="ObjectInherit";Propagation="InheritOnly"};
        New-Object psobject -Property @{Message="Child file only";Inheritance="ObjectInherit";Propagation="InheritOnly,NoPropagateInherit"};
        New-Object psobject -Property @{Message="This folder and subfolders";Inheritance="ContainerInherit";Propagation="None"};
        New-Object psobject -Property @{Message="This folder and child folder only";Inheritance="ContainerInherit";Propagation="NoPropagateInherit"};
        New-Object psobject -Property @{Message="Subfolders only";Inheritance="ContainerInherit";Propagation="InheritOnly"};
        New-Object psobject -Property @{Message="Child folder only";Inheritance="ContainerInherit";Propagation="InheritOnly,NoPropagateInherit"};
        New-Object psobject -Property @{Message="This folder, subfolder and files";Inheritance="ContainerInherit,ObjectInherit";Propagation="None"};
        New-Object psobject -Property @{Message="This folder, child folder and child file only";Inheritance="ContainerInherit","ObjectInherit";Propagation="NoPropagateInherit"};
        New-Object psobject -Property @{Message="Subfolders and files only";Inheritance="ContainerInherit,ObjectInherit";Propagation="InheritOnly"};
        New-Object psobject -Property @{Message="Child folder and child file only";Inheritance="ContainerInherit,ObjectInherit";Propagation="NoPropagateInherit,InheritOnly"}
    
    )

    $Props = $PropagationRules | where{$_.Message -like $Propagation}
    
    try{
        if (!$Props){throw}
        
        try {
                # Get a list of folders and files
                $Item = Get-Item -Path $Path -Force -ErrorAction Stop

            try {
                # Define the Principal and Permissions
                if($Item.PSIsContainer){
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal,$Access,$props.Inheritance,$props.Propagation,$AccessType) -ErrorAction Stop
        
                }else{
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal,$Access,$AccessType) -ErrorAction Stop
        
                }

                try {
                    # Get the ACL from the item
                    $Acl = Get-Acl -Path $Item -ErrorAction Stop

                    # Update the in-memory ACL
                    $Acl.SetAccessRule($AccessRule)
                    
                    try {
                        # Set the updated ACL on the target item
                        Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop

                    }
                    catch [System.Exception] {
                        throw "Could not set ACL for path. Error Message: $($_)"
                    }
                    
                }
                catch [System.Exception] {
                    throw "Could not get ACL from path. Error Message: $($_)"
                }
            }
            catch [System.Exception] {
                throw "Could not define principal and permissions. Error Message: $($_)"
            }
        }
        catch [System.Exception] {
            throw "Could not find path. Error Message: $($_)"
        }
    }
    catch [System.Exception] {
        throw "Propagation value is invalid."
    }
}

Function Remove-NTAccess{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$Path,

        [Parameter(Mandatory=$True)]
        [String]$Principal,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Read","Write","ReadAndExecute","Modify","FullControl")]
        [String]$Access,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Allow","Deny")]
        [String]$AccessType = "Allow"

    )

    try {
        # Get a list of folders and files
        $Item = Get-Item -Path $Path -Force -ErrorAction Stop

        try {
            # Define the Principal and Permissions
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal,$Access,$AccessType) -ErrorAction Stop

            try {
                # Get the ACL from the item
                $Acl = Get-Acl -Path $Item -ErrorAction Stop

                # Update the in-memory ACL
                $Acl.RemoveAccessRule($AccessRule) | Out-Null

                try {
                    # Set the updated ACL on the target item
                    Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop
                
                }
                catch [System.Exception] {  
                    throw "Could not set ACL for path. Error Message: $($_)"
                }
            }
            catch [System.Exception] {
                throw "Could not get ACL from path. Error Message: $($_)"
            }
        }
        catch [System.Exception] {
            throw "Could not define principal and permissions. Error Message: $($_)"
        }
    }
    catch [System.Exception] {
        throw "Could not find path. Error Message: $($_)"
    }
}

Function Purge-NTAccess{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$Path,

        [Parameter(Mandatory=$True)]
        [String]$Principal

    )

    try {
        # Get a list of folders and files
        $Item = Get-Item -Path $Path -Force -ErrorAction Stop

        try {
            # Define the Principal
            $PrincipalObject = New-Object System.Security.Principal.Ntaccount ($Principal) -ErrorAction Stop

            try {
                # Get the ACL from the item
                $Acl = Get-Acl -Path $Item -ErrorAction Stop

                # Update the in-memory ACL
                $Acl.PurgeAccessRules($PrincipalObject)

                try {
                    # Set the updated ACL on the target item
                    Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop

                }
                catch [System.Exception] {
                    throw "Could not set ACL for path. Error Message: $($_)"
                }
            }
            catch [System.Exception] {
                throw "Could not get ACL from path. Error Message: $($_)"
            }
        }
        catch [System.Exception] {
            throw "Could not define principal and permissions. Error Message: $($_)"
        }
    }
    catch [System.Exception] {
        throw "Could not find path. Error Message: $($_)"
    }
}

Function Purge-NTAllAccess{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$Path

    )

    try {
        # Get a list of folders and files
        $Item = Get-Item -Path $Path -Force -ErrorAction Stop

        try {
            # Get the ACL from the item
            $Acl = Get-Acl -Path $Item -ErrorAction Stop

            $Acl.Access | where{$_.isinherited -eq $false} | foreach{
                $Acl.RemoveAccessRule(
                    $(
                        if($_.identityreference -match "^APPLICATION PACKAGE AUTHORITY\\"){
                            New-Object System.Security.AccessControl.FileSystemAccessRule(($_.IdentityReference -replace "^APPLICATION PACKAGE AUTHORITY\\"),$_.FileSystemRights,$_.AccessControlType)
                        }else{
                            $_
                        }
                    )
                ) | Out-Null
            }

            try {
                # Set the updated ACL on the target item
                Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop

            }
            catch [System.Exception] {
                throw "Could not set ACL for path. Error Message: $($_)"
            }
        }
        catch [System.Exception] {
            throw "Could not get ACL from path. Error Message: $($_)"
        }
    }
    catch [System.Exception] {
        throw "Could not find path. Error Message: $($_)"
    }
}

Function Set-NTInheritance{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$Path,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Enable","Disable")]
        [String]$Inheritance,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Retain","Remove")]
        [String]$ExistingAccess = "Retain"

    )
    
    if ($Inheritance -like "Enable") {
        $inh = $False
    }elseif($Inheritance -like "Disable"){
        $inh = $True
    }

    if ($ExistingAccess -like "Retain") {
        $acc = $True
    }elseif($ExistingAccess -like "Remove"){
        $acc = $False
    }

    try {
        # Get a list of folders and files
        $Item = Get-Item -Path $Path -Force -ErrorAction Stop

        try {
            # Get the ACL from the item
            $Acl = Get-Acl -Path $Item -ErrorAction Stop

            # Update the in-memory ACL
            $Acl.SetAccessRuleProtection($inh,$acc)

            try {
                # Set the updated ACL on the target item
                Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop
                
                if (($inh -eq $False) -AND ($acc -eq $False)) {
                    try {
                        # Get the ACL from the item
                        $Acl = Get-Acl -Path $Item -ErrorAction Stop
                        
                        $Acl.Access | where{$_.isinherited -eq $false} | foreach{
                            $Acl.RemoveAccessRule(
                                $(
                                    if($_.identityreference -match "^APPLICATION PACKAGE AUTHORITY\\"){
                                        New-Object System.Security.AccessControl.FileSystemAccessRule(($_.IdentityReference -replace "^APPLICATION PACKAGE AUTHORITY\\"),$_.FileSystemRights,$_.AccessControlType)
                                    }else{
                                        $_
                                    }
                                )
                            ) | Out-Null
                        }

                        try {
                            # Set the updated ACL on the target item
                            Set-Acl -Path $Item -AclObject $Acl -ErrorAction Stop
                        }
                        catch [System.Exception] {
                            throw "Could not set ACL for path. Error Message: $($_)"
                        }
                    }
                    catch [System.Exception] {
                        throw "Could not get ACL from path. Error Message: $($_)"
                    }
                }
            }
            catch [System.Exception] {
                throw "Could not set ACL for path. Error Message: $($_)"
            }
        }
        catch [System.Exception] {
            throw "Could not get ACL from path. Error Message: $($_)"
        }
    }
    catch [System.Exception] {
        throw "Could not find path. Error Message: $($_)"
    }
}




