<#
╔═════════════╦═════════════╦═══════════════════════════════╦════════════════════════╦══════════════════╦═══════════════════════════════╦═════════════════╦══════════════╗
║             ║ folder only ║ folder, sub-folders and files ║ folder and sub-folders ║ folder and files ║ sub-folders and files         ║ sub-folders     ║    files     ║
╠═════════════╬═════════════╬═══════════════════════════════╬════════════════════════╬══════════════════╬═══════════════════════════════╬═════════════════╬══════════════╣
║ Propagation ║ none        ║ none                          ║ none                   ║ none             ║ InheritOnly                   ║ InheritOnly     ║ InheritOnly  ║
║ Inheritance ║ none        ║ ContainerInherit|ObjectInherit║ ContainerInherit       ║ ObjectInherit    ║ ContainerInherit|ObjectInherit║ ContainerInherit║ ObjectInherit║
╚═════════════╩═════════════╩═══════════════════════════════╩════════════════════════╩══════════════════╩═══════════════════════════════╩═════════════════╩══════════════╝





No Flags                                                          -  Target folder.

ObjectInherit                                                     -  Target folder, child object (file), grandchild object (file).

ObjectInherit and NoPropagateInherit                              -  Target folder, child object (file).

ObjectInherit and InheritOnly                                     -  Child object (file), grandchild object (file).

ObjectInherit, InheritOnly, and NoPropagateInherit                -  Child object (file).

ContainerInherit                                                  -  Target folder, child folder, grandchild folder.

ContainerInherit, and NoPropagateInherit                          -  Target folder, child folder.

ContainerInherit, and InheritOnly                                 -  Child folder, grandchild folder.

ContainerInherit, InheritOnly, and NoPropagateInherit             -  Child folder.

ContainerInherit, and ObjectInherit                               -  Target folder, child folder, child object (file), grandchild folder, grandchild object (file).

ContainerInherit, ObjectInherit, and NoPropagateInherit           -  Target folder, child folder, child object (file).

ContainerInherit, ObjectInherit, and InheritOnly                  -  Child folder, child object (file), grandchild folder, grandchild object (file).

ContainerInherit, ObjectInherit, NoPropagateInherit, InheritOnly  -  Child folder, child object (file).

#>

$PropagationRules = @(

    New-Object psobject -Property @{Message="This folder only";Flags="None","None"};
    New-Object psobject -Property @{Message="This folder and files";Flags="ObjectInherit","None"};
    New-Object psobject -Property @{Message="This folder and child file only";Flags="ObjectInherit","NoPropagateInherit"};
    New-Object psobject -Property @{Message="Files only";Flags="ObjectInherit","InheritOnly"};
    New-Object psobject -Property @{Message="Child file only";Flags="ObjectInherit","InheritOnly","NoPropagateInherit"};
    New-Object psobject -Property @{Message="This folder and subfolders";Flags="ContainerInherit","None"};
    New-Object psobject -Property @{Message="This folder and child folder only";Flags="ContainerInherit","NoPropagateInherit"};
    New-Object psobject -Property @{Message="Subfolders only";Flags="ContainerInherit","InheritOnly"};
    New-Object psobject -Property @{Message="Child folder only";Flags="ContainerInherit","InheritOnly","NoPropagateInherit"};
    New-Object psobject -Property @{Message="This folder, subfolder and files";Flags="ContainerInherit","ObjectInherit","None"};
    New-Object psobject -Property @{Message="This folder, child folder and child file only";Flags="ContainerInherit","ObjectInherit","NoPropagateInherit"};
    New-Object psobject -Property @{Message="Subfolders and files only";Flags="ContainerInherit","ObjectInherit","InheritOnly"};
    New-Object psobject -Property @{Message="Child folder and child file only";Flags="ContainerInherit","ObjectInherit","NoPropagateInherit","InheritOnly"}

)



Function Get-ACLPropagation{

    Param(

        $ACLAccessObject,

        $PropagationRules

    )

    Clear-Variable Flags -ErrorAction SilentlyContinue
    $Flags = $ACLAccessObject.InheritanceFlags -Split ", "
    $Flags += $ACLAccessObject.PropagationFlags -split ", "

    Foreach($Propagation in $PropagationRules){

        Clear-Variable AppliedToCheck -ErrorAction SilentlyContinue
        $AppliedToCheck = @(Compare-Object -ReferenceObject $Flags -DifferenceObject $Propagation.Flags -Verbose).Length -eq 0

        IF($AppliedToCheck){
            
            $Propagation.Message
    
        }
    }
}