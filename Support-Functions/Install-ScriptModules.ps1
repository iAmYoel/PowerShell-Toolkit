function Install-ScriptModules{
    param(
        [parameter(Mandatory=$true)]
        [string[]]$Modules = @()
    )

    foreach ($Module in $Modules) {
        Clear-Variable CurrentModule -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Stop"
        try{
            Import-Module -Name $Module
            $CurrentModule = Get-Module -Name $Module
            IF(!$CurrentModule){
                try{
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name NuGet -Force -ErrorAction Stop -Verbose:$false -Scope CurrentUser
                    try {
                        # Install current missing module
                        Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Scope CurrentUser
                        try {
                            # Import installed module
                            Import-Module -Name $Module
                            # Get imported module
                            $CurrentModule = Get-Module -Name $Module
                            IF(!$CurrentModule){
                                # Log module install failed
                                Break
                            }
                        }catch [System.Exception] {
                            Break
                        }
                    }catch [System.Exception] {
                        Break
                    }
                }catch [System.Exception] {
                    Break
                }
            }ELSE{
                # Log module import success
            }
        }catch{
            Break
        }
        $ErrorActionPreference = "Continue"
    }
}
