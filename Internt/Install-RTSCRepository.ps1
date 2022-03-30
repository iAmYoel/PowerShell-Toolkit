$BaseURL = "https://nuget.rtscloud.se"
$URLCheck = Invoke-WebRequest -Uri $BaseURL

if ($URLCheck.StatusCode -ne 200) {
    Write-Output "Base URL to the RTSC Powershell repository did not return status code 200."
    Exit 1603
}

$URL = "$BaseURL/nuget/rtsc-psmodules"
$URL2 = "$BaseURL/nuget/rtsc-psscripts"

try {
    Register-PSRepository -Name RTSC -SourceLocation $URL -PublishLocation $URL -ScriptSourceLocation $URL2 -ScriptPublishLocation $URL2 -InstallationPolicy Trusted -PackageManagementProvider NuGet -ErrorAction Stop
}
catch [System.Exception] {
    Write-Output "An error occurred while registering RTSC repository. Error Message: $_"
    Exit 1603
}
    

if (Get-PSRepository RTSC) {
    Write-Output "RTSC Powershell repository was successfully registered."
    Exit 0
}else{
    Write-Output "RTSC Repository was not found after registration."
    Exit 1603
}
