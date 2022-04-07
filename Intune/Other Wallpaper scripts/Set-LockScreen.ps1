Function Set-LockScreen {
    param(
        <#

        .SYNOPSIS
        Applies a specified wallpaper to the current user's lock screen

        .PARAMETER ImagePath
        Provide the exact path to the image

        .EXAMPLE
        Set-LockScreen -ImagePath "C:\Wallpaper\Default.jpg"

    #>

        [parameter(Mandatory=$True)]
        # Provide path to image
        [string]$ImagePath
    )

    [Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,ContentType=WindowsRuntime] | Out-Null

    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    Function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }
    Function AwaitAction($WinRtAction) {
        $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]
        $netTask = $asTask.Invoke($null, @($WinRtAction))
        $netTask.Wait(-1) | Out-Null
    }

    [Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime] | Out-Null

    $image = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync("$ImagePath")) ([Windows.Storage.StorageFile])

    AwaitAction ([Windows.System.UserProfile.LockScreen]::SetImageFileAsync($image))

}