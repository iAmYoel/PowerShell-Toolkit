Add-Type -Path (Join-Path -Path (Split-Path $script:MyInvocation.MyCommand.Path) -ChildPath 'bin\CubicOrange.Windows.Forms.ActiveDirectory.dll')

$DialogPicker = New-Object CubicOrange.Windows.Forms.ActiveDirectory.DirectoryObjectPickerDialog

$DialogPicker.AllowedLocations = [CubicOrange.Windows.Forms.ActiveDirectory.Locations]::All
$DialogPicker.AllowedObjectTypes = [CubicOrange.Windows.Forms.ActiveDirectory.ObjectTypes]::Groups,[CubicOrange.Windows.Forms.ActiveDirectory.ObjectTypes]::Users,[CubicOrange.Windows.Forms.ActiveDirectory.ObjectTypes]::Computers
$DialogPicker.DefaultLocations = [CubicOrange.Windows.Forms.ActiveDirectory.Locations]::JoinedDomain
$DialogPicker.DefaultObjectTypes = [CubicOrange.Windows.Forms.ActiveDirectory.ObjectTypes]::Users
$DialogPicker.ShowAdvancedView = $false
$DialogPicker.MultiSelect = $true
$DialogPicker.SkipDomainControllerCheck = $true
$DialogPicker.Providers = [CubicOrange.Windows.Forms.ActiveDirectory.ADsPathsProviders]::Default

$DialogPicker.AttributesToFetch.Add('samAccountName')
$DialogPicker.AttributesToFetch.Add('title')
$DialogPicker.AttributesToFetch.Add('department')
$DialogPicker.AttributesToFetch.Add('distinguishedName')


$DialogPicker.ShowDialog() | Out-Null

$DialogPick = ($DialogPicker.Selectedobject).Name
$DialogPick
pause