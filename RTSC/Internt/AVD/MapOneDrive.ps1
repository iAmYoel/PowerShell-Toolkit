$Path = $env:OneDrive -replace "C\:\\Users","\\localhost\Users$"
net use O: $Path
$Rename = New-Object -ComObject Shell.Application
$Rename.NameSpace("O:").Self.Name = "OneDrive"