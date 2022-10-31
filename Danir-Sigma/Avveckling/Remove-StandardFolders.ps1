$LogPath = "C:\RTSC-Delete.log"
$NewDeleteFolder = "C:\RTSC-Delete"

Start-Transcript -Path $LogPath -Append -Force

$DeleteFolders = @(
    "C:\SigmaFolder",
    "C:\RTSCloud",
    "C:\Scripts",
    "C:\SITS"
)

try {
    New-Item -Path $NewDeleteFolder -ItemType Directory -Force -ErrorAction Stop
}
catch {
    throw "Could not create the folder C:\RTSC-Delete"
    Break
}

foreach ($item in $DeleteFolders) {
    if(Test-Path $item){
        Move-Item -Path $item -Destination $NewDeleteFolder -Force
    }


}

Stop-Transcript