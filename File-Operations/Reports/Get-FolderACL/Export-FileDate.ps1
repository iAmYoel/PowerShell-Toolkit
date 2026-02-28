#Inventerar en mapp med alla dess filer rekursivt för att exportera en lista på alla filer och datum för skapat, senast ändrat och senast öppnat.
#Exporters till C:\Temp\ExportFileList.csv
$Path = Read-Host "Please provide a path to search"
IF(Test-Path -Path $Path -PathType Container){
    Write-Host "`tGathering files..." -ForegroundColor Yellow
    $Result = Get-ChildItem $Path -Recurse -File | select FullName,Name,CreationTime,LastAccessTime,LastWriteTime
    Try{
        Write-Host "`tExporting to CSV..." -ForegroundColor Yellow
        $ExportPath = "C:\Temp\FileListExport.csv"
        $Result | Export-Csv -Path $ExportPath -Force -Encoding UTF8 -Delimiter ";" -NoTypeInformation -ErrorAction Stop
        Write-Host "CSV file was exported to $ExportPath"
        Write-Host "`tDone!" -ForegroundColor Yellow
        Pause
    }Catch [System.Exception] {
        Write-Host "Failed to export list to CSV!" -ForegroundColor Red -BackgroundColor Black
    }
}ELSE{
    Write-Warning "Not a valid path!"
    Pause
}

