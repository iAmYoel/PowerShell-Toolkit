@ECHO off
@setlocal EnableDelayedExpansion

@set LF=^


@SET command=#
@FOR /F "tokens=*" %%i in ('findstr -bv @ "%~f0"') DO SET command=!command!!LF!%%i
@Powershell.exe -NoLogo -NoProfile -Command !command! & goto:eof


# *** POWERSHELL CODE STARTS HERE *** #

# Open new Powershell windows as Administrator
Start-Process Powershell.exe -verb runAs -ArgumentList '-ExecutionPolicy Bypass -NoLogo -NoProfile -Command """^&{

	# Script start
	try {
		Write-Host "`nDownloading Autopilot import script..." -ForegroundColor Yellow
		Install-Script -Name Get-WindowsAutopilotInfo -Force -ErrorAction Stop

		try {
			Get-InstalledScript -Name Get-WindowsAutoPilotInfo -ErrorAction Stop | Out-Null
			Write-Host "`nAutopilot import script has successfully been installed!" -ForegroundColor Yellow

			try {
				Write-Host "`nImporting device to Autopilot..." -ForegroundColor Yellow
				Get-WindowsAutopilotInfo.ps1 -Online -Grouptag "SEEN" -Assign -ErrorAction Stop
				Pause
			}
			catch [System.Exception] {
				Write-Host "`nFailed to import device to Autopilot.`n`nError message:`n$_`n" -ForegroundColor Red -BackgroundColor Black
				Pause
			}
		}
		catch [System.Exception] {
			Write-Host "`nFailed to find downloaded Autopilot import script.`n`nError message:`n$_`n" -ForegroundColor Red -BackgroundColor Black
			Pause
		}
	}
	catch [System.Exception] {
		Write-Host "`nFailed install Autopilot import script.`n`nError message:`n$_`n" -ForegroundColor Red -BackgroundColor Black
		Pause
	}
	# Script end

}"""
'
