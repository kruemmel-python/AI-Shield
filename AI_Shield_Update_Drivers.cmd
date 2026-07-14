@echo off
setlocal
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0platform\windows\installer\update_and_install_drivers.ps1"" -Configuration Release'"
if errorlevel 1 pause
