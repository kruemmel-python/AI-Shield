@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0platform\windows\protect_system.ps1" -StrictBrowser -BlockUnsolicitedInbound -HardenDownloads -HardenKernelHardware
if errorlevel 1 pause
