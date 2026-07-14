@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_private_desktop.ps1"
if errorlevel 1 pause
