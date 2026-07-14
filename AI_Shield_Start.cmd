@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0platform\windows\protect_system.ps1"
if errorlevel 1 pause
