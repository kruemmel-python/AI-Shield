@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0platform\windows\security\system_security_posture.ps1"
if errorlevel 1 pause

