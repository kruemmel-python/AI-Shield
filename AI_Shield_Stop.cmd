@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0platform\windows\stop_ai_shield.ps1"
if errorlevel 1 pause

