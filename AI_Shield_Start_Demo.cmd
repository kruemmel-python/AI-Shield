@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0platform\windows\start_ai_shield.ps1" -Mode Demo -ListenPort 18080
if errorlevel 1 pause

