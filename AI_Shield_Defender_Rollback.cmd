@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0platform\windows\security\defender_audit_baseline.ps1"" -Action rollback -ConfirmSystemChange'"
if errorlevel 1 pause

