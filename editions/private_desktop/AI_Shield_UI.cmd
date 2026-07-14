@echo off
setlocal
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File "%~dp0ui\start_private_ui.ps1"
if errorlevel 1 pause
