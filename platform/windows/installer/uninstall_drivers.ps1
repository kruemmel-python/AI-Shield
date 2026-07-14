$ErrorActionPreference = "Stop"
$driverctl = Join-Path $PSScriptRoot "..\..\..\build_vs\Release\ai_shield_driverctl.exe"
Stop-Service -Name "AIShieldBroker" -Force -ErrorAction SilentlyContinue
& $driverctl stop
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $driverctl uninstall
exit $LASTEXITCODE
