$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    Start-AIShieldElevated $PSCommandPath
    exit 0
}
$root = Get-AIShieldPrivateRoot
Write-Output "AI Shield Private Desktop status"
& (Join-Path $root "build_vs\Release\ai_shield_driverctl.exe") status
Write-Output ""
Get-Service AIShieldCore,AIShieldBroker -ErrorAction SilentlyContinue |
    Select-Object Name,Status,StartType | Format-Table -AutoSize
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "private_posture.ps1")
