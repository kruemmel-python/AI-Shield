$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    Start-AIShieldElevated $PSCommandPath
    exit 0
}
$root = Get-AIShieldPrivateRoot
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\stop_ai_shield.ps1")
if ($LASTEXITCODE -ne 0) { throw "AI Shield could not be stopped cleanly." }
