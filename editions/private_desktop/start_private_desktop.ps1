param(
    [switch]$HardenDownloads,
    [switch]$StrictBrowser,
    [switch]$BlockUnsolicitedInbound
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    $forward = @()
    if ($HardenDownloads) { $forward += "-HardenDownloads" }
    if ($StrictBrowser) { $forward += "-StrictBrowser" }
    if ($BlockUnsolicitedInbound) { $forward += "-BlockUnsolicitedInbound" }
    Start-AIShieldElevated $PSCommandPath $forward
    exit 0
}

$root = Get-AIShieldPrivateRoot
$protectScript = Join-Path $root "platform\windows\protect_system.ps1"
Assert-AIShieldFile $protectScript "Protection script"
$arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $protectScript)
if ($HardenDownloads) { $arguments += "-HardenDownloads" }
if ($StrictBrowser) { $arguments += "-StrictBrowser" }
if ($BlockUnsolicitedInbound) { $arguments += "-BlockUnsolicitedInbound" }
& powershell.exe @arguments
if ($LASTEXITCODE -ne 0) { throw "AI Shield protection activation failed with exit code $LASTEXITCODE." }
Write-Output "Private workstation protection is active. No local web backend or server port is required."
