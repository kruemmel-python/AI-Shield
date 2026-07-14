param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script from an elevated PowerShell."
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$runtime = Join-Path $repo "runtime"
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
Start-Transcript -Path (Join-Path $runtime "driver_update.log") -Force | Out-Null
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$buildScript = Join-Path $repo "platform\windows\build_drivers.ps1"
$signScript = Join-Path $repo "platform\windows\installer\sign_driver_package.ps1"
$installScript = Join-Path $repo "platform\windows\installer\install_drivers.ps1"
$package = Join-Path $repo "driver_package\$Configuration"

Stop-Service -Name "AIShieldBroker" -Force -ErrorAction SilentlyContinue
& $driverctl stop
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $buildScript -Configuration $Configuration
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript -PackageDir $package
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -PackageDir $package
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $kernelctl audit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_broker.ps1") -Action install
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$policyState = Join-Path $env:ProgramData "AIShield\policy\state.json"
if (Test-Path -LiteralPath $policyState) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action recover
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $driverctl status
& $kernelctl status
Stop-Transcript | Out-Null
