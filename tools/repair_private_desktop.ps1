param(
    [string]$DriverPackageDirectory = "driver_package\RC14",
    [switch]$LaunchUi
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run the AI Shield repair from an elevated PowerShell."
}
$package = if ([IO.Path]::IsPathRooted($DriverPackageDirectory)) {
    [IO.Path]::GetFullPath($DriverPackageDirectory)
} else { [IO.Path]::GetFullPath((Join-Path $repo $DriverPackageDirectory)) }
$releasePackage = Join-Path $repo "driver_package\Release"
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$signScript = Join-Path $repo "platform\windows\installer\sign_driver_package.ps1"
$uninstallDrivers = Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1"
$installer = Join-Path $repo "editions\private_desktop\install_private_desktop.ps1"

foreach ($name in @("AIShieldWfp.sys", "AIShieldMiniFilter.sys", "AIShieldProcessGuard.sys",
        "ai_shield_wfp.inf", "ai_shield_minifilter.inf", "ai_shield_process_guard.inf",
        "ai_shield_testsigning.cer")) {
    if (-not (Test-Path -LiteralPath (Join-Path $package $name) -PathType Leaf)) {
        throw "Repair package is incomplete: $name"
    }
}

Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
& $driverctl stop | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Old drivers could not be stopped." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstallDrivers | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Old drivers could not be removed." }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript -PackageDir $package
if ($LASTEXITCODE -ne 0) { throw "Corrected drivers could not be signed." }
New-Item -ItemType Directory -Force -Path $releasePackage | Out-Null
Get-ChildItem -LiteralPath $package -File | Copy-Item -Destination $releasePackage -Force

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -SuppressUiLaunch -RefreshInstalledComponents
if ($LASTEXITCODE -ne 0) { throw "Private Desktop repair installation failed." }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "tests\windows_content_policy_bypass.ps1")
if ($LASTEXITCODE -ne 0) { throw "Content-policy bypass regression failed." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "tests\windows_process_guard_rules.ps1")
if ($LASTEXITCODE -ne 0) { throw "ProcessGuard false-positive regression failed." }

$status = (& $driverctl status 2>&1) -join "`n"
if (([regex]::Matches($status, "state=4 win32_exit=0")).Count -ne 3) {
    throw "Driver health verification failed: $status"
}
if ($LaunchUi) { Start-Process -FilePath (Join-Path $repo "editions\private_desktop\AI_Shield_UI.cmd") }
Write-Output "AI Shield Private Desktop repair: PASS"
Write-Output $status
