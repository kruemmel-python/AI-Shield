param([switch]$SkipRuntimeTest)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$staging = Join-Path $repo "runtime\driver-rc5"
$package = Join-Path $repo "driver_package\Release"
$installedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AI_Shield_Private_Desktop"))
$expectedRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + "\AI_Shield_Private_Desktop"
$log = Join-Path $repo "runtime\deploy-private-rc5.log"
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "RC5 patch deployment requires an elevated PowerShell."
}
if ($installedRoot -ne $expectedRoot -or -not (Test-Path -LiteralPath $installedRoot)) {
    throw "Installed Private Desktop root is missing or invalid."
}

Start-Transcript -LiteralPath $log -Force | Out-Null
try {
    $drivers = @("AIShieldWfp.sys", "AIShieldMiniFilter.sys", "AIShieldProcessGuard.sys")
    foreach ($name in $drivers) {
        $source = Join-Path $staging $name
        $signature = Get-AuthenticodeSignature -LiteralPath $source
        if ($signature.Status -ne "Valid") { throw "Invalid staged driver signature: $name" }
    }

    Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
    $driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
    & $driverctl stop
    if ($LASTEXITCODE -ne 0) { throw "Driver stop failed with exit code $LASTEXITCODE." }

    $installedPackage = Join-Path $installedRoot "driver_package\Release"
    foreach ($name in @($drivers + @("ai_shield_wfp.inf", "ai_shield_minifilter.inf",
            "ai_shield_process_guard.inf", "ai_shield_testsigning.cer"))) {
        $source = Join-Path $staging $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Staged file missing: $name" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $package $name) -Force
        Copy-Item -LiteralPath $source -Destination (Join-Path $installedPackage $name) -Force
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\install_drivers.ps1") -PackageDir $installedPackage
    if ($LASTEXITCODE -ne 0) { throw "Updated driver installation failed with exit code $LASTEXITCODE." }

    foreach ($relative in @("edition.json", "install_private_desktop.ps1",
            "ui\start_private_ui.ps1", "ui\AIShield.PrivateDesktop.UI.xaml")) {
        Copy-Item -LiteralPath (Join-Path $repo "editions\private_desktop\$relative") `
            -Destination (Join-Path $installedRoot $relative) -Force
    }
    foreach ($relative in @("manifest.json", "service_worker.js", "install_browser_sensor.ps1")) {
        Copy-Item -LiteralPath (Join-Path $repo "platform\windows\browser_extension\$relative") `
            -Destination (Join-Path $installedRoot "platform\windows\browser_extension\$relative") -Force
    }

    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $installedPackage "ai_shield_testsigning.cer"))
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\browser_extension\install_browser_sensor.ps1") `
        -Action install -PublisherThumbprint $certificate.Thumbprint -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Browser sensor update failed with exit code $LASTEXITCODE." }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\install_broker.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Broker restart failed with exit code $LASTEXITCODE." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\install_core_service.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Core restart failed with exit code $LASTEXITCODE." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "editions\private_desktop\start_private_desktop.ps1") -HardenDownloads
    if ($LASTEXITCODE -ne 0) { throw "Hardened policy activation failed with exit code $LASTEXITCODE." }

    if (-not $SkipRuntimeTest) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
            (Join-Path $repo "tests\windows_process_guard_rules.ps1")
        if ($LASTEXITCODE -ne 0) { throw "ProcessGuard runtime test failed with exit code $LASTEXITCODE." }
    }
    & $driverctl status
    Write-Output "AI Shield Private Desktop rc.5 patch is installed and download hardening is active."
} finally {
    Stop-Transcript | Out-Null
}
